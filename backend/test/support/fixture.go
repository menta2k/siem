package support

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/clickhouse" // register the driver
	_ "github.com/golang-migrate/migrate/v4/source/file"         // register the source
	"github.com/google/uuid"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/menta2k/siem/internal/conf"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	redisdata "github.com/menta2k/siem/internal/data/redis"
	"github.com/menta2k/siem/internal/data/stream"
	"github.com/menta2k/siem/internal/tenancy"
)

// Fixture is a fully-migrated environment: containers, connections, and repositories.
type Fixture struct {
	Stack      *Stack
	ClickHouse *chdata.Client
	Redis      *redisdata.Client
	Locker     chdata.Locker
	Tenants    *chdata.TenantRepo
	Users      *chdata.UserRepo
	Audit      *chdata.AuditRepo
	Feeds      *chdata.FeedRepo
	Events     *chdata.EventRepo
	Health     *chdata.HealthRepo
	Producer   *stream.Producer
	// Database is the schema the stack created, so a test that reads ClickHouse's own
	// system tables can filter to it without hardcoding the name.
	Database string
}

// newSharedFixture builds a fixture and its teardown.
//
// It returns errors rather than taking a *testing.T because it runs from TestMain,
// where no test exists yet to fail.
func newSharedFixture(ctx context.Context) (*Fixture, func(), error) {
	stack, down, err := startStack(ctx)
	stopContainers := func() {
		if teardownErr := down.run(); teardownErr != nil {
			fmt.Printf("container teardown: %v\n", teardownErr)
		}
	}
	if err != nil {
		stopContainers()
		return nil, func() {}, err
	}

	fixture, closeConns, err := connect(ctx, stack)
	if err != nil {
		stopContainers()
		return nil, func() {}, err
	}

	return fixture, func() {
		closeConns()
		stopContainers()
	}, nil
}

// connect applies migrations and opens every client the repositories need.
func connect(ctx context.Context, stack *Stack) (*Fixture, func(), error) {
	if err := applyMigrations(stack.ClickHouseDSN); err != nil {
		return nil, func() {}, err
	}

	chClient, err := chdata.New(ctx, conf.ClickHouse{
		Addr:             stack.ClickHouseAddr,
		Database:         testDatabase,
		Username:         testUser,
		Password:         testPassword,
		MaxExecutionTime: 30 * time.Second,
		MaxOpenConns:     16,
	}, chdata.Options{})
	if err != nil {
		return nil, func() {}, fmt.Errorf("connect clickhouse: %w", err)
	}

	redisClient, err := redisdata.New(ctx, conf.Redis{Addr: stack.RedisAddr})
	if err != nil {
		_ = chClient.Close()
		return nil, func() {}, fmt.Errorf("connect redis: %w", err)
	}

	// Topics are created explicitly rather than relying on auto-creation.
	//
	// Redpanda's auto-create fires on a metadata request, not on a produce, so the
	// first publish to a fresh topic races it and fails with
	// UNKNOWN_TOPIC_OR_PARTITION — or, worse, blocks on retries until the produce
	// timeout and surfaces as an unexplained 503. Creating them up front makes the
	// suite deterministic.
	if err := ensureTopics(ctx, stack); err != nil {
		_ = redisClient.Close()
		_ = chClient.Close()
		return nil, func() {}, err
	}

	producer, err := stream.NewProducer(redpandaConf(stack))
	if err != nil {
		_ = redisClient.Close()
		_ = chClient.Close()
		return nil, func() {}, fmt.Errorf("connect redpanda: %w", err)
	}

	return wire(stack, chClient, redisClient, producer), func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = producer.Close(closeCtx)
		_ = redisClient.Close()
		_ = chClient.Close()
	}, nil
}

// EnsureTopics creates the named topics, tolerating ones that already exist.
//
// Tests that consume give themselves their own topic names. Sharing topics across a
// package would otherwise make every consumer group replay the whole history — the
// consumer deliberately starts at the beginning so a new production group cannot skip
// committed events, and that same property makes shared test topics unusable.
func (f *Fixture) EnsureTopics(ctx context.Context, topics ...string) error {
	return createTopics(ctx, f.Stack, topics...)
}

// ensureTopics creates the pipeline topics before any producer touches them.
func ensureTopics(ctx context.Context, stack *Stack) error {
	cfg := redpandaConf(stack)
	return createTopics(ctx, stack, cfg.TopicRaw, cfg.TopicNormalized, cfg.TopicDLQ)
}

func createTopics(ctx context.Context, stack *Stack, topics ...string) error {
	client, err := kgo.NewClient(kgo.SeedBrokers(stack.RedpandaBroker))
	if err != nil {
		return fmt.Errorf("open admin client: %w", err)
	}
	defer client.Close()

	admin := kadm.NewClient(client)
	// One partition and one replica: this is a single-node container, and a higher
	// replication factor would simply fail to satisfy.
	resp, err := admin.CreateTopics(ctx, 1, 1, nil, topics...)
	if err != nil {
		return fmt.Errorf("create topics: %w", err)
	}
	for _, result := range resp {
		// TOPIC_ALREADY_EXISTS is fine — a previous run may have created it.
		if result.Err != nil && !errors.Is(result.Err, kerr.TopicAlreadyExists) {
			return fmt.Errorf("create topic %s: %w", result.Topic, result.Err)
		}
	}
	return nil
}

// wire assembles the repositories over the open connections.
func wire(
	stack *Stack, ch *chdata.Client, rdb *redisdata.Client, producer *stream.Producer,
) *Fixture {
	locker := chdata.NewLocker(rdb)

	return &Fixture{
		Stack:      stack,
		ClickHouse: ch,
		Redis:      rdb,
		Locker:     locker,
		Tenants:    chdata.NewTenantRepo(ch, locker),
		Users:      chdata.NewUserRepo(ch, locker),
		Audit:      chdata.NewAuditRepo(ch, locker),
		Feeds:      chdata.NewFeedRepo(ch, locker),
		Events:     chdata.NewEventRepo(ch),
		Health:     chdata.NewHealthRepo(ch),
		Producer:   producer,
		Database:   testDatabase,
	}
}

// applyMigrations runs the same files `make migrate` runs.
//
// A hand-written test schema would drift from production and quietly stop testing the
// real thing, so these tests deliberately use the shipped migrations.
func applyMigrations(dsn string) error {
	dir, err := MigrationsDir()
	if err != nil {
		return err
	}

	m, err := migrate.New("file://"+dir, dsn)
	if err != nil {
		return fmt.Errorf("open migrations: %w", err)
	}
	defer func() { _, _ = m.Close() }()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}

func redpandaConf(stack *Stack) conf.Redpanda {
	return conf.Redpanda{
		Brokers:         []string{stack.RedpandaBroker},
		TopicRaw:        "siem.events.raw",
		TopicNormalized: "siem.events.normalized",
		TopicDLQ:        "siem.events.dlq",
		ProduceTimeout:  10 * time.Second,
	}
}

// RedpandaConf returns broker settings pointing at this fixture's container.
func (f *Fixture) RedpandaConf() conf.Redpanda { return redpandaConf(f.Stack) }

// NewTenant creates an isolated tenant and returns a context scoped to it.
//
// This is what makes container sharing safe. Tenant scoping is a physical property of
// every table's sort key, so two tests on one ClickHouse instance cannot see each
// other's rows any more than two customers can — and a test that leaks rows cannot
// make another pass or fail spuriously.
func (f *Fixture) NewTenant(t *testing.T, name string) (context.Context, chdata.Tenant) {
	t.Helper()

	unique := fmt.Sprintf("%s-%s", name, uuid.NewString()[:8])
	created, err := f.Tenants.Create(context.Background(), chdata.Tenant{
		Name:                    unique,
		Status:                  chdata.TenantStatusActive,
		RawRetentionDays:        30,
		CorrelatedRetentionDays: 90,
		AlertRetentionDays:      365,
		CorrelationWindowMS:     5000,
		LatenessBoundMS:         900000,
		ScoreConflictThreshold:  0.8,
	})
	if err != nil {
		t.Fatalf("create tenant %q: %v", unique, err)
	}

	ctx := tenancy.WithTenant(context.Background(),
		tenancy.Tenant{ID: created.ID, Name: created.Name})
	return ctx, created
}

// NewFixture starts a DEDICATED stack for one test, and tears it down afterwards.
//
// Almost nothing should call this. Prefer SharedTenant, which reuses the package's
// containers and is an order of magnitude faster; a suite that reaches for NewFixture
// by habit pays roughly ten seconds per test and starts failing on container startup
// timeouts under load. This exists for the rare test that needs a pristine server,
// such as one asserting on migration behaviour itself.
func NewFixture(t *testing.T) *Fixture {
	t.Helper()

	if skipContainers() {
		t.Skip("docker unavailable — skipping container-backed test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()

	fixture, cleanup, err := newSharedFixture(ctx)
	t.Cleanup(cleanup)
	if err != nil {
		t.Fatalf("start dedicated test stack: %v", err)
	}
	return fixture
}

// Sync makes recent inserts visible to subsequent reads.
//
// ClickHouse inserts land asynchronously at the part level, so a read immediately
// after a write can miss it. Production reads tolerate that; a test asserting on a
// just-written row cannot, so it synchronises explicitly rather than sleeping and
// hoping.
func (f *Fixture) Sync(t *testing.T, table string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := f.ClickHouse.Exec(ctx, fmt.Sprintf("OPTIMIZE TABLE %s FINAL", table)); err != nil {
		t.Logf("optimize %s: %v", table, err)
	}
}

// CountRows returns the row count for a table within the context's tenant.
//
// Pass "FINAL" for a ReplacingMergeTree table, or a pre-merge duplicate will be
// miscounted as two rows.
func (f *Fixture) CountRows(ctx context.Context, t *testing.T, table, final string) uint64 {
	t.Helper()

	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		t.Fatalf("count %s: %v", table, err)
	}

	query := fmt.Sprintf("SELECT count() FROM %s %s WHERE tenant_id = ?", table, final)

	rows, err := f.ClickHouse.Query(ctx, query, tenantID)
	if err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	defer func() { _ = rows.Close() }()

	var count uint64
	if rows.Next() {
		if err := rows.Scan(&count); err != nil {
			t.Fatalf("scan count for %s: %v", table, err)
		}
	}
	return count
}
