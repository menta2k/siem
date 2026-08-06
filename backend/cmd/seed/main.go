// Command seed creates the demo tenant, an admin user, and one feed per vendor.
//
// This is the first thing a new developer runs, so it optimises for being obvious
// rather than clever: it prints the credentials it created, and it is IDEMPOTENT —
// running it twice reuses what exists instead of failing on a duplicate or, worse,
// creating a second tenant with the same name.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/auth"
	"github.com/menta2k/siem/internal/conf"
	"github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/data/redis"
	"github.com/menta2k/siem/internal/secrets"
	"github.com/menta2k/siem/internal/tenancy"
	"github.com/menta2k/siem/internal/vendors"
)

func main() {
	var (
		tenantName = flag.String("tenant", "acme", "demo tenant name")
		email      = flag.String("email", "admin@example.com", "admin login address")
		password   = flag.String("password", "", "admin password; generated when empty")
	)
	flag.Parse()

	if err := run(context.Background(), *tenantName, *email, *password); err != nil {
		fmt.Fprintln(os.Stderr, "seed failed:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, tenantName, email, password string) error {
	cfg, err := conf.Load()
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}

	ch, err := clickhouse.New(ctx, cfg.ClickHouse, clickhouse.Options{Profile: "default"})
	if err != nil {
		return fmt.Errorf("connect clickhouse: %w", err)
	}
	defer func() { _ = ch.Close() }()

	rdb, err := redis.New(ctx, cfg.Redis)
	if err != nil {
		return fmt.Errorf("connect redis: %w", err)
	}
	defer func() { _ = rdb.Close() }()

	locker := clickhouse.NewLocker(rdb)
	tenants := clickhouse.NewTenantRepo(ch, locker)
	users := clickhouse.NewUserRepo(ch, locker)
	feeds := clickhouse.NewFeedRepo(ch, locker)
	secretStore := secrets.NewRedisStore(rdb)

	tenant, err := ensureTenant(ctx, tenants, tenantName)
	if err != nil {
		return err
	}
	scoped := tenancy.WithTenant(ctx, tenancy.Tenant{ID: tenant.ID, Name: tenant.Name})

	generated := false
	if password == "" {
		if password, err = auth.GenerateFeedToken(); err != nil {
			return fmt.Errorf("generate a password: %w", err)
		}
		generated = true
	}

	user, created, err := ensureAdmin(scoped, users, email, password)
	if err != nil {
		return err
	}

	tokens, err := ensureFeeds(scoped, feeds, secretStore)
	if err != nil {
		return err
	}

	report(tenant, user, password, generated, created, tokens)
	return nil
}

// ensureTenant creates the demo tenant, or returns the existing one.
func ensureTenant(
	ctx context.Context, tenants *clickhouse.TenantRepo, name string,
) (clickhouse.Tenant, error) {
	existing, err := tenants.ListAll(ctx)
	if err != nil {
		return clickhouse.Tenant{}, fmt.Errorf("list tenants: %w", err)
	}
	for _, tenant := range existing {
		if tenant.Name == name {
			return tenant, nil
		}
	}

	created, err := tenants.Create(ctx, clickhouse.Tenant{
		ID: uuid.New(), Name: name, Status: clickhouse.TenantStatusActive,
		RawRetentionDays: 30, CorrelatedRetentionDays: 90, AlertRetentionDays: 365,
		// Redacted by default: the demo data contains user agents, and a developer
		// should see the redaction working rather than have to switch it on to learn
		// that it exists.
		RedactedFields:         []string{"user_agent"},
		CorrelationWindowMS:    5000,
		LatenessBoundMS:        900_000,
		ScoreConflictThreshold: 0.8,
	})
	if err != nil {
		return clickhouse.Tenant{}, fmt.Errorf("create tenant: %w", err)
	}
	return created, nil
}

// ensureAdmin creates the admin user, or returns the existing one.
func ensureAdmin(
	ctx context.Context, users *clickhouse.UserRepo, email, password string,
) (clickhouse.User, bool, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return clickhouse.User{}, false, err
	}

	switch existing, err := users.FindByEmail(ctx, tenantID, email); {
	case err == nil:
		return existing, false, nil
	case !errors.Is(err, clickhouse.ErrNotFound):
		return clickhouse.User{}, false, fmt.Errorf("look up admin: %w", err)
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		return clickhouse.User{}, false, fmt.Errorf("hash the password: %w", err)
	}

	secret, err := auth.GenerateMFASecret("siem", email)
	if err != nil {
		return clickhouse.User{}, false, fmt.Errorf("generate an MFA secret: %w", err)
	}

	created, err := users.Create(ctx, clickhouse.User{
		Email: email, PasswordHash: hash, Role: "admin",
		Status: clickhouse.UserStatusActive,
		// MFA is seeded but NOT enabled: forcing an enrolment before the first login
		// would make the demo stack unusable without an authenticator app, and the
		// enrolment flow is exercised by its own tests.
		MFASecret: secret.Secret, MFAEnabled: false,
	})
	if err != nil {
		return clickhouse.User{}, false, fmt.Errorf("create admin: %w", err)
	}
	return created, true, nil
}

// feedToken pairs a created feed with the token a vendor must present.
type feedToken struct {
	vendor string
	feedID uuid.UUID
	token  string
}

// ensureFeeds creates one push feed per vendor.
func ensureFeeds(
	ctx context.Context, feeds *clickhouse.FeedRepo, secretStore secrets.Store,
) ([]feedToken, error) {
	existing, err := feeds.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list feeds: %w", err)
	}

	byVendor := map[string]clickhouse.Feed{}
	for _, feed := range existing {
		byVendor[feed.Vendor] = feed
	}

	var out []feedToken
	for _, vendor := range []string{vendors.Cloudflare, vendors.F5, vendors.DataDome} {
		if feed, ok := byVendor[vendor]; ok {
			// The token cannot be recovered — only its reference is stored — so a
			// pre-existing feed reports the id and leaves the operator to rotate if
			// they need a token they no longer have.
			out = append(out, feedToken{vendor: vendor, feedID: feed.ID, token: ""})
			continue
		}

		token, err := auth.GenerateFeedToken()
		if err != nil {
			return nil, fmt.Errorf("generate a feed token: %w", err)
		}
		ref, err := secretStore.Put(ctx, "feed-credential", token)
		if err != nil {
			return nil, fmt.Errorf("store the feed token: %w", err)
		}

		created, err := feeds.Create(ctx, clickhouse.Feed{
			Vendor: vendor, Name: vendor + " (demo)",
			Delivery: clickhouse.DeliveryPush, Enabled: true, CredentialRef: ref,
		})
		if err != nil {
			return nil, fmt.Errorf("create %s feed: %w", vendor, err)
		}
		out = append(out, feedToken{vendor: vendor, feedID: created.ID, token: token})
	}
	return out, nil
}

// report prints what was created.
//
// The password is printed ONCE, here, because it is not recoverable afterwards — it is
// stored as an argon2id hash. Saying so explicitly is what stops someone closing the
// terminal and losing access to their own demo stack.
func report(
	tenant clickhouse.Tenant, user clickhouse.User,
	password string, generated, createdUser bool, tokens []feedToken,
) {
	fmt.Println()
	fmt.Println("seeded in", time.Now().UTC().Format(time.RFC3339))
	fmt.Println()
	fmt.Printf("  tenant   %s (%s)\n", tenant.Name, tenant.ID)
	fmt.Printf("  admin    %s\n", user.Email)

	if createdUser {
		if generated {
			fmt.Printf("  password %s\n", password)
			fmt.Println("           ^ shown once; it is stored hashed and cannot be recovered")
		} else {
			fmt.Println("  password (as supplied)")
		}
	} else {
		fmt.Println("  password (unchanged — the user already existed)")
	}

	fmt.Println()
	fmt.Println("  feeds")
	for _, feed := range tokens {
		if feed.token == "" {
			fmt.Printf("    %-11s %s  (existing; token not recoverable)\n",
				feed.vendor, feed.feedID)
			continue
		}
		fmt.Printf("    %-11s %s  token=%s\n", feed.vendor, feed.feedID, feed.token)
	}

	fmt.Println()
	fmt.Println("  send traffic:")
	for _, feed := range tokens {
		if feed.token == "" {
			continue
		}
		fmt.Printf("    go run ./test/tools/sendfixtures --vendor=%s --feed=%s --token=%s --count=5000\n",
			feed.vendor, feed.feedID, feed.token)
	}
	fmt.Println()
}
