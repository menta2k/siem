package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/tenancy"
)

// ErrFeedNameTaken is returned when a tenant already has a feed with that name.
var ErrFeedNameTaken = errors.New("clickhouse: a feed with that name already exists")

// Delivery modes.
const (
	DeliveryPush = "push"
	DeliveryPull = "pull"
)

// Feed is a configured connection to one vendor for one tenant.
type Feed struct {
	TenantID uuid.UUID
	ID       uuid.UUID
	Vendor   string
	Name     string
	Delivery string
	Enabled  bool

	// CredentialRef is a POINTER into the secret manager. The vendor credential
	// itself is never stored here — persisting it would put every customer's log
	// credentials in the analytical store.
	CredentialRef string
	// SigningSecretRef points at the HMAC key for vendors that sign their payloads.
	SigningSecretRef string

	PullConfig    string
	PullWatermark string

	QuotaEventsPerSec uint32
	QuotaBytesPerDay  uint64

	CreatedAt time.Time
	UpdatedAt time.Time
	Version   uint64
}

// FeedRepo reads and writes feed configuration.
type FeedRepo struct {
	client *Client
	locker Locker
}

// NewFeedRepo constructs the repository.
func NewFeedRepo(client *Client, locker Locker) *FeedRepo {
	return &FeedRepo{client: client, locker: locker}
}

const feedColumns = `tenant_id, feed_id, vendor, name, delivery_mode, enabled,
	credential_ref, signing_secret_ref, pull_config, pull_watermark,
	quota_events_per_sec, quota_bytes_per_day, created_at, updated_at, version`

// Get loads a feed within the context's tenant.
func (r *FeedRepo) Get(ctx context.Context, feedID uuid.UUID) (Feed, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return Feed{}, err
	}

	query := fmt.Sprintf(
		`SELECT %s FROM feeds FINAL WHERE tenant_id = ? AND feed_id = ? LIMIT 1`, feedColumns)

	return r.scanOne(ctx, query, tenantID, feedID)
}

// GetForIngest loads a feed by id without a tenant context.
//
// The ingest path authenticates with a feed token and must resolve the feed BEFORE a
// tenant is known — the feed is what establishes the tenant. This is the one
// permitted exception, and the caller must immediately scope subsequent work to the
// tenant this returns.
func (r *FeedRepo) GetForIngest(ctx context.Context, feedID uuid.UUID) (Feed, error) {
	query := fmt.Sprintf(
		`SELECT %s FROM feeds FINAL WHERE feed_id = ? LIMIT 1`, feedColumns)

	return r.scanOne(ctx, query, feedID)
}

// List returns the tenant's feeds.
func (r *FeedRepo) List(ctx context.Context) ([]Feed, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}

	query := fmt.Sprintf(
		`SELECT %s FROM feeds FINAL WHERE tenant_id = ? ORDER BY vendor, name`, feedColumns)

	rows, err := r.client.Query(ctx, query, tenantID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var feeds []Feed
	for rows.Next() {
		f, err := scanFeed(rows)
		if err != nil {
			return nil, err
		}
		feeds = append(feeds, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate feeds: %w", err)
	}
	return feeds, nil
}

// ListPullFeeds returns every enabled pull feed across ALL tenants.
//
// This is one of only two queries in the system that deliberately crosses the tenant
// boundary — the other is GetForIngest. The pull worker is a background process with
// no request and therefore no tenant context; it must poll every customer's feeds.
// Each feed carries its tenant, and the worker scopes its context to that tenant
// before touching any other repository.
func (r *FeedRepo) ListPullFeeds(ctx context.Context) ([]Feed, error) {
	query := fmt.Sprintf(
		`SELECT %s FROM feeds FINAL WHERE delivery_mode = ? AND enabled = true
		 ORDER BY tenant_id, feed_id`, feedColumns)

	rows, err := r.client.Query(ctx, query, DeliveryPull)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var feeds []Feed
	for rows.Next() {
		f, err := scanFeed(rows)
		if err != nil {
			return nil, err
		}
		feeds = append(feeds, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pull feeds: %w", err)
	}
	return feeds, nil
}

// Create inserts a feed, enforcing per-tenant name uniqueness under a lock.
func (r *FeedRepo) Create(ctx context.Context, f Feed) (Feed, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return Feed{}, err
	}
	f.TenantID = tenantID

	release, err := r.locker.Lock(ctx, fmt.Sprintf("feed:%s:%s", tenantID, f.Name))
	if err != nil {
		return Feed{}, err
	}
	defer release()

	existing, err := r.List(ctx)
	if err != nil {
		return Feed{}, err
	}
	for _, e := range existing {
		if e.Name == f.Name {
			return Feed{}, ErrFeedNameTaken
		}
	}

	if f.ID == uuid.Nil {
		f.ID = uuid.New()
	}
	if f.Delivery == "" {
		f.Delivery = DeliveryPush
	}
	if f.PullConfig == "" {
		f.PullConfig = "{}"
	}
	now := time.Now().UTC()
	f.CreatedAt, f.UpdatedAt, f.Version = now, now, 1

	if err := r.insert(ctx, f); err != nil {
		return Feed{}, err
	}
	return f, nil
}

// Update writes a new version of a feed. mutate receives a copy.
func (r *FeedRepo) Update(
	ctx context.Context, feedID uuid.UUID, mutate func(Feed) Feed,
) (Feed, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return Feed{}, err
	}

	release, err := r.locker.Lock(ctx, fmt.Sprintf("feed:%s:%s", tenantID, feedID))
	if err != nil {
		return Feed{}, err
	}
	defer release()

	current, err := r.Get(ctx, feedID)
	if err != nil {
		return Feed{}, err
	}

	updated := mutate(current)
	// Identity, tenant, and creation time are not the caller's to change.
	updated.TenantID, updated.ID = current.TenantID, current.ID
	updated.CreatedAt = current.CreatedAt
	updated.UpdatedAt = time.Now().UTC()
	updated.Version = current.Version + 1

	if err := r.insert(ctx, updated); err != nil {
		return Feed{}, err
	}
	return updated, nil
}

// SetWatermark records a pull worker's progress.
//
// An object or page is marked complete only after every event in it is durably
// committed, so a crash replays the object rather than skipping it (FR-003).
func (r *FeedRepo) SetWatermark(ctx context.Context, feedID uuid.UUID, watermark string) error {
	_, err := r.Update(ctx, feedID, func(f Feed) Feed {
		f.PullWatermark = watermark
		return f
	})
	return err
}

func (r *FeedRepo) insert(ctx context.Context, f Feed) error {
	batch, err := r.client.PrepareBatch(ctx, "INSERT INTO feeds")
	if err != nil {
		return err
	}
	if err := batch.Append(
		f.TenantID, f.ID, f.Vendor, f.Name, f.Delivery, f.Enabled,
		f.CredentialRef, f.SigningSecretRef, f.PullConfig, f.PullWatermark,
		f.QuotaEventsPerSec, f.QuotaBytesPerDay, f.CreatedAt, f.UpdatedAt, f.Version,
	); err != nil {
		return fmt.Errorf("append feed %s: %w", f.ID, err)
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("insert feed %s: %w", f.ID, err)
	}
	return nil
}

func (r *FeedRepo) scanOne(ctx context.Context, query string, args ...any) (Feed, error) {
	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return Feed{}, err
	}
	defer func() { _ = rows.Close() }()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return Feed{}, fmt.Errorf("load feed: %w", err)
		}
		return Feed{}, ErrNotFound
	}
	return scanFeed(rows)
}

func scanFeed(row rowScanner) (Feed, error) {
	var f Feed
	err := row.Scan(&f.TenantID, &f.ID, &f.Vendor, &f.Name, &f.Delivery, &f.Enabled,
		&f.CredentialRef, &f.SigningSecretRef, &f.PullConfig, &f.PullWatermark,
		&f.QuotaEventsPerSec, &f.QuotaBytesPerDay, &f.CreatedAt, &f.UpdatedAt, &f.Version)
	if err != nil {
		return Feed{}, fmt.Errorf("scan feed: %w", err)
	}
	return f, nil
}
