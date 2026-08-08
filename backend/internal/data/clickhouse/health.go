package clickhouse

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/ingest"
	"github.com/menta2k/siem/internal/tenancy"
)

// HealthRepo reads and writes per-minute feed health.
type HealthRepo struct {
	client *Client
}

// NewHealthRepo constructs the repository.
func NewHealthRepo(client *Client) *HealthRepo {
	return &HealthRepo{client: client}
}

// InsertFeedHealth writes accumulated per-minute counters.
//
// The table is a SummingMergeTree, so concurrent writers from several ingest replicas
// add up rather than overwrite each other. That is what makes a per-instance
// aggregator correct without any coordination between instances.
func (r *HealthRepo) InsertFeedHealth(ctx context.Context, rows []ingest.FeedHealthRow) error {
	if len(rows) == 0 {
		return nil
	}

	// Columns are NAMED. A bare INSERT binds positionally against the table's physical
	// column order, so adding one breaks every running build until code and schema are
	// redeployed together — and this row gained a column for exactly that reason.
	const feedHealthColumns = `tenant_id, feed_id, minute, events_received, events_rejected,
		events_filtered, duplicates_suppressed, bytes_received, max_ingest_lag_ms,
		unknown_field_events, credential_valid`

	batch, err := r.client.PrepareBatch(ctx, "INSERT INTO feed_health ("+feedHealthColumns+")")
	if err != nil {
		return err
	}
	for _, row := range rows {
		credentialValid := uint8(1)
		if !row.CredentialValid {
			credentialValid = 0
		}
		if err := batch.Append(
			row.TenantID, row.FeedID, row.Minute,
			row.EventsReceived, row.EventsRejected, row.EventsFiltered, row.DuplicatesSuppressed,
			row.BytesReceived, row.MaxIngestLagMS, row.UnknownFieldEvents, credentialValid,
		); err != nil {
			return fmt.Errorf("append feed health for %s: %w", row.FeedID, err)
		}
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("insert %d feed health rows: %w", len(rows), err)
	}
	return nil
}

// FeedHealth is the current state of one feed.
type FeedHealth struct {
	FeedID               uuid.UUID
	LastEventAt          time.Time
	Silent               bool
	EventsPerSec         float64
	EventsReceived1h     uint64
	EventsRejected1h     uint64
	DuplicatesSuppressed uint64
	BytesReceived1h      uint64
	MaxIngestLagMS       uint32
	UnknownFieldEvents1h uint64
	CredentialValid      bool
}

// SchemaDriftWarning reports whether unrecognized fields crossed the threshold.
func (h FeedHealth) SchemaDriftWarning() bool {
	if h.EventsReceived1h == 0 {
		return false
	}
	return float64(h.UnknownFieldEvents1h)/float64(h.EventsReceived1h) > 0.01
}

// GetFeedHealth summarizes the last hour for one feed.
func (r *HealthRepo) GetFeedHealth(ctx context.Context, feedID uuid.UUID) (FeedHealth, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return FeedHealth{}, err
	}

	// The last-event time comes from the newest minute that actually carried events.
	// Using max(minute) over all rows would report a feed as alive purely because a
	// zero-count row exists, which is exactly the silence the query must detect.
	const query = `SELECT
			maxIf(minute, events_received > 0) AS last_event_minute,
			sum(events_received)               AS total_received,
			sum(events_rejected)               AS total_rejected,
			sum(duplicates_suppressed)         AS total_duplicates,
			sum(bytes_received)                AS total_bytes,
			max(max_ingest_lag_ms)             AS peak_lag,
			sum(unknown_field_events)          AS total_unknown_fields,
			min(credential_valid)              AS all_credentials_valid
		FROM feed_health
		WHERE tenant_id = ? AND feed_id = ? AND minute >= ?`

	since := time.Now().UTC().Add(-time.Hour).Truncate(time.Minute)

	rows, err := r.client.Query(ctx, query, tenantID, feedID, since)
	if err != nil {
		return FeedHealth{}, err
	}
	defer func() { _ = rows.Close() }()

	health := FeedHealth{FeedID: feedID, CredentialValid: true}
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return FeedHealth{}, fmt.Errorf("read feed health: %w", err)
		}
		return health, nil
	}

	var (
		lastEventMinute time.Time
		credentialValid uint8
	)
	if err := rows.Scan(&lastEventMinute,
		&health.EventsReceived1h, &health.EventsRejected1h, &health.DuplicatesSuppressed,
		&health.BytesReceived1h, &health.MaxIngestLagMS, &health.UnknownFieldEvents1h,
		&credentialValid); err != nil {
		return FeedHealth{}, fmt.Errorf("scan feed health: %w", err)
	}

	health.LastEventAt = lastEventMinute
	health.CredentialValid = credentialValid == 1
	health.Silent = ingest.IsSilent(lastEventMinute, time.Now().UTC())
	health.EventsPerSec = float64(health.EventsReceived1h) / 3600.0

	return health, nil
}

// ListFeedHealth summarizes every feed in the tenant, for the feeds list and the
// feed-health dashboard tile.
func (r *HealthRepo) ListFeedHealth(ctx context.Context) (map[uuid.UUID]FeedHealth, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}

	const query = `SELECT
			feed_id,
			maxIf(minute, events_received > 0) AS last_event_minute,
			sum(events_received),
			sum(events_rejected),
			sum(duplicates_suppressed),
			sum(bytes_received),
			max(max_ingest_lag_ms),
			sum(unknown_field_events),
			min(credential_valid)
		FROM feed_health
		WHERE tenant_id = ? AND minute >= ?
		GROUP BY feed_id`

	since := time.Now().UTC().Add(-time.Hour).Truncate(time.Minute)

	rows, err := r.client.Query(ctx, query, tenantID, since)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	now := time.Now().UTC()
	out := map[uuid.UUID]FeedHealth{}

	for rows.Next() {
		health, err := scanFeedHealth(rows, now)
		if err != nil {
			return nil, err
		}
		out[health.FeedID] = health
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate feed health: %w", err)
	}
	return out, nil
}

// scanFeedHealth reads one aggregated row and derives its computed fields.
func scanFeedHealth(row rowScanner, now time.Time) (FeedHealth, error) {
	var (
		health          FeedHealth
		lastEventMinute time.Time
		credentialValid uint8
	)
	if err := row.Scan(&health.FeedID, &lastEventMinute,
		&health.EventsReceived1h, &health.EventsRejected1h, &health.DuplicatesSuppressed,
		&health.BytesReceived1h, &health.MaxIngestLagMS, &health.UnknownFieldEvents1h,
		&credentialValid); err != nil {
		return FeedHealth{}, fmt.Errorf("scan feed health: %w", err)
	}

	health.LastEventAt = lastEventMinute
	health.CredentialValid = credentialValid == 1
	health.Silent = ingest.IsSilent(lastEventMinute, now)
	health.EventsPerSec = float64(health.EventsReceived1h) / 3600.0
	return health, nil
}
