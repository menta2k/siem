package clickhouse

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/tenancy"
)

// RawEvent is the vendor payload exactly as received.
//
// This row is written BEFORE any parsing is attempted, so a parse failure can never
// cost the original data (FR-005). It is immutable and append-only.
type RawEvent struct {
	TenantID   uuid.UUID
	FeedID     uuid.UUID
	Vendor     string
	EventID    string
	ReceivedAt time.Time
	Payload    []byte
	Format     string
	BatchID    uuid.UUID
}

// NormalizedEvent is the common-model projection of a raw event.
type NormalizedEvent struct {
	TenantID          uuid.UUID
	EventID           string
	EventTime         time.Time
	EventTimeOriginal string
	ReceivedAt        time.Time

	Vendor        string
	FeedID        uuid.UUID
	VendorAccount string
	// VendorRequestID is the identifier shared BETWEEN vendors — the CF-Ray — and is
	// what the tier-1 exact join matches on.
	VendorRequestID string
	// VendorEventID is the vendor's OWN reference for its record of the request: F5's
	// support_id, the value quoted to support and searched for in the ASM event log.
	// Empty for Cloudflare, whose RayID already serves both roles.
	VendorEventID string
	// LinkedRequestID is a second identifier for the same request, joining hops that
	// share no other id. See vendors.Event.LinkedRequestID.
	LinkedRequestID string

	ClientIP       net.IP
	ClientIPShared bool
	ClientASN      uint32
	ClientCountry  string

	RequestHost   string
	RequestPath   string
	RequestQuery  string
	RequestMethod string
	UserAgent     string
	HTTPStatus    uint16

	Verdict       string
	VerdictReason string
	RuleID        string
	RuleIDs       []string
	Score         *float32
	ScoreKind     string

	IngestVersion uint64
}

// RejectedEvent is a dead-lettered delivery (FR-006).
type RejectedEvent struct {
	TenantID     uuid.UUID
	FeedID       uuid.UUID
	Vendor       string
	RejectedAt   time.Time
	ReasonCode   string
	ReasonDetail string
	Payload      []byte
	BatchID      uuid.UUID
}

// EventRepo writes and reads the event pipeline tables.
type EventRepo struct {
	client *Client
}

// NewEventRepo constructs the repository.
func NewEventRepo(client *Client) *EventRepo {
	return &EventRepo{client: client}
}

// InsertRaw writes raw events in one batch.
//
// Batching is not an optimization here: ClickHouse creates one part per insert, so
// per-row writes at ingest volume trigger merge storms that eventually stall the
// server.
func (r *EventRepo) InsertRaw(ctx context.Context, events []RawEvent) error {
	if len(events) == 0 {
		return nil
	}

	batch, err := r.client.PrepareBatch(ctx, "INSERT INTO raw_events")
	if err != nil {
		return err
	}
	for _, e := range events {
		if err := batch.Append(
			e.TenantID, e.FeedID, e.Vendor, e.EventID, e.ReceivedAt,
			string(e.Payload), e.Format, e.BatchID,
		); err != nil {
			return fmt.Errorf("append raw event %s: %w", e.EventID, err)
		}
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("insert %d raw events: %w", len(events), err)
	}
	return nil
}

// InsertNormalized writes normalized events in one batch.
func (r *EventRepo) InsertNormalized(ctx context.Context, events []NormalizedEvent) error {
	if len(events) == 0 {
		return nil
	}

	batch, err := r.client.PrepareBatch(ctx,
		"INSERT INTO normalized_events ("+normalizedColumns+")")
	if err != nil {
		return err
	}
	for _, e := range events {
		if err := batch.Append(
			e.TenantID, e.EventID, e.EventTime, e.EventTimeOriginal, e.ReceivedAt,
			e.Vendor, e.FeedID, e.VendorAccount, e.VendorRequestID, e.VendorEventID,
			e.LinkedRequestID,
			ipOrZero(e.ClientIP), e.ClientIPShared, e.ClientASN, e.ClientCountry,
			e.RequestHost, e.RequestPath, e.RequestQuery, e.RequestMethod,
			e.UserAgent, e.HTTPStatus,
			e.Verdict, e.VerdictReason, e.RuleID, orEmptySlice(e.RuleIDs),
			e.Score, e.ScoreKind, e.IngestVersion,
		); err != nil {
			return fmt.Errorf("append normalized event %s: %w", e.EventID, err)
		}
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("insert %d normalized events: %w", len(events), err)
	}
	return nil
}

// InsertRejected writes dead-lettered events.
func (r *EventRepo) InsertRejected(ctx context.Context, events []RejectedEvent) error {
	if len(events) == 0 {
		return nil
	}

	batch, err := r.client.PrepareBatch(ctx, "INSERT INTO rejected_events")
	if err != nil {
		return err
	}
	for _, e := range events {
		if err := batch.Append(
			e.TenantID, e.FeedID, e.Vendor, e.RejectedAt,
			e.ReasonCode, e.ReasonDetail, string(e.Payload), e.BatchID,
		); err != nil {
			return fmt.Errorf("append rejected event: %w", err)
		}
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("insert %d rejected events: %w", len(events), err)
	}
	return nil
}

// normalizedColumns names every column of normalized_events, in the order both the
// insert binds them and the scan reads them.
//
// Naming them on the INSERT is not style. PrepareBatch with a bare table name binds
// POSITIONALLY against whatever columns the table currently has, so a schema change
// silently shifts every value after it and the insert fails with "expected N arguments,
// got M" — which is exactly what migration 0006 did in production, crash-looping the
// normalizer until the binary caught up. With the columns named, schema and binary can
// be deployed in either order: an unmigrated database rejects the unknown column
// outright, and a migrated one defaults it.
const normalizedColumns = `tenant_id, event_id, event_time, event_time_original, received_at,
	vendor, feed_id, vendor_account, vendor_request_id, vendor_event_id, linked_request_id,
	client_ip, client_ip_shared, client_asn, client_country,
	request_host, request_path, request_query, request_method, user_agent, http_status,
	verdict, verdict_reason, rule_id, rule_ids, score, score_kind, ingest_version`

// GetNormalized loads one normalized event within the context's tenant.
//
// FINAL is required: normalized_events is a ReplacingMergeTree, so a read without it
// can return both a pre- and post-reprocessing version of the same event.
func (r *EventRepo) GetNormalized(ctx context.Context, eventID string) (NormalizedEvent, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return NormalizedEvent{}, err
	}

	query := fmt.Sprintf(
		`SELECT %s FROM normalized_events FINAL WHERE tenant_id = ? AND event_id = ? LIMIT 1`,
		normalizedColumns)

	rows, err := r.client.Query(ctx, query, tenantID, eventID)
	if err != nil {
		return NormalizedEvent{}, err
	}
	defer func() { _ = rows.Close() }()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return NormalizedEvent{}, fmt.Errorf("load normalized event: %w", err)
		}
		return NormalizedEvent{}, ErrNotFound
	}
	return scanNormalized(rows)
}

// GetRawPayload returns the vendor's original bytes for an event.
//
// The detail view shows this alongside the normalized fields so an analyst can settle
// "did the platform read this correctly" without leaving the console (FR-005).
func (r *EventRepo) GetRawPayload(ctx context.Context, eventID string) ([]byte, string, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, "", err
	}

	const query = `SELECT payload, payload_format FROM raw_events
		WHERE tenant_id = ? AND event_id = ? LIMIT 1`

	rows, err := r.client.Query(ctx, query, tenantID, eventID)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = rows.Close() }()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, "", fmt.Errorf("load raw payload: %w", err)
		}
		return nil, "", ErrNotFound
	}

	var payload, format string
	if err := rows.Scan(&payload, &format); err != nil {
		return nil, "", fmt.Errorf("scan raw payload: %w", err)
	}
	return []byte(payload), format, nil
}

// RejectedFilter narrows a dead-letter query.
type RejectedFilter struct {
	FeedID     uuid.UUID
	ReasonCode string
	From       time.Time
	To         time.Time
	Limit      int32
}

// ListRejected returns dead-lettered events for the console's rejects view.
func (r *EventRepo) ListRejected(ctx context.Context, f RejectedFilter) ([]RejectedEvent, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}

	query := `SELECT tenant_id, feed_id, vendor, rejected_at, reason_code, reason_detail,
		payload, batch_id FROM rejected_events
		WHERE tenant_id = ? AND rejected_at >= ? AND rejected_at <= ?`
	args := []any{tenantID, f.From.UTC(), f.To.UTC()}

	if f.FeedID != uuid.Nil {
		query += " AND feed_id = ?"
		args = append(args, f.FeedID)
	}
	if f.ReasonCode != "" {
		query += " AND reason_code = ?"
		args = append(args, f.ReasonCode)
	}

	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query += " ORDER BY rejected_at DESC LIMIT ?"
	args = append(args, limit)

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var events []RejectedEvent
	for rows.Next() {
		var (
			e       RejectedEvent
			payload string
		)
		if err := rows.Scan(&e.TenantID, &e.FeedID, &e.Vendor, &e.RejectedAt,
			&e.ReasonCode, &e.ReasonDetail, &payload, &e.BatchID); err != nil {
			return nil, fmt.Errorf("scan rejected event: %w", err)
		}
		e.Payload = []byte(payload)
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rejected events: %w", err)
	}
	return events, nil
}

func scanNormalized(row rowScanner) (NormalizedEvent, error) {
	var e NormalizedEvent
	err := row.Scan(
		&e.TenantID, &e.EventID, &e.EventTime, &e.EventTimeOriginal, &e.ReceivedAt,
		&e.Vendor, &e.FeedID, &e.VendorAccount, &e.VendorRequestID, &e.VendorEventID,
		&e.LinkedRequestID,
		&e.ClientIP, &e.ClientIPShared, &e.ClientASN, &e.ClientCountry,
		&e.RequestHost, &e.RequestPath, &e.RequestQuery, &e.RequestMethod,
		&e.UserAgent, &e.HTTPStatus,
		&e.Verdict, &e.VerdictReason, &e.RuleID, &e.RuleIDs, &e.Score, &e.ScoreKind,
		&e.IngestVersion,
	)
	if err != nil {
		return NormalizedEvent{}, fmt.Errorf("scan normalized event: %w", err)
	}
	return e, nil
}

// ipOrZero substitutes the zero address for a nil IP, since the column is not
// nullable and a missing client address is legitimate for some vendor records.
func ipOrZero(ip net.IP) net.IP {
	if ip == nil {
		return net.IPv6zero
	}
	return ip
}

func orEmptySlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func orEmptyMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// ---------------------------------------------------------------- retention

// DeleteEventsBefore removes a tenant's events older than a cutoff.
//
// A lightweight DELETE, which ClickHouse applies asynchronously. That is the right
// trade here: retention is a deadline measured in days, and a synchronous mutation
// over a hundred million rows would compete with ingestion for exactly the merge
// capacity the pipeline depends on.
//
// The tenant predicate is explicit rather than taken from the context because the
// caller is a background worker reconciling every tenant in turn, and a mistake here
// deletes another customer's data.
func (r *EventRepo) DeleteEventsBefore(
	ctx context.Context, tenantID uuid.UUID, before time.Time,
) error {
	statements := []string{
		"DELETE FROM normalized_events WHERE tenant_id = ? AND event_time < ?",
		"DELETE FROM raw_events WHERE tenant_id = ? AND received_at < ?",
		"DELETE FROM rejected_events WHERE tenant_id = ? AND rejected_at < ?",
	}

	for _, statement := range statements {
		if err := r.client.Exec(ctx, statement, tenantID, before.UTC()); err != nil {
			return fmt.Errorf("delete events before %s: %w", before, err)
		}
	}
	return nil
}

// DeleteEventsInRange removes a tenant's events inside a window.
//
// Used only by the explicit, audited purge path. Bounded on BOTH sides so an operator
// cannot accidentally express "everything before now" when they meant one incident.
func (r *EventRepo) DeleteEventsInRange(
	ctx context.Context, tenantID uuid.UUID, from, to time.Time,
) error {
	if !from.Before(to) {
		return fmt.Errorf("purge range must start before it ends")
	}

	statements := []string{
		"DELETE FROM normalized_events WHERE tenant_id = ? AND event_time >= ? AND event_time < ?",
		"DELETE FROM raw_events WHERE tenant_id = ? AND received_at >= ? AND received_at < ?",
	}

	for _, statement := range statements {
		if err := r.client.Exec(ctx, statement, tenantID, from.UTC(), to.UTC()); err != nil {
			return fmt.Errorf("purge events in range: %w", err)
		}
	}
	return nil
}
