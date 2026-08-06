package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/tenancy"
)

// CorrelatedRequest is one request as seen by every vendor that reported it.
//
// A record with VendorCount == 1 is normal, not an error: plenty of hostnames sit
// behind a single vendor, and discarding those observations would lose the only
// evidence the platform has for them (FR-016).
type CorrelatedRequest struct {
	TenantID      uuid.UUID
	CorrelationID uuid.UUID

	WindowStart    time.Time
	FirstEventTime time.Time
	LastEventTime  time.Time

	Vendors     []string
	VendorCount uint8
	EventIDs    []string

	ClientIP       net.IP
	ClientIPShared bool
	ClientASN      uint32
	ClientCountry  string
	RequestHost    string
	RequestPath    string
	RequestMethod  string

	Verdicts map[string]string
	RuleIDs  map[string]string
	Scores   map[string]float32

	CombinedOutcome  string
	HasDisagreement  bool
	DisagreementKind string

	JoinSignals    []string
	JoinTier       uint8
	Confidence     string
	CandidateCount uint8

	// Version drives the ReplacingMergeTree merge. A late arrival re-emits the same
	// CorrelationID at a higher version, which is what makes it an amendment rather
	// than a duplicate row.
	Version uint64
	Amended bool
}

// CorrelatedRepo reads and writes correlated requests.
type CorrelatedRepo struct {
	client *Client
}

// NewCorrelatedRepo builds the repository.
func NewCorrelatedRepo(client *Client) *CorrelatedRepo {
	return &CorrelatedRepo{client: client}
}

const correlatedColumns = `tenant_id, correlation_id, window_start, first_event_time,
	last_event_time, vendors, vendor_count, event_ids, client_ip, client_ip_shared,
	client_asn, client_country, request_host, request_path, request_method, verdicts,
	rule_ids, scores, combined_outcome, has_disagreement, disagreement_kind,
	join_signals, join_tier, confidence, candidate_count, version, amended`

// Insert writes correlated records.
//
// Writes are idempotent by (correlation_id, version): re-emitting an unchanged record
// is harmless, which is what lets the worker retry a failed batch without reasoning
// about which half of it landed.
func (r *CorrelatedRepo) Insert(ctx context.Context, records []CorrelatedRequest) error {
	if len(records) == 0 {
		return nil
	}

	batch, err := r.client.PrepareBatch(ctx,
		"INSERT INTO correlated_requests ("+correlatedColumns+")")
	if err != nil {
		return fmt.Errorf("prepare correlated batch: %w", err)
	}

	for _, record := range records {
		if err := batch.Append(
			record.TenantID, record.CorrelationID, record.WindowStart,
			record.FirstEventTime, record.LastEventTime,
			orEmptySlice(record.Vendors), record.VendorCount, orEmptySlice(record.EventIDs),
			ipOrZero(record.ClientIP), record.ClientIPShared, record.ClientASN,
			record.ClientCountry, record.RequestHost, record.RequestPath, record.RequestMethod,
			orEmptyMap(record.Verdicts), orEmptyMap(record.RuleIDs),
			orEmptyScores(record.Scores),
			record.CombinedOutcome, record.HasDisagreement, record.DisagreementKind,
			orEmptySlice(record.JoinSignals), record.JoinTier, record.Confidence,
			record.CandidateCount, record.Version, record.Amended,
		); err != nil {
			return fmt.Errorf("append correlated record %s: %w", record.CorrelationID, err)
		}
	}

	if err := batch.Send(); err != nil {
		return fmt.Errorf("send correlated batch: %w", err)
	}
	return nil
}

// ErrCorrelatedNotFound reports that no record exists for a correlation id.
var ErrCorrelatedNotFound = errors.New("correlated request not found")

// Versions returns the current version of each correlation id that already exists.
//
// The closer needs exactly one fact about a record it is about to write — whether it
// exists, and at what version — for every record in a whole close pass. Asking with
// one point query each puts a ClickHouse round trip on every correlated record, which
// is the dominant cost of closing a window. Ids with no existing record are simply
// absent from the map; that is the "this is a new record" answer, not an error.
func (r *CorrelatedRepo) Versions(
	ctx context.Context, correlationIDs []uuid.UUID,
) (map[uuid.UUID]uint64, error) {
	versions := make(map[uuid.UUID]uint64, len(correlationIDs))
	if len(correlationIDs) == 0 {
		return versions, nil
	}

	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}

	// FINAL for the same reason Get needs it: without it an amended record returns
	// every version it has ever had, and max() would still be right but the scan would
	// be over every superseded row.
	rows, err := r.client.Query(ctx,
		"SELECT correlation_id, max(version) FROM correlated_requests FINAL "+
			"WHERE tenant_id = ? AND correlation_id IN (?) GROUP BY correlation_id",
		tenantID, correlationIDs)
	if err != nil {
		return nil, fmt.Errorf("query correlated versions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			id      uuid.UUID
			version uint64
		)
		if err := rows.Scan(&id, &version); err != nil {
			return nil, fmt.Errorf("scan correlated version: %w", err)
		}
		versions[id] = version
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("query correlated versions: %w", err)
	}
	return versions, nil
}

// Get returns one correlated request.
//
// FINAL is required, not an optimization: without it a record that has been amended
// returns every version it has ever had, and the caller would see a stale row roughly
// as often as the current one.
func (r *CorrelatedRepo) Get(
	ctx context.Context, correlationID uuid.UUID,
) (CorrelatedRequest, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return CorrelatedRequest{}, err
	}

	rows, err := r.client.Query(ctx,
		"SELECT "+correlatedColumns+" FROM correlated_requests FINAL "+
			"WHERE tenant_id = ? AND correlation_id = ? LIMIT 1",
		tenantID, correlationID)
	if err != nil {
		return CorrelatedRequest{}, fmt.Errorf("query correlated request: %w", err)
	}
	defer func() { _ = rows.Close() }()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return CorrelatedRequest{}, fmt.Errorf("query correlated request: %w", err)
		}
		return CorrelatedRequest{}, ErrCorrelatedNotFound
	}

	record, err := scanCorrelated(rows)
	if err != nil {
		return CorrelatedRequest{}, err
	}
	return record, rows.Err()
}

// CorrelatedFilter narrows a correlated-request listing.
type CorrelatedFilter struct {
	From, To        time.Time
	Confidence      string
	OnlyDisagreeing bool
	MinVendorCount  uint8
	Limit           int
}

// List returns correlated requests inside a time range, newest first.
func (r *CorrelatedRepo) List(
	ctx context.Context, f CorrelatedFilter,
) ([]CorrelatedRequest, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}

	query := "SELECT " + correlatedColumns + " FROM correlated_requests FINAL " +
		"WHERE tenant_id = ? AND window_start >= ? AND window_start < ?"
	args := []any{tenantID, f.From.UTC(), f.To.UTC()}

	if f.Confidence != "" {
		query += " AND confidence = ?"
		args = append(args, f.Confidence)
	}
	if f.OnlyDisagreeing {
		query += " AND has_disagreement"
	}
	if f.MinVendorCount > 0 {
		query += " AND vendor_count >= ?"
		args = append(args, f.MinVendorCount)
	}

	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query += " ORDER BY last_event_time DESC LIMIT ?"
	args = append(args, limit)

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list correlated requests: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]CorrelatedRequest, 0, limit)
	for rows.Next() {
		record, err := scanCorrelated(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

func scanCorrelated(row rowScanner) (CorrelatedRequest, error) {
	var (
		record   CorrelatedRequest
		clientIP net.IP
	)
	if err := row.Scan(
		&record.TenantID, &record.CorrelationID, &record.WindowStart,
		&record.FirstEventTime, &record.LastEventTime,
		&record.Vendors, &record.VendorCount, &record.EventIDs,
		&clientIP, &record.ClientIPShared, &record.ClientASN, &record.ClientCountry,
		&record.RequestHost, &record.RequestPath, &record.RequestMethod,
		&record.Verdicts, &record.RuleIDs, &record.Scores,
		&record.CombinedOutcome, &record.HasDisagreement, &record.DisagreementKind,
		&record.JoinSignals, &record.JoinTier, &record.Confidence,
		&record.CandidateCount, &record.Version, &record.Amended,
	); err != nil {
		return CorrelatedRequest{}, fmt.Errorf("scan correlated request: %w", err)
	}
	record.ClientIP = clientIP
	return record, nil
}

// orEmptyScores mirrors orEmptyMap for float values: ClickHouse rejects a nil Map.
func orEmptyScores(m map[string]float32) map[string]float32 {
	if m == nil {
		return map[string]float32{}
	}
	return m
}

// DeleteCorrelatedBefore removes a tenant's correlated records older than a cutoff.
func (r *CorrelatedRepo) DeleteCorrelatedBefore(
	ctx context.Context, tenantID uuid.UUID, before time.Time,
) error {
	err := r.client.Exec(ctx,
		"DELETE FROM correlated_requests WHERE tenant_id = ? AND window_start < ?",
		tenantID, before.UTC())
	if err != nil {
		return fmt.Errorf("delete correlated records before %s: %w", before, err)
	}
	return nil
}
