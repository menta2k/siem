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
	// MatchedRuleIDs is EVERY rule each vendor matched, where RuleIDs above is the one
	// that decided the outcome. They differ whenever more than one rule matches — a
	// Cloudflare rule in log mode does not terminate evaluation, so a later `skip`
	// becomes the decision and the log-mode match would otherwise be lost. That match is
	// the entire subject of the WAF migration stages.
	MatchedRuleIDs map[string][]string
	Scores         map[string]float32

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

// correlatedColumns is the column list for the INSERT and for every SELECT that scans a
// whole record through scanCorrelated. Adding a column here means adding a destination
// there in the same commit: the driver reports the mismatch as "expected N destination
// arguments in Scan", which surfaces at runtime in the closer rather than at compile time.
const correlatedColumns = `tenant_id, correlation_id, window_start, first_event_time,
	last_event_time, vendors, vendor_count, event_ids, client_ip, client_ip_shared,
	client_asn, client_country, request_host, request_path, request_method, verdicts,
	rule_ids, matched_rule_ids, scores, combined_outcome, has_disagreement, disagreement_kind,
	join_signals, join_tier, confidence, candidate_count, version, amended`

// PartitionBound narrows a correlation-id lookup to the partitions an existing copy of
// those records could be in.
//
// correlated_requests is PARTITIONed BY toDate(window_start) and ORDERed BY
// (tenant_id, toDate(window_start), correlation_id), so a lookup that names no date has
// to visit all ninety days: correlation_id is the THIRD key column and prunes nothing
// without the second. Measured on production, the closer's version lookup averaged 964ms
// over 68 million rows per call and spent 246 seconds of every 600 doing it — the single
// largest cost in a close pass, and the reason the closer could not keep up with the rate
// windows were being filed. With the date named, the same lookup is a binary search
// inside one or two partitions.
//
// The range is derived from the records being written, widened by the lateness bound and
// a day. That is not a guess: a record's window_start only ever moves EARLIER, because
// mergeRecords keeps the stored one, and it can only move by the drift of the events a
// window is still accepting — which is what the lateness bound bounds. The extra day is
// slack for a backfilling feed whose events are hours old, which production does have.
//
// The residual is deliberate. An amendment arriving more than a day past its record is
// not found, and is written as a first emission rather than a new version — which the
// engine then discards in favour of the stored row. An arrival that late is already
// outside the lateness bound the tenant configured, so it is a correlation the platform
// has said it will not make; this reads it the same way rather than paying ninety
// partitions on every close pass to honour the exception.
type PartitionBound struct {
	From time.Time
	To   time.Time
}

// where renders the bound as a partition-pruning predicate.
//
// Written over toDate(window_start) rather than over window_start because that IS the
// partition expression, so the pruning is exact rather than inferred from a range.
func (b PartitionBound) where() string {
	return "toDate(window_start) >= toDate(?) AND toDate(window_start) <= toDate(?) "
}

// ByIDs loads the stored records for a set of correlation ids.
//
// Exists so the closer can MERGE a late arrival into what is already stored rather than
// replacing it. A correlation id is stable forever while the window state behind it is
// not, so an event arriving after the lateness bound refills an empty window — and an
// amendment built from that window alone would overwrite a four-vendor record with a
// one-vendor one.
//
// Returns only what it finds. A first emission has nothing stored, which is the ordinary
// case and not an error.
func (r *CorrelatedRepo) ByIDs(
	ctx context.Context, correlationIDs []uuid.UUID, bound PartitionBound,
) (map[uuid.UUID]CorrelatedRequest, error) {
	out := make(map[uuid.UUID]CorrelatedRequest, len(correlationIDs))
	if len(correlationIDs) == 0 {
		return out, nil
	}

	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}

	// The engine keeps every version until it merges, so the winning row has to be picked
	// explicitly: without that the same id returns each version it has ever had, and the
	// merge would fold in a superseded copy of itself.
	//
	// LIMIT 1 BY, NOT FINAL, and the difference matters here more than anywhere else in
	// this file. FINAL merges the matching parts to produce the answer; LIMIT 1 BY reads
	// the rows and keeps the highest version of each, which is the same answer for a
	// ReplacingMergeTree versioned on this column. This query is the most expensive read
	// the closer makes — every column, including the arrays and maps, for every amendment
	// in a tick — and during a backlog replay nearly every record IS an amendment.
	rows, err := r.client.Query(ctx,
		"SELECT "+correlatedColumns+" FROM correlated_requests "+
			"WHERE tenant_id = ? AND "+bound.where()+"AND correlation_id IN (?) "+
			"ORDER BY version DESC LIMIT 1 BY correlation_id",
		tenantID, bound.From, bound.To, correlationIDs)
	if err != nil {
		return nil, fmt.Errorf("query correlated records: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		record, err := scanCorrelated(rows)
		if err != nil {
			return nil, err
		}
		out[record.CorrelationID] = record
	}
	return out, rows.Err()
}

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
			orEmptyRuleLists(record.MatchedRuleIDs), orEmptyScores(record.Scores),
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
	ctx context.Context, correlationIDs []uuid.UUID, bound PartitionBound,
) (map[uuid.UUID]uint64, error) {
	versions := make(map[uuid.UUID]uint64, len(correlationIDs))
	if len(correlationIDs) == 0 {
		return versions, nil
	}

	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}

	// DELIBERATELY NOT FINAL. Everywhere else in this file FINAL is load-bearing, because
	// the caller wants the winning row's CONTENTS and an unmerged read hands back stale
	// ones. Here the only thing asked for is the highest version, and max() computes that
	// from the superseded rows just as correctly as from the merged one — FINAL would buy
	// an identical answer for the cost of a merge-on-read.
	//
	// It is not a micro-optimisation either. This runs on the closer's hot path, every
	// ten seconds, in chunks of VersionLookupChunk over a tick's whole output.
	rows, err := r.client.Query(ctx,
		"SELECT correlation_id, max(version) FROM correlated_requests "+
			"WHERE tenant_id = ? AND "+bound.where()+
			"AND correlation_id IN (?) GROUP BY correlation_id",
		tenantID, bound.From, bound.To, correlationIDs)
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
		&record.Verdicts, &record.RuleIDs, &record.MatchedRuleIDs, &record.Scores,
		&record.CombinedOutcome, &record.HasDisagreement, &record.DisagreementKind,
		&record.JoinSignals, &record.JoinTier, &record.Confidence,
		&record.CandidateCount, &record.Version, &record.Amended,
	); err != nil {
		return CorrelatedRequest{}, fmt.Errorf("scan correlated request: %w", err)
	}
	record.ClientIP = ipOrNil(clientIP)
	return record, nil
}

// orEmptyScores mirrors orEmptyMap for float values: ClickHouse rejects a nil Map.
// orEmptyRuleLists keeps a nil map out of the driver, and drops the empty lists a vendor
// that matched nothing would otherwise contribute — a key mapping to [] says "this vendor
// matched no rules", which the absence of the key already says more cheaply.
func orEmptyRuleLists(m map[string][]string) map[string][]string {
	out := make(map[string][]string, len(m))
	for vendor, rules := range m {
		if len(rules) == 0 {
			continue
		}
		out[vendor] = rules
	}
	return out
}

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

// EventCorrelationSlack is how far either side of an event its correlated record may start.
//
// A record's window_start is the start of the bucket its events fell into, so it is at
// most one correlation window before the earliest event and never after the latest. Ten
// minutes is enormous against a five-second window, and it is what keeps the lookup below
// affordable: the same query unbounded reads the whole 90-day retention.
const EventCorrelationSlack = 10 * time.Minute

// CorrelationForEvent finds the correlated record one event belongs to.
//
// An event does not carry a correlation id — the record stores event ids, and writing the
// reverse would mean rewriting every event after the join — so this is a search rather
// than a lookup, and the event's OWN TIME is what makes it a cheap one. Bounded to the
// minutes around the event, it reads a few hundred thousand rows; unbounded it reads
// hundreds of millions and is cancelled before it answers.
//
// No FINAL: the only column read is the correlation id, and every version of a record
// carries the same one, so deduplicating would double the work to return the same answer.
//
// Not found is a normal answer. An event correlated with nothing — the only vendor that
// saw the request — has no record, and that is a fact about the traffic rather than a
// failure.
func (r *CorrelatedRepo) CorrelationForEvent(
	ctx context.Context, eventID string, eventTime time.Time,
) (uuid.UUID, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	if eventID == "" || eventTime.IsZero() {
		// Without a time there is no window, and the query would be the unbounded scan
		// this function exists to avoid.
		return uuid.Nil, ErrNotFound
	}

	rows, err := r.client.Query(ctx,
		`SELECT correlation_id FROM correlated_requests
		 WHERE tenant_id = ? AND window_start >= ? AND window_start <= ?
		   AND has(event_ids, ?) LIMIT 1`,
		tenantID,
		eventTime.Add(-EventCorrelationSlack).UTC(),
		eventTime.Add(EventCorrelationSlack).UTC(),
		eventID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("find correlation for event: %w", err)
	}
	defer func() { _ = rows.Close() }()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return uuid.Nil, fmt.Errorf("find correlation for event: %w", err)
		}
		return uuid.Nil, ErrNotFound
	}

	var correlationID uuid.UUID
	if err := rows.Scan(&correlationID); err != nil {
		return uuid.Nil, fmt.Errorf("scan correlation id: %w", err)
	}
	return correlationID, rows.Err()
}
