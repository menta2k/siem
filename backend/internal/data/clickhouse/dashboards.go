package clickhouse

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/menta2k/siem/internal/query"
	"github.com/menta2k/siem/internal/tenancy"
)

// DashboardRepo reads the panel data.
//
// Every query here reads a rollup table and none reads normalized_events. That is the
// whole design: a panel that scans raw events looks fine on a demo dataset and becomes
// unusable at production volume, and the discovery happens in production.
//
// The rollups store uniqCombined(12) STATES, so every read applies uniqCombinedMerge(12).
// Reading the state column directly returns an opaque binary blob rather than a number — a
// mistake that produces nonsense rather than an error.
//
// The precision argument is part of the TYPE: uniqCombinedMerge(12) over a
// uniqCombined(12) state, and a mismatch is rejected by ClickHouse rather than silently
// misread. These counts carry roughly 1% error by design — the states are capped so that
// merging them stays cheap (see migration 0005). Anything needing exact figures must read
// normalized_events directly.
type DashboardRepo struct {
	client *Client
}

// NewDashboardRepo builds the repository.
func NewDashboardRepo(client *Client) *DashboardRepo {
	return &DashboardRepo{client: client}
}

// Interval is the bucket width a panel requests.
type Interval string

// The supported bucket widths.
//
// A closed set, because the interval reaches a SQL function name. Accepting an
// arbitrary string here would hand a caller the one position in these queries that no
// placeholder can protect.
const (
	Interval5m Interval = "5m"
	Interval1h Interval = "1h"
	Interval1d Interval = "1d"
)

// bucketExpr maps an interval to its ClickHouse rounding function.
func bucketExpr(interval Interval) (string, error) {
	switch interval {
	case Interval5m:
		return "toStartOfFiveMinute(bucket)", nil
	case Interval1h:
		return "toStartOfHour(bucket)", nil
	case Interval1d:
		return "toStartOfDay(bucket)", nil
	default:
		return "", fmt.Errorf("unsupported interval %q", interval)
	}
}

// DashboardQuery is the shared range every panel accepts, so a range change updates
// all of them consistently (FR-025).
type DashboardQuery struct {
	Range    query.TimeRange
	Interval Interval
	// Limit caps the rows a "top N" panel returns.
	Limit int
}

func (q DashboardQuery) limitOrDefault() int {
	if q.Limit <= 0 || q.Limit > 100 {
		return 10
	}
	return q.Limit
}

// VolumePoint is one bucket of one vendor's traffic.
type VolumePoint struct {
	Bucket time.Time
	Vendor string
	Events uint64
}

// VendorVolume returns event volume per vendor over time.
func (r *DashboardRepo) VendorVolume(
	ctx context.Context, q DashboardQuery,
) ([]VolumePoint, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}
	expr, err := bucketExpr(q.Interval)
	if err != nil {
		return nil, err
	}

	rows, err := r.client.Query(ctx, fmt.Sprintf(`
		SELECT %s AS ts, vendor, uniqCombinedMerge(12)(events) AS events
		FROM rollup_vendor_volume_5m
		WHERE tenant_id = ? AND bucket >= ? AND bucket < ?
		GROUP BY ts, vendor
		ORDER BY ts, vendor`, expr),
		tenantID, q.Range.From, q.Range.To)
	if err != nil {
		return nil, query.TranslateError(err)
	}
	defer func() { _ = rows.Close() }()

	var out []VolumePoint
	for rows.Next() {
		var p VolumePoint
		if err := rows.Scan(&p.Bucket, &p.Vendor, &p.Events); err != nil {
			return nil, fmt.Errorf("scan vendor volume: %w", err)
		}
		out = append(out, p)
	}
	return out, query.TranslateError(rows.Err())
}

// VerdictPoint is one bucket of one vendor's verdict mix.
type VerdictPoint struct {
	Bucket  time.Time
	Vendor  string
	Verdict string
	Events  uint64
}

// VerdictMix returns the verdict breakdown over time.
func (r *DashboardRepo) VerdictMix(
	ctx context.Context, q DashboardQuery,
) ([]VerdictPoint, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}
	expr, err := bucketExpr(q.Interval)
	if err != nil {
		return nil, err
	}

	rows, err := r.client.Query(ctx, fmt.Sprintf(`
		SELECT %s AS ts, vendor, verdict, uniqCombinedMerge(12)(events) AS events
		FROM rollup_verdict_mix_5m
		WHERE tenant_id = ? AND bucket >= ? AND bucket < ?
		GROUP BY ts, vendor, verdict
		ORDER BY ts, vendor, verdict`, expr),
		tenantID, q.Range.From, q.Range.To)
	if err != nil {
		return nil, query.TranslateError(err)
	}
	defer func() { _ = rows.Close() }()

	var out []VerdictPoint
	for rows.Next() {
		var p VerdictPoint
		if err := rows.Scan(&p.Bucket, &p.Vendor, &p.Verdict, &p.Events); err != nil {
			return nil, fmt.Errorf("scan verdict mix: %w", err)
		}
		out = append(out, p)
	}
	return out, query.TranslateError(rows.Err())
}

// RuleCount is one rule's trigger count for the range.
type RuleCount struct {
	Vendor string
	RuleID string
	Events uint64
}

// TopRules returns the most frequently triggered rules per vendor.
func (r *DashboardRepo) TopRules(
	ctx context.Context, q DashboardQuery,
) ([]RuleCount, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}

	rows, err := r.client.Query(ctx, `
		SELECT vendor, rule_id, uniqCombinedMerge(12)(events) AS events
		FROM rollup_top_rules_1h
		WHERE tenant_id = ? AND bucket >= ? AND bucket < ?
		GROUP BY vendor, rule_id
		ORDER BY events DESC
		LIMIT ?`,
		tenantID, q.Range.From, q.Range.To, q.limitOrDefault())
	if err != nil {
		return nil, query.TranslateError(err)
	}
	defer func() { _ = rows.Close() }()

	var out []RuleCount
	for rows.Next() {
		var c RuleCount
		if err := rows.Scan(&c.Vendor, &c.RuleID, &c.Events); err != nil {
			return nil, fmt.Errorf("scan top rules: %w", err)
		}
		out = append(out, c)
	}
	return out, query.TranslateError(rows.Err())
}

// SourceCount is one client's activity for the range.
type SourceCount struct {
	ClientIP net.IP
	Country  string
	ASN      uint32
	Events   uint64
	Blocked  uint64
}

// TopSources returns the busiest client addresses.
func (r *DashboardRepo) TopSources(
	ctx context.Context, q DashboardQuery,
) ([]SourceCount, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}

	rows, err := r.client.Query(ctx, `
		SELECT client_ip, client_country, client_asn,
		       uniqCombinedMerge(12)(events) AS events, uniqCombinedMerge(12)(blocked) AS blocked
		FROM rollup_top_sources_1h
		WHERE tenant_id = ? AND bucket >= ? AND bucket < ?
		GROUP BY client_ip, client_country, client_asn
		ORDER BY events DESC
		LIMIT ?`,
		tenantID, q.Range.From, q.Range.To, q.limitOrDefault())
	if err != nil {
		return nil, query.TranslateError(err)
	}
	defer func() { _ = rows.Close() }()

	var out []SourceCount
	for rows.Next() {
		var (
			c  SourceCount
			ip net.IP
		)
		if err := rows.Scan(&ip, &c.Country, &c.ASN, &c.Events, &c.Blocked); err != nil {
			return nil, fmt.Errorf("scan top sources: %w", err)
		}
		c.ClientIP = ip
		out = append(out, c)
	}
	return out, query.TranslateError(rows.Err())
}

// ASNCount is one origin network's activity for the range.
type ASNCount struct {
	ASN uint32
	// Country is where most of this network's traffic came from, not where the network
	// is registered — an ASN routinely spans several.
	Country string
	Events  uint64
	Blocked uint64
	// Clients is the number of distinct addresses seen on the network, which is what
	// separates one noisy client from a distributed source.
	Clients uint64
}

// TopASNs returns the busiest origin networks.
//
// Reads the SAME rollup as TopSources rather than a rollup of its own. The uniqCombined
// states are per address, and merging them across the addresses of one network unions
// the sets — so an event redelivered by the ReplacingMergeTree is still counted once,
// exactly as it is per source. A second materialised view would have bought nothing and
// cost another write path.
//
// Rows with no ASN are EXCLUDED. Only Cloudflare reports one, so a zero means "this
// vendor does not say", and letting those collapse into a single AS0 row would put a
// meaningless bucket at the top of the panel on most ranges.
func (r *DashboardRepo) TopASNs(ctx context.Context, q DashboardQuery) ([]ASNCount, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}

	rows, err := r.client.Query(ctx, `
		SELECT client_asn,
		       -- The country of the addresses that carried the most traffic. argMax over
		       -- the per-address event count, so a handful of events from a network's
		       -- outlier country cannot outvote its bulk.
		       argMax(client_country, address_events) AS country,
		       sum(address_events) AS events,
		       sum(address_blocked) AS blocked,
		       uniqExact(client_ip) AS clients
		FROM (
			-- Merged per ADDRESS first, then summed. An event belongs to exactly one
			-- address, so the per-address sets are disjoint and summing their sizes is
			-- exact — while each set still absorbs a redelivery of its own events.
			SELECT client_asn, client_country, client_ip,
			       uniqCombinedMerge(12)(events) AS address_events,
			       uniqCombinedMerge(12)(blocked) AS address_blocked
			FROM rollup_top_sources_1h
			WHERE tenant_id = ? AND bucket >= ? AND bucket < ? AND client_asn > 0
			GROUP BY client_asn, client_country, client_ip
		)
		GROUP BY client_asn
		ORDER BY events DESC
		LIMIT ?`,
		tenantID, q.Range.From, q.Range.To, q.limitOrDefault())
	if err != nil {
		return nil, query.TranslateError(err)
	}
	defer func() { _ = rows.Close() }()

	var out []ASNCount
	for rows.Next() {
		var c ASNCount
		if err := rows.Scan(&c.ASN, &c.Country, &c.Events, &c.Blocked, &c.Clients); err != nil {
			return nil, fmt.Errorf("scan top asns: %w", err)
		}
		out = append(out, c)
	}
	return out, query.TranslateError(rows.Err())
}

// DisagreementPoint is one bucket's disagreement breakdown.
type DisagreementPoint struct {
	Bucket time.Time
	Kind   string
	// Records is the number of correlated requests exhibiting this kind.
	Records uint64
	// Total is every correlated request in the bucket, so a rate can be computed from
	// one row rather than by dividing figures fetched separately.
	Total uint64
}

// Disagreements returns the disagreement rate and breakdown over time.
func (r *DashboardRepo) Disagreements(
	ctx context.Context, q DashboardQuery,
) ([]DisagreementPoint, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}
	expr, err := bucketExpr(q.Interval)
	if err != nil {
		return nil, err
	}

	rows, err := r.client.Query(ctx, fmt.Sprintf(`
		SELECT %s AS ts, disagreement_kind,
		       uniqCombinedMerge(12)(records) AS records, uniqCombinedMerge(12)(total) AS total
		FROM rollup_disagreement_5m
		WHERE tenant_id = ? AND bucket >= ? AND bucket < ?
		GROUP BY ts, disagreement_kind
		ORDER BY ts, disagreement_kind`, expr),
		tenantID, q.Range.From, q.Range.To)
	if err != nil {
		return nil, query.TranslateError(err)
	}
	defer func() { _ = rows.Close() }()

	var out []DisagreementPoint
	for rows.Next() {
		var p DisagreementPoint
		if err := rows.Scan(&p.Bucket, &p.Kind, &p.Records, &p.Total); err != nil {
			return nil, fmt.Errorf("scan disagreements: %w", err)
		}
		out = append(out, p)
	}
	return out, query.TranslateError(rows.Err())
}
