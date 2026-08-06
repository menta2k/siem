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
// The rollups store uniq STATES, so every read applies uniqMerge. Reading the state
// column directly returns an opaque binary blob rather than a number — a mistake that
// produces nonsense rather than an error.
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
		SELECT %s AS ts, vendor, uniqMerge(events) AS events
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
		SELECT %s AS ts, vendor, verdict, uniqMerge(events) AS events
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
		SELECT vendor, rule_id, uniqMerge(events) AS events
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
		       uniqMerge(events) AS events, uniqMerge(blocked) AS blocked
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
		       uniqMerge(records) AS records, uniqMerge(total) AS total
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
