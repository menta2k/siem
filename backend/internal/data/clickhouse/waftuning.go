package clickhouse

import (
	"context"
	"fmt"

	"github.com/menta2k/siem/internal/query"
	"github.com/menta2k/siem/internal/tenancy"
)

// WAFRuleProfile is one rule's behaviour on one host, as the tuning view reads it.
//
// THE BANDS ARE THE FINDING, not the total. A rule that fires ten times on real attacks
// and ninety times on clean traffic has a mean that reads as harmless and a split that
// reads as "working, but far too broadly". Only one of those tells an operator what to
// change.
type WAFRuleProfile struct {
	RuleID      string
	RequestHost string
	// Action is the vendor's own verb. `log` means the rule matched and was not
	// enforced, which is the state a tuning decision acts on.
	Action string
	// Source is firewallManaged or firewallCustom, which decides how the rule is tuned.
	Source string

	Events uint64
	// Scored on Cloudflare's INVERTED scale: attack is 1-20, suspicious 21-50, clean
	// above 50.
	AttackEvents     uint64
	SuspiciousEvents uint64
	CleanEvents      uint64
	// MeanScore is 0 when nothing in the group carried a score.
	MeanScore float64
}

// WAFPathCount is one host and path a rule matched on.
type WAFPathCount struct {
	RequestHost string
	RequestPath string
	Events      uint64
	MeanScore   float64
}

// WAFCoverageGap is traffic the WAF scored as an attack that no rule matched.
type WAFCoverageGap struct {
	RequestHost      string
	Events           uint64
	AttackEvents     uint64
	SuspiciousEvents uint64
}

// WAFCorroboration is what the other vendors did with the same requests.
//
// The strongest evidence available for a tuning decision, and the one thing a
// single-vendor WAF console can never show: if Cloudflare only logged a request while
// F5 blocked it independently, the rule is catching something real and is safe to
// enforce. If nobody else reacted at all, the case for it is weaker.
type WAFCorroboration struct {
	RuleID string
	// Correlated is how many of the rule's requests joined another vendor's record at
	// all. It is the denominator, and without it the counts below cannot be read: two
	// confirmations out of two is a very different finding from two out of two hundred.
	Correlated uint64
	// ConfirmedByOthers counts records where a DIFFERENT vendor blocked or challenged.
	ConfirmedByOthers uint64
	// AllowedByOthers counts records where every other vendor let it through, which is
	// the shape of a false positive.
	AllowedByOthers uint64
}

// WAFTuningRepo reads the WAF rule profile.
type WAFTuningRepo struct {
	client *Client
}

// NewWAFTuningRepo constructs the repository.
func NewWAFTuningRepo(client *Client) *WAFTuningRepo { return &WAFTuningRepo{client: client} }

// RuleProfile returns the top rules by volume, split by host, action and source.
func (r *WAFTuningRepo) RuleProfile(
	ctx context.Context, q DashboardQuery,
) ([]WAFRuleProfile, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}

	// The mean is derived here rather than stored, and guarded: score_count is 0 for a
	// group where nothing was scored, and dividing by it would make every such row NaN.
	const sql = `
		SELECT rule_id, request_host, waf_action, waf_source,
		       uniqCombinedMerge(12)(events) AS events,
		       sum(attack_events)     AS attack_events,
		       sum(suspicious_events) AS suspicious_events,
		       sum(clean_events)      AS clean_events,
		       if(sum(score_count) > 0, sum(score_sum) / sum(score_count), 0) AS mean_score
		FROM rollup_waf_rules_1h
		WHERE tenant_id = ? AND bucket >= ? AND bucket < ?
		GROUP BY rule_id, request_host, waf_action, waf_source
		ORDER BY events DESC
		LIMIT ?`

	rows, err := r.client.Query(ctx, sql, tenantID, q.Range.From, q.Range.To, q.limitOrDefault())
	if err != nil {
		return nil, query.TranslateError(err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]WAFRuleProfile, 0, q.limitOrDefault())
	for rows.Next() {
		var p WAFRuleProfile
		if err := rows.Scan(&p.RuleID, &p.RequestHost, &p.Action, &p.Source,
			&p.Events, &p.AttackEvents, &p.SuspiciousEvents, &p.CleanEvents,
			&p.MeanScore); err != nil {
			return nil, fmt.Errorf("scan waf rule profile: %w", err)
		}
		out = append(out, p)
	}
	return out, query.TranslateError(rows.Err())
}

// RulePaths returns the URLs one rule matched on.
//
// A LIVE QUERY over the events, not a rollup. Paths are effectively unbounded — one of
// these hosts shows 1,892 distinct paths in three minutes — so rolling them up would
// cost more than the whole rest of this feature to answer a question that is only ever
// asked about one rule at a time. Filtering by rule_id uses the existing bloom index,
// and the range and limit bound the rest.
func (r *WAFTuningRepo) RulePaths(
	ctx context.Context, ruleID string, q DashboardQuery,
) ([]WAFPathCount, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}

	// FINAL because normalized_events is a ReplacingMergeTree: without it a redelivered
	// event is counted once per version, and an operator judging how noisy a rule is
	// would be reading merge history rather than traffic.
	const sql = `
		SELECT request_host, request_path, count() AS events,
		       if(countIf(waf_attack_score > 0) > 0,
		          sum(waf_attack_score) / countIf(waf_attack_score > 0), 0) AS mean_score
		FROM normalized_events FINAL
		WHERE tenant_id = ? AND vendor = 'cloudflare' AND rule_id = ?
		  AND event_time >= ? AND event_time < ?
		GROUP BY request_host, request_path
		ORDER BY events DESC
		LIMIT ?`

	rows, err := r.client.Query(ctx, sql,
		tenantID, ruleID, q.Range.From, q.Range.To, q.limitOrDefault())
	if err != nil {
		return nil, query.TranslateError(err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]WAFPathCount, 0, q.limitOrDefault())
	for rows.Next() {
		var p WAFPathCount
		if err := rows.Scan(&p.RequestHost, &p.RequestPath, &p.Events, &p.MeanScore); err != nil {
			return nil, fmt.Errorf("scan waf rule path: %w", err)
		}
		out = append(out, p)
	}
	return out, query.TranslateError(rows.Err())
}

// CoverageGaps returns hosts receiving attack-scored traffic that no rule matched.
func (r *WAFTuningRepo) CoverageGaps(
	ctx context.Context, q DashboardQuery,
) ([]WAFCoverageGap, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}

	const sql = `
		SELECT request_host,
		       uniqCombinedMerge(12)(events) AS events,
		       sum(attack_events)     AS attack_events,
		       sum(suspicious_events) AS suspicious_events
		FROM rollup_waf_gaps_1h
		WHERE tenant_id = ? AND bucket >= ? AND bucket < ?
		GROUP BY request_host
		ORDER BY attack_events DESC, events DESC
		LIMIT ?`

	rows, err := r.client.Query(ctx, sql, tenantID, q.Range.From, q.Range.To, q.limitOrDefault())
	if err != nil {
		return nil, query.TranslateError(err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]WAFCoverageGap, 0, q.limitOrDefault())
	for rows.Next() {
		var g WAFCoverageGap
		if err := rows.Scan(&g.RequestHost, &g.Events,
			&g.AttackEvents, &g.SuspiciousEvents); err != nil {
			return nil, fmt.Errorf("scan waf coverage gap: %w", err)
		}
		out = append(out, g)
	}
	return out, query.TranslateError(rows.Err())
}

// Corroboration reports what the other vendors made of one rule's requests.
//
// Read from correlated_requests, which already carries a per-vendor verdict map, so this
// is an aggregate rather than a join through event ids. `rule_ids['cloudflare']` is the
// Cloudflare rule on the joined record, which is exactly the key needed.
func (r *WAFTuningRepo) Corroboration(
	ctx context.Context, ruleID string, q DashboardQuery,
) (WAFCorroboration, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return WAFCorroboration{}, err
	}

	// vendor_count > 1 is what makes "another vendor" meaningful: a single-vendor record
	// is Cloudflare agreeing with itself, and counting it as unconfirmed would report
	// every unjoined request as evidence against the rule.
	const sql = `
		SELECT count() AS correlated,
		       countIf(has(map_values, 'blocked') OR has(map_values, 'challenged')) AS confirmed,
		       countIf(NOT has(map_values, 'blocked') AND NOT has(map_values, 'challenged')) AS allowed
		FROM (
			SELECT arrayFilter(
			           (v, k) -> k != 'cloudflare',
			           mapValues(verdicts), mapKeys(verdicts)
			       ) AS map_values
			FROM correlated_requests FINAL
			WHERE tenant_id = ? AND last_event_time >= ? AND last_event_time < ?
			  AND rule_ids['cloudflare'] = ? AND vendor_count > 1
		)`

	rows, err := r.client.Query(ctx, sql, tenantID, q.Range.From, q.Range.To, ruleID)
	if err != nil {
		return WAFCorroboration{}, query.TranslateError(err)
	}
	defer func() { _ = rows.Close() }()

	out := WAFCorroboration{RuleID: ruleID}
	if !rows.Next() {
		return out, query.TranslateError(rows.Err())
	}
	if err := rows.Scan(&out.Correlated, &out.ConfirmedByOthers, &out.AllowedByOthers); err != nil {
		return WAFCorroboration{}, fmt.Errorf("scan waf corroboration: %w", err)
	}
	return out, nil
}
