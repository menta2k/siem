package clickhouse

import (
	"context"
	"fmt"

	"github.com/google/uuid"

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
	// Reading is the classification of the split above: one of the Reading* constants.
	// Computed in SQL so the filter and the label can never disagree.
	Reading string
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

// WAF readings. The classification of a rule's score split, and the vocabulary the
// filter offers.
//
// DEFINED ONCE, HERE, and computed in SQL rather than in the browser. Filtering has to
// happen before the top-N limit — a detection matching ten requests would otherwise be
// crowded out by an allowlist matching six thousand, and the filter would appear to
// return nothing. Deriving the label a second time in the frontend would then be a
// threshold that could drift from the one the filter uses.
const (
	// ReadingExempting is a skip rule: not a detection at all, but an exemption, and
	// everything behind it never runs.
	ReadingExempting = "exempting"
	// ReadingAttacks means the WAF's own model agrees with the rule.
	ReadingAttacks = "attacks"
	// ReadingClean means it disagrees: the rule fires on traffic scored as harmless.
	ReadingClean = "clean"
	ReadingMixed = "mixed"
	// ReadingUnscored is a rule whose events carry no score, which every row written
	// before migration 0015 does.
	ReadingUnscored = "unscored"
)

// readingExpr classifies a group by its score split.
//
// The thresholds are deliberately wide. A rule is worth acting on when it is
// overwhelmingly one thing or the other, and anything between 20% and 80% is reported
// as mixed rather than nudged toward a conclusion the numbers do not support.
const readingExpr = `
	multiIf(
		waf_action = 'skip', '` + ReadingExempting + `',
		sum(attack_events) + sum(suspicious_events) + sum(clean_events) = 0, '` + ReadingUnscored + `',
		(sum(attack_events) + sum(suspicious_events)) /
			(sum(attack_events) + sum(suspicious_events) + sum(clean_events)) >= 0.8,
			'` + ReadingAttacks + `',
		(sum(attack_events) + sum(suspicious_events)) /
			(sum(attack_events) + sum(suspicious_events) + sum(clean_events)) <= 0.2,
			'` + ReadingClean + `',
		'` + ReadingMixed + `'
	)`

// WAFRuleFilter narrows the profile. Both fields are optional, and an empty value means
// no filter rather than a match against the empty string.
type WAFRuleFilter struct {
	// Action matches the vendor's own verb: log, skip, block, managedChallenge.
	Action string
	// Reading matches one of the constants above.
	Reading string
}

// WAFTuningRepo reads the WAF rule profile.
type WAFTuningRepo struct {
	client *Client
}

// NewWAFTuningRepo constructs the repository.
func NewWAFTuningRepo(client *Client) *WAFTuningRepo { return &WAFTuningRepo{client: client} }

// RuleProfile returns the top rules by volume, split by host, action and source.
func (r *WAFTuningRepo) RuleProfile(
	ctx context.Context, q DashboardQuery, filter WAFRuleFilter,
) ([]WAFRuleProfile, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}

	// The mean is derived here rather than stored, and guarded: score_count is 0 for a
	// group where nothing was scored, and dividing by it would make every such row NaN.
	sql, args := ruleProfileQuery(tenantID, q, filter)

	rows, err := r.client.Query(ctx, sql, args...)
	if err != nil {
		return nil, query.TranslateError(err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]WAFRuleProfile, 0, q.limitOrDefault())
	for rows.Next() {
		var p WAFRuleProfile
		if err := rows.Scan(&p.RuleID, &p.RequestHost, &p.Action, &p.Source,
			&p.Events, &p.AttackEvents, &p.SuspiciousEvents, &p.CleanEvents,
			&p.MeanScore, &p.Reading); err != nil {
			return nil, fmt.Errorf("scan waf rule profile: %w", err)
		}
		out = append(out, p)
	}
	return out, query.TranslateError(rows.Err())
}

// ruleProfileQuery assembles the profile query and its arguments.
//
// Both filters run BEFORE the limit, which is the entire reason they are server-side. A
// detection matching ten requests would never survive an ordering by volume against an
// allowlist matching six thousand, so filtering the response instead would return an
// empty list for exactly the rules worth looking at.
func ruleProfileQuery(
	tenantID uuid.UUID, q DashboardQuery, filter WAFRuleFilter,
) (string, []any) {
	sql := `
		SELECT rule_id, request_host, waf_action, waf_source,
		       uniqCombinedMerge(12)(events) AS events,
		       sum(attack_events)     AS attack_events,
		       sum(suspicious_events) AS suspicious_events,
		       sum(clean_events)      AS clean_events,
		       if(sum(score_count) > 0, sum(score_sum) / sum(score_count), 0) AS mean_score,
		       ` + readingExpr + ` AS reading
		FROM rollup_waf_rules_1h
		WHERE tenant_id = ? AND bucket >= ? AND bucket < ?`
	args := []any{tenantID, q.Range.From, q.Range.To}

	// In the WHERE, before grouping: it is a key column and narrowing early is free.
	if filter.Action != "" {
		sql += ` AND waf_action = ?`
		args = append(args, filter.Action)
	}

	sql += ` GROUP BY rule_id, request_host, waf_action, waf_source`

	// In the HAVING, because the reading is an aggregate over the group.
	if filter.Reading != "" {
		sql += ` HAVING reading = ?`
		args = append(args, filter.Reading)
	}

	sql += ` ORDER BY events DESC LIMIT ?`
	return sql, append(args, q.limitOrDefault())
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

	// NO FINAL, and counting distinct event ids instead.
	//
	// FINAL was the obvious way to avoid counting a redelivered event twice, and it made
	// this query read 3.4 GiB and take 7.7 seconds against a 10 second limit — because
	// FINAL merges every part in range BEFORE the rule_id filter is applied, so the bloom
	// index that should have skipped almost everything never got the chance. Counting
	// distinct ids deduplicates the same redeliveries without the merge, and the filter
	// then does its job: the same query drops to 4.2 seconds.
	//
	// uniqCombined(12) rather than uniqExact for consistency with every rollup in the
	// platform, which accept ~1% error for a large constant-memory saving. Measured on
	// the largest rule here the difference was 0.02%, against a question — how noisy is
	// this rule on this path — that is answered in orders of magnitude.
	//
	// avgIf rather than sum/count so an unscored row cannot drag the mean toward zero,
	// which on this INVERTED scale would read as "these requests were attacks".
	//
	// GUARDED, because avgIf over no matching rows returns NaN rather than 0 — and NaN is
	// not representable in JSON, so a single such group would break the whole response
	// rather than show an odd number. A rule whose events all predate migration 0015 is
	// exactly that group, and every row written before it reads 0.
	const sql = `
		SELECT request_host, request_path,
		       uniqCombined(12)(event_id) AS events,
		       if(countIf(waf_attack_score > 0) > 0,
		          avgIf(waf_attack_score, waf_attack_score > 0), 0) AS mean_score
		FROM normalized_events
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
	//
	// NO FINAL HERE EITHER, and this one was not merely slow — it timed out. Reading
	// 4.3 GiB across 45M rows, it never finished inside the 10 second limit, so the
	// panel it feeds always failed. correlated_requests is a ReplacingMergeTree whose
	// rows are genuinely amended when a late event joins, so the duplicates are real and
	// cannot simply be ignored: the newest version per correlation is selected explicitly
	// with argMax over the version column, which is what FINAL would have done and costs
	// a GROUP BY instead of a merge. 10 seconds and failing becomes 2 seconds.
	const sql = `
		SELECT count() AS correlated,
		       countIf(has(others, 'blocked') OR has(others, 'challenged')) AS confirmed,
		       countIf(NOT has(others, 'blocked') AND NOT has(others, 'challenged')) AS allowed
		FROM (
			SELECT arrayFilter(
			           (v, k) -> k != 'cloudflare',
			           mapValues(argMax(verdicts, version)),
			           mapKeys(argMax(verdicts, version))
			       ) AS others
			FROM correlated_requests
			WHERE tenant_id = ? AND last_event_time >= ? AND last_event_time < ?
			  AND rule_ids['cloudflare'] = ? AND vendor_count > 1
			GROUP BY correlation_id
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
