package clickhouse

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/query"
	"github.com/menta2k/siem/internal/tenancy"
)

// Reading the migration from correlated records rather than from two vendor counts.
//
// "F5 blocked 400 requests and Cloudflare logged 380" is not evidence of anything: it
// does not say they were the same requests, and on this deployment they mostly are not.
// Every query here starts from correlated_requests, where a row IS one request as both
// vendors saw it, and where the join tier records how it was established. Measured on
// production, every F5 record that joins a Cloudflare one joins on a shared CF-Ray —
// tier 1, high confidence — so this evidence is exact and not heuristic.

// WAFUncoveredGroup is one F5 violation on one host and method that Cloudflare did not
// act on: the unit a single new Cloudflare rule would be written for.
type WAFUncoveredGroup struct {
	// Violation is F5's own name for what it caught, which is what the new Cloudflare
	// rule has to reproduce.
	Violation     string
	RequestHost   string
	RequestMethod string

	Requests uint64
	// Paths and Clients are the breadth of the group, which separates a targeted probe
	// from a scan: 40 requests over 2 paths is one broken client, over 30 it is someone
	// walking the site.
	Paths   uint64
	Clients uint64
	// CloudflareAllowlisted counts requests where a Cloudflare rule DID match but let
	// them through — a skip or an allow. It needs the opposite fix from the rest of the
	// group: an exemption is overriding the edge, so adding a detection behind it would
	// change nothing.
	CloudflareAllowlisted uint64

	FirstSeen time.Time
	LastSeen  time.Time
}

// WAFRuleAgreement is one Cloudflare rule measured against F5 on the same requests.
//
// THE THREE F5 COUNTS ARE NEVER MERGED. F5 has a transparent mode of its own, and a
// request it flagged without blocking is weaker evidence than one it stopped and
// stronger than one it ignored. Folding "flagged" into either neighbour would make a
// rule read as ready to enforce, or as a false positive, on evidence that says neither.
type WAFRuleAgreement struct {
	RuleID string
	Action string

	// Correlated is the denominator: how many of the rule's requests joined an F5
	// record at all. Two confirmations out of two is a very different finding from two
	// out of two hundred.
	Correlated uint64
	F5Blocked  uint64
	F5Flagged  uint64
	F5Allowed  uint64

	Hosts uint64
	// RequestHost names the site when the rule only fires on one, and is empty when it
	// fires on several — naming one of them would be wrong.
	RequestHost string
	// Reading classifies the split, computed in SQL so the value a filter matches and
	// the value shown beside it are the same value.
	Reading string

	FirstSeen time.Time
	LastSeen  time.Time
}

// WAFMigrationSample is one request as BOTH vendors saw it.
type WAFMigrationSample struct {
	CorrelationID     string
	F5EventID         string
	CloudflareEventID string

	EventTime     time.Time
	ClientIP      net.IP
	Country       string
	ClientASN     uint32
	RequestHost   string
	RequestPath   string
	RequestQuery  string
	RequestMethod string
	UserAgent     string

	F5Verdict string
	// F5Violations is every violation F5 recorded on the request, not only the one being
	// grouped on: a request that tripped four is a different case from one that tripped
	// this one alone.
	F5Violations      []string
	CloudflareVerdict string
	CloudflareRuleID  string
	AttackScore       uint8
}

// Migration readings. How a rule's agreement with F5 classifies.
//
// DEFINED ONCE, HERE, and computed in SQL. The stage a rule appears under and the label
// shown beside it must come from the same expression, or a rule can be listed as ready
// to enforce while its own row calls it disputed.
const (
	// ReadingReady means F5 blocks nearly everything this rule logs. Safe to enforce.
	ReadingReady = "ready"
	// ReadingDisputed means both vendors hold a real share of the group, so it needs
	// reading before it is acted on.
	ReadingDisputed = "disputed"
	// ReadingFalsePositive means F5 lets through nearly everything this rule logs.
	ReadingFalsePositive = "false_positive"
	// ReadingInsufficient means too few correlated requests to say anything yet. It is
	// its own answer, not a quiet omission: a rule with three matching requests is not
	// evidence, and rounding it to either conclusion would invent one.
	ReadingInsufficient = "insufficient"
)

// minCorrelatedForReading is the floor below which a rule is reported as insufficient.
//
// Ten is low enough that a genuinely rare detection still becomes actionable within a
// day, and high enough that a single unlucky pair cannot read as a verdict.
const minCorrelatedForReading = 10

// agreementReadingExpr classifies a rule by how F5 treated the same requests.
//
// The aggregates name the SOURCE columns, so a SELECT using this must alias its own sums
// to something else — f5_blocked_total rather than f5_blocked. Aliasing an aggregate back
// to the column it aggregates makes ClickHouse resolve the reference inside this
// expression to that alias and reject the query; waftuning.go and cfrules.go carry the
// same warning for the same reason.
//
// A flagged request counts as agreement at HALF weight. F5 saw it and chose not to stop
// it, which is neither the confirmation a block gives nor the contradiction an allow
// gives, and the arithmetic should say so rather than pick a side.
//
// The thresholds are deliberately wide, matching the tuning view: a rule is worth acting
// on when it is overwhelmingly one thing or the other, and anything between is reported
// as disputed rather than nudged toward a conclusion the numbers do not support.
const agreementReadingExpr = `
	multiIf(
		count() < ` + `?` + `, '` + ReadingInsufficient + `',
		(countIf(f5_verdict = 'blocked') + countIf(f5_verdict = 'monitored') / 2) /
			count() >= 0.8, '` + ReadingReady + `',
		(countIf(f5_verdict = 'blocked') + countIf(f5_verdict = 'monitored') / 2) /
			count() <= 0.2, '` + ReadingFalsePositive + `',
		'` + ReadingDisputed + `'
	)`

// eventJoinWindow is how far outside the correlated window to look for the vendor events
// a record names.
//
// The events and the record they were correlated into are written from the same
// delivery, so they should sit inside the same hour. An hour of slack absorbs a record
// whose window opened just before the range without widening the scan beyond a partition
// either side, since normalized_events is partitioned by day.
const eventJoinWindow = time.Hour

// WAFMigrationFilter narrows a panel. Empty fields mean no filter rather than a match
// against the empty string.
type WAFMigrationFilter struct {
	// RequestHost narrows to one site, which is how a migration is actually run: host by
	// host rather than all at once.
	RequestHost string
}

// WAFMigrationRepo reads the three migration stages.
type WAFMigrationRepo struct {
	client *Client
}

// NewWAFMigrationRepo constructs the repository.
func NewWAFMigrationRepo(client *Client) *WAFMigrationRepo {
	return &WAFMigrationRepo{client: client}
}

// Uncovered returns traffic F5 blocked that no Cloudflare rule matched.
func (r *WAFMigrationRepo) Uncovered(
	ctx context.Context, q DashboardQuery, filter WAFMigrationFilter,
) ([]WAFUncoveredGroup, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}

	sql, args := uncoveredQuery(tenantID, q, filter)
	rows, err := r.client.Query(ctx, sql, args...)
	if err != nil {
		return nil, query.TranslateError(err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]WAFUncoveredGroup, 0, q.limitOrDefault())
	for rows.Next() {
		var g WAFUncoveredGroup
		if err := rows.Scan(&g.Violation, &g.RequestHost, &g.RequestMethod,
			&g.Requests, &g.Paths, &g.Clients, &g.CloudflareAllowlisted,
			&g.FirstSeen, &g.LastSeen); err != nil {
			return nil, fmt.Errorf("scan waf uncovered group: %w", err)
		}
		out = append(out, g)
	}
	return out, query.TranslateError(rows.Err())
}

// RuleAgreement returns Cloudflare rules running in log mode, measured against F5.
//
// One query serves stages 2 and 3: they are the same aggregation read from opposite
// ends, and the reading decides which stage a rule belongs to. Splitting them into two
// queries would let the two stages disagree about the same rule.
func (r *WAFMigrationRepo) RuleAgreement(
	ctx context.Context, q DashboardQuery, filter WAFMigrationFilter, readings []string,
) ([]WAFRuleAgreement, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}

	sql, args := ruleAgreementQuery(tenantID, q, filter, readings)
	rows, err := r.client.Query(ctx, sql, args...)
	if err != nil {
		return nil, query.TranslateError(err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]WAFRuleAgreement, 0, q.limitOrDefault())
	for rows.Next() {
		var a WAFRuleAgreement
		if err := rows.Scan(&a.RuleID, &a.Action, &a.Correlated,
			&a.F5Blocked, &a.F5Flagged, &a.F5Allowed,
			&a.Hosts, &a.RequestHost, &a.Reading,
			&a.FirstSeen, &a.LastSeen); err != nil {
			return nil, fmt.Errorf("scan waf rule agreement: %w", err)
		}
		out = append(out, a)
	}
	return out, query.TranslateError(rows.Err())
}

// Samples returns the requests behind one row, with both verdicts on each.
//
// Two round trips. The F5 side comes back with the correlated record's whole event list
// on each row; the Cloudflare side is then fetched for exactly those ids. Reaching it
// through the same join instead cost seven seconds, because Cloudflare logs twenty-five
// times as many events as F5 and the join reads all of them to find forty.
func (r *WAFMigrationRepo) Samples(
	ctx context.Context, sel WAFMigrationSelector, q DashboardQuery,
) ([]WAFMigrationSample, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}

	sql, args := migrationSamplesQuery(tenantID, sel, q)
	rows, err := r.client.Query(ctx, sql, args...)
	if err != nil {
		return nil, query.TranslateError(err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]WAFMigrationSample, 0, q.limitOrDefault())
	// The candidate ids per sample, kept beside it so the Cloudflare pass can attribute
	// what it finds back to the right request.
	candidates := make([][]string, 0, q.limitOrDefault())
	for rows.Next() {
		var s WAFMigrationSample
		var ip net.IP
		var eventIDs []string
		if err := rows.Scan(&s.CorrelationID, &s.F5EventID, &eventIDs,
			&s.EventTime, &ip, &s.Country, &s.ClientASN,
			&s.RequestHost, &s.RequestPath, &s.RequestQuery, &s.RequestMethod,
			&s.UserAgent, &s.F5Verdict, &s.F5Violations,
			&s.CloudflareVerdict, &s.CloudflareRuleID); err != nil {
			return nil, fmt.Errorf("scan waf migration sample: %w", err)
		}
		s.ClientIP = ip
		out = append(out, s)
		candidates = append(candidates, eventIDs)
	}
	if err := rows.Err(); err != nil {
		return nil, query.TranslateError(err)
	}

	if err := r.attachCloudflare(ctx, tenantID, out, candidates, q); err != nil {
		return nil, err
	}
	return out, nil
}

// cloudflareEvent is one Cloudflare event's contribution to a sample row.
type cloudflareEvent struct {
	eventID string
	ruleID  string
	score   uint8
}

// attachCloudflare fills in the Cloudflare event and score on a page of samples.
//
// A miss is not an error. The Cloudflare event can have aged out of retention while the
// correlated record and the F5 event survive, and a sample with an empty score is still
// the evidence the page was opened for — dropping the row would silently shorten it.
func (r *WAFMigrationRepo) attachCloudflare(
	ctx context.Context, tenantID uuid.UUID,
	samples []WAFMigrationSample, candidates [][]string, q DashboardQuery,
) error {
	ids := make([]string, 0, len(samples)*2)
	for _, list := range candidates {
		ids = append(ids, list...)
	}
	if len(ids) == 0 {
		return nil
	}

	sql, args := cloudflareScoresQuery(tenantID, ids, q)
	rows, err := r.client.Query(ctx, sql, args...)
	if err != nil {
		return query.TranslateError(err)
	}
	defer func() { _ = rows.Close() }()

	found := make(map[string]cloudflareEvent, len(ids))
	for rows.Next() {
		var e cloudflareEvent
		if err := rows.Scan(&e.eventID, &e.ruleID, &e.score); err != nil {
			return fmt.Errorf("scan cloudflare sample event: %w", err)
		}
		found[e.eventID] = e
	}
	if err := rows.Err(); err != nil {
		return query.TranslateError(err)
	}

	for i := range samples {
		if best, ok := pickCloudflareEvent(candidates[i], found); ok {
			samples[i].CloudflareEventID = best.eventID
			samples[i].AttackScore = best.score
		}
	}
	return nil
}

// pickCloudflareEvent chooses ONE event per request.
//
// Cloudflare logs a row per hop of a Worker-protected request — the client-facing
// request, the Worker's subrequest, the origin fetch — and all of them belong to the same
// correlated record. The hop that carries a security decision is the one worth showing,
// then one that carries a score, with the id as a deterministic tiebreak so the same
// request does not change appearance between refreshes.
func pickCloudflareEvent(
	ids []string, found map[string]cloudflareEvent,
) (cloudflareEvent, bool) {
	var best cloudflareEvent
	var ok bool
	for _, id := range ids {
		candidate, present := found[id]
		if !present {
			continue
		}
		if !ok || betterCloudflareEvent(candidate, best) {
			best, ok = candidate, true
		}
	}
	return best, ok
}

// betterCloudflareEvent ranks two hops of the same request.
func betterCloudflareEvent(a, b cloudflareEvent) bool {
	if (a.ruleID != "") != (b.ruleID != "") {
		return a.ruleID != ""
	}
	if (a.score > 0) != (b.score > 0) {
		return a.score > 0
	}
	return a.eventID > b.eventID
}
