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
	// Action is the rule's CONFIGURED action — log or simulate — filled in by the caller
	// from the rule table. It is deliberately not read from the requests: the action
	// recorded against a request is whichever rule decided it, which for a rule in log
	// mode is somebody else.
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

	EventTime time.Time
	// ReceivedAt and SourceVendor narrow the raw-payload lookup to a seek. Without them
	// that lookup scans, which the search detail view learned the hard way.
	ReceivedAt    time.Time
	SourceVendor  string
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

// ActionObservedMonitored labels a rule whose non-enforcement was seen on requests rather
// than read from its configuration — a managed rule a ruleset override runs as log, where
// the rule's own stored action still says block.
const ActionObservedMonitored = "log (observed)"

// MinCorrelatedForReading is the floor below which a rule is reported as insufficient.
//
// Exported because the console reports it: "8 of 10" tells a rule's author what is missing
// and when it will change, where "not enough evidence" tells them only that something is.
//
// Ten is low enough that a genuinely rare detection still becomes actionable within a
// day, and high enough that a single unlucky pair cannot read as a verdict.
const MinCorrelatedForReading = 10

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
	ctx context.Context, q DashboardQuery, filter WAFMigrationFilter,
	readings, monitoredRuleIDs []string,
) ([]WAFRuleAgreement, error) {
	// No candidates, no stage. Returning every rule instead would fill a migration
	// worklist with rules that are already enforcing, which is finished work.
	if len(monitoredRuleIDs) == 0 {
		return nil, nil
	}

	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}

	sql, args := ruleAgreementQuery(tenantID, q, filter, readings, monitoredRuleIDs)
	rows, err := r.client.Query(ctx, sql, args...)
	if err != nil {
		return nil, query.TranslateError(err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]WAFRuleAgreement, 0, q.limitOrDefault())
	for rows.Next() {
		var a WAFRuleAgreement
		if err := rows.Scan(&a.RuleID, &a.Correlated,
			&a.F5Blocked, &a.F5Flagged, &a.F5Allowed,
			&a.Hosts, &a.RequestHost, &a.Reading,
			&a.FirstSeen, &a.LastSeen); err != nil {
			return nil, fmt.Errorf("scan waf rule agreement: %w", err)
		}
		out = append(out, a)
	}
	return out, query.TranslateError(rows.Err())
}

// ObservedMonitoredRules returns the rules seen acting as non-enforcing in the window.
//
// Complements the rule table, which knows a managed rule's DEFAULT action and not the
// override that actually runs. Together they cover both kinds of candidate: a custom rule
// the customer set to log, and a managed rule a ruleset override runs as log.
func (r *WAFMigrationRepo) ObservedMonitoredRules(
	ctx context.Context, q DashboardQuery,
) ([]string, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}

	sql, args := observedMonitoredQuery(tenantID, q)
	rows, err := r.client.Query(ctx, sql, args...)
	if err != nil {
		return nil, query.TranslateError(err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]string, 0, 16)
	for rows.Next() {
		var ruleID string
		if err := rows.Scan(&ruleID); err != nil {
			return nil, fmt.Errorf("scan observed monitored rule: %w", err)
		}
		out = append(out, ruleID)
	}
	return out, query.TranslateError(rows.Err())
}

// Samples returns the requests behind one row, with both verdicts on each.
//
// TWO SHAPES, because the two kinds of row ask different questions of storage.
//
// A stage-1 row is keyed on an F5 VIOLATION, which lives on the F5 event rather than on
// the correlated record — so the rows cannot be limited before the join without
// truncating the evidence, and the join happens in SQL.
//
// A rule row carries no filter on the event at all, so its page of records is read first
// and their events fetched by id. That matters because its verdict is `allowed`: narrowing
// the events side by it selects forty million rows, and the false-positive drill-down timed
// out doing exactly that.
//
// Either way the Cloudflare side is a separate lookup — see attachCloudflare.
func (r *WAFMigrationRepo) Samples(
	ctx context.Context, sel WAFMigrationSelector, q DashboardQuery,
) ([]WAFMigrationSample, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}

	var samples []WAFMigrationSample
	var candidates [][]string
	if sel.Violation != "" {
		samples, candidates, err = r.samplesByViolation(ctx, tenantID, sel, q)
	} else {
		samples, candidates, err = r.samplesByRecord(ctx, tenantID, sel, q)
	}
	if err != nil {
		return nil, err
	}

	if err := r.attachCloudflare(ctx, tenantID, samples, candidates, q); err != nil {
		return nil, err
	}
	return samples, nil
}

// samplesByViolation joins the records to their F5 events in one query, so a filter on the
// event can be applied without limiting the rows first.
func (r *WAFMigrationRepo) samplesByViolation(
	ctx context.Context, tenantID uuid.UUID, sel WAFMigrationSelector, q DashboardQuery,
) ([]WAFMigrationSample, [][]string, error) {
	sql, args := migrationSamplesQuery(tenantID, sel, q)
	rows, err := r.client.Query(ctx, sql, args...)
	if err != nil {
		return nil, nil, query.TranslateError(err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]WAFMigrationSample, 0, q.limitOrDefault())
	candidates := make([][]string, 0, q.limitOrDefault())
	for rows.Next() {
		var s WAFMigrationSample
		var ip net.IP
		var eventIDs []string
		if err := rows.Scan(&s.CorrelationID, &s.F5EventID, &eventIDs,
			&s.EventTime, &s.ReceivedAt, &s.SourceVendor, &ip, &s.Country, &s.ClientASN,
			&s.RequestHost, &s.RequestPath, &s.RequestQuery, &s.RequestMethod,
			&s.UserAgent, &s.F5Verdict, &s.F5Violations,
			&s.CloudflareVerdict, &s.CloudflareRuleID); err != nil {
			return nil, nil, fmt.Errorf("scan waf migration sample: %w", err)
		}
		s.ClientIP = ip
		out = append(out, s)
		candidates = append(candidates, eventIDs)
	}
	return out, candidates, query.TranslateError(rows.Err())
}

// migrationRecord is one correlated record on its way to becoming a sample.
type migrationRecord struct {
	correlationID string
	eventIDs      []string
	requestHost   string
	requestMethod string
	f5Verdict     string
	cfVerdict     string
	cfRule        string
}

// samplesByRecord reads a page of records, then their F5 events by id.
func (r *WAFMigrationRepo) samplesByRecord(
	ctx context.Context, tenantID uuid.UUID, sel WAFMigrationSelector, q DashboardQuery,
) ([]WAFMigrationSample, [][]string, error) {
	records, err := r.sampleRecords(ctx, tenantID, sel, q)
	if err != nil {
		return nil, nil, err
	}
	if len(records) == 0 {
		return nil, nil, nil
	}

	ids := make([]string, 0, len(records)*2)
	for _, rec := range records {
		ids = append(ids, rec.eventIDs...)
	}

	events, err := r.f5Events(ctx, tenantID, ids, q)
	if err != nil {
		return nil, nil, err
	}

	out := make([]WAFMigrationSample, 0, len(records))
	candidates := make([][]string, 0, len(records))
	for _, rec := range records {
		event, ok := pickF5Event(rec.eventIDs, events)
		// A record whose F5 event has aged out of retention has nothing left to show:
		// the request path, the violations and the time all come from that event.
		if !ok {
			continue
		}
		out = append(out, WAFMigrationSample{
			CorrelationID:     rec.correlationID,
			F5EventID:         event.eventID,
			EventTime:         event.eventTime,
			ReceivedAt:        event.receivedAt,
			SourceVendor:      event.sourceVendor,
			ClientIP:          event.clientIP,
			Country:           event.country,
			ClientASN:         event.clientASN,
			RequestHost:       rec.requestHost,
			RequestPath:       event.requestPath,
			RequestQuery:      event.requestQuery,
			RequestMethod:     rec.requestMethod,
			UserAgent:         event.userAgent,
			F5Verdict:         rec.f5Verdict,
			F5Violations:      event.violations,
			CloudflareVerdict: rec.cfVerdict,
			CloudflareRuleID:  rec.cfRule,
		})
		candidates = append(candidates, rec.eventIDs)
	}
	return out, candidates, nil
}

// sampleRecords reads the page of correlated records behind a rule row.
func (r *WAFMigrationRepo) sampleRecords(
	ctx context.Context, tenantID uuid.UUID, sel WAFMigrationSelector, q DashboardQuery,
) ([]migrationRecord, error) {
	sql, args := sampleRecordsQuery(tenantID, sel, q)
	rows, err := r.client.Query(ctx, sql, args...)
	if err != nil {
		return nil, query.TranslateError(err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]migrationRecord, 0, q.limitOrDefault())
	for rows.Next() {
		var rec migrationRecord
		if err := rows.Scan(&rec.correlationID, &rec.eventIDs, &rec.requestHost,
			&rec.requestMethod, &rec.f5Verdict, &rec.cfVerdict, &rec.cfRule); err != nil {
			return nil, fmt.Errorf("scan waf migration record: %w", err)
		}
		out = append(out, rec)
	}
	return out, query.TranslateError(rows.Err())
}

// f5Event is one F5 event's contribution to a sample row.
type f5Event struct {
	eventID      string
	eventTime    time.Time
	receivedAt   time.Time
	sourceVendor string
	clientIP     net.IP
	country      string
	clientASN    uint32
	requestPath  string
	requestQuery string
	userAgent    string
	violations   []string
}

// f5Events fetches the F5 events a page of records names, by id.
func (r *WAFMigrationRepo) f5Events(
	ctx context.Context, tenantID uuid.UUID, eventIDs []string, q DashboardQuery,
) (map[string]f5Event, error) {
	sql, args := f5EventsQuery(tenantID, eventIDs, q)
	rows, err := r.client.Query(ctx, sql, args...)
	if err != nil {
		return nil, query.TranslateError(err)
	}
	defer func() { _ = rows.Close() }()

	found := make(map[string]f5Event, len(eventIDs))
	for rows.Next() {
		var e f5Event
		var ip net.IP
		if err := rows.Scan(&e.eventID, &e.eventTime, &e.receivedAt, &e.sourceVendor,
			&ip, &e.country, &e.clientASN,
			&e.requestPath, &e.requestQuery, &e.userAgent, &e.violations); err != nil {
			return nil, fmt.Errorf("scan f5 sample event: %w", err)
		}
		e.clientIP = ip
		found[e.eventID] = e
	}
	return found, query.TranslateError(rows.Err())
}

// pickF5Event chooses the F5 event for a record.
//
// Normally there is exactly one. When a record holds several — a redelivery, or a retried
// request — the LATEST is the one that describes what finally happened, with the id as a
// deterministic tiebreak so the row does not change between refreshes.
func pickF5Event(ids []string, found map[string]f5Event) (f5Event, bool) {
	var best f5Event
	var ok bool
	for _, id := range ids {
		candidate, present := found[id]
		if !present {
			continue
		}
		if !ok || candidate.eventTime.After(best.eventTime) ||
			(candidate.eventTime.Equal(best.eventTime) && candidate.eventID > best.eventID) {
			best, ok = candidate, true
		}
	}
	return best, ok
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
