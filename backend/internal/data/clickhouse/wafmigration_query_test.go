package clickhouse

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/query"
)

// The queries here are validated for SHAPE, not for results: what they must never do is
// leak a tenant, drop a filter, or emit SQL ClickHouse rejects. The joins themselves were
// run against production data before this landed.

func testQuery() DashboardQuery {
	from := time.Date(2026, 8, 16, 0, 0, 0, 0, time.UTC)
	return DashboardQuery{
		Range: query.TimeRange{From: from, To: from.Add(24 * time.Hour)},
		Limit: 25,
	}
}

// EVERY query is tenant-scoped, on every table it touches. A migration panel reads two
// tables and a missed predicate on either one is a cross-tenant leak, not a wrong number.
func TestMigrationQueriesScopeEveryTable(t *testing.T) {
	tenant := uuid.New()
	q := testQuery()

	cases := map[string]struct {
		sql  string
		args []any
	}{}

	uncoveredSQL, uncoveredArgs := uncoveredQuery(tenant, q, WAFMigrationFilter{})
	cases["uncovered"] = struct {
		sql  string
		args []any
	}{uncoveredSQL, uncoveredArgs}

	agreementSQL, agreementArgs := ruleAgreementQuery(tenant, q, WAFMigrationFilter{}, nil)
	cases["agreement"] = struct {
		sql  string
		args []any
	}{agreementSQL, agreementArgs}

	samplesSQL, samplesArgs := migrationSamplesQuery(tenant, WAFMigrationSelector{}, q)
	cases["samples"] = struct {
		sql  string
		args []any
	}{samplesSQL, samplesArgs}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			tables := strings.Count(c.sql, "FROM correlated_requests") +
				strings.Count(c.sql, "FROM normalized_events")
			scopes := strings.Count(c.sql, "tenant_id = ?")
			if scopes != tables {
				t.Errorf("%d table reads but %d tenant predicates: an unscoped read is a cross-tenant leak",
					tables, scopes)
			}

			var tenants int
			for _, arg := range c.args {
				if id, ok := arg.(uuid.UUID); ok && id == tenant {
					tenants++
				}
			}
			if tenants != scopes {
				t.Errorf("%d tenant predicates but %d tenant arguments bound", scopes, tenants)
			}

			if strings.Count(c.sql, "?") != len(c.args) {
				t.Errorf("%d placeholders against %d arguments: the binding is off by %d",
					strings.Count(c.sql, "?"), len(c.args),
					strings.Count(c.sql, "?")-len(c.args))
			}
		})
	}
}

// The host filter is the one an operator actually uses — a migration is run site by site
// — and it has to run BEFORE the limit. Applied to the response instead, a quiet host
// that a busy one crowds out of the top N would come back empty.
func TestMigrationFilterRunsInSQL(t *testing.T) {
	tenant := uuid.New()
	q := testQuery()

	sql, args := uncoveredQuery(tenant, q, WAFMigrationFilter{RequestHost: "jobs.bg"})
	if !strings.Contains(sql, "WHERE request_host = ?") {
		t.Error("uncovered: the host filter is not in the SQL")
	}
	if !containsArg(args, "jobs.bg") {
		t.Error("uncovered: the host is not bound as an argument")
	}
	if strings.Index(sql, "request_host = ?") > strings.Index(sql, "LIMIT") {
		t.Error("uncovered: the filter runs after the limit, " +
			"which empties exactly the rows it was meant to find")
	}

	sql, args = ruleAgreementQuery(tenant, q, WAFMigrationFilter{RequestHost: "jobs.bg"}, nil)
	if !strings.Contains(sql, "WHERE request_host = ?") || !containsArg(args, "jobs.bg") {
		t.Error("agreement: the host filter is not applied server-side")
	}
}

// The reading decides which STAGE a rule appears under, so it must be a HAVING before the
// limit. A rule with ten matching requests would never survive an ordering by volume
// against one with six thousand.
func TestAgreementReadingFiltersBeforeLimit(t *testing.T) {
	sql, args := ruleAgreementQuery(
		uuid.New(), testQuery(), WAFMigrationFilter{}, []string{ReadingReady})

	if !strings.Contains(sql, "HAVING reading IN (?)") {
		t.Fatal("the reading filter is not in the HAVING")
	}
	if strings.Index(sql, "HAVING") > strings.Index(sql, "LIMIT") {
		t.Error("the reading is filtered after the limit")
	}
	if !containsArg(args, []string{ReadingReady}) {
		t.Error("the readings are not bound as an argument")
	}
}

// Only rules Cloudflare is NOT enforcing are migration candidates. Including a blocking
// rule would put finished work back on the worklist.
func TestAgreementConsidersOnlyLoggingRules(t *testing.T) {
	sql, args := ruleAgreementQuery(uuid.New(), testQuery(), WAFMigrationFilter{}, nil)

	if !strings.Contains(sql, "cf_verdict = ?") {
		t.Fatal("the Cloudflare verdict is not constrained")
	}
	if !containsArg(args, "monitored") {
		t.Error("monitored is not bound: the panel would include rules already blocking")
	}
	// A rule id is required, or the row would be "everything Cloudflare logged without a
	// rule", which is not something that can be enforced.
	if !strings.Contains(sql, "cf_rule != ?") {
		t.Error("rows without a Cloudflare rule are not excluded")
	}
}

// The spine reads the MATERIALIZED verdict columns, not the map. Answering
// verdicts['f5'] = ... decompresses the whole map for every row in range, and ClickHouse
// will not put a skip index on that form — which is how the panel came to time out at its
// own default range.
func TestSpineReadsTheVerdictColumns(t *testing.T) {
	for name, sql := range map[string]string{
		"uncovered": first(uncoveredQuery(uuid.New(), testQuery(), WAFMigrationFilter{})),
		"agreement": first(ruleAgreementQuery(uuid.New(), testQuery(), WAFMigrationFilter{}, nil)),
		"samples":   first(migrationSamplesQuery(uuid.New(), WAFMigrationSelector{}, testQuery())),
	} {
		t.Run(name, func(t *testing.T) {
			if strings.Contains(sql, "verdicts['") {
				t.Error("the map is read instead of the materialized column")
			}
			// The array read answered a question the verdict already answers, for 1.2s.
			if strings.Contains(sql, "has(vendors") {
				t.Error("the vendors array is still read")
			}
		})
	}
}

// A redundant guard beside an equality is not free: it reads the column a second way and
// cost 2.1s against 1.3s across seven days.
func TestVerdictIsConstrainedExactlyOnce(t *testing.T) {
	sql := first(uncoveredQuery(uuid.New(), testQuery(), WAFMigrationFilter{}))

	if strings.Contains(sql, "f5_verdict != ") {
		t.Error("a non-empty guard sits beside the equality that already implies it")
	}
	// And the flag that stood in for the index before 0018 is gone with it.
	if strings.Contains(sql, "has_disagreement") {
		t.Error("has_disagreement is still filtered on, which the verdict index made redundant")
	}
}

// Every row a panel counts is a request BOTH vendors reported. The spine no longer says
// so, so each query has to — including the samples query when the caller named no verdict.
func TestEveryQueryConstrainsBothVendors(t *testing.T) {
	samples := func(sel WAFMigrationSelector) string {
		return first(migrationSamplesQuery(uuid.New(), sel, testQuery()))
	}
	for name, sql := range map[string]string{
		"uncovered":       first(uncoveredQuery(uuid.New(), testQuery(), WAFMigrationFilter{})),
		"agreement":       first(ruleAgreementQuery(uuid.New(), testQuery(), WAFMigrationFilter{}, nil)),
		"samples/unnamed": samples(WAFMigrationSelector{}),
		"samples/named": samples(WAFMigrationSelector{
			F5Verdict: "blocked", CloudflareVerdict: "allowed",
		}),
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(sql, "f5_verdict") || !strings.Contains(sql, "cf_verdict") {
				t.Error("a record only one vendor reported would pass this query")
			}
		})
	}
}

// The OTHER two stages must NOT carry it. F5 blocked against Cloudflare monitored leaves
// the flag false — 404 of 434 such records on this deployment — so the same predicate
// that speeds up stage 1 would silently hide most of stage 2's worklist.
func TestAgreementDoesNotUseTheDisagreementFlag(t *testing.T) {
	sql := first(ruleAgreementQuery(uuid.New(), testQuery(), WAFMigrationFilter{}, nil))

	if strings.Contains(sql, "has_disagreement") {
		t.Error("the agreement stages filter on has_disagreement, which drops most of their rows")
	}
}

// A row's counts are computed for ONE pair of verdicts. Without the Cloudflare side the
// drill-down listed requests Cloudflare had acted on beneath a group that had not counted
// them — evidence contradicting the number above it.
func TestSamplesNarrowToBothVerdicts(t *testing.T) {
	sql, args := migrationSamplesQuery(uuid.New(), WAFMigrationSelector{
		F5Verdict: "blocked", CloudflareVerdict: "allowed",
	}, testQuery())

	if !strings.Contains(sql, "AND f5_verdict = ?") || !strings.Contains(sql, "AND cf_verdict = ?") {
		t.Fatal("the samples are not narrowed to both vendors' verdicts")
	}
	if !containsArg(args, "blocked") || !containsArg(args, "allowed") {
		t.Error("both verdicts must be bound, or the samples belong to a different group than the counts")
	}
}

// Stage 1 is defined by the ABSENCE of a Cloudflare decision on traffic F5 blocked.
func TestUncoveredPairsBlockedWithAllowed(t *testing.T) {
	sql, args := uncoveredQuery(uuid.New(), testQuery(), WAFMigrationFilter{})

	if !containsArg(args, "blocked") || !containsArg(args, "allowed") {
		t.Fatal("the stage is not pinned to F5 blocked against Cloudflare allowed")
	}
	// The violation comes off the F5 event, because the correlated record carries F5's
	// POLICY name — the same value for every violation the policy holds.
	if !strings.Contains(sql, "arrayJoin(e.rule_ids) AS violation") {
		t.Error("the violation is not read from the F5 event")
	}
	// An exemption already in place needs the opposite fix, so it is counted apart.
	if !strings.Contains(sql, "countIf(cf_rule != '')") {
		t.Error("requests a Cloudflare rule explicitly allowed are not counted separately")
	}
}

// The events side of both joins must be bounded, or it is a full table scan.
func TestEventLookupsAreTimeBounded(t *testing.T) {
	q := testQuery()

	for name, sql := range map[string]string{
		"uncovered": first(uncoveredQuery(uuid.New(), q, WAFMigrationFilter{})),
		"samples":   first(migrationSamplesQuery(uuid.New(), WAFMigrationSelector{}, q)),
	} {
		t.Run(name, func(t *testing.T) {
			events := strings.Count(sql, "FROM normalized_events")
			bounds := strings.Count(sql, "event_time >= ? AND event_time < ?")
			if bounds != events {
				t.Errorf("%d reads of normalized_events but %d time bounds: an unbounded read scans the table",
					events, bounds)
			}
		})
	}
}

// THE BUG THIS PINS. ClickHouse INLINES a CTE rather than materialising it, so the first
// version of this query — which named the pair set once and referenced it from three CTEs
// — read as one scan and ran as six: 10 to 18 seconds, and clicking a row timed out.
func TestSamplesScanTheCorrelatedTableOnce(t *testing.T) {
	sql := first(migrationSamplesQuery(uuid.New(), WAFMigrationSelector{
		F5Verdict: "blocked", RequestHost: "www.jobs.bg",
	}, testQuery()))

	if n := strings.Count(sql, "FROM correlated_requests"); n != 1 {
		t.Errorf("correlated_requests is read %d times; every extra reference is another full scan", n)
	}
	if strings.Contains(sql, "WITH ") {
		t.Error("a CTE is back, and ClickHouse re-runs it per reference")
	}
}

// The events side is narrowed by what the ROW already says rather than by an
// `event_id IN (pair set)` prefilter, which costs a second evaluation of the pair scan.
// Dropping it took the query from 3.0s to 1.8s.
func TestSamplesNarrowEventsByTheRowItself(t *testing.T) {
	sql, args := migrationSamplesQuery(uuid.New(), WAFMigrationSelector{
		F5Verdict: "blocked", RequestHost: "www.jobs.bg",
	}, testQuery())

	if strings.Contains(sql, "event_id IN (SELECT") {
		t.Error("the id prefilter is still there, which re-runs the pair scan")
	}
	if !containsArg(args, "www.jobs.bg") {
		t.Error("the host is not used to narrow the events side")
	}
}

// With neither a verdict nor a host the join would read every F5 event in range, so the
// prefilter has to come back.
func TestSamplesFallBackToTheIDPrefilter(t *testing.T) {
	sql := first(migrationSamplesQuery(uuid.New(), WAFMigrationSelector{
		RuleID: "abc",
	}, testQuery()))

	if !strings.Contains(sql, "event_id IN (SELECT arrayJoin(event_ids)") {
		t.Error("nothing narrows the events side, which makes the join a full scan")
	}
}

// Cloudflare is fetched by id in a SECOND query. Joining it into the first cost seven
// seconds on its own: Cloudflare logs twenty-five times as many events as F5, so the join
// reads all of them to find forty.
func TestCloudflareScoresAreFetchedByID(t *testing.T) {
	sql, args := cloudflareScoresQuery(
		uuid.New(), []string{"a", "b"}, testQuery())

	if !strings.Contains(sql, "vendor = 'cloudflare'") || !strings.Contains(sql, "event_id IN (?)") {
		t.Fatal("the Cloudflare lookup is not an exact id lookup")
	}
	if !strings.Contains(sql, "tenant_id = ?") {
		t.Error("the Cloudflare lookup is not tenant-scoped")
	}
	if !containsArg(args, []string{"a", "b"}) {
		t.Error("the ids are not bound")
	}
}

// Cloudflare logs a row per HOP of a Worker-protected request — the client-facing
// request, the Worker's subrequest, the origin fetch — and all of them belong to the same
// correlated record. Showing an arbitrary one would make the same request look different
// between refreshes.
func TestPickCloudflareEventPrefersTheDecidingHop(t *testing.T) {
	found := map[string]cloudflareEvent{
		"hop-a": {eventID: "hop-a", score: 93},
		"hop-b": {eventID: "hop-b", ruleID: "rule-1", score: 0},
		"hop-c": {eventID: "hop-c"},
	}

	got, ok := pickCloudflareEvent([]string{"hop-a", "hop-b", "hop-c"}, found)
	if !ok || got.eventID != "hop-b" {
		t.Errorf("picked %q, want the hop carrying a rule", got.eventID)
	}

	// Then a hop that at least carries a score.
	delete(found, "hop-b")
	got, _ = pickCloudflareEvent([]string{"hop-a", "hop-c"}, found)
	if got.eventID != "hop-a" {
		t.Errorf("picked %q, want the scored hop", got.eventID)
	}

	// Deterministic when nothing distinguishes them, so the row does not change on a
	// refresh.
	tie := map[string]cloudflareEvent{"x": {eventID: "x"}, "y": {eventID: "y"}}
	a, _ := pickCloudflareEvent([]string{"x", "y"}, tie)
	b, _ := pickCloudflareEvent([]string{"y", "x"}, tie)
	if a.eventID != b.eventID {
		t.Error("the pick depends on the order the ids arrive in")
	}
}

// A Cloudflare event can age out while the correlated record and the F5 event survive.
// That sample is still the evidence the page was opened for, so it keeps its place with
// an empty score rather than being dropped.
func TestPickCloudflareEventToleratesAMiss(t *testing.T) {
	if _, ok := pickCloudflareEvent(
		[]string{"gone"}, map[string]cloudflareEvent{}); ok {
		t.Error("a hit was reported for an event that is not there")
	}
}

// Each part of a selector narrows a different thing, and the violation has to be applied
// AFTER the join because it lives on the F5 event.
func TestSamplesSelectorNarrowsEveryField(t *testing.T) {
	sql, args := migrationSamplesQuery(uuid.New(), WAFMigrationSelector{
		Violation:     "Illegal file type",
		RuleID:        "23548ee2b36547a1be09bb2c0550c529",
		RequestHost:   "www.jobs.bg",
		RequestMethod: "GET",
		F5Verdict:     "blocked",
	}, testQuery())

	for _, want := range []string{
		"Illegal file type", "23548ee2b36547a1be09bb2c0550c529", "www.jobs.bg", "GET", "blocked",
	} {
		if !containsArg(args, want) {
			t.Errorf("selector value %q is not bound", want)
		}
	}
	if !strings.Contains(sql, "has(f5_violations, ?)") {
		t.Error("the violation is not matched against the F5 event's violation list")
	}
	if strings.Index(sql, "has(f5_violations") < strings.Index(sql, "INNER JOIN f5") {
		t.Error("the violation is filtered before the join that produces it")
	}
}

func first(sql string, _ []any) string { return sql }

func containsArg(args []any, want any) bool {
	for _, arg := range args {
		if s, ok := arg.(string); ok {
			if w, ok := want.(string); ok && s == w {
				return true
			}
			continue
		}
		if ss, ok := arg.([]string); ok {
			if ws, ok := want.([]string); ok && len(ss) == len(ws) {
				same := true
				for i := range ss {
					if ss[i] != ws[i] {
						same = false
						break
					}
				}
				if same {
					return true
				}
			}
		}
	}
	return false
}
