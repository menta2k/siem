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

// has_disagreement is redundant with the two verdicts and is there for its INDEX: it took
// the seven-day scan from 6.5s to 1.3s, the difference between the panel loading and
// timing out at its own default range. It is safe only because normalize.Classify sets
// the flag on exactly `sawAllowed && sawBlocked`.
func TestUncoveredUsesTheDisagreementIndex(t *testing.T) {
	sql := first(uncoveredQuery(uuid.New(), testQuery(), WAFMigrationFilter{}))

	if !strings.Contains(sql, "AND has_disagreement") {
		t.Error("the disagreement flag is not used, so the scan reads the verdicts map in full")
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

// A join condition in ClickHouse has to be an equality. has(event_ids, event_id) is the
// obvious way to express this join and the server rejects it, so the ids are unrolled
// into a CTE and joined on the correlation id instead.
func TestSamplesJoinsOnEquality(t *testing.T) {
	sql := first(migrationSamplesQuery(uuid.New(), WAFMigrationSelector{}, testQuery()))

	if strings.Contains(sql, "JOIN") && strings.Contains(sql, "ON has(") {
		t.Error("a join is conditioned on has(), which ClickHouse will not run")
	}
	if !strings.Contains(sql, "USING (correlation_id)") {
		t.Error("the vendor events are not joined on the correlation id")
	}
	// The Cloudflare side is LEFT: an F5 record whose Cloudflare event aged out still has
	// evidence worth reading.
	if !strings.Contains(sql, "LEFT JOIN cf") {
		t.Error("the Cloudflare join is not a LEFT join, so retention would shorten the evidence")
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

// THE BUG THIS PINS. Cloudflare logs a row per HOP of a Worker-protected request — the
// client-facing request, the Worker's subrequest, the origin fetch — and all of them land
// in the same correlated record. Joining every one of them turned 130 requests into 260
// rows that read as 260 requests, which on a page whose entire job is counting agreement
// is not a cosmetic fault.
func TestSamplesKeepOneCloudflareEventPerRecord(t *testing.T) {
	sql := first(migrationSamplesQuery(uuid.New(), WAFMigrationSelector{}, testQuery()))

	if !strings.Contains(sql, "FROM cf_events GROUP BY correlation_id") {
		t.Error("the Cloudflare events are not collapsed to one per correlated record")
	}
	// The alias must NOT be event_id: aliasing an aggregate back to the column it
	// aggregates makes ClickHouse resolve the inner reference to the alias and reject the
	// query. It has now bitten in three files.
	if strings.Contains(sql, "argMax(event_id, (rule_id != '', score > 0, event_id)) AS event_id") {
		t.Error("an aggregate is aliased back to the column it aggregates, which ClickHouse rejects")
	}
}

// Without the IN, the join builds a hash table over every event in the window — thirteen
// million rows on this deployment — and discards them afterwards. Measured: 10.9s against
// a 10s limit, versus 2.9s with it.
func TestSamplesPrefiltersEventsByID(t *testing.T) {
	sql := first(migrationSamplesQuery(uuid.New(), WAFMigrationSelector{}, testQuery()))

	if strings.Count(sql, "event_id IN (SELECT event_id FROM ids)") != 2 {
		t.Error("a vendor lookup is not prefiltered to the ids the records name, " +
			"which makes it a full scan")
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
