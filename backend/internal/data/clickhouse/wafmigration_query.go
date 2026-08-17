package clickhouse

import (
	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/vendors"
)

// The SQL behind the three migration stages, kept apart from the repository so the
// shapes above stay readable and each query can carry the reasoning for its own joins.

// WAFMigrationSelector identifies the group whose requests are being asked for.
//
// Either Violation (stage 1) or RuleID (stages 2 and 3) keys the group; the host and
// method narrow it to exactly the row that was clicked. One selector serves all three
// stages because the underlying evidence is the same correlated record.
type WAFMigrationSelector struct {
	Violation     string
	RuleID        string
	RequestHost   string
	RequestMethod string
	// F5Verdict narrows to what F5 did: blocked, monitored or allowed.
	F5Verdict string
	// CloudflareVerdict narrows to what Cloudflare did: allowed on stage 1, monitored on
	// stages 2 and 3.
	//
	// Not optional in practice. A row's counts are computed for ONE pair of verdicts, so
	// leaving this off listed requests Cloudflare had acted on underneath a group that
	// had not counted them — evidence that contradicted the number above it.
	CloudflareVerdict string
}

// correlatedF5Pairs is the shared spine of every query here: one row per request that
// both F5 and Cloudflare saw, with each vendor's verdict beside the other's.
//
// Starting from correlated_requests rather than joining the two vendors by hand is not a
// convenience — it is the point. The correlation engine already decided which records
// describe the same request, including the CF-Ray bridging that lets an origin fetch
// join F5 through its own ray and DataDome through its parent's. Re-deriving that join
// in a reporting query would produce a second, quietly different answer.
// f5_verdict and cf_verdict are REAL COLUMNS, materialized from the map by migration
// 0018, and reading them is the difference between these panels loading and timing out.
// Answering `verdicts['f5'] = ...` means decompressing the whole Map for every row in
// range — 1.9s across seven days here against 0.5s for the LowCardinality column — and no
// skip index is possible on the Map form: ClickHouse 24.8 silently declines to use one,
// which is what 0017 found out the expensive way.
//
// The spine constrains NOTHING but the tenant and the window. Every caller must narrow
// both verdicts itself, either to a value or to non-empty, and that is not tidiness: a
// redundant `f5_verdict != ”` sitting beside `f5_verdict = 'blocked'` is not free, it
// reads the column a second way and cost 2.1s against 1.3s. The vendor pair is expressed
// through those same predicates rather than through has(vendors, 'f5'), which read the
// array for another 1.2s to answer a question the verdict already answers: a vendor in a
// correlated record always carries a verdict.
const correlatedF5Pairs = `
	SELECT correlation_id, event_ids, request_host, request_path, request_method,
	       client_ip, first_event_time, last_event_time,
	       f5_verdict, cf_verdict,
	       rule_ids['cloudflare']        AS cf_rule
	FROM correlated_requests
	WHERE tenant_id = ? AND window_start >= ? AND window_start < ?`

// uncoveredQuery finds traffic F5 blocked that no Cloudflare rule matched.
//
// The violation is what a new Cloudflare rule has to reproduce, and it lives on the F5
// EVENT rather than on the correlated record — correlated_requests carries F5's policy
// name in rule_ids, which is the same value for every violation the policy holds and so
// cannot group anything. The record's event_ids are unrolled and joined back to
// normalized_events to recover it.
//
// The events side is bounded by the same range widened by eventJoinWindow. Without a
// bound it is a full scan of the table; with the record's own window it would miss an
// event written just outside it.
//
// An earlier version also filtered on has_disagreement, to borrow the one skip index this
// table already had. Migration 0018 made that unnecessary — the verdict columns carry
// their own indexes now and the flag saves nothing measurable — so it is gone. Worth
// knowing it was only ever safe HERE: normalize.Classify sets Disagreement on exactly
// `sawAllowed && sawBlocked`, so it holds for this pair of verdicts and not for the other
// two stages, where F5 blocked against Cloudflare monitored leaves it false.
func uncoveredQuery(
	tenantID uuid.UUID, q DashboardQuery, filter WAFMigrationFilter,
) (string, []any) {
	sql := `
		SELECT violation, request_host, request_method,
		       count()                        AS requests,
		       uniqExact(request_path)        AS paths,
		       uniqExact(client_ip)           AS clients,
		       countIf(cf_rule != '')         AS cloudflare_allowlisted,
		       min(first_event_time)          AS first_seen,
		       max(last_event_time)           AS last_seen
		FROM (
			SELECT c.request_host AS request_host, c.request_method AS request_method,
			       c.request_path AS request_path, c.client_ip AS client_ip,
			       c.cf_rule AS cf_rule,
			       c.first_event_time AS first_event_time,
			       c.last_event_time AS last_event_time,
			       arrayJoin(e.rule_ids) AS violation
			FROM (
				SELECT arrayJoin(event_ids) AS event_id, request_host, request_path,
				       request_method, client_ip, cf_rule,
				       first_event_time, last_event_time
				FROM (` + correlatedF5Pairs + `
					  AND f5_verdict = ?
					  AND cf_verdict = ?)
			) AS c
			INNER JOIN (
				SELECT event_id, rule_ids
				FROM normalized_events
				WHERE tenant_id = ? AND vendor = 'f5' AND verdict = ?
				  AND event_time >= ? AND event_time < ?
			) AS e USING (event_id)
		)`
	args := []any{
		tenantID, q.Range.From, q.Range.To,
		vendors.VerdictBlocked, vendors.VerdictAllowed,
		tenantID, vendors.VerdictBlocked,
		q.Range.From.Add(-eventJoinWindow), q.Range.To.Add(eventJoinWindow),
	}

	// Applied here rather than to the response: rows are ordered by volume, and a
	// migration is run one site at a time. Filtering afterwards would return nothing for
	// a quiet host that a busy one crowds out of the limit.
	if filter.RequestHost != "" {
		sql += ` WHERE request_host = ?`
		args = append(args, filter.RequestHost)
	}

	sql += `
		GROUP BY violation, request_host, request_method
		ORDER BY requests DESC
		LIMIT ?`
	return sql, append(args, q.limitOrDefault())
}

// ruleAgreementQuery measures each logging Cloudflare rule against F5.
//
// Only rules Cloudflare is NOT enforcing appear: a rule already blocking is not a
// migration candidate, and including it would put finished work back on the worklist.
// `monitored` is the common model's word for Cloudflare's log and simulate actions.
func ruleAgreementQuery(
	tenantID uuid.UUID, q DashboardQuery, filter WAFMigrationFilter, readings []string,
) (string, []any) {
	sql := `
		SELECT cf_rule                                  AS rule_id,
		       any(cf_action)                           AS action,
		       count()                                  AS correlated,
		       countIf(f5_verdict = ?)                  AS f5_blocked_total,
		       countIf(f5_verdict = ?)                  AS f5_flagged_total,
		       countIf(f5_verdict = ?)                  AS f5_allowed_total,
		       uniqExact(request_host)                  AS hosts,
		       if(uniqExact(request_host) = 1, any(request_host), '') AS host,
		       ` + agreementReadingExpr + ` AS reading,
		       min(first_event_time)                    AS first_seen,
		       max(last_event_time)                     AS last_seen
		FROM (
			SELECT correlation_id, request_host, f5_verdict, cf_rule,
			       first_event_time, last_event_time,
			       -- Carried alongside the rule so the panel can name what Cloudflare is
			       -- doing today rather than leaving the reader to assume it.
			       cf_verdict AS cf_action
			FROM (` + correlatedF5Pairs + `
				  AND cf_verdict = ?
				  AND cf_rule != ?
				  -- Left unconstrained by value, because the three F5 outcomes are what
				  -- this stage COUNTS. Non-empty is what makes the row a pair at all.
				  AND f5_verdict != ?)
		)`
	args := []any{
		vendors.VerdictBlocked, vendors.VerdictMonitored, vendors.VerdictAllowed,
		minCorrelatedForReading,
		tenantID, q.Range.From, q.Range.To,
		vendors.VerdictMonitored, "", "",
	}

	if filter.RequestHost != "" {
		sql += ` WHERE request_host = ?`
		args = append(args, filter.RequestHost)
	}

	sql += ` GROUP BY cf_rule`

	// In the HAVING, because the reading is an aggregate over the group — and BEFORE the
	// limit, which is the whole reason the stage is a server-side filter. A rule with ten
	// matching requests would never survive an ordering by volume against one with six
	// thousand, so filtering the response would empty exactly the stage being read.
	if len(readings) > 0 {
		sql += ` HAVING reading IN (?)`
		args = append(args, readings)
	}

	sql += ` ORDER BY correlated DESC LIMIT ?`
	return sql, append(args, q.limitOrDefault())
}

// migrationSamplesQuery returns the requests behind a stage-1 row, keyed on a violation.
//
// This path JOINS in SQL because the filter it has to apply — F5's violation — lives on
// the F5 event and not on the correlated record, so the rows cannot be limited before the
// join without truncating the evidence. The events side is narrowed by what the row
// supplies: a stage-1 row always carries a host, a method and the `blocked` verdict, and
// blocked traffic is a small slice of any deployment's traffic by definition. 1.8s.
//
// The rule stages take a different path — see sampleRecordsQuery — because they need no
// post-join filter, and their verdict is `allowed`, which is most of the traffic there is.
//
// ClickHouse INLINES a CTE rather than materialising it, which is why nothing here is one:
// the first version named the pair set once, referenced it from three CTEs, read as one
// scan and ran as six. 10 to 18 seconds, and clicking a row timed out.
func migrationSamplesQuery(
	tenantID uuid.UUID, sel WAFMigrationSelector, q DashboardQuery,
) (string, []any) {
	records, recordArgs := samplePairRecords(tenantID, sel, q)

	sql := `
		SELECT p.correlation_id AS correlation_id, e.event_id AS f5_event_id,
		       p.event_ids AS event_ids,
		       e.event_time AS event_time, e.client_ip AS client_ip,
		       e.client_country AS country, e.client_asn AS client_asn,
		       p.request_host AS request_host, e.request_path AS request_path,
		       e.request_query AS request_query, p.request_method AS request_method,
		       e.user_agent AS user_agent, p.f5_verdict AS f5_verdict,
		       e.rule_ids AS f5_violations, p.cf_verdict AS cf_verdict,
		       p.cf_rule AS cf_rule
		FROM (` + samplePairs(records) + `) AS p
		INNER JOIN (
			SELECT event_id, event_time, client_ip, client_country, client_asn,
			       request_path, request_query, user_agent, rule_ids
			FROM normalized_events
			WHERE tenant_id = ? AND vendor = 'f5'
			  AND event_time >= ? AND event_time < ?`
	args := append(recordArgs, tenantID,
		q.Range.From.Add(-eventJoinWindow), q.Range.To.Add(eventJoinWindow))

	narrowSQL, narrowArgs := narrowF5Events(sel)
	sql += narrowSQL + `
		) AS e USING (event_id)`
	args = append(args, narrowArgs...)

	// After the join, because the violation lives on the F5 event rather than on the
	// correlated record.
	if sel.Violation != "" {
		sql += ` WHERE has(f5_violations, ?)`
		args = append(args, sel.Violation)
	}

	sql += `
		ORDER BY event_time DESC
		LIMIT ?`
	return sql, append(args, q.limitOrDefault())
}

// narrowF5Events restricts the events side of the stage-1 sample join.
//
// By the row's own host and verdict. Both are always present on a stage-1 row, and an
// `event_id IN (record set)` prefilter instead would cost a second evaluation of the record
// scan — 1.8s against 4.4s, and worse when a record carries several vendor events.
//
// This is safe HERE and nowhere else: the verdict is `blocked`, which selects 2,929 events
// across seven days on this deployment because blocking most of your traffic is not a
// thing anyone does. The same narrowing on the false-positive stage selects `allowed` —
// forty million — which is why that stage does not use this path at all.
func narrowF5Events(sel WAFMigrationSelector) (string, []any) {
	sql := ""
	args := make([]any, 0, 2)

	if sel.F5Verdict != "" {
		sql += ` AND verdict = ?`
		args = append(args, sel.F5Verdict)
	}
	if sel.RequestHost != "" {
		sql += ` AND request_host = ?`
		args = append(args, sel.RequestHost)
	}
	return sql, args
}

// sampleRecordsQuery reads a PAGE of correlated records for the rule stages.
//
// Step one of two. No filter on this path touches the F5 event, so the limit can be
// applied here — which makes the whole thing cost one indexed scan of the correlated table
// (0.8s) plus an exact lookup of the events it names (0.5s), independent of how common the
// verdict is. Doing it as a join instead cost 6.7 to 7.9 seconds on the false-positive
// stage, because narrowing the events side by `allowed` narrows it to forty million rows.
func sampleRecordsQuery(
	tenantID uuid.UUID, sel WAFMigrationSelector, q DashboardQuery,
) (string, []any) {
	records, args := samplePairRecords(tenantID, sel, q)
	return `
		SELECT correlation_id, event_ids, request_host, request_method,
		       f5_verdict, cf_verdict, cf_rule
		FROM (` + records + `)
		ORDER BY last_event_time DESC
		LIMIT ?`, append(args, q.limitOrDefault())
}

// f5EventsQuery reads the F5 side of a page of records, by id.
//
// Step two. The ids come from the records the page already selected, so this is an exact
// lookup on the last column of the primary key rather than a scan.
func f5EventsQuery(
	tenantID uuid.UUID, eventIDs []string, q DashboardQuery,
) (string, []any) {
	return `
		SELECT event_id, event_time, client_ip, client_country, client_asn,
		       request_path, request_query, user_agent, rule_ids
		FROM normalized_events
		WHERE tenant_id = ? AND vendor = 'f5'
		  AND event_time >= ? AND event_time < ?
		  AND event_id IN (?)`, []any{
			tenantID,
			q.Range.From.Add(-eventJoinWindow), q.Range.To.Add(eventJoinWindow),
			eventIDs,
		}
}

// cloudflareScoresQuery reads the Cloudflare side for a page of samples, by id.
//
// Deliberately a SECOND round trip. Cloudflare logs a row per hop of a Worker-protected
// request and twenty-five times as many events as F5 overall, so reaching it through the
// join above meant reading all of them: seven seconds, against 0.4 for an exact lookup of
// the forty ids a page of twenty samples actually names.
func cloudflareScoresQuery(
	tenantID uuid.UUID, eventIDs []string, q DashboardQuery,
) (string, []any) {
	return `
		SELECT event_id, rule_id, waf_attack_score
		FROM normalized_events
		WHERE tenant_id = ? AND vendor = 'cloudflare'
		  AND event_time >= ? AND event_time < ?
		  AND event_id IN (?)`, []any{
			tenantID,
			q.Range.From.Add(-eventJoinWindow), q.Range.To.Add(eventJoinWindow),
			eventIDs,
		}
}

// samplePairRecords is the filtered set of correlated records a sample list comes from.
//
// One record per row, NOT one event per row. The exploded form is built from this by
// samplePairs, and the id prefilter reads this form directly — feeding it the exploded one
// made every record re-explode its own event list, so a record with three events
// contributed nine ids instead of three and the query went from 1.8s to 9s.
func samplePairRecords(
	tenantID uuid.UUID, sel WAFMigrationSelector, q DashboardQuery,
) (string, []any) {
	sql := correlatedF5Pairs
	args := []any{tenantID, q.Range.From, q.Range.To}

	// Both sides are always constrained — a verdict when the caller named one, non-empty
	// when it did not. A missing constraint would let through a record only one vendor
	// reported, which is not a comparison at all.
	if sel.F5Verdict != "" {
		sql += ` AND f5_verdict = ?`
		args = append(args, sel.F5Verdict)
	} else {
		sql += ` AND f5_verdict != ?`
		args = append(args, "")
	}
	if sel.CloudflareVerdict != "" {
		sql += ` AND cf_verdict = ?`
		args = append(args, sel.CloudflareVerdict)
	} else {
		sql += ` AND cf_verdict != ?`
		args = append(args, "")
	}
	if sel.RuleID != "" {
		sql += ` AND cf_rule = ?`
		args = append(args, sel.RuleID)
	}
	if sel.RequestHost != "" {
		sql += ` AND request_host = ?`
		args = append(args, sel.RequestHost)
	}
	if sel.RequestMethod != "" {
		sql += ` AND request_method = ?`
		args = append(args, sel.RequestMethod)
	}
	return sql, args
}

// samplePairs explodes those records into one row per vendor event, which is what the
// join below matches on. event_ids rides along so the Cloudflare lookup afterwards knows
// which events to ask for without going back to the correlated table again.
func samplePairs(records string) string {
	return `
		SELECT correlation_id, event_ids, arrayJoin(event_ids) AS event_id,
		       request_host, request_method, f5_verdict, cf_verdict, cf_rule
		FROM (` + records + `)`
}
