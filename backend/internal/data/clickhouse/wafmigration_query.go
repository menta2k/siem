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
const correlatedF5Pairs = `
	SELECT correlation_id, event_ids, request_host, request_path, request_method,
	       client_ip, first_event_time, last_event_time,
	       verdicts['f5']                AS f5_verdict,
	       verdicts['cloudflare']        AS cf_verdict,
	       rule_ids['cloudflare']        AS cf_rule
	FROM correlated_requests
	WHERE tenant_id = ? AND window_start >= ? AND window_start < ?
	  AND has(vendors, 'f5') AND has(vendors, 'cloudflare')`

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
// has_disagreement is redundant with the two verdicts and is there for its INDEX. It is
// the only pre-computed flag on this table that a skip index already covers, and adding
// it took the seven-day scan from 6.5s to 1.3s — the difference between the panel loading
// and the panel timing out at its own default range.
//
// It is safe because it is structural, not incidental: normalize.Classify sets
// Disagreement on `sawAllowed && sawBlocked`, which is precisely this pair of verdicts.
// A record matching the two predicates below therefore ALWAYS carries the flag, and the
// filter cannot drop a row the panel should have shown. It is not safe on the other two
// stages, where F5 blocked against Cloudflare monitored leaves the flag false — 404 of
// 434 such records here — and where adding it would silently hide most of the worklist.
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
					  AND has_disagreement
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
				  AND cf_rule != ?)
		)`
	args := []any{
		vendors.VerdictBlocked, vendors.VerdictMonitored, vendors.VerdictAllowed,
		minCorrelatedForReading,
		tenantID, q.Range.From, q.Range.To,
		vendors.VerdictMonitored, "",
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

// samplePairs builds the narrowed pair set every sample join reads from.
//
// Each narrowing runs inside the CTE, so all three joins below see the same rows. The F5
// verdict is what lets one sample list serve all three stages.
func samplePairs(
	tenantID uuid.UUID, sel WAFMigrationSelector, q DashboardQuery,
) (string, []any) {
	sql := `
		WITH pairs AS (` + correlatedF5Pairs
	args := []any{tenantID, q.Range.From, q.Range.To}

	if sel.F5Verdict != "" {
		sql += ` AND f5_verdict = ?`
		args = append(args, sel.F5Verdict)
	}
	if sel.CloudflareVerdict != "" {
		sql += ` AND cf_verdict = ?`
		args = append(args, sel.CloudflareVerdict)
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

// sampleJoins resolves each record's two vendor events and puts them on one row.
//
// ids unrolls each record's event list so the vendor events can be reached by an
// EQUI-join. Joining on has(event_ids, event_id) would be the obvious way to say it and
// ClickHouse will not run it: a join condition has to be an equality.
//
// Each vendor lookup then re-states `event_id IN (SELECT ...)`. It looks redundant beside
// the join that follows and it is the difference between 2.9 seconds and 10.9: without it
// the join builds a hash table over EVERY event in the window — thirteen million rows on
// this deployment — and only then discards the ones no record names. With it, event_id is
// the last column of the primary key, so the scan skips granules instead.
const sampleJoins = `),
		ids AS (SELECT correlation_id, arrayJoin(event_ids) AS event_id FROM pairs),
		f5 AS (
			SELECT i.correlation_id AS correlation_id, n.event_id AS event_id,
			       n.event_time AS event_time, n.client_ip AS client_ip,
			       n.client_country AS country, n.client_asn AS client_asn,
			       n.request_path AS request_path, n.request_query AS request_query,
			       n.user_agent AS user_agent, n.rule_ids AS violations
			FROM ids AS i
			INNER JOIN (
				SELECT event_id, event_time, client_ip, client_country, client_asn,
				       request_path, request_query, user_agent, rule_ids
				FROM normalized_events
				WHERE tenant_id = ? AND vendor = 'f5'
				  AND event_time >= ? AND event_time < ?
				  AND event_id IN (SELECT event_id FROM ids)
			) AS n USING (event_id)
		),
		cf_events AS (
			SELECT i.correlation_id AS correlation_id, n.event_id AS event_id,
			       n.waf_attack_score AS score, n.rule_id AS rule_id
			FROM ids AS i
			INNER JOIN (
				SELECT event_id, waf_attack_score, rule_id
				FROM normalized_events
				WHERE tenant_id = ? AND vendor = 'cloudflare'
				  AND event_time >= ? AND event_time < ?
				  AND event_id IN (SELECT event_id FROM ids)
			) AS n USING (event_id)
		),
		-- ONE Cloudflare event per record, or the row count is a lie. Cloudflare logs a
		-- row per hop of a Worker-protected request -- the client-facing request, the
		-- Worker's subrequest, the origin fetch -- and all three land in the same
		-- correlated record. Joining them all turned 130 requests into 260 rows that
		-- read as 260 requests. The one kept is the hop carrying a security decision,
		-- then one carrying a score, with the id as a deterministic tiebreak so the same
		-- request does not change appearance between refreshes.
		--
		-- The alias is cf_event_id and NOT event_id: aliasing an aggregate back to the
		-- column it aggregates makes ClickHouse resolve the inner reference to the alias
		-- and reject the query outright. waftuning.go and cfrules.go carry the same
		-- warning; this is the third place it has bitten.
		cf AS (
			SELECT correlation_id,
			       argMax(event_id, (rule_id != '', score > 0, event_id)) AS cf_event_id,
			       argMax(score, (rule_id != '', score > 0, event_id))    AS attack_score
			FROM cf_events GROUP BY correlation_id
		)
		SELECT p.correlation_id AS correlation_id,
		       f5.event_id AS f5_event_id,
		       cf.cf_event_id AS cloudflare_event_id,
		       f5.event_time AS event_time, f5.client_ip AS client_ip,
		       f5.country AS country, f5.client_asn AS client_asn,
		       p.request_host AS request_host, f5.request_path AS request_path,
		       f5.request_query AS request_query, p.request_method AS request_method,
		       f5.user_agent AS user_agent, p.f5_verdict AS f5_verdict,
		       f5.violations AS f5_violations, p.cf_verdict AS cf_verdict,
		       p.cf_rule AS cf_rule, cf.attack_score AS attack_score
		FROM pairs AS p
		INNER JOIN f5 USING (correlation_id)
		-- LEFT, not INNER: a record whose Cloudflare event has aged out of retention still
		-- has an F5 side worth reading, and dropping the row would silently shorten the
		-- evidence rather than show it with a blank score.
		LEFT JOIN cf USING (correlation_id)`

// migrationSamplesQuery returns the requests behind one row, with both verdicts.
//
// The F5 event supplies the violations and is what a client opens to read the raw
// payload; the Cloudflare event supplies the score. Both ids are carried so the client
// can link to either without a second round trip.
func migrationSamplesQuery(
	tenantID uuid.UUID, sel WAFMigrationSelector, q DashboardQuery,
) (string, []any) {
	sql, args := samplePairs(tenantID, sel, q)
	sql += sampleJoins
	args = append(args,
		tenantID, q.Range.From.Add(-eventJoinWindow), q.Range.To.Add(eventJoinWindow),
		tenantID, q.Range.From.Add(-eventJoinWindow), q.Range.To.Add(eventJoinWindow))

	// After the joins, because the violation lives on the F5 event rather than on the
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
