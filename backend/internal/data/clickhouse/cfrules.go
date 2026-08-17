package clickhouse

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/tenancy"
)

// CloudflareRule is one rule with the name an analyst needs.
type CloudflareRule struct {
	ZoneName    string
	ZoneID      string
	RuleID      string
	RulesetID   string
	RulesetName string
	RulesetKind string
	Description string
	Action      string
	Ref         string
	Categories  []string
}

// CloudflareRuleRepo stores and reads rule names.
//
// TENANT-SCOPED at every entry point, and unlike the ASN table that is not optional:
// these rows are the customer's WAF configuration, fetched with their token. The write
// path takes the tenant explicitly because the refresh worker iterates tenants outside
// any request; the read path takes it from the context, so a caller cannot ask for
// another tenant's rules even by mistake.
type CloudflareRuleRepo struct {
	client *Client
}

// NewCloudflareRuleRepo constructs the repository.
func NewCloudflareRuleRepo(client *Client) *CloudflareRuleRepo {
	return &CloudflareRuleRepo{client: client}
}

const cloudflareRuleColumns = `tenant_id, zone_name, zone_id, rule_id, ruleset_id,
	ruleset_name, ruleset_kind, description, action, ref, categories, updated_at`

// Replace writes a tenant's current rule snapshot.
//
// Inserts rather than truncating, and the engine collapses: the table is a
// ReplacingMergeTree keyed on (tenant, zone, rule) and versioned by updated_at, so a
// re-import of an unchanged rule becomes one row and a renamed one keeps the newer name.
// Truncating first would leave a window in which a lookup finds nothing, and an analyst
// reading a blocked request during a nightly refresh would see the ids they had before.
//
// An EMPTY snapshot is refused. A zone whose rules all vanished is a failed fetch far
// more often than it is a customer deleting every rule, and writing it would replace
// good names with none.
func (r *CloudflareRuleRepo) Replace(
	ctx context.Context, tenantID uuid.UUID, rules []CloudflareRule, at time.Time,
) error {
	if len(rules) == 0 {
		return fmt.Errorf("refusing to replace tenant %s rules with an empty snapshot", tenantID)
	}

	batch, err := r.client.PrepareBatch(ctx,
		"INSERT INTO cloudflare_rules ("+cloudflareRuleColumns+")")
	if err != nil {
		return err
	}

	stamp := at.UTC()
	for _, rule := range rules {
		if err := batch.Append(
			tenantID, rule.ZoneName, rule.ZoneID, rule.RuleID, rule.RulesetID,
			rule.RulesetName, rule.RulesetKind, rule.Description, rule.Action,
			rule.Ref, orEmptySlice(rule.Categories), stamp,
		); err != nil {
			return fmt.Errorf("append rule %s: %w", rule.RuleID, err)
		}
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("insert %d cloudflare rules: %w", len(rules), err)
	}
	return nil
}

// DescriptionsFor resolves rule ids to their descriptions, within the caller's tenant.
//
// Keyed by rule id ALONE, not by (zone, rule). Cloudflare's ruleset engine gives every
// rule a uuid, and a managed rule keeps the same id — and the same description — on every
// zone it is deployed to, so the zone adds nothing to the answer. It also is not always
// available to ask with: a correlated record carries the rules its vendors reported but
// no zone, and forcing one would leave that page unable to name anything. The zone is
// still STORED, because an operator looking at the table needs to know where a rule came
// from.
//
// Returns only what it FINDS. A missing rule is not an error: it may have been deleted
// since the event was logged, or belong to a zone the token cannot see, and the console
// must render the bare id rather than fail.
func (r *CloudflareRuleRepo) DescriptionsFor(
	ctx context.Context, ruleIDs []string,
) (map[string]string, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}
	if len(ruleIDs) == 0 {
		return map[string]string{}, nil
	}

	// FINAL because the engine collapses duplicate rows on merge, which happens in the
	// background: without it a renamed rule can briefly resolve to both names.
	//
	// any() rather than a join over zones: the same managed rule appears once per zone
	// with an identical description, and returning it four times would make the caller
	// pick arbitrarily anyway.
	// The aggregate is aliased to a DIFFERENT name than the column. Aliasing it back to
	// `description` makes ClickHouse resolve the name in WHERE to the aggregate and
	// reject the query outright — "aggregate function is found in WHERE".
	rows, err := r.client.Query(ctx, `
		SELECT rule_id, any(description) AS name
		FROM cloudflare_rules FINAL
		WHERE tenant_id = ? AND rule_id IN (?) AND description != ''
		GROUP BY rule_id`,
		tenantID, ruleIDs)
	if err != nil {
		return nil, fmt.Errorf("resolve cloudflare rules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	found := make(map[string]string, len(ruleIDs))
	for rows.Next() {
		var ruleID, description string
		if err := rows.Scan(&ruleID, &description); err != nil {
			return nil, fmt.Errorf("scan cloudflare rule: %w", err)
		}
		found[ruleID] = description
	}
	return found, rows.Err()
}

// CountFor reports how many rules are stored for a tenant, which is what the refresh
// worker logs and an operator checks when names stop appearing.
func (r *CloudflareRuleRepo) CountFor(ctx context.Context, tenantID uuid.UUID) (uint64, error) {
	rows, err := r.client.Query(ctx,
		"SELECT count() FROM cloudflare_rules FINAL WHERE tenant_id = ?", tenantID)
	if err != nil {
		return 0, fmt.Errorf("count cloudflare rules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var count uint64
	if rows.Next() {
		if err := rows.Scan(&count); err != nil {
			return 0, fmt.Errorf("scan cloudflare rule count: %w", err)
		}
	}
	return count, rows.Err()
}

// MonitoredActions are the Cloudflare actions that DO NOT enforce.
//
// `log` records the match and lets the request through; `simulate` is the same thing under
// a managed ruleset's name. A rule in either state is the subject of a migration: it has
// been written, it is matching traffic, and nothing has been trusted to it yet.
var MonitoredActions = []string{"log", "simulate"}

// MonitoredRules returns the rules configured not to enforce, as rule id to action.
//
// The RULE's configured action, not what happened on some request, and that distinction is
// the whole point. A log-mode rule does not terminate evaluation, so the action recorded
// against a request is frequently a later `skip` — asking the event what the rule does
// gives the wrong answer for exactly the rules being migrated.
//
// Reads today's configuration, so a rule switched to block stops appearing as a candidate.
// That is the desired behaviour: it is no longer waiting to be migrated.
func (r *CloudflareRuleRepo) MonitoredRules(ctx context.Context) (map[string]string, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return nil, err
	}

	// FINAL for the same reason as DescriptionsFor: a rule whose action was just changed
	// would otherwise be readable in both states until the parts merge.
	//
	// The aggregate is aliased away from the column name it aggregates, which ClickHouse
	// requires — see the note above.
	rows, err := r.client.Query(ctx, `
		SELECT rule_id, any(action) AS verb
		FROM cloudflare_rules FINAL
		WHERE tenant_id = ? AND action IN (?)
		GROUP BY rule_id`,
		tenantID, MonitoredActions)
	if err != nil {
		return nil, fmt.Errorf("read monitored cloudflare rules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	found := map[string]string{}
	for rows.Next() {
		var ruleID, action string
		if err := rows.Scan(&ruleID, &action); err != nil {
			return nil, fmt.Errorf("scan monitored cloudflare rule: %w", err)
		}
		found[ruleID] = action
	}
	return found, rows.Err()
}
