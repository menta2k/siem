package service

import (
	"context"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
	"github.com/menta2k/siem/internal/cfrules"
)

// RuleNamer resolves rule ids to the rule's name within the caller's tenant.
//
// An interface rather than the concrete resolver so a service can be constructed without
// one — a deployment with no Cloudflare token passes nil, and every call below leaves the
// description empty.
type RuleNamer interface {
	Describe(ctx context.Context, ruleIDs []string) map[string]string
}

// Compile-time proof that the resolver satisfies what the services need.
var _ RuleNamer = (*cfrules.Resolver)(nil)

// describeEvents fills in the rule name on a page of event summaries.
//
// ONE lookup for the whole page. A search filtered to a rule is entirely that rule, and
// even an unfiltered page is dominated by a handful, so resolving per row would turn one
// query into fifty.
func describeEvents(ctx context.Context, namer RuleNamer, items []*pb.EventSummary) {
	if namer == nil || len(items) == 0 {
		return
	}

	ids := make([]string, 0, len(items))
	for _, item := range items {
		if item.GetRuleId() != "" {
			ids = append(ids, item.GetRuleId())
		}
	}
	if len(ids) == 0 {
		return
	}

	names := namer.Describe(ctx, ids)
	for _, item := range items {
		if name, ok := names[item.GetRuleId()]; ok {
			item.RuleDescription = name
		}
	}
}

// describeVerdicts fills in the rule name on the vendor verdicts of correlated records.
//
// Takes the whole page rather than one record: a page of correlated requests triggered by
// the same rule is the common case when an analyst is investigating one, and it should
// cost a single lookup.
func describeVerdicts(ctx context.Context, namer RuleNamer, records []*pb.CorrelatedRequest) {
	if namer == nil || len(records) == 0 {
		return
	}

	var verdicts []*pb.VendorVerdict
	var ids []string
	for _, record := range records {
		for _, verdict := range record.GetVendorVerdicts() {
			if verdict.GetRuleId() == "" {
				continue
			}
			verdicts = append(verdicts, verdict)
			ids = append(ids, verdict.GetRuleId())
		}
	}
	if len(ids) == 0 {
		return
	}

	names := namer.Describe(ctx, ids)
	for _, verdict := range verdicts {
		if name, ok := names[verdict.GetRuleId()]; ok {
			verdict.RuleDescription = name
		}
	}
}

// describeRuleCounts fills in the rule name on the dashboard's top-rules panel.
func describeRuleCounts(ctx context.Context, namer RuleNamer, rules []*pb.RuleCount) {
	if namer == nil || len(rules) == 0 {
		return
	}

	ids := make([]string, 0, len(rules))
	for _, rule := range rules {
		if rule.GetRuleId() != "" {
			ids = append(ids, rule.GetRuleId())
		}
	}
	if len(ids) == 0 {
		return
	}

	names := namer.Describe(ctx, ids)
	for _, rule := range rules {
		if name, ok := names[rule.GetRuleId()]; ok {
			rule.RuleDescription = name
		}
	}
}
