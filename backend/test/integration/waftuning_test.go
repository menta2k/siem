//go:build integration

package integration

import (
	"context"
	"math"
	"net"
	"testing"
	"time"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/query"
	"github.com/menta2k/siem/internal/vendors"
	"github.com/menta2k/siem/test/support"
)

var wafBase = time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)

func wafRange() query.TimeRange {
	return query.TimeRange{From: wafBase.Add(-time.Hour), To: wafBase.Add(time.Hour)}
}

// seedWAFCorpus writes one rule behaving in two opposite ways on two hosts.
//
// THE WHOLE POINT OF THE FEATURE IS SEPARATING THESE TWO. The same rule fires on
// api.example.com against traffic the WAF scores 2 — a real attack — and on
// shop.example.com against traffic it scores 95 — clean. A corpus where both hosts
// scored alike would pass whether or not the split worked, which is the mistake worth
// designing against.
func seedWAFCorpus(ctx context.Context, t *testing.T, f *support.Fixture, tenantID [16]byte) {
	t.Helper()

	var events []chdata.NormalizedEvent
	add := func(id, host, path string, score uint8, action, source, rule string) {
		events = append(events, chdata.NormalizedEvent{
			TenantID: tenantID, EventID: id, Vendor: vendors.Cloudflare,
			ClientIP:    net.ParseIP("203.0.113.10"),
			RequestHost: host, RequestPath: path, RequestMethod: "GET",
			Verdict: vendors.VerdictMonitored, RuleID: rule,
			WAFAttackScore: score, WAFAction: action, WAFSource: source,
		})
	}

	// A real detection: three hits on one path, all scoring as attacks.
	for i, id := range []string{"waf-a1", "waf-a2", "waf-a3"} {
		add(id, "api.example.com", "/?q=%27or%201=1", uint8(2+i), "log", "firewallManaged", "sqli-rule")
	}
	// The same rule on another host, on traffic the WAF calls clean — a false positive.
	for _, id := range []string{"waf-c1", "waf-c2"} {
		add(id, "shop.example.com", "/catalog", 95, "log", "firewallManaged", "sqli-rule")
	}
	// A coverage gap: scored as an attack, matched by NOTHING.
	add("waf-gap1", "api.example.com", "/admin.php", 3, "", "", "")
	add("waf-gap2", "api.example.com", "/.env", 12, "", "", "")
	// Clean and unmatched, which must NOT appear as a gap.
	add("waf-quiet", "api.example.com", "/health", 100, "", "", "")

	for i := range events {
		events[i].EventTime = wafBase.Add(time.Duration(i) * time.Second)
		events[i].ReceivedAt = events[i].EventTime
		events[i].IngestVersion = 1
	}

	if err := chdata.NewEventRepo(f.ClickHouse).InsertNormalized(ctx, events); err != nil {
		t.Fatalf("seed waf corpus: %v", err)
	}
	f.Sync(t, "normalized_events")
	// The rollups are materialized views, so they are written by the INSERT above rather
	// than by anything this test can flush directly.
	f.Sync(t, "rollup_waf_rules_1h")
	f.Sync(t, "rollup_waf_gaps_1h")
}

// The finding is the SPLIT, not the total. Both rows below are the same rule with the
// same action and source, and an implementation that summed them into one line — or
// reported only a mean — would hide exactly the thing an operator needs to see.
func TestRuleProfileSeparatesRealDetectionsFromFalsePositives(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "waf-profile")
	seedWAFCorpus(ctx, t, f, tenant.ID)

	profiles, err := chdata.NewWAFTuningRepo(f.ClickHouse).RuleProfile(ctx,
		chdata.DashboardQuery{Range: wafRange(), Limit: 50})
	if err != nil {
		t.Fatalf("RuleProfile: %v", err)
	}

	byHost := map[string]chdata.WAFRuleProfile{}
	for _, p := range profiles {
		if p.RuleID == "sqli-rule" {
			byHost[p.RequestHost] = p
		}
	}

	api, ok := byHost["api.example.com"]
	if !ok {
		t.Fatalf("no profile row for the attacked host: %+v", profiles)
	}
	if api.Events != 3 || api.AttackEvents != 3 || api.CleanEvents != 0 {
		t.Errorf("attacked host = %d events / %d attack / %d clean, want 3/3/0",
			api.Events, api.AttackEvents, api.CleanEvents)
	}

	shop, ok := byHost["shop.example.com"]
	if !ok {
		t.Fatalf("no profile row for the clean host: %+v", profiles)
	}
	if shop.Events != 2 || shop.CleanEvents != 2 || shop.AttackEvents != 0 {
		t.Errorf("clean host = %d events / %d attack / %d clean, want 2/0/2",
			shop.Events, shop.AttackEvents, shop.CleanEvents)
	}

	// The action and engine ride along, because they decide what can be done about it.
	if api.Action != "log" || api.Source != "firewallManaged" {
		t.Errorf("action/source = %q/%q, want log/firewallManaged", api.Action, api.Source)
	}
	// The mean is offered but is exactly the summary that hides the finding: these two
	// rows average to something unremarkable while describing opposite situations.
	if api.MeanScore >= shop.MeanScore {
		t.Errorf("mean scores did not preserve the direction: attacked %.1f, clean %.1f",
			api.MeanScore, shop.MeanScore)
	}
}

// The mirror image of a false positive: traffic the WAF scored as an attack that no
// rule matched at all. Clean unmatched traffic — the overwhelming majority — must stay
// out, or the view is just a list of every host.
func TestCoverageGapsFindUnmatchedAttacksAndIgnoreCleanTraffic(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "waf-gaps")
	seedWAFCorpus(ctx, t, f, tenant.ID)

	gaps, err := chdata.NewWAFTuningRepo(f.ClickHouse).CoverageGaps(ctx,
		chdata.DashboardQuery{Range: wafRange(), Limit: 50})
	if err != nil {
		t.Fatalf("CoverageGaps: %v", err)
	}

	if len(gaps) != 1 {
		t.Fatalf("gaps = %+v, want exactly the one host taking unmatched attacks", gaps)
	}
	gap := gaps[0]
	if gap.RequestHost != "api.example.com" {
		t.Errorf("host = %q, want api.example.com", gap.RequestHost)
	}
	// Two unmatched attack-scored requests. The clean unmatched one must not be counted,
	// and neither must the three that a rule DID match.
	if gap.Events != 2 || gap.AttackEvents != 2 {
		t.Errorf("gap = %d events / %d attack, want 2/2 — matched or clean traffic leaked in",
			gap.Events, gap.AttackEvents)
	}
}

// The drill-down an operator uses to write an exception: which URLs is this rule
// actually firing on.
func TestRulePathsShowWhereTheRuleFires(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "waf-paths")
	seedWAFCorpus(ctx, t, f, tenant.ID)

	paths, err := chdata.NewWAFTuningRepo(f.ClickHouse).RulePaths(ctx, "sqli-rule",
		chdata.DashboardQuery{Range: wafRange(), Limit: 50})
	if err != nil {
		t.Fatalf("RulePaths: %v", err)
	}

	found := map[string]uint64{}
	for _, p := range paths {
		found[p.RequestHost+p.RequestPath] = p.Events
	}
	if found["api.example.com/?q=%27or%201=1"] != 3 {
		t.Errorf("attacked path count = %d, want 3: %+v", found["api.example.com/?q=%27or%201=1"], paths)
	}
	if found["shop.example.com/catalog"] != 2 {
		t.Errorf("clean path count = %d, want 2: %+v", found["shop.example.com/catalog"], paths)
	}
	// The unmatched gap traffic belongs to no rule and must not appear here.
	if _, leaked := found["api.example.com/admin.php"]; leaked {
		t.Error("a request no rule matched was attributed to the rule")
	}
}

// Tenant isolation, on a path that reads a rollup rather than the events table. Every
// query here is tenant-scoped from the context, and a rollup that forgot the predicate
// would still return rows.
func TestWAFProfileIsTenantScoped(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "waf-tenant-a")
	seedWAFCorpus(ctx, t, f, tenant.ID)

	otherCtx, _ := f.NewTenant(t, "waf-tenant-b")

	profiles, err := chdata.NewWAFTuningRepo(f.ClickHouse).RuleProfile(otherCtx,
		chdata.DashboardQuery{Range: wafRange(), Limit: 50})
	if err != nil {
		t.Fatalf("RuleProfile: %v", err)
	}
	if len(profiles) != 0 {
		t.Errorf("another tenant's rules were visible: %+v", profiles)
	}

	gaps, err := chdata.NewWAFTuningRepo(f.ClickHouse).CoverageGaps(otherCtx,
		chdata.DashboardQuery{Range: wafRange(), Limit: 50})
	if err != nil {
		t.Fatalf("CoverageGaps: %v", err)
	}
	if len(gaps) != 0 {
		t.Errorf("another tenant's gaps were visible: %+v", gaps)
	}
}

// avgIf over no matching rows returns NaN, and NaN is not representable in JSON — one
// such group would break the entire response rather than showing an odd number. A rule
// whose events all predate the score columns is exactly that group, so it is not
// hypothetical: every event written before migration 0015 reads 0.
func TestUnscoredEventsDoNotProduceNaN(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "waf-unscored")

	events := []chdata.NormalizedEvent{{
		TenantID: tenant.ID, EventID: "waf-unscored-1", Vendor: vendors.Cloudflare,
		EventTime: wafBase, ReceivedAt: wafBase, IngestVersion: 1,
		RequestHost: "old.example.com", RequestPath: "/", RequestMethod: "GET",
		Verdict: vendors.VerdictAllowed, RuleID: "legacy-rule",
		// No score at all, exactly as every row written before migration 0015 reads.
		WAFAttackScore: 0,
	}}
	if err := chdata.NewEventRepo(f.ClickHouse).InsertNormalized(ctx, events); err != nil {
		t.Fatalf("InsertNormalized: %v", err)
	}
	f.Sync(t, "normalized_events")

	paths, err := chdata.NewWAFTuningRepo(f.ClickHouse).RulePaths(ctx, "legacy-rule",
		chdata.DashboardQuery{Range: wafRange(), Limit: 10})
	if err != nil {
		t.Fatalf("RulePaths: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("paths = %+v, want the one unscored path", paths)
	}
	if math.IsNaN(paths[0].MeanScore) {
		t.Error("mean score is NaN, which cannot be encoded as JSON")
	}
	if paths[0].MeanScore != 0 {
		t.Errorf("mean score = %v, want 0 for events that were never scored", paths[0].MeanScore)
	}
}
