//go:build integration

package integration

import (
	"testing"
	"time"

	"github.com/menta2k/siem/internal/cfrules"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/test/support"
)

var rulesStamp = time.Date(2026, 8, 10, 4, 0, 0, 0, time.UTC)

func cfRule(zone, id, description string) chdata.CloudflareRule {
	return chdata.CloudflareRule{
		ZoneName: zone, ZoneID: "zone-" + zone, RuleID: id,
		RulesetID: "rs1", RulesetName: "Cloudflare Managed Ruleset", RulesetKind: "managed",
		Description: description, Action: "block",
	}
}

func TestCloudflareRulesResolveWhatWasStored(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "cf-rules")
	repo := chdata.NewCloudflareRuleRepo(f.ClickHouse)

	err := repo.Replace(ctx, tenant.ID, []chdata.CloudflareRule{
		cfRule("example.com", "r1", "SQLi - Body detection"),
		cfRule("example.com", "r2", "Block known scrapers"),
	}, rulesStamp)
	if err != nil {
		t.Fatalf("Replace(): %v", err)
	}
	f.Sync(t, "cloudflare_rules")

	names, err := repo.DescriptionsFor(ctx, []string{"r1", "r2", "never-existed"})
	if err != nil {
		t.Fatalf("DescriptionsFor(): %v", err)
	}

	if names["r1"] != "SQLi - Body detection" || names["r2"] != "Block known scrapers" {
		t.Errorf("names = %+v", names)
	}
	// A rule deleted from Cloudflare since the event was logged resolves to nothing
	// rather than to an error: the console shows the bare id, as it did before.
	if _, present := names["never-existed"]; present {
		t.Errorf("an unknown rule was named: %+v", names)
	}
}

// THE PROPERTY THAT MATTERS. These rows are a customer's WAF configuration, read with
// their API token. Every Cloudflare customer is deployed the SAME managed rule ids, so a
// lookup that forgot its tenant predicate would return another customer's description
// for an id they have in common — and it would look entirely plausible.
func TestCloudflareRulesAreNotVisibleToAnotherTenant(t *testing.T) {
	f := support.Shared(t)
	repo := chdata.NewCloudflareRuleRepo(f.ClickHouse)

	ctxA, tenantA := f.NewTenant(t, "cf-rules-a")
	ctxB, tenantB := f.NewTenant(t, "cf-rules-b")

	// The same rule id, described differently, as two customers of the same managed
	// ruleset would have.
	if err := repo.Replace(ctxA, tenantA.ID,
		[]chdata.CloudflareRule{cfRule("a.example", "shared-id", "Tenant A description")},
		rulesStamp); err != nil {
		t.Fatalf("Replace(A): %v", err)
	}
	if err := repo.Replace(ctxB, tenantB.ID,
		[]chdata.CloudflareRule{cfRule("b.example", "shared-id", "Tenant B description")},
		rulesStamp); err != nil {
		t.Fatalf("Replace(B): %v", err)
	}
	f.Sync(t, "cloudflare_rules")

	namesA, err := repo.DescriptionsFor(ctxA, []string{"shared-id"})
	if err != nil {
		t.Fatalf("DescriptionsFor(A): %v", err)
	}
	namesB, err := repo.DescriptionsFor(ctxB, []string{"shared-id"})
	if err != nil {
		t.Fatalf("DescriptionsFor(B): %v", err)
	}

	if namesA["shared-id"] != "Tenant A description" {
		t.Errorf("tenant A got %q", namesA["shared-id"])
	}
	if namesB["shared-id"] != "Tenant B description" {
		t.Errorf("tenant B got %q — a tenant read another's rule name", namesB["shared-id"])
	}
}

// A refresh re-imports the whole snapshot. The engine must collapse it to one row per
// rule, and a rename must win, or the table grows without bound and a lookup starts
// returning whichever copy it reached first.
func TestARefreshCollapsesToOneRowPerRule(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "cf-rules-refresh")
	repo := chdata.NewCloudflareRuleRepo(f.ClickHouse)

	for i, description := range []string{"Original name", "Original name", "Renamed"} {
		err := repo.Replace(ctx, tenant.ID,
			[]chdata.CloudflareRule{cfRule("example.com", "r9", description)},
			rulesStamp.Add(time.Duration(i)*time.Hour))
		if err != nil {
			t.Fatalf("Replace(%d): %v", i, err)
		}
	}
	f.Sync(t, "cloudflare_rules")

	count, err := repo.CountFor(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("CountFor(): %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1 row after three imports of one rule", count)
	}

	names, err := repo.DescriptionsFor(ctx, []string{"r9"})
	if err != nil {
		t.Fatalf("DescriptionsFor(): %v", err)
	}
	if names["r9"] != "Renamed" {
		t.Errorf("description = %q, want the newest", names["r9"])
	}
}

// A fetch that returned nothing is a failed fetch far more often than it is a customer
// deleting every rule, and writing it would replace good names with none.
func TestAnEmptyRuleSnapshotIsRefused(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "cf-rules-empty")

	err := chdata.NewCloudflareRuleRepo(f.ClickHouse).Replace(ctx, tenant.ID, nil, rulesStamp)
	if err == nil {
		t.Error("Replace() accepted an empty snapshot")
	}
}

// The resolver is what the read paths hold, so it is worth driving against the real
// table rather than only against a stub.
func TestTheResolverNamesRulesFromStorage(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "cf-rules-resolver")
	repo := chdata.NewCloudflareRuleRepo(f.ClickHouse)

	err := repo.Replace(ctx, tenant.ID,
		[]chdata.CloudflareRule{cfRule("example.com", "r5", "Rate limit - login")}, rulesStamp)
	if err != nil {
		t.Fatalf("Replace(): %v", err)
	}
	f.Sync(t, "cloudflare_rules")

	names := cfrules.NewResolver(repo, time.Minute).Describe(ctx, []string{"r5", "r6"})

	if names["r5"] != "Rate limit - login" {
		t.Errorf("names = %+v", names)
	}
	if _, present := names["r6"]; present {
		t.Errorf("an unknown rule was named: %+v", names)
	}
}
