//go:build integration

package integration

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/query"
	"github.com/menta2k/siem/internal/vendors"
	"github.com/menta2k/siem/test/support"
)

var dashBase = time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)

// seedEvents writes normalized events and returns the range covering them.
func seedEvents(
	ctx context.Context, t *testing.T, f *support.Fixture, events []chdata.NormalizedEvent,
) query.TimeRange {
	t.Helper()

	repo := chdata.NewEventRepo(f.ClickHouse)
	if err := repo.InsertNormalized(ctx, events); err != nil {
		t.Fatalf("insert normalized events: %v", err)
	}
	f.Sync(t, "normalized_events")

	return query.TimeRange{From: dashBase.Add(-time.Hour), To: dashBase.Add(2 * time.Hour)}
}

func dashEvent(
	tenantID [16]byte, id, vendor, verdict, rule string, at time.Time,
	mutate ...func(*chdata.NormalizedEvent),
) chdata.NormalizedEvent {
	event := chdata.NormalizedEvent{
		TenantID:      tenantID,
		EventID:       id,
		EventTime:     at.UTC(),
		ReceivedAt:    at.UTC(),
		Vendor:        vendor,
		ClientIP:      net.ParseIP("203.0.113.10"),
		ClientCountry: "DE",
		ClientASN:     64512,
		RequestHost:   "shop.example.com",
		RequestPath:   "/checkout",
		RequestMethod: "GET",
		Verdict:       verdict,
		RuleID:        rule,
		IngestVersion: 1,
	}
	for _, m := range mutate {
		m(&event)
	}
	return event
}

// The panels must agree with the events they summarize. A rollup that drifts from the
// source is worse than no rollup: an analyst reconciles a dashboard against a search,
// finds a mismatch, and stops trusting both.
func TestVendorVolumeReconcilesWithEventCounts(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "dash-volume")

	want := map[string]int{vendors.Cloudflare: 7, vendors.F5: 4, vendors.DataDome: 2}

	var events []chdata.NormalizedEvent
	for vendor, count := range want {
		for i := range count {
			events = append(events, dashEvent(tenant.ID,
				fmt.Sprintf("%s-%d", vendor, i), vendor, vendors.VerdictAllowed, "",
				dashBase.Add(time.Duration(i)*time.Second)))
		}
	}
	rng := seedEvents(ctx, t, f, events)

	points, err := chdata.NewDashboardRepo(f.ClickHouse).VendorVolume(ctx,
		chdata.DashboardQuery{Range: rng, Interval: chdata.Interval1h})
	if err != nil {
		t.Fatalf("VendorVolume: %v", err)
	}

	got := map[string]uint64{}
	for _, p := range points {
		got[p.Vendor] += p.Events
	}
	for vendor, expected := range want {
		if got[vendor] != uint64(expected) {
			t.Errorf("%s volume = %d, want %d", vendor, got[vendor], expected)
		}
	}
}

// The rollups aggregate over uniq(event_id) rather than count() precisely for this:
// normalized_events is a ReplacingMergeTree, and a re-ingested event arrives as a
// second row. A counting rollup would report a vendor's retry as a traffic spike.
func TestRollupsAreIdempotentUnderRedelivery(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "dash-redelivery")

	events := []chdata.NormalizedEvent{
		dashEvent(tenant.ID, "dup-1", vendors.Cloudflare, vendors.VerdictAllowed, "", dashBase),
		dashEvent(tenant.ID, "dup-2", vendors.Cloudflare, vendors.VerdictAllowed, "", dashBase),
	}
	rng := seedEvents(ctx, t, f, events)

	// The vendor retries the same batch; identical event ids, higher ingest version.
	retry := make([]chdata.NormalizedEvent, len(events))
	copy(retry, events)
	for i := range retry {
		retry[i].IngestVersion = 2
	}
	seedEvents(ctx, t, f, retry)

	points, err := chdata.NewDashboardRepo(f.ClickHouse).VendorVolume(ctx,
		chdata.DashboardQuery{Range: rng, Interval: chdata.Interval1h})
	if err != nil {
		t.Fatalf("VendorVolume: %v", err)
	}

	var total uint64
	for _, p := range points {
		total += p.Events
	}
	if total != 2 {
		t.Errorf("volume = %d after a redelivery, want 2 — a retry is not new traffic", total)
	}
}

func TestVerdictMixReconciles(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "dash-verdicts")

	want := map[string]int{
		vendors.VerdictAllowed:    5,
		vendors.VerdictBlocked:    3,
		vendors.VerdictChallenged: 2,
	}

	var events []chdata.NormalizedEvent
	i := 0
	for verdict, count := range want {
		for range count {
			events = append(events, dashEvent(tenant.ID,
				fmt.Sprintf("v-%d", i), vendors.Cloudflare, verdict, "",
				dashBase.Add(time.Duration(i)*time.Second)))
			i++
		}
	}
	rng := seedEvents(ctx, t, f, events)

	points, err := chdata.NewDashboardRepo(f.ClickHouse).VerdictMix(ctx,
		chdata.DashboardQuery{Range: rng, Interval: chdata.Interval1h})
	if err != nil {
		t.Fatalf("VerdictMix: %v", err)
	}

	got := map[string]uint64{}
	for _, p := range points {
		got[p.Verdict] += p.Events
	}
	for verdict, expected := range want {
		if got[verdict] != uint64(expected) {
			t.Errorf("%s = %d, want %d", verdict, got[verdict], expected)
		}
	}
}

// Events that triggered no rule are the overwhelming majority. Including them would
// produce one enormous empty-string entry that dominates every "top rules" panel.
func TestTopRulesExcludesEventsWithNoRule(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "dash-rules")

	var events []chdata.NormalizedEvent
	for i := range 20 {
		events = append(events, dashEvent(tenant.ID, fmt.Sprintf("norule-%d", i),
			vendors.Cloudflare, vendors.VerdictAllowed, "",
			dashBase.Add(time.Duration(i)*time.Second)))
	}
	for i := range 3 {
		events = append(events, dashEvent(tenant.ID, fmt.Sprintf("rule-%d", i),
			vendors.F5, vendors.VerdictBlocked, "waf-sqli",
			dashBase.Add(time.Duration(i)*time.Second)))
	}
	rng := seedEvents(ctx, t, f, events)

	rules, err := chdata.NewDashboardRepo(f.ClickHouse).TopRules(ctx,
		chdata.DashboardQuery{Range: rng, Interval: chdata.Interval1h, Limit: 10})
	if err != nil {
		t.Fatalf("TopRules: %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1: %+v", len(rules), rules)
	}
	if rules[0].RuleID != "waf-sqli" || rules[0].Events != 3 {
		t.Errorf("got %+v, want waf-sqli with 3 events", rules[0])
	}
}

// The blocked counter must be a subset of the event counter, not a separate tally that
// can disagree with it — a source showing more blocks than requests is nonsense an
// analyst cannot act on.
func TestTopSourcesTracksBlockedAsASubset(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "dash-sources")

	var events []chdata.NormalizedEvent
	for i := range 6 {
		verdict := vendors.VerdictAllowed
		if i%2 == 0 {
			verdict = vendors.VerdictBlocked
		}
		events = append(events, dashEvent(tenant.ID, fmt.Sprintf("src-%d", i),
			vendors.Cloudflare, verdict, "", dashBase.Add(time.Duration(i)*time.Second)))
	}
	rng := seedEvents(ctx, t, f, events)

	sources, err := chdata.NewDashboardRepo(f.ClickHouse).TopSources(ctx,
		chdata.DashboardQuery{Range: rng, Interval: chdata.Interval1h, Limit: 10})
	if err != nil {
		t.Fatalf("TopSources: %v", err)
	}
	if len(sources) == 0 {
		t.Fatal("no sources returned")
	}

	source := sources[0]
	if source.Events != 6 {
		t.Errorf("events = %d, want 6", source.Events)
	}
	if source.Blocked != 3 {
		t.Errorf("blocked = %d, want 3", source.Blocked)
	}
	if source.Blocked > source.Events {
		t.Error("blocked exceeds total events, which cannot be true")
	}
	if source.Country != "DE" || source.ASN != 64512 {
		t.Errorf("source attribution lost: country=%q asn=%d", source.Country, source.ASN)
	}
}

// Panels must be scoped to the caller's tenant. The rollups carry tenant_id in their
// sort key, but a repository that forgot the predicate would still return rows.
func TestDashboardsAreTenantScoped(t *testing.T) {
	f := support.Shared(t)
	ctxA, tenantA := f.NewTenant(t, "dash-tenant-a")
	ctxB, _ := f.NewTenant(t, "dash-tenant-b")

	rng := seedEvents(ctxA, t, f, []chdata.NormalizedEvent{
		dashEvent(tenantA.ID, "a-1", vendors.Cloudflare, vendors.VerdictAllowed, "", dashBase),
		dashEvent(tenantA.ID, "a-2", vendors.Cloudflare, vendors.VerdictAllowed, "", dashBase),
	})

	repo := chdata.NewDashboardRepo(f.ClickHouse)
	q := chdata.DashboardQuery{Range: rng, Interval: chdata.Interval1h}

	own, err := repo.VendorVolume(ctxA, q)
	if err != nil {
		t.Fatalf("VendorVolume for the owning tenant: %v", err)
	}
	if len(own) == 0 {
		t.Fatal("the owning tenant sees none of its own events")
	}

	other, err := repo.VendorVolume(ctxB, q)
	if err != nil {
		t.Fatalf("VendorVolume for the other tenant: %v", err)
	}
	if len(other) != 0 {
		t.Errorf("tenant B sees %d of tenant A's buckets", len(other))
	}
}

// The interval reaches a SQL function name, which is the one position in these queries
// a placeholder cannot protect.
func TestUnsupportedIntervalIsRejected(t *testing.T) {
	f := support.Shared(t)
	ctx, _ := f.NewTenant(t, "dash-interval")

	repo := chdata.NewDashboardRepo(f.ClickHouse)
	rng := query.TimeRange{From: dashBase.Add(-time.Hour), To: dashBase.Add(time.Hour)}

	for _, interval := range []chdata.Interval{
		"", "1s", "toStartOfHour(bucket)); DROP TABLE normalized_events --",
	} {
		if _, err := repo.VendorVolume(ctx,
			chdata.DashboardQuery{Range: rng, Interval: interval}); err == nil {
			t.Errorf("interval %q was accepted", interval)
		}
	}
}

// All panels share one range control, so they must move together (FR-025). A panel
// that silently widens its own range is how two figures on one screen disagree.
func TestPanelsHonourTheSharedRange(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "dash-range")

	inside := dashEvent(tenant.ID, "in-1", vendors.Cloudflare, vendors.VerdictBlocked,
		"waf-1", dashBase)
	outside := dashEvent(tenant.ID, "out-1", vendors.Cloudflare, vendors.VerdictBlocked,
		"waf-1", dashBase.Add(-48*time.Hour))
	seedEvents(ctx, t, f, []chdata.NormalizedEvent{inside, outside})

	narrow := query.TimeRange{From: dashBase.Add(-time.Hour), To: dashBase.Add(time.Hour)}
	repo := chdata.NewDashboardRepo(f.ClickHouse)

	volume, err := repo.VendorVolume(ctx,
		chdata.DashboardQuery{Range: narrow, Interval: chdata.Interval1h})
	if err != nil {
		t.Fatalf("VendorVolume: %v", err)
	}
	var total uint64
	for _, p := range volume {
		total += p.Events
	}
	if total != 1 {
		t.Errorf("volume = %d in the narrow range, want 1", total)
	}

	rules, err := repo.TopRules(ctx,
		chdata.DashboardQuery{Range: narrow, Interval: chdata.Interval1h, Limit: 10})
	if err != nil {
		t.Fatalf("TopRules: %v", err)
	}
	if len(rules) != 1 || rules[0].Events != 1 {
		t.Errorf("top rules = %+v, want one rule with one event in the same range", rules)
	}
}
