//go:build integration

package integration

import (
	"fmt"
	"net"
	"testing"
	"time"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/vendors"
	"github.com/menta2k/siem/test/support"
)

// An event with no client address is ordinary, not exceptional: every DataDome-derived
// row has none, because the Worker's call to DataDome is not the visitor's request. The
// column cannot be null, so all of them are stored as the all-zeros address — and the
// console then presented that as a client, ranking "::" among the busiest sources with
// every address-less event in the platform aggregated behind it.
func TestSourcesPanelExcludesEventsWithNoClientAddress(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "dash-no-client")

	var events []chdata.NormalizedEvent
	// Address-less events OUTNUMBER the real client, so a panel that ranked them would
	// put the fiction first.
	for i := range 20 {
		events = append(events, dashEvent(tenant.ID, fmt.Sprintf("noip-%d", i),
			vendors.DataDome, vendors.VerdictAllowed, "",
			dashBase.Add(time.Duration(i)*time.Second),
			func(e *chdata.NormalizedEvent) {
				e.ClientIP = nil
				e.ClientASN, e.ClientCountry = 0, ""
			}))
	}
	for i := range 3 {
		events = append(events, dashEvent(tenant.ID, fmt.Sprintf("realip-%d", i),
			vendors.Cloudflare, vendors.VerdictAllowed, "",
			dashBase.Add(time.Duration(i)*time.Second)))
	}
	rng := seedEvents(ctx, t, f, events)

	sources, err := chdata.NewDashboardRepo(f.ClickHouse).TopSources(ctx,
		chdata.DashboardQuery{Range: rng, Interval: chdata.Interval1h, Limit: 10})
	if err != nil {
		t.Fatalf("TopSources: %v", err)
	}

	if len(sources) != 1 {
		t.Fatalf("got %d sources, want 1 — only the address that exists: %+v", len(sources), sources)
	}
	if sources[0].ClientIP == nil || sources[0].ClientIP.IsUnspecified() {
		t.Errorf("the panel returned %v as a client address", sources[0].ClientIP)
	}
	if sources[0].Events != 3 {
		t.Errorf("events = %d, want 3", sources[0].Events)
	}
}

// The storage convention must not leak past the repository. A reader asking for an event
// with no client address gets nil — absent — rather than a valid-looking "::" that every
// renderer downstream would have to know to special-case.
func TestAnAbsentClientAddressReadsBackAsAbsent(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "no-client-roundtrip")

	event := dashEvent(tenant.ID, "roundtrip-noip", vendors.DataDome,
		vendors.VerdictAllowed, "", dashBase,
		func(e *chdata.NormalizedEvent) { e.ClientIP = nil })

	if err := f.Events.InsertNormalized(ctx, []chdata.NormalizedEvent{event}); err != nil {
		t.Fatalf("InsertNormalized: %v", err)
	}
	f.Sync(t, "normalized_events")

	stored, err := f.Events.GetNormalized(ctx, "roundtrip-noip")
	if err != nil {
		t.Fatalf("GetNormalized: %v", err)
	}

	if stored.ClientIP != nil {
		t.Errorf("ClientIP = %v, want nil — the zero address means no address was reported",
			stored.ClientIP)
	}
}

// A real address must survive the same path untouched, so the mapping above cannot be
// mistaken for "addresses are dropped".
func TestARealClientAddressSurvivesTheRoundTrip(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "client-roundtrip")

	event := dashEvent(tenant.ID, "roundtrip-ip", vendors.Cloudflare,
		vendors.VerdictAllowed, "", dashBase,
		func(e *chdata.NormalizedEvent) { e.ClientIP = net.ParseIP("198.51.100.7") })

	if err := f.Events.InsertNormalized(ctx, []chdata.NormalizedEvent{event}); err != nil {
		t.Fatalf("InsertNormalized: %v", err)
	}
	f.Sync(t, "normalized_events")

	stored, err := f.Events.GetNormalized(ctx, "roundtrip-ip")
	if err != nil {
		t.Fatalf("GetNormalized: %v", err)
	}

	if stored.ClientIP == nil || !stored.ClientIP.Equal(net.ParseIP("198.51.100.7")) {
		t.Errorf("ClientIP = %v, want 198.51.100.7", stored.ClientIP)
	}
}
