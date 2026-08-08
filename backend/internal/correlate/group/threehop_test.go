package group_test

import (
	"net"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/correlate/group"
	"github.com/menta2k/siem/internal/correlate/keys"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
)

var (
	hopTenant = uuid.MustParse("00000000-0000-4000-8000-00000000000c")
	hopBase   = time.Date(2026, 8, 8, 17, 0, 0, 0, time.UTC)
)

// The three Cloudflare rows a Worker-protected request produces, plus F5's view.
//
//	P — the client-facing request
//	X — the Worker's call to DataDome, whose parent is P
//	Y — the Worker's fetch to the origin, whose parent is P
//
// F5 receives Y in its CF-Ray header, which is what makes Y the only bridge: DataDome
// is reachable through P and F5 through Y, and nothing else carries both.
func hopEvents() []group.Event {
	row := func(vendor, requestID, linked, verdict string, offset time.Duration) group.Event {
		return group.Event{Row: chdata.NormalizedEvent{
			TenantID: hopTenant, Vendor: vendor, EventID: vendor + requestID,
			VendorRequestID: requestID, LinkedRequestID: linked,
			EventTime: hopBase.Add(offset), Verdict: verdict,
			ClientIP: net.ParseIP("203.0.113.10"), RequestHost: "www.jobs.bg",
			RequestPath: "/job/1", RequestMethod: "GET",
		}}
	}

	return []group.Event{
		// The client-facing request: its own ray, no parent.
		row("cloudflare", "P", "", "allowed", 0),
		// DataDome's verdict, keyed on the parent it was made for.
		row("datadome", "P", "", "challenged", time.Second),
		// The origin fetch: its own ray AND the parent's. The bridge.
		row("cloudflare", "Y", "P", "allowed", time.Second),
		// F5 sees only the origin fetch's ray.
		row("f5", "Y", "", "blocked", 2*time.Second),
	}
}

// THE SYMPTOM THIS FIXES. The request passed Cloudflare, then DataDome, then F5, so it
// has three verdicts — but no single identifier reaches all three vendors. Keying each
// event on one identifier put them in two disjoint groups of two, and production showed
// exactly zero records with three verdicts however long anyone waited.
func TestOneRequestThroughThreeVendorsFormsOneGroup(t *testing.T) {
	groups := group.Batch(hopEvents(), keys.DefaultSettings())

	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1 — the hops of one request were split apart",
			len(groups))
	}
	if got := groups[0].Vendors(); len(got) != 3 {
		t.Errorf("vendors = %v, want all three", got)
	}
	if groups[0].Key.Tier != keys.TierExact {
		t.Errorf("tier = %v, want exact — every hop is tied by a shared identifier",
			groups[0].Key.Tier)
	}
}

// The group key must be a pure function of the membership, not of the order events
// were discovered in. A late arrival recomputes it to find the record it amends, so a
// key that shifted with arrival order would write a SECOND record instead.
func TestTheGroupKeyDoesNotDependOnArrivalOrder(t *testing.T) {
	events := hopEvents()
	forward := group.Batch(events, keys.DefaultSettings())

	reversed := make([]group.Event, len(events))
	for i, e := range events {
		reversed[len(events)-1-i] = e
	}
	backward := group.Batch(reversed, keys.DefaultSettings())

	if len(forward) != 1 || len(backward) != 1 {
		t.Fatalf("got %d and %d groups, want 1 each", len(forward), len(backward))
	}
	if forward[0].Key.Value != backward[0].Key.Value {
		t.Errorf("key depends on arrival order: %q vs %q — an amendment would land on a "+
			"different record and duplicate it",
			forward[0].Key.Value, backward[0].Key.Value)
	}
}

// A partial arrival must still produce the same key, so the record that appears first
// is the one later hops amend rather than a second one appearing beside it.
func TestAPartialGroupKeepsTheSameKeyOnceTheRestArrives(t *testing.T) {
	all := hopEvents()

	// Only the bridge and F5 have arrived so far.
	partial := group.Batch([]group.Event{all[2], all[3]}, keys.DefaultSettings())
	if len(partial) != 1 {
		t.Fatalf("got %d groups from the partial batch, want 1", len(partial))
	}

	complete := group.Batch(all, keys.DefaultSettings())
	if partial[0].Key.Value != complete[0].Key.Value {
		t.Errorf("key changed when the remaining hops arrived: %q -> %q — the amendment "+
			"would create a second record instead of updating the first",
			partial[0].Key.Value, complete[0].Key.Value)
	}
}

// Unrelated requests must not be dragged together. The linking is only ever through a
// shared identifier, so two independent requests stay independent.
func TestUnrelatedRequestsAreNotMerged(t *testing.T) {
	events := append(hopEvents(), group.Event{Row: chdata.NormalizedEvent{
		TenantID: hopTenant, Vendor: "cloudflare", EventID: "other",
		VendorRequestID: "Q", EventTime: hopBase,
		ClientIP: net.ParseIP("203.0.113.99"), RequestHost: "www.jobs.bg",
		RequestPath: "/other", RequestMethod: "GET",
	}})

	groups := group.Batch(events, keys.DefaultSettings())
	for _, g := range groups {
		for _, m := range g.Members {
			if m.Row.EventID != "other" {
				continue
			}
			if len(g.Members) != 1 {
				t.Errorf("an unrelated request was merged into a group of %d", len(g.Members))
			}
		}
	}
}

// A single vendor reporting both identifiers is NOT a cross-vendor join. Without the
// distinct-vendor test the bridge row alone would confirm its own component.
func TestTheBridgeAloneDoesNotConfirmAJoin(t *testing.T) {
	bridge := hopEvents()[2]

	groups := group.Batch([]group.Event{bridge}, keys.DefaultSettings())
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(groups))
	}
	if groups[0].Key.Tier == keys.TierExact {
		t.Error("one vendor's event confirmed an exact join on its own")
	}
}
