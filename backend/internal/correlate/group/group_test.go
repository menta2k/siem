package group_test

import (
	"net"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/correlate/confidence"
	"github.com/menta2k/siem/internal/correlate/group"
	"github.com/menta2k/siem/internal/correlate/keys"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
)

var (
	tenant = uuid.MustParse("00000000-0000-4000-8000-000000000001")
	base   = time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
)

type opt func(*chdata.NormalizedEvent)

func withRequestID(id string) opt {
	return func(e *chdata.NormalizedEvent) { e.VendorRequestID = id }
}
func withIP(ip string) opt {
	return func(e *chdata.NormalizedEvent) { e.ClientIP = net.ParseIP(ip) }
}
func withShared() opt       { return func(e *chdata.NormalizedEvent) { e.ClientIPShared = true } }
func withPath(p string) opt { return func(e *chdata.NormalizedEvent) { e.RequestPath = p } }
func at(offset time.Duration) opt {
	return func(e *chdata.NormalizedEvent) { e.EventTime = base.Add(offset) }
}

func event(vendor string, opts ...opt) group.Event {
	row := chdata.NormalizedEvent{
		TenantID: tenant, Vendor: vendor, EventTime: base,
		RequestHost: "shop.example.com", RequestPath: "/checkout", RequestMethod: "GET",
	}
	withIP("203.0.113.10")(&row)
	for _, o := range opts {
		o(&row)
	}
	return group.Event{Ref: vendor + "/" + row.VendorRequestID, Row: row}
}

func TestSharedRequestIDJoinsAtTierOne(t *testing.T) {
	groups := group.Batch([]group.Event{
		event("cloudflare", withRequestID("ray-1")),
		event("f5", withRequestID("ray-1")),
	}, keys.DefaultSettings())

	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(groups))
	}
	if groups[0].Key.Tier != keys.TierExact {
		t.Errorf("tier = %v, want exact", groups[0].Key.Tier)
	}
	if groups[0].Confidence != confidence.High {
		t.Errorf("confidence = %q, want high", groups[0].Confidence)
	}
}

// The regression this package exists for. Each vendor stamps its OWN id, so an exact
// key exists for every event and matches no one. Preferring it per-event strands each
// event alone and tier 2 never runs.
func TestDistinctVendorIDsStillJoinOnTierTwo(t *testing.T) {
	groups := group.Batch([]group.Event{
		event("cloudflare", withRequestID("ray-1"), at(0)),
		event("f5", withRequestID("support-9"), at(time.Second)),
	}, keys.DefaultSettings())

	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1 — distinct vendor ids must not block the heuristic", len(groups))
	}
	if groups[0].Key.Tier != keys.TierHeuristic {
		t.Errorf("tier = %v, want heuristic", groups[0].Key.Tier)
	}
	if groups[0].Confidence != confidence.Medium {
		t.Errorf("confidence = %q, want medium", groups[0].Confidence)
	}
}

// A repeated id from ONE vendor is a retry or a duplicate delivery, not corroboration.
// Confirming on event count rather than distinct vendors would build a "cross-vendor"
// record holding the same vendor twice.
func TestSameVendorRepeatingAnIDDoesNotConfirmTierOne(t *testing.T) {
	groups := group.Batch([]group.Event{
		event("cloudflare", withRequestID("ray-1"), withPath("/a")),
		event("cloudflare", withRequestID("ray-1"), withPath("/b")),
	}, keys.DefaultSettings())

	for _, g := range groups {
		if g.Key.Tier == keys.TierExact {
			t.Errorf("one vendor confirmed its own id at tier 1: %v", g.Members)
		}
	}
}

func TestSharedAddressDegradesConfidence(t *testing.T) {
	groups := group.Batch([]group.Event{
		event("cloudflare", withRequestID("ray-1"), withIP("100.64.0.5"), withShared()),
		event("f5", withRequestID("support-9"), withIP("100.64.0.5"), withShared()),
	}, keys.DefaultSettings())

	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(groups))
	}
	if groups[0].Confidence != confidence.Low {
		t.Errorf("confidence = %q, want low for a shared client address", groups[0].Confidence)
	}
}

// One member on a shared address makes the whole join uncertain, regardless of which
// event happened to open the group.
func TestAmbiguityIsAPropertyOfTheGroup(t *testing.T) {
	clean := event("cloudflare", withRequestID("ray-1"), withIP("100.64.0.5"))
	shared := event("f5", withRequestID("support-9"), withIP("100.64.0.5"), withShared())

	groups := group.Batch([]group.Event{clean, shared}, keys.DefaultSettings())
	if len(groups) != 1 || groups[0].Confidence != confidence.Low {
		t.Fatalf("groups=%d confidence=%q, want 1 group at low confidence",
			len(groups), groups[0].Confidence)
	}
}

func TestEventsOutsideTheWindowDoNotJoin(t *testing.T) {
	groups := group.Batch([]group.Event{
		event("cloudflare", withRequestID("ray-1"), at(0)),
		event("f5", withRequestID("support-9"), at(25*time.Second)),
	}, keys.DefaultSettings())

	if len(groups) != 2 {
		t.Errorf("got %d groups, want 2 — 25s apart is two separate requests", len(groups))
	}
}

// Truncated windows put events milliseconds apart on opposite sides of a boundary.
func TestBoundaryStraddleStillJoins(t *testing.T) {
	settings := keys.DefaultSettings()
	edge := base.Truncate(settings.Window).Add(settings.Window)

	groups := group.Batch([]group.Event{
		event("cloudflare", withRequestID("ray-1"), at(edge.Add(-time.Millisecond).Sub(base))),
		event("f5", withRequestID("support-9"), at(edge.Sub(base))),
	}, settings)

	if len(groups) != 1 {
		t.Errorf("got %d groups, want 1 — 1ms apart is one request", len(groups))
	}
}

func TestSingleVendorEventProducesItsOwnRecord(t *testing.T) {
	groups := group.Batch([]group.Event{
		event("datadome", withRequestID("dd-1")),
	}, keys.DefaultSettings())

	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1 — single-vendor traffic must not be discarded", len(groups))
	}
	if groups[0].Confidence != confidence.High {
		t.Errorf("confidence = %q, want high; no join happened, so nothing is uncertain",
			groups[0].Confidence)
	}
}

// Grouping must be a pure function of its input: a late arrival recomputes the
// correlation id to find the record it amends, so a different order must not produce
// different groups.
func TestGroupingIsOrderIndependent(t *testing.T) {
	events := []group.Event{
		event("cloudflare", withRequestID("ray-1"), at(0)),
		event("f5", withRequestID("support-9"), at(time.Second)),
		event("datadome", withRequestID("dd-1"), at(2*time.Second)),
	}
	reversed := []group.Event{events[2], events[1], events[0]}

	forward := group.Batch(events, keys.DefaultSettings())
	backward := group.Batch(reversed, keys.DefaultSettings())

	if len(forward) != len(backward) {
		t.Fatalf("group count differs by input order: %d vs %d", len(forward), len(backward))
	}
	for i := range forward {
		if forward[i].Key.Value != backward[i].Key.Value {
			t.Errorf("group %d key differs by input order: %q vs %q",
				i, forward[i].Key.Value, backward[i].Key.Value)
		}
	}
}

// Batch must not reorder the caller's slice; the worker still needs it to ack offsets.
func TestBatchDoesNotMutateInput(t *testing.T) {
	events := []group.Event{
		event("f5", withRequestID("support-9"), at(2*time.Second)),
		event("cloudflare", withRequestID("ray-1"), at(0)),
	}
	first := events[0].Ref

	group.Batch(events, keys.DefaultSettings())

	if events[0].Ref != first {
		t.Errorf("input slice was reordered: head is now %v, want %v", events[0].Ref, first)
	}
}
