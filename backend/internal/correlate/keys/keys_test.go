package keys_test

import (
	"net"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/correlate/keys"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
)

var (
	tenantA = uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	tenantB = uuid.MustParse("00000000-0000-4000-8000-00000000000b")
	base    = time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
)

func row(mutate ...func(*chdata.NormalizedEvent)) chdata.NormalizedEvent {
	e := chdata.NormalizedEvent{
		TenantID: tenantA, Vendor: "cloudflare", EventTime: base,
		ClientIP: net.ParseIP("203.0.113.10"), RequestHost: "shop.example.com",
		RequestPath: "/checkout", RequestMethod: "GET",
	}
	for _, m := range mutate {
		m(&e)
	}
	return e
}

func TestExactKeyIsDerivedFromTheVendorRequestID(t *testing.T) {
	got := keys.Derive(row(func(e *chdata.NormalizedEvent) {
		e.VendorRequestID = "ray-1"
	}), keys.DefaultSettings())

	if !got.HasExact() {
		t.Fatal("no exact key derived from a present vendor request id")
	}
	if got.Exact.Tier != keys.TierExact {
		t.Errorf("tier = %v, want exact", got.Exact.Tier)
	}
	if len(got.Exact.Signals) != 1 || got.Exact.Signals[0] != keys.SignalVendorRequestID {
		t.Errorf("signals = %v, want [vendor_request_id]", got.Exact.Signals)
	}
}

func TestBlankRequestIDYieldsNoExactKey(t *testing.T) {
	for _, id := range []string{"", "   ", "\t"} {
		got := keys.Derive(row(func(e *chdata.NormalizedEvent) {
			e.VendorRequestID = id
		}), keys.DefaultSettings())
		if got.HasExact() {
			t.Errorf("request id %q produced an exact key; whitespace is not an identifier "+
				"and joining on it would merge every id-less event in the tenant", id)
		}
	}
}

// Both keys are always returned. Returning only the exact one when it exists is the
// bug that made tier 2 unreachable: every vendor stamps its own id, so the fallback
// must stay available.
func TestHeuristicKeyIsDerivedEvenWhenAnExactKeyExists(t *testing.T) {
	got := keys.Derive(row(func(e *chdata.NormalizedEvent) {
		e.VendorRequestID = "ray-1"
	}), keys.DefaultSettings())

	if got.Heuristic.Tier != keys.TierHeuristic {
		t.Fatalf("heuristic tier = %v, want heuristic — the fallback must remain available",
			got.Heuristic.Tier)
	}
}

// Two tenants can legitimately observe the same identifier — a shared Cloudflare zone,
// for one — and their requests must never merge into a single record.
func TestKeysAreScopedToTheTenant(t *testing.T) {
	a := keys.Derive(row(func(e *chdata.NormalizedEvent) { e.VendorRequestID = "ray-1" }),
		keys.DefaultSettings())
	b := keys.Derive(row(func(e *chdata.NormalizedEvent) {
		e.TenantID, e.VendorRequestID = tenantB, "ray-1"
	}), keys.DefaultSettings())

	if a.Exact.Value == b.Exact.Value {
		t.Error("two tenants sharing a vendor request id produced the same exact key")
	}
	if a.Heuristic.Value == b.Heuristic.Value {
		t.Error("two tenants produced the same heuristic key")
	}
}

// Vendors report the same URI differently. Any difference that survives normalization
// is a silent missed join, so these all have to collapse to one key.
func TestHeuristicKeyIsStableAcrossPathAndHostSpelling(t *testing.T) {
	want := keys.Derive(row(), keys.DefaultSettings()).Heuristic.Value

	variants := []struct {
		name string
		path string
		host string
	}{
		{"trailing slash", "/checkout/", "shop.example.com"},
		{"upper case path", "/CHECKOUT", "shop.example.com"},
		{"repeated slashes", "//checkout", "shop.example.com"},
		{"mixed", "//CheckOut/", "shop.example.com"},
		{"upper case host", "/checkout", "SHOP.EXAMPLE.COM"},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			got := keys.Derive(row(func(e *chdata.NormalizedEvent) {
				e.RequestPath, e.RequestHost = v.path, v.host
			}), keys.DefaultSettings()).Heuristic.Value
			if got != want {
				t.Errorf("key = %q, want %q", got, want)
			}
		})
	}
}

func TestMethodCaseDoesNotAffectTheKey(t *testing.T) {
	upper := keys.Derive(row(), keys.DefaultSettings()).Heuristic.Value
	lower := keys.Derive(row(func(e *chdata.NormalizedEvent) {
		e.RequestMethod = "get"
	}), keys.DefaultSettings()).Heuristic.Value

	if upper != lower {
		t.Errorf("method case changed the key: %q vs %q", upper, lower)
	}
}

// Different requests must not collide. Each of these is a genuinely distinct request.
func TestDistinctRequestsProduceDistinctKeys(t *testing.T) {
	baseline := keys.Derive(row(), keys.DefaultSettings()).Heuristic.Value

	cases := map[string]func(*chdata.NormalizedEvent){
		"different path":   func(e *chdata.NormalizedEvent) { e.RequestPath = "/cart" },
		"different method": func(e *chdata.NormalizedEvent) { e.RequestMethod = "POST" },
		"different host":   func(e *chdata.NormalizedEvent) { e.RequestHost = "api.example.com" },
		"different client": func(e *chdata.NormalizedEvent) { e.ClientIP = net.ParseIP("203.0.113.11") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if got := keys.Derive(row(mutate), keys.DefaultSettings()).Heuristic.Value; got == baseline {
				t.Errorf("%s collided with the baseline key %q", name, baseline)
			}
		})
	}
}

func TestMissingClientOrHostYieldsNoHeuristicKey(t *testing.T) {
	cases := map[string]func(*chdata.NormalizedEvent){
		"no client ip": func(e *chdata.NormalizedEvent) { e.ClientIP = nil },
		"no host":      func(e *chdata.NormalizedEvent) { e.RequestHost = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			got := keys.Derive(row(mutate), keys.DefaultSettings()).Heuristic
			if got.Tier != keys.TierNone {
				t.Errorf("tier = %v, want none — there is nothing to match on", got.Tier)
			}
		})
	}
}

func TestSharedClientAddressMarksTheKeyAmbiguous(t *testing.T) {
	got := keys.Derive(row(func(e *chdata.NormalizedEvent) {
		e.ClientIPShared = true
	}), keys.DefaultSettings()).Heuristic

	if !got.Ambiguous {
		t.Error("a shared client address did not mark the key ambiguous")
	}
}

func TestWindowStartTruncatesToTheWindow(t *testing.T) {
	settings := keys.DefaultSettings()
	within := keys.Derive(row(func(e *chdata.NormalizedEvent) {
		e.EventTime = base.Add(settings.Window - time.Millisecond)
	}), settings).Heuristic
	beyond := keys.Derive(row(func(e *chdata.NormalizedEvent) {
		e.EventTime = base.Add(settings.Window)
	}), settings).Heuristic

	if within.Value != keys.Derive(row(), settings).Heuristic.Value {
		t.Error("an event inside the window landed in a different bucket")
	}
	if beyond.Value == within.Value {
		t.Error("an event a full window later shared a bucket")
	}
}

func TestAdjacentWindowsBracketTheKey(t *testing.T) {
	settings := keys.DefaultSettings()
	key := keys.Derive(row(), settings).Heuristic

	adjacent := keys.AdjacentWindows(key, settings)
	if len(adjacent) != 2 {
		t.Fatalf("got %d adjacent windows, want 2 (previous and next)", len(adjacent))
	}
	for _, value := range adjacent {
		if value == key.Value {
			t.Error("an adjacent window equals the key's own window")
		}
	}

	previous := keys.Derive(row(func(e *chdata.NormalizedEvent) {
		e.EventTime = base.Add(-settings.Window)
	}), settings).Heuristic.Value
	next := keys.Derive(row(func(e *chdata.NormalizedEvent) {
		e.EventTime = base.Add(settings.Window)
	}), settings).Heuristic.Value

	if adjacent[0] != previous || adjacent[1] != next {
		t.Errorf("adjacent = %v, want [%q %q]", adjacent, previous, next)
	}
}

func TestAdjacentWindowsAreEmptyForExactKeys(t *testing.T) {
	key := keys.Derive(row(func(e *chdata.NormalizedEvent) {
		e.VendorRequestID = "ray-1"
	}), keys.DefaultSettings()).Exact

	if got := keys.AdjacentWindows(key, keys.DefaultSettings()); got != nil {
		t.Errorf("got %v, want nil — an exact match does not depend on time at all", got)
	}
}

// Determinism is what makes a late arrival an amendment rather than a duplicate.
func TestCorrelationIDIsDeterministic(t *testing.T) {
	key := keys.Derive(row(), keys.DefaultSettings()).Heuristic
	// Recomputed from a separately derived key, not from the same value twice: the
	// property under test is that derivation itself is reproducible.
	same := keys.Derive(row(), keys.DefaultSettings()).Heuristic
	if keys.CorrelationID(key) != keys.CorrelationID(same) {
		t.Fatal("the same key produced two different correlation ids")
	}

	other := keys.Derive(row(func(e *chdata.NormalizedEvent) {
		e.RequestPath = "/cart"
	}), keys.DefaultSettings()).Heuristic
	if keys.CorrelationID(key) == keys.CorrelationID(other) {
		t.Error("two different keys produced the same correlation id")
	}
}
