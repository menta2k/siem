// Package keys derives the join keys that decide which events describe the same
// request.
//
// This is where SC-004 is won or lost. Two tiers, tried in order:
//
//	Tier 1 — an exact shared vendor request id. No false-join risk: two vendors
//	         reporting the same identifier are describing the same request, whatever
//	         their clocks say. Joins at high confidence.
//	Tier 2 — a heuristic over client IP, host, path and method within a time window.
//	         This is the entire risk surface, which is why ambiguity degrades the
//	         confidence rather than being papered over.
package keys

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/vendors"
)

// Tier identifies which mechanism produced a key.
type Tier uint8

// The join tiers.
const (
	// TierNone means no key could be derived and the event can only stand alone.
	TierNone Tier = 0
	// TierExact is a shared vendor request id.
	TierExact Tier = 1
	// TierHeuristic is the IP/host/path/method/time match.
	TierHeuristic Tier = 2
)

// Signal names the evidence a key rests on, recorded on the correlated record so an
// analyst can see WHY two events were joined (FR-015).
type Signal string

// The join signals.
const (
	SignalVendorRequestID  Signal = "vendor_request_id"
	SignalIPHostPathMethod Signal = "ip_host_path_method"
	SignalTimeWindow       Signal = "time_window"
)

// Key is a derived join key for one event.
type Key struct {
	// Value is what events are grouped by. Two events with the same Value and the
	// same Tier are candidates for one correlated record.
	Value string
	Tier  Tier
	// Signals records the evidence, in the order it contributed.
	Signals []Signal
	// WindowStart is the correlation window this event falls into. Zero for tier 1,
	// which does not depend on time at all.
	WindowStart time.Time
	// Ambiguous marks a key derived from a shared client address, where many distinct
	// clients plausibly produce the same key.
	Ambiguous bool
}

// Settings are the per-tenant correlation parameters.
type Settings struct {
	// Window is how far apart two events may be and still describe one request.
	Window time.Duration
	// LatenessBound is how late an event may arrive and still amend a record.
	LatenessBound time.Duration
}

// Total is how long a window's state must remain addressable: the window itself plus
// the period in which a late event may still amend it.
func (s Settings) Total() time.Duration { return s.Window + s.LatenessBound }

// DefaultSettings matches the platform defaults in the data model.
func DefaultSettings() Settings {
	return Settings{Window: 5 * time.Second, LatenessBound: 15 * time.Minute}
}

// Candidates holds BOTH keys an event can be joined on.
//
// Returning both is not redundancy — it is the correction to an assumption that looks
// obvious and is wrong. "Use the exact id, otherwise the heuristic" fails for the
// common case: every vendor stamps its OWN request id, so an exact key almost always
// exists and almost never matches another vendor's. Choosing it up front strands each
// event in a group of one and the heuristic never runs at all.
//
// The exact key is therefore a HYPOTHESIS: it wins only if some other vendor actually
// produced the same id. The correlator resolves that by grouping on Exact first and
// falling back to Heuristic for any group that stayed alone.
type Candidates struct {
	// Exact is the tier-1 key, empty when the vendor supplied no request id.
	Exact Key
	// Heuristic is the tier-2 key, always derived so the fallback is available.
	Heuristic Key
}

// HasExact reports whether a tier-1 hypothesis exists.
func (c Candidates) HasExact() bool { return c.Exact.Tier == TierExact }

// Derive returns both join keys for an event.
func Derive(event chdata.NormalizedEvent, settings Settings) Candidates {
	candidates := Candidates{Heuristic: heuristicKey(event, settings)}
	if exact, ok := exactKey(event); ok {
		candidates.Exact = exact
	}
	return candidates
}

// ExactKeyValue formats a tier-1 key.
//
// Exported because the correlation closer has to address an exact bucket built by a
// DIFFERENT event — a partner that landed in another time window is reachable only
// through the identifier it shares — and reconstructing the format by hand at the call
// site is how the two copies quietly drift apart.
//
// The tenant is part of the key because two tenants can legitimately see the same
// identifier — they may share a Cloudflare zone — and their requests must never be
// joined into one record.
func ExactKeyValue(tenantID uuid.UUID, requestID string) string {
	return fmt.Sprintf("t1|%s|%s", tenantID, strings.TrimSpace(requestID))
}

// exactKey builds a tier-1 key from the vendor's request identifier.
func exactKey(event chdata.NormalizedEvent) (Key, bool) {
	requestID := strings.TrimSpace(event.VendorRequestID)
	if requestID == "" {
		return Key{}, false
	}
	return Key{
		Value:   ExactKeyValue(event.TenantID, requestID),
		Tier:    TierExact,
		Signals: []Signal{SignalVendorRequestID},
	}, true
}

// heuristicKey builds a tier-2 key from the request's observable shape and time.
func heuristicKey(event chdata.NormalizedEvent, settings Settings) Key {
	if event.RequestHost == "" || event.ClientIP == nil {
		// Without a client and a host there is nothing to match on. The event still
		// becomes a valid single-vendor record; it simply cannot attract a partner.
		return Key{Tier: TierNone}
	}

	window := WindowStart(event.EventTime, settings.Window)

	// Path normalization is the single most correctness-sensitive step here: two
	// vendors reporting the same URI differently (case, trailing slash, doubled
	// slashes) would otherwise silently fail to join.
	normalizedPath := vendors.NormalizePath(event.RequestPath)

	value := fmt.Sprintf("t2|%s|%s|%s|%s|%s|%d",
		event.TenantID,
		event.ClientIP.String(),
		strings.ToLower(event.RequestHost),
		normalizedPath,
		strings.ToUpper(event.RequestMethod),
		window.Unix())

	return Key{
		Value:       value,
		Tier:        TierHeuristic,
		Signals:     []Signal{SignalIPHostPathMethod, SignalTimeWindow},
		WindowStart: window,
		// A shared address means many clients produce this same key. The join is
		// probably still right, but the platform cannot be sure — and saying so is
		// what keeps the false-join rate inside its budget.
		Ambiguous: event.ClientIPShared,
	}
}

// WindowStart truncates a timestamp to its correlation window.
//
// Truncation, not a sliding window: a sliding window would need every event to be
// compared against every other, which cannot hold at 15k events/sec. The cost is a
// boundary effect — two events 1ms apart can land either side of a truncation —
// which AdjacentWindows exists to recover.
func WindowStart(eventTime time.Time, window time.Duration) time.Time {
	if window <= 0 {
		window = time.Second
	}
	return eventTime.UTC().Truncate(window)
}

// AdjacentWindows returns the keys an event should ALSO be matched against.
//
// Without this, two events milliseconds apart that straddle a window boundary would
// never join — the single largest source of missed joins in a truncating scheme, and
// exactly the sort of silent failure the SC-004 target is meant to catch.
func AdjacentWindows(key Key, settings Settings) []string {
	if key.Tier != TierHeuristic || key.Value == "" {
		return nil
	}

	// The key ends with the window's Unix timestamp; only that suffix changes.
	prefix := key.Value[:strings.LastIndex(key.Value, "|")+1]
	window := settings.Window
	if window <= 0 {
		window = time.Second
	}

	return []string{
		fmt.Sprintf("%s%d", prefix, key.WindowStart.Add(-window).Unix()),
		fmt.Sprintf("%s%d", prefix, key.WindowStart.Add(window).Unix()),
	}
}

// CorrelationID derives the deterministic record id for a key.
//
// Determinism is what makes a late arrival an AMENDMENT rather than a duplicate: the
// same key and window always resolve to the same record.
func CorrelationID(key Key) uuid.UUID {
	return deterministicUUID(key.Value)
}
