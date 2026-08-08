// Package group resolves which events belong to the same request.
//
// It exists because the two-tier design has a trap in it. Read literally — "join on
// the shared vendor request id, otherwise fall back to the heuristic" — it sounds
// like a per-event decision, and implementing it that way makes tier 2 dead code:
// every vendor stamps its own request id, so an exact key nearly always exists and
// nearly never matches anyone else's. Each event lands in a group of one and the
// heuristic never runs. Measured against the labelled corpus that reads as a 28.6%
// join rate against a 95% target.
//
// The rule that actually works: an exact key is a HYPOTHESIS, confirmed only when a
// SECOND VENDOR independently reported the same identifier. Confirmed hypotheses win
// outright — nothing about timing can undermine a shared id. Everything else falls
// through to the heuristic, which is where the false-join risk lives and where
// confidence gets degraded accordingly.
package group

import (
	"sort"
	"strconv"

	"github.com/menta2k/siem/internal/correlate/confidence"
	"github.com/menta2k/siem/internal/correlate/keys"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
)

// Event pairs a normalized row with a caller-supplied handle.
//
// Ref is opaque here: the worker passes the Kafka record, the accuracy harness passes
// a corpus label. Grouping never inspects it, so the same logic serves both.
type Event struct {
	Ref any
	Row chdata.NormalizedEvent
}

// Group is one correlated request.
type Group struct {
	// Key is the join key the group formed on.
	Key keys.Key
	// Members are the events that make up the request.
	Members []Event
	// CandidateCount is the largest number of events a SINGLE vendor contributed.
	// More than one means several of that vendor's events competed for the slot and
	// the chosen partner may be the wrong one — which is what makes a join ambiguous,
	// as opposed to merely involving several vendors.
	CandidateCount int
	// Confidence is the scored trust in the join.
	Confidence confidence.Level
}

// Vendors returns the distinct vendors that contributed.
func (g Group) Vendors() []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(g.Members))
	for _, m := range g.Members {
		if !seen[m.Row.Vendor] {
			seen[m.Row.Vendor] = true
			out = append(out, m.Row.Vendor)
		}
	}
	sort.Strings(out)
	return out
}

// Batch groups a set of events that fall inside one correlation horizon.
//
// Batch is deterministic: events are ordered by time before any window merging, so
// replaying the same input always produces the same groups and therefore the same
// correlation ids. Without that, a late arrival could not find the record it amends.
func Batch(events []Event, settings keys.Settings) []Group {
	ordered := sortEvents(events)

	confirmed, exactOf := confirmExact(ordered)
	groups := groupsFromExact(ordered, confirmed, exactOf)
	groups = append(groups, groupsFromHeuristic(ordered, confirmed, exactOf, settings)...)

	for i := range groups {
		score(&groups[i])
	}
	return groups
}

// sortEvents returns a time-ordered copy, leaving the caller's slice untouched.
func sortEvents(events []Event) []Event {
	ordered := make([]Event, len(events))
	copy(ordered, events)
	sort.SliceStable(ordered, func(i, j int) bool {
		if !ordered[i].Row.EventTime.Equal(ordered[j].Row.EventTime) {
			return ordered[i].Row.EventTime.Before(ordered[j].Row.EventTime)
		}
		return ordered[i].Row.Vendor < ordered[j].Row.Vendor
	})
	return ordered
}

// confirmExact finds the exact identities that MORE THAN ONE VENDOR reported.
//
// The distinct-vendor test is the whole point. Counting events instead would confirm
// an identity that one vendor happened to emit twice — a retry or a duplicate delivery
// — and a "cross-vendor" record containing one vendor twice is worse than no record.
//
// Events are grouped by CONNECTED COMPONENT over their identifiers, not by a single
// key. A Worker-protected request is logged by Cloudflare three times under three
// different rays, and no one identifier reaches every vendor: F5 sees the origin
// fetch's ray, DataDome is reachable only through the client-facing one, and the origin
// fetch carries both. Keying on one identifier each puts those events in two separate
// groups holding two verdicts apiece, which is exactly the "never three verdicts"
// symptom this resolves.
func confirmExact(events []Event) (map[string]bool, map[int]keys.Key) {
	union := newUnionFind()
	identifiersOf := make(map[int][]string, len(events))

	for i, event := range events {
		ids := keys.Identifiers(event.Row)
		if len(ids) == 0 {
			continue
		}
		identifiersOf[i] = ids
		for _, id := range ids[1:] {
			union.link(ids[0], id)
		}
	}

	// The component's canonical identifier is its SMALLEST, chosen so the same set of
	// events always yields the same correlation id however they were discovered.
	vendorsPerRoot := map[string]map[string]bool{}
	exactOf := make(map[int]keys.Key, len(events))
	for i, ids := range identifiersOf {
		root := union.find(ids[0])
		exactOf[i] = keys.Key{
			Value:   root,
			Tier:    keys.TierExact,
			Signals: []keys.Signal{keys.SignalVendorRequestID},
		}
		if vendorsPerRoot[root] == nil {
			vendorsPerRoot[root] = map[string]bool{}
		}
		vendorsPerRoot[root][events[i].Row.Vendor] = true
	}

	confirmed := map[string]bool{}
	for value, seen := range vendorsPerRoot {
		if len(seen) > 1 {
			confirmed[value] = true
		}
	}
	return confirmed, exactOf
}

// unionFind groups identifiers that belong to the same request.
//
// The canonical representative is always the lexicographically smallest identifier in
// the component, which makes the resulting group key a pure function of its membership
// rather than of the order events happened to arrive in. Determinism matters here for
// the same reason it does everywhere else in correlation: a late arrival recomputes the
// key to find the record it amends, and a key that shifted would create a second record
// instead.
type unionFind struct{ parent map[string]string }

func newUnionFind() *unionFind { return &unionFind{parent: map[string]string{}} }

func (u *unionFind) find(value string) string {
	root, seen := u.parent[value]
	if !seen {
		u.parent[value] = value
		return value
	}
	if root == value {
		return value
	}
	resolved := u.find(root)
	u.parent[value] = resolved // path compression
	return resolved
}

func (u *unionFind) link(a, b string) {
	rootA, rootB := u.find(a), u.find(b)
	if rootA == rootB {
		return
	}
	// Smaller value wins, so the representative never depends on link order.
	if rootB < rootA {
		rootA, rootB = rootB, rootA
	}
	u.parent[rootB] = rootA
}

// groupsFromExact builds the tier-1 groups.
func groupsFromExact(events []Event, confirmed map[string]bool, exactOf map[int]keys.Key) []Group {
	byKey := map[string]*Group{}
	var order []string

	for i, event := range events {
		key, ok := exactOf[i]
		if !ok || !confirmed[key.Value] {
			continue
		}
		existing, seen := byKey[key.Value]
		if !seen {
			existing = &Group{Key: key}
			byKey[key.Value] = existing
			order = append(order, key.Value)
		}
		existing.Members = append(existing.Members, event)
	}

	out := make([]Group, 0, len(order))
	for _, value := range order {
		out = append(out, *byKey[value])
	}
	return out
}

// groupsFromHeuristic builds the tier-2 groups from everything tier 1 did not claim.
func groupsFromHeuristic(
	events []Event, confirmed map[string]bool, exactOf map[int]keys.Key, settings keys.Settings,
) []Group {
	byKey := map[string]*Group{}
	var order []string

	for i, event := range events {
		if key, ok := exactOf[i]; ok && confirmed[key.Value] {
			continue // already correlated on an exact identifier
		}

		key := keys.Derive(event.Row, settings).Heuristic
		if key.Tier == keys.TierNone {
			// No client address or host: the event cannot attract a partner. It still
			// becomes a record — a single-vendor observation is a valid answer, and
			// dropping it would lose the only evidence the platform has for it.
			out := Group{Key: key, Members: []Event{event}}
			byKey[soloKey(i)] = &out
			order = append(order, soloKey(i))
			continue
		}

		value := resolveWindow(key, byKey, settings)
		existing, seen := byKey[value]
		if !seen {
			existing = &Group{Key: key}
			byKey[value] = existing
			order = append(order, value)
		}
		existing.Members = append(existing.Members, event)
		// Ambiguity is a property of the group, not of the event that opened it: one
		// member on a shared address makes the whole join uncertain.
		existing.Key.Ambiguous = existing.Key.Ambiguous || key.Ambiguous
	}

	out := make([]Group, 0, len(order))
	for _, value := range order {
		out = append(out, *byKey[value])
	}
	return out
}

// resolveWindow returns the key an event should join, folding in a neighbouring
// window when one is already open.
//
// Window truncation is what keeps grouping linear, but it means two events a
// millisecond apart can land either side of a boundary. Checking the neighbours
// recovers those; without it, the boundary straddle is a silent missed join.
func resolveWindow(key keys.Key, open map[string]*Group, settings keys.Settings) string {
	if _, exists := open[key.Value]; exists {
		return key.Value
	}
	for _, adjacent := range keys.AdjacentWindows(key, settings) {
		if _, exists := open[adjacent]; exists {
			return adjacent
		}
	}
	return key.Value
}

// soloKey names a bucket that only ever holds one event, so it must not collide
// with any other event's bucket.
func soloKey(index int) string { return "solo|" + strconv.Itoa(index) }

// score fills in the derived fields once a group's membership is final.
func score(g *Group) {
	perVendor := map[string]int{}
	for _, m := range g.Members {
		perVendor[m.Row.Vendor]++
	}
	g.CandidateCount = 1
	for _, count := range perVendor {
		if count > g.CandidateCount {
			g.CandidateCount = count
		}
	}
	g.Confidence = confidence.Score(confidence.Input{
		Tier:           g.Key.Tier,
		Ambiguous:      g.Key.Ambiguous,
		CandidateCount: g.CandidateCount,
		VendorCount:    len(perVendor),
	})
}
