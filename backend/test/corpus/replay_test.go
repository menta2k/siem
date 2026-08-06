//go:build corpus

// Package corpus_test measures correlation accuracy against ground truth.
//
// This is the only place SC-004 becomes a number rather than an aspiration:
//
//	join rate       ≥ 95% of multi-vendor requests correctly correlated
//	false-join rate <  1% of records containing events that do not belong together
//
// Both are needed. A join rate alone is trivially gamed by joining everything, which
// is why the corpus contains near-miss traps and why every record is checked for
// contamination as well as completeness.
package corpus_test

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/correlate/confidence"
	"github.com/menta2k/siem/internal/correlate/group"
	"github.com/menta2k/siem/internal/correlate/keys"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/normalize"
	"github.com/menta2k/siem/internal/vendors"
	"github.com/menta2k/siem/internal/vendors/cloudflare"
	"github.com/menta2k/siem/internal/vendors/datadome"
	"github.com/menta2k/siem/internal/vendors/f5"
	"github.com/menta2k/siem/test/corpus"
)

// SC-004 thresholds.
const (
	minJoinRate      = 0.95
	maxFalseJoinRate = 0.01
)

var corpusTenant = uuid.MustParse("00000000-0000-4000-8000-000000000001")

// record is one correlated group produced by replaying the corpus.
type record struct {
	events     []corpus.EventKey
	tier       keys.Tier
	confidence confidence.Level
	verdicts   []normalize.VendorVerdict
}

func (r record) vendorCount() int {
	seen := map[string]bool{}
	for _, e := range r.events {
		seen[e.Vendor] = true
	}
	return len(seen)
}

// indexByEvent maps every event to the record it landed in.
func indexByEvent(groups []record) map[string]*record {
	out := map[string]*record{}
	for i := range groups {
		for _, e := range groups[i].events {
			out[e.String()] = &groups[i]
		}
	}
	return out
}

// replay parses the corpus and runs the REAL grouping logic over it.
//
// Nothing about the join is reimplemented here. If the harness had its own copy of
// the tier resolution it would be measuring the harness, and the production defect
// this corpus exists to catch would pass with full marks.
func replay(t *testing.T, c corpus.Corpus, settings keys.Settings) []record {
	t.Helper()

	events := parseAll(t, c)
	in := make([]group.Event, 0, len(events))
	for _, e := range events {
		in = append(in, group.Event{Ref: e.key, Row: e.row})
	}

	groups := group.Batch(in, settings)

	out := make([]record, 0, len(groups))
	for _, g := range groups {
		r := record{tier: g.Key.Tier, confidence: g.Confidence}
		for _, m := range g.Members {
			r.events = append(r.events, m.Ref.(corpus.EventKey))
			r.verdicts = append(r.verdicts, normalize.VendorVerdict{
				Vendor: m.Row.Vendor, Verdict: m.Row.Verdict,
				Score: m.Row.Score, ScoreKind: m.Row.ScoreKind,
			})
		}
		out = append(out, r)
	}
	return out
}

type parsedEvent struct {
	key corpus.EventKey
	row chdata.NormalizedEvent
}

func parseAll(t *testing.T, c corpus.Corpus) []parsedEvent {
	t.Helper()

	var events []parsedEvent
	events = append(events, parseVendor(t, cloudflare.New(), c.Cloudflare, vendors.FormatNDJSON)...)
	events = append(events, parseVendor(t, f5.New(), c.F5, vendors.FormatJSON)...)
	events = append(events, parseVendor(t, datadome.New(), c.DataDome, vendors.FormatJSON)...)
	return events
}

func parseVendor(
	t *testing.T, adapter vendors.Adapter, payload []byte, format vendors.Format,
) []parsedEvent {
	t.Helper()

	records, err := adapter.Parse(payload, format)
	if err != nil {
		t.Fatalf("parse %s corpus: %v", adapter.Vendor(), err)
	}

	out := make([]parsedEvent, 0, len(records))
	for i, r := range records {
		event, err := adapter.Normalize(r)
		if err != nil {
			t.Fatalf("normalize %s record %d: %v", adapter.Vendor(), i, err)
		}
		out = append(out, parsedEvent{
			key: corpus.EventKey{Vendor: event.Vendor, RequestID: event.VendorRequestID},
			row: chdata.NormalizedEvent{
				TenantID: corpusTenant, EventID: event.VendorRequestID,
				EventTime: event.EventTime, Vendor: event.Vendor,
				VendorRequestID: event.VendorRequestID,
				ClientIP:        event.ClientIP, ClientIPShared: event.ClientIPShared,
				RequestHost: event.RequestHost, RequestPath: event.RequestPath,
				RequestMethod: event.RequestMethod,
				Verdict:       event.Verdict, Score: event.Score, ScoreKind: event.ScoreKind,
			},
		})
	}
	return out
}

// ---------------------------------------------------------------- the measurement

// TestCorrelationAccuracy is the SC-004 gate.
func TestCorrelationAccuracy(t *testing.T) {
	c, err := corpus.Build()
	if err != nil {
		t.Fatalf("build corpus: %v", err)
	}

	groups := replay(t, c, keys.DefaultSettings())

	// Index every event to the group it landed in.
	groupOf := indexByEvent(groups)

	var (
		multiVendorTotal int
		joined           int
		falseJoins       int
		missed           []string
		contaminated     []string
	)

	for _, expected := range c.Expected {
		if len(expected.Events) >= 2 {
			multiVendorTotal++
		}

		rec := groupOf[expected.Events[0].String()]
		if rec == nil {
			missed = append(missed, expected.Name+" (no record at all)")
			continue
		}

		if len(expected.Events) >= 2 {
			if containsAll(rec.events, expected.Events) {
				joined++
			} else {
				missed = append(missed, fmt.Sprintf("%s (got %v)", expected.Name, rec.events))
			}
		}

		// Contamination: an event the answer key says must NOT be here.
		for _, forbidden := range expected.MustNotJoin {
			if contains(rec.events, forbidden) {
				falseJoins++
				contaminated = append(contaminated,
					fmt.Sprintf("%s wrongly absorbed %s", expected.Name, forbidden))
			}
		}
	}

	joinRate := float64(joined) / float64(multiVendorTotal)
	falseJoinRate := float64(falseJoins) / float64(len(groups))

	t.Logf("join rate       %.2f%% (%d/%d multi-vendor requests)",
		joinRate*100, joined, multiVendorTotal)
	t.Logf("false-join rate %.2f%% (%d contaminated of %d records)",
		falseJoinRate*100, falseJoins, len(groups))

	if joinRate < minJoinRate {
		t.Errorf("join rate %.2f%% is below the %.0f%% target (SC-004)\nmissed:\n  %s",
			joinRate*100, minJoinRate*100, strings.Join(head(missed, 10), "\n  "))
	}
	if falseJoinRate > maxFalseJoinRate {
		t.Errorf("false-join rate %.2f%% exceeds the %.0f%% budget (SC-004)\ncontaminated:\n  %s",
			falseJoinRate*100, maxFalseJoinRate*100, strings.Join(head(contaminated, 10), "\n  "))
	}
}

// Tier 1 rests on an exact identifier, so it has no false-join budget at all: a
// tier-1 mistake is a defect, not a tuning problem.
func TestTierOneJoinsAreExact(t *testing.T) {
	c, err := corpus.Build()
	if err != nil {
		t.Fatalf("build corpus: %v", err)
	}
	groups := replay(t, c, keys.DefaultSettings())

	groupOf := indexByEvent(groups)

	for _, expected := range c.Expected {
		if expected.Tier != 1 {
			continue
		}
		rec := groupOf[expected.Events[0].String()]
		if rec == nil {
			t.Errorf("%s produced no record", expected.Name)
			continue
		}
		if !containsAll(rec.events, expected.Events) || len(rec.events) != len(expected.Events) {
			t.Errorf("%s: got %v, want exactly %v — a shared request id must join "+
				"exactly, with nothing extra", expected.Name, rec.events, expected.Events)
		}
		if rec.confidence != confidence.High {
			t.Errorf("%s confidence = %q, want high for an exact identifier match",
				expected.Name, rec.confidence)
		}
	}
}

// NAT traffic must join at LOW confidence. Joining it at medium would assert a
// certainty the platform does not have, and is how a false-join budget gets spent.
func TestNATJoinsAreMarkedLowConfidence(t *testing.T) {
	c, err := corpus.Build()
	if err != nil {
		t.Fatalf("build corpus: %v", err)
	}
	groups := replay(t, c, keys.DefaultSettings())

	groupOf := indexByEvent(groups)

	for _, expected := range c.Expected {
		if expected.Confidence != "low" {
			continue
		}
		rec := groupOf[expected.Events[0].String()]
		if rec == nil {
			t.Errorf("%s produced no record", expected.Name)
			continue
		}
		if rec.confidence != confidence.Low {
			t.Errorf("%s confidence = %q, want low — a shared client address means the "+
				"join is probable, not certain", expected.Name, rec.confidence)
		}
	}
}

// Near misses are the trap: same client, host, path and method, but far apart in
// time. A correlator that widens its window to lift the join rate joins these.
func TestNearMissesAreNotJoined(t *testing.T) {
	c, err := corpus.Build()
	if err != nil {
		t.Fatalf("build corpus: %v", err)
	}
	groups := replay(t, c, keys.DefaultSettings())

	groupOf := indexByEvent(groups)

	for _, expected := range c.Expected {
		if len(expected.MustNotJoin) == 0 {
			continue
		}
		rec := groupOf[expected.Events[0].String()]
		if rec == nil {
			continue
		}
		for _, forbidden := range expected.MustNotJoin {
			if contains(rec.events, forbidden) {
				t.Errorf("%s absorbed %s — these are 25 seconds apart and are two "+
					"separate requests", expected.Name, forbidden)
			}
		}
	}
}

// Single-vendor traffic is normal. It must produce records, not be discarded, and
// must never be reported as a disagreement.
func TestSingleVendorEventsProduceRecords(t *testing.T) {
	c, err := corpus.Build()
	if err != nil {
		t.Fatalf("build corpus: %v", err)
	}
	groups := replay(t, c, keys.DefaultSettings())

	groupOf := indexByEvent(groups)

	for _, solo := range c.SingleVendor {
		rec := groupOf[solo.String()]
		if rec == nil {
			t.Errorf("%s produced no record; single-vendor traffic must not be discarded", solo)
			continue
		}
		if rec.vendorCount() != 1 {
			t.Errorf("%s was joined with another vendor: %v", solo, rec.events)
		}

		classification := normalize.Classify(rec.verdicts, normalize.DefaultScoreConflictThreshold)
		if classification.Disagreement {
			t.Errorf("%s was flagged as a disagreement; one vendor cannot disagree "+
				"with itself", solo)
		}
	}
}

// Disagreement classification must match the answer key exactly — this is the
// product's headline output, and a miscategorised conflict is worse than none.
func TestDisagreementClassification(t *testing.T) {
	c, err := corpus.Build()
	if err != nil {
		t.Fatalf("build corpus: %v", err)
	}
	groups := replay(t, c, keys.DefaultSettings())

	groupOf := indexByEvent(groups)

	for _, expected := range c.Expected {
		if expected.Disagreement == "" || len(expected.Events) < 2 {
			continue
		}
		rec := groupOf[expected.Events[0].String()]
		if rec == nil || !containsAll(rec.events, expected.Events) {
			continue // a missed join is measured by the accuracy test, not here
		}

		got := normalize.Classify(rec.verdicts, normalize.DefaultScoreConflictThreshold)
		if string(got.Kind) != expected.Disagreement {
			t.Errorf("%s classified as %q, want %q",
				expected.Name, got.Kind, expected.Disagreement)
		}
	}
}

// ---------------------------------------------------------------- helpers

func contains(haystack []corpus.EventKey, needle corpus.EventKey) bool {
	for _, e := range haystack {
		if e == needle {
			return true
		}
	}
	return false
}

func containsAll(haystack, needles []corpus.EventKey) bool {
	for _, n := range needles {
		if !contains(haystack, n) {
			return false
		}
	}
	return true
}

func head(items []string, n int) []string {
	sort.Strings(items)
	if len(items) <= n {
		return items
	}
	return append(items[:n:n], fmt.Sprintf("... and %d more", len(items)-n))
}
