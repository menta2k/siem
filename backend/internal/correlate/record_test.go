package correlate

import (
	"net"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/correlate/confidence"
	"github.com/menta2k/siem/internal/correlate/group"
	"github.com/menta2k/siem/internal/correlate/keys"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/normalize"
	"github.com/menta2k/siem/internal/vendors"
)

// An internal test: buildRecord is unexported because it is an implementation detail
// of the closer, but it decides what an analyst actually sees, so it is worth pinning
// directly rather than only through the integration suite.

var (
	recTenant = uuid.MustParse("00000000-0000-4000-8000-0000000000e1")
	recBase   = time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
)

func recEvent(
	id, vendor, verdict string, at time.Time, mutate ...func(*chdata.NormalizedEvent),
) group.Event {
	row := chdata.NormalizedEvent{
		TenantID: recTenant, EventID: id, Vendor: vendor, EventTime: at,
		ClientIP: net.ParseIP("203.0.113.10"), ClientCountry: "DE", ClientASN: 64512,
		RequestHost: "shop.example.com", RequestPath: "/checkout", RequestMethod: "GET",
		Verdict: verdict,
	}
	for _, m := range mutate {
		m(&row)
	}
	return group.Event{Ref: id, Row: row}
}

func TestRecordCarriesEveryVendorsView(t *testing.T) {
	score := float32(0.9)

	g := group.Group{
		Key: keys.Key{
			Tier: keys.TierHeuristic, WindowStart: recBase,
			Signals: []keys.Signal{keys.SignalIPHostPathMethod, keys.SignalTimeWindow},
		},
		Members: []group.Event{
			recEvent("cf-1", vendors.Cloudflare, vendors.VerdictAllowed, recBase,
				func(e *chdata.NormalizedEvent) {
					e.Score, e.ScoreKind = &score, vendors.ScoreKindBot
				}),
			recEvent("f5-1", vendors.F5, vendors.VerdictBlocked, recBase.Add(time.Second),
				func(e *chdata.NormalizedEvent) { e.RuleID = "waf-sqli" }),
		},
		CandidateCount: 1,
		Confidence:     confidence.Medium,
	}

	record := buildRecord(recTenant, g, normalize.DefaultScoreConflictThreshold)

	if record.VendorCount != 2 {
		t.Errorf("vendor_count = %d, want 2", record.VendorCount)
	}
	if len(record.EventIDs) != 2 {
		t.Errorf("event_ids = %v, want both", record.EventIDs)
	}

	// Per-vendor maps are the point of the record: flattening them would say the
	// vendors disagreed without saying which said what.
	if record.Verdicts[vendors.Cloudflare] != vendors.VerdictAllowed {
		t.Errorf("cloudflare verdict = %q", record.Verdicts[vendors.Cloudflare])
	}
	if record.Verdicts[vendors.F5] != vendors.VerdictBlocked {
		t.Errorf("f5 verdict = %q", record.Verdicts[vendors.F5])
	}
	if record.RuleIDs[vendors.F5] != "waf-sqli" {
		t.Errorf("f5 rule = %q, want waf-sqli", record.RuleIDs[vendors.F5])
	}
	if record.Scores[vendors.Cloudflare] != score {
		t.Errorf("cloudflare score = %v, want %v", record.Scores[vendors.Cloudflare], score)
	}

	if !record.HasDisagreement {
		t.Error("allow vs block was not flagged as a disagreement")
	}
	if record.CombinedOutcome != vendors.VerdictBlocked {
		t.Errorf("combined_outcome = %q, want the most restrictive", record.CombinedOutcome)
	}
}

// A vendor that does not score requests must not appear to have rated every one of
// them as human.
func TestAnAbsentScoreIsOmittedNotZeroed(t *testing.T) {
	g := group.Group{
		Key:     keys.Key{Tier: keys.TierHeuristic, WindowStart: recBase},
		Members: []group.Event{recEvent("f5-1", vendors.F5, vendors.VerdictBlocked, recBase)},
	}

	record := buildRecord(recTenant, g, normalize.DefaultScoreConflictThreshold)

	if _, present := record.Scores[vendors.F5]; present {
		t.Error("a vendor with no score was recorded as scoring 0")
	}
}

// A zero window_start would file the record under 1970 and the retention TTL would
// drop it on the next pass.
func TestTierOneRecordsGetAWindowStart(t *testing.T) {
	g := group.Group{
		// Tier 1 carries no window: an exact identifier does not depend on time.
		Key: keys.Key{Tier: keys.TierExact, Signals: []keys.Signal{keys.SignalVendorRequestID}},
		Members: []group.Event{
			recEvent("cf-1", vendors.Cloudflare, vendors.VerdictAllowed, recBase),
		},
	}

	record := buildRecord(recTenant, g, normalize.DefaultScoreConflictThreshold)

	if record.WindowStart.IsZero() {
		t.Fatal("a tier-1 record got a zero window_start; retention would drop it")
	}
	if record.WindowStart.Year() != recBase.Year() {
		t.Errorf("window_start = %v, want it near the event time", record.WindowStart)
	}
}

// Vendors differ in what they log. Taking every field from one designated member would
// leave holes the others could fill.
func TestRequestShapeIsFilledFromWhicheverVendorReportedIt(t *testing.T) {
	g := group.Group{
		Key: keys.Key{Tier: keys.TierHeuristic, WindowStart: recBase},
		Members: []group.Event{
			recEvent("cf-1", vendors.Cloudflare, vendors.VerdictAllowed, recBase,
				func(e *chdata.NormalizedEvent) {
					e.RequestHost, e.ClientCountry = "", ""
				}),
			recEvent("f5-1", vendors.F5, vendors.VerdictAllowed, recBase.Add(time.Second)),
		},
	}

	record := buildRecord(recTenant, g, normalize.DefaultScoreConflictThreshold)

	if record.RequestHost != "shop.example.com" {
		t.Errorf("host = %q, want it taken from the vendor that reported one",
			record.RequestHost)
	}
	if record.ClientCountry != "DE" {
		t.Errorf("country = %q, want it taken from the vendor that reported one",
			record.ClientCountry)
	}
}

// One member on a shared address makes the whole join uncertain.
func TestSharedAddressIsSticky(t *testing.T) {
	g := group.Group{
		Key: keys.Key{Tier: keys.TierHeuristic, WindowStart: recBase},
		Members: []group.Event{
			recEvent("cf-1", vendors.Cloudflare, vendors.VerdictAllowed, recBase),
			recEvent("f5-1", vendors.F5, vendors.VerdictAllowed, recBase,
				func(e *chdata.NormalizedEvent) { e.ClientIPShared = true }),
		},
	}

	record := buildRecord(recTenant, g, normalize.DefaultScoreConflictThreshold)

	if !record.ClientIPShared {
		t.Error("one member on a shared address did not mark the record shared")
	}
}

// First and last must bound the members regardless of the order they arrived in.
func TestEventTimesBoundTheMembers(t *testing.T) {
	g := group.Group{
		Key: keys.Key{Tier: keys.TierHeuristic, WindowStart: recBase},
		Members: []group.Event{
			recEvent("late", vendors.F5, vendors.VerdictAllowed, recBase.Add(5*time.Second)),
			recEvent("early", vendors.Cloudflare, vendors.VerdictAllowed, recBase),
		},
	}

	record := buildRecord(recTenant, g, normalize.DefaultScoreConflictThreshold)

	if !record.FirstEventTime.Equal(recBase) {
		t.Errorf("first = %v, want the earliest member", record.FirstEventTime)
	}
	if !record.LastEventTime.Equal(recBase.Add(5 * time.Second)) {
		t.Errorf("last = %v, want the latest member", record.LastEventTime)
	}
}

// The columns are UInt8. A window with 300 members must read as "many", not as zero.
func TestCountsSaturateRatherThanWrap(t *testing.T) {
	members := make([]group.Event, 0, 300)
	for i := range 300 {
		members = append(members, recEvent(
			"e"+string(rune('a'+i%26))+string(rune('a'+i/26)),
			vendors.Cloudflare, vendors.VerdictAllowed, recBase))
	}

	g := group.Group{
		Key:     keys.Key{Tier: keys.TierHeuristic, WindowStart: recBase},
		Members: members, CandidateCount: 300,
	}

	record := buildRecord(recTenant, g, normalize.DefaultScoreConflictThreshold)

	if record.CandidateCount != 255 {
		t.Errorf("candidate_count = %d, want it saturated at 255", record.CandidateCount)
	}
}

// The round trip through the window store must not lose the fields a record is built
// from, or an amendment rebuilds a poorer record than the original.
func TestMemberProjectionRoundTrips(t *testing.T) {
	score := float32(0.42)
	original := chdata.NormalizedEvent{
		TenantID: recTenant, EventID: "e1", Vendor: vendors.Cloudflare,
		EventTime: recBase, VendorRequestID: "ray-1",
		ClientIP: net.ParseIP("203.0.113.10"), ClientIPShared: true,
		ClientASN: 64512, ClientCountry: "DE",
		RequestHost: "shop.example.com", RequestPath: "/checkout", RequestMethod: "GET",
		Verdict: vendors.VerdictBlocked, RuleID: "waf-1",
		RuleIDs: []string{"waf-1"}, Score: &score, ScoreKind: vendors.ScoreKindBot,
	}

	restored := toRow(recTenant, toMember(original))

	if restored.EventID != original.EventID || restored.Vendor != original.Vendor {
		t.Error("identity was lost in the projection")
	}
	if restored.ClientIP.String() != original.ClientIP.String() {
		t.Errorf("client ip = %v, want %v", restored.ClientIP, original.ClientIP)
	}
	if !restored.ClientIPShared {
		t.Error("the shared-address flag was lost")
	}
	if restored.Score == nil || *restored.Score != score {
		t.Errorf("score = %v, want %v", restored.Score, score)
	}
	if restored.RuleID != original.RuleID || restored.ScoreKind != original.ScoreKind {
		t.Error("verdict detail was lost in the projection")
	}
}
