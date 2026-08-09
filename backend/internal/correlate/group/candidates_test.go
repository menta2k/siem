package group_test

import (
	"net"
	"testing"
	"time"

	"github.com/menta2k/siem/internal/correlate/group"
	"github.com/menta2k/siem/internal/correlate/keys"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
)

// candidateEvent builds one member of a request.
func candidateEvent(vendor, requestID, linked, path string, offset time.Duration) group.Event {
	return group.Event{Row: chdata.NormalizedEvent{
		TenantID: hopTenant, Vendor: vendor, EventID: vendor + requestID + path,
		VendorRequestID: requestID, LinkedRequestID: linked,
		EventTime: hopBase.Add(offset), Verdict: "allowed",
		ClientIP: net.ParseIP("203.0.113.10"), RequestHost: "www.jobs.bg",
		RequestPath: path, RequestMethod: "GET",
	}}
}

// THE FALSE ALARM THIS REMOVES. candidate_count drives the console's warning that
// "events from a single vendor competed for this join, so the partner chosen here may
// be the wrong one" — and it was firing on 48,446 of 50,552 exact joins in production,
// 95.8%, which is very nearly every four-vendor record an analyst could open.
//
// The cause is that a Worker-protected request legitimately produces TWO Cloudflare
// rows: the client-facing request and the fetch to the origin. Both belong in the
// record, and a shared ray is what put them there. Nothing competed.
func TestAnExactJoinHasNoCompetingCandidates(t *testing.T) {
	// The real shape: Cloudflare twice, plus DataDome, F5 and nginx.
	events := []group.Event{
		candidateEvent("cloudflare", "P", "", "/job/1", 0),
		candidateEvent("datadome", "P", "", "/job/1", time.Second),
		candidateEvent("cloudflare", "Y", "P", "/job/1", time.Second),
		candidateEvent("f5", "Y", "", "/job/1", 2*time.Second),
		candidateEvent("nginx", "Y", "", "/job/1", 2*time.Second),
	}

	groups := group.Batch(events, keys.DefaultSettings())
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(groups))
	}
	if groups[0].Key.Tier != keys.TierExact {
		t.Fatalf("tier = %v, want exact", groups[0].Key.Tier)
	}

	if got := groups[0].CandidateCount; got != 1 {
		t.Errorf("CandidateCount = %d, want 1 — an identifier every member carries is "+
			"what joined them, so nothing competed and the console must not warn that "+
			"the partner may be wrong", got)
	}
}

// THE SIGNAL THAT MUST SURVIVE. A heuristic join matches on client, host, path, method
// and a time window, so a vendor appearing twice really is two plausible partners and
// the platform really did pick one. Production shows that count running to 76, and it
// is the only thing telling an analyst the join is a guess.
func TestAHeuristicJoinStillCountsCompetingCandidates(t *testing.T) {
	// No request ids at all, so the exact tier cannot claim these and they fall to the
	// heuristic — where two events from one vendor genuinely compete.
	events := []group.Event{
		candidateEvent("cloudflare", "", "", "/job/1", 0),
		candidateEvent("cloudflare", "", "", "/job/1", time.Second),
		candidateEvent("f5", "", "", "/job/1", time.Second),
	}
	// Distinct event ids, or window membership collapses them as one redelivery.
	events[1].Row.EventID = "cloudflare-second"

	groups := group.Batch(events, keys.DefaultSettings())
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(groups))
	}
	if groups[0].Key.Tier != keys.TierHeuristic {
		t.Fatalf("tier = %v, want heuristic", groups[0].Key.Tier)
	}

	if got := groups[0].CandidateCount; got != 2 {
		t.Errorf("CandidateCount = %d, want 2 — two of one vendor's events matched by "+
			"shape and time, so one of them was chosen and may be the wrong one", got)
	}
}

// Confidence must not move. The scorer already returns high for an exact join before it
// reads CandidateCount, so this change corrects what is REPORTED without altering how
// much any record is trusted.
func TestConfidenceIsUnchangedByTheCandidateFix(t *testing.T) {
	exact := group.Batch([]group.Event{
		candidateEvent("cloudflare", "P", "", "/job/1", 0),
		candidateEvent("cloudflare", "Y", "P", "/job/1", time.Second),
		candidateEvent("f5", "Y", "", "/job/1", 2*time.Second),
	}, keys.DefaultSettings())

	if len(exact) != 1 {
		t.Fatalf("got %d groups, want 1", len(exact))
	}
	if exact[0].Confidence != "high" {
		t.Errorf("confidence = %q, want high — an exact join is trusted on its "+
			"identifier, not on how many rows a vendor contributed", exact[0].Confidence)
	}
}

// A single-vendor record involved no join at all, so it cannot have competing
// candidates whatever tier it lands in.
func TestASingleVendorRecordHasOneCandidate(t *testing.T) {
	groups := group.Batch([]group.Event{
		candidateEvent("f5", "solo-ray", "", "/job/1", 0),
	}, keys.DefaultSettings())

	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(groups))
	}
	if got := groups[0].CandidateCount; got != 1 {
		t.Errorf("CandidateCount = %d, want 1 — nothing was joined", got)
	}
}
