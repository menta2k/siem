package correlate

import (
	"net"
	"testing"
	"time"

	"github.com/google/uuid"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/vendors"
)

var mergeBase = time.Date(2026, 8, 10, 5, 30, 0, 0, time.UTC)

// storedFourVendor is the record an analyst already has: every vendor's view of one
// request, agreed.
func storedFourVendor() chdata.CorrelatedRequest {
	return chdata.CorrelatedRequest{
		CorrelationID:  uuid.MustParse("00000000-0000-4000-8000-00000000000c"),
		WindowStart:    mergeBase,
		FirstEventTime: mergeBase,
		LastEventTime:  mergeBase.Add(2 * time.Second),
		Vendors:        []string{vendors.Cloudflare, vendors.F5, vendors.Nginx},
		VendorCount:    3,
		EventIDs:       []string{"cf-1", "f5-1", "nginx-1"},
		ClientIP:       net.ParseIP("203.0.113.10"),
		ClientCountry:  "BG",
		ClientASN:      8866,
		RequestHost:    "shop.example.com",
		RequestPath:    "/checkout",
		RequestMethod:  "GET",
		Verdicts: map[string]string{
			vendors.Cloudflare: vendors.VerdictAllowed,
			vendors.F5:         vendors.VerdictAllowed,
			vendors.Nginx:      vendors.VerdictAllowed,
		},
		RuleIDs:         map[string]string{vendors.F5: "waf-1"},
		Scores:          map[string]float32{},
		JoinSignals:     []string{"vendor_request_id"},
		JoinTier:        1,
		Confidence:      "high",
		CombinedOutcome: vendors.VerdictAllowed,
	}
}

// lateSingleVendor is what a closing produces when the window state has expired and only
// the late event refilled it.
func lateSingleVendor() chdata.CorrelatedRequest {
	return chdata.CorrelatedRequest{
		CorrelationID:  storedFourVendor().CorrelationID,
		WindowStart:    mergeBase,
		FirstEventTime: mergeBase.Add(5 * time.Second),
		LastEventTime:  mergeBase.Add(5 * time.Second),
		Vendors:        []string{vendors.DataDome},
		VendorCount:    1,
		EventIDs:       []string{"dd-1"},
		Verdicts:       map[string]string{vendors.DataDome: vendors.VerdictBlocked},
		RuleIDs:        map[string]string{},
		Scores:         map[string]float32{},
		JoinSignals:    []string{"vendor_request_id"},
		JoinTier:       1,
		Confidence:     "high",
	}
}

// THE FAILURE THIS PREVENTS. A correlation id outlives the window state behind it, so an
// event arriving past the lateness bound refills an empty window — and the amendment
// built from it alone used to REPLACE the stored record, turning three vendors into one.
func TestAnAmendmentAddsToTheStoredRecordRatherThanReplacingIt(t *testing.T) {
	merged := mergeRecords(storedFourVendor(), lateSingleVendor(), 0.8)

	if merged.VendorCount != 4 {
		t.Errorf("vendor_count = %d, want 4 — the late vendor must be ADDED to the "+
			"three already stored, not substituted for them", merged.VendorCount)
	}
	if len(merged.EventIDs) != 4 {
		t.Errorf("event_ids = %v, want all four", merged.EventIDs)
	}
	for _, vendor := range []string{
		vendors.Cloudflare, vendors.F5, vendors.Nginx, vendors.DataDome,
	} {
		if _, ok := merged.Verdicts[vendor]; !ok {
			t.Errorf("%s lost its verdict in the merge: %+v", vendor, merged.Verdicts)
		}
	}
}

// The merged record must re-derive its headline. A vendor added late can turn agreement
// into a disagreement, and that is the single field an analyst acts on.
func TestAMergeRecomputesTheDisagreement(t *testing.T) {
	stored := storedFourVendor() // everyone allowed
	if stored.HasDisagreement {
		t.Fatal("the fixture should start in agreement")
	}

	merged := mergeRecords(stored, lateSingleVendor(), 0.8) // DataDome blocked

	if !merged.HasDisagreement {
		t.Error("allow-vs-block was not flagged after the blocking vendor arrived late")
	}
	if merged.CombinedOutcome != vendors.VerdictBlocked {
		t.Errorf("combined_outcome = %q, want the most restrictive verdict",
			merged.CombinedOutcome)
	}
}

// The span has to cover both closings, or the record understates how far apart the
// vendors observed the request.
func TestAMergeWidensTheObservedSpan(t *testing.T) {
	stored := storedFourVendor()
	merged := mergeRecords(stored, lateSingleVendor(), 0.8)

	if !merged.FirstEventTime.Equal(stored.FirstEventTime) {
		t.Errorf("first_event_time = %v, want the earlier of the two", merged.FirstEventTime)
	}
	if !merged.LastEventTime.Equal(mergeBase.Add(5 * time.Second)) {
		t.Errorf("last_event_time = %v, want the later of the two", merged.LastEventTime)
	}
}

// A late arrival must not blank fields it simply does not carry. A DataDome-derived row
// has no client address at all by design.
func TestAMergeKeepsFieldsTheLateArrivalDoesNotCarry(t *testing.T) {
	merged := mergeRecords(storedFourVendor(), lateSingleVendor(), 0.8)

	if merged.ClientIP == nil || merged.ClientIP.String() != "203.0.113.10" {
		t.Errorf("client ip = %v, want the stored one", merged.ClientIP)
	}
	if merged.ClientASN != 8866 || merged.ClientCountry != "BG" {
		t.Errorf("client network lost: asn=%d country=%q",
			merged.ClientASN, merged.ClientCountry)
	}
	if merged.RequestHost != "shop.example.com" || merged.RequestPath != "/checkout" {
		t.Errorf("request shape lost: %s %s", merged.RequestHost, merged.RequestPath)
	}
}

// The join is as good as its strongest evidence. An exact partner arriving late upgrades
// a heuristic record, and a heuristic one must never downgrade an exact record.
func TestAMergeKeepsTheStrongerJoin(t *testing.T) {
	tests := []struct {
		name       string
		storedTier uint8
		freshTier  uint8
		wantTier   uint8
	}{
		{"exact stored, heuristic late", 1, 2, 1},
		{"heuristic stored, exact late", 2, 1, 1},
		{"both exact", 1, 1, 1},
		{"no join stored", 0, 2, 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stored := storedFourVendor()
			stored.JoinTier, stored.Confidence = tc.storedTier, "high"
			fresh := lateSingleVendor()
			fresh.JoinTier, fresh.Confidence = tc.freshTier, "medium"

			if got := mergeRecords(stored, fresh, 0.8).JoinTier; got != tc.wantTier {
				t.Errorf("join_tier = %d, want %d", got, tc.wantTier)
			}
		})
	}
}

// Redelivery must not inflate the record: the same event arriving twice is one event.
func TestAMergeDoesNotDuplicateSharedEvents(t *testing.T) {
	stored := storedFourVendor()
	fresh := lateSingleVendor()
	fresh.EventIDs = []string{"cf-1", "dd-1"} // cf-1 is already stored
	fresh.Vendors = []string{vendors.Cloudflare, vendors.DataDome}

	merged := mergeRecords(stored, fresh, 0.8)

	if len(merged.EventIDs) != 4 {
		t.Errorf("event_ids = %v, want four distinct", merged.EventIDs)
	}
	if int(merged.VendorCount) != len(merged.Vendors) || merged.VendorCount != 4 {
		t.Errorf("vendor_count = %d over vendors %v", merged.VendorCount, merged.Vendors)
	}
}
