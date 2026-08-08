package normalize_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/normalize"
	"github.com/menta2k/siem/internal/vendors"
)

var identityFeed = uuid.MustParse("00000000-0000-4000-8000-0000000000fe")

// THE PRODUCTION DATA LOSS THIS PREVENTS.
//
// A vendor request id identifies a REQUEST, not a record of one. Deriving the DataDome
// verdict from Cloudflare's log made one feed produce events for two vendors, so the
// DataDome event and the Cloudflare event of the same request legitimately carried the
// same request id — and, without the vendor in the hash, the same event id. The ingest
// deduper read the second as a redelivery and dropped it: suppressed duplicates went
// from 0 per minute to between 2,300 and 4,900, roughly a quarter of all traffic,
// silently discarding real user requests.
func TestTwoVendorsSharingARequestIDGetDifferentIdentities(t *testing.T) {
	raw := []byte(`{"RayID":"a27fe3039e6f1216"}`)

	parent := normalize.EventIDFor(identityFeed, vendors.Event{
		Vendor: vendors.Cloudflare, VendorRequestID: "a27fe3039e6f1216",
	}, raw)
	derived := normalize.EventIDFor(identityFeed, vendors.Event{
		Vendor: vendors.DataDome, VendorRequestID: "a27fe3039e6f1216",
	}, raw)

	if parent == derived {
		t.Fatalf("both vendors produced event id %s — the deduper will drop one of them "+
			"as a redelivery and a real request is lost", parent)
	}
}

// The identity must still be stable across a redelivery, which is what makes a vendor
// retry safe in the first place.
func TestIdentityIsStableForTheSameVendorAndRequest(t *testing.T) {
	event := vendors.Event{Vendor: vendors.Cloudflare, VendorRequestID: "ray-1"}

	first := normalize.EventIDFor(identityFeed, event, []byte(`{"a":1}`))
	// Different bytes, same vendor and request id: a redelivery whose formatting
	// changed must still be recognised as the same event.
	second := normalize.EventIDFor(identityFeed, event, []byte(`{"a": 1}`))

	if first != second {
		t.Errorf("identity changed across a redelivery: %s vs %s", first, second)
	}
}

// THE TRAP IN THE FIX ITSELF. When a vendor supplies no request id the identity falls
// back to hashing the raw bytes. Passing the vendor name alone in that case would give
// every id-less event of that vendor ONE identity, collapsing them all into a single
// row — a far worse failure than the one being fixed.
func TestEventsWithNoRequestIDStayDistinct(t *testing.T) {
	event := vendors.Event{Vendor: vendors.Cloudflare}

	first := normalize.EventIDFor(identityFeed, event, []byte(`{"a":1}`))
	second := normalize.EventIDFor(identityFeed, event, []byte(`{"a":2}`))

	if first == second {
		t.Fatal("two different id-less events share one identity — every event without " +
			"a request id would collapse into a single row")
	}
}

// Whitespace-only request ids must be treated as absent, not as a shared identity.
func TestBlankRequestIDsFallBackToTheRawBytes(t *testing.T) {
	for _, blank := range []string{"", "   ", "\t"} {
		event := vendors.Event{Vendor: vendors.F5, VendorRequestID: blank}

		first := normalize.EventIDFor(identityFeed, event, []byte(`{"a":1}`))
		second := normalize.EventIDFor(identityFeed, event, []byte(`{"a":2}`))
		if first == second {
			t.Errorf("request id %q collapsed two distinct events into one identity", blank)
		}
	}
}

// Two tenants sharing a Cloudflare zone see the same ray. They must not collide.
func TestDifferentFeedsStillDoNotCollide(t *testing.T) {
	event := vendors.Event{Vendor: vendors.Cloudflare, VendorRequestID: "ray-1"}
	other := uuid.MustParse("00000000-0000-4000-8000-0000000000ff")

	if normalize.EventIDFor(identityFeed, event, nil) == normalize.EventIDFor(other, event, nil) {
		t.Error("two feeds produced the same identity for the same request id")
	}
}
