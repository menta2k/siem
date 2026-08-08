package f5

import (
	"testing"

	"github.com/menta2k/siem/internal/vendors"
)

// normalizeFields runs the adapter over a bare field map.
func normalizeFields(t *testing.T, fields map[string]any) vendors.Event {
	t.Helper()

	fields["date_time"] = "2026-08-07 07:09:00"
	event, err := (&Adapter{}).Normalize(vendors.RawRecord{Fields: fields})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	return event
}

// THE REGRESSION THIS EXISTS FOR. support_id used to survive only in raw_extra, which
// migration 0006 dropped as duplicated storage — correct for fields the common model
// already held, wrong for this one, which had no column. After that it was reachable
// only by scanning the raw payload, which is not a search.
//
// It must be recorded on EVERY event, not just the minority where it also wins the join.
// CF-Ray is present on ~99% of ASM events and is preferred as the join key precisely
// because it is shared, so "record it only when it is the request id" would leave
// support_id invisible on almost all traffic — exactly the state this fixes.
func TestSupportIDIsRecordedEvenWhenTheRayWinsTheJoin(t *testing.T) {
	event := normalizeFields(t, map[string]any{
		"support_id": "2773644993865649202",
		"request":    cloudflareFrontedRequest,
	})

	if event.VendorRequestID != "a27533e76c55d101" {
		t.Errorf("VendorRequestID = %q, want the ray — the shared id must win the join",
			event.VendorRequestID)
	}
	if event.VendorEventID != "2773644993865649202" {
		t.Errorf("VendorEventID = %q, want the support id — it is invisible otherwise",
			event.VendorEventID)
	}
}

// The two identifiers must not be collapsed into one column. Storing support_id in
// vendor_request_id would either break the tier-1 join (no other vendor reports it) or
// lose the support reference.
func TestTheTwoIdentifiersStaySeparate(t *testing.T) {
	event := normalizeFields(t, map[string]any{
		"support_id": "12345",
		"request":    cloudflareFrontedRequest,
	})

	if event.VendorRequestID == event.VendorEventID {
		t.Errorf("both identifiers are %q — the join key and the support reference are "+
			"different values and must stay in different columns", event.VendorRequestID)
	}
}

// With no CDN in front, support_id is both the support reference AND the best available
// join key. Recording it twice is right: the columns mean different things, and the
// search for either has to find the event.
func TestSupportIDFillsBothWhenThereIsNoRay(t *testing.T) {
	event := normalizeFields(t, map[string]any{"support_id": "98765"})

	if event.VendorRequestID != "98765" {
		t.Errorf("VendorRequestID = %q, want the support id as the fallback join key",
			event.VendorRequestID)
	}
	if event.VendorEventID != "98765" {
		t.Errorf("VendorEventID = %q, want the support id", event.VendorEventID)
	}
}

// ASM's CEF encoding names it cs3. An event logged in that format must be searchable by
// the same value as one logged as key-value pairs.
func TestTheCEFAliasIsRecorded(t *testing.T) {
	event := normalizeFields(t, map[string]any{"cs3": "55555"})

	if event.VendorEventID != "55555" {
		t.Errorf("VendorEventID = %q, want 55555 from the cs3 alias", event.VendorEventID)
	}
}

// An event with no support_id must record an empty string rather than inventing one.
func TestAMissingSupportIDIsEmpty(t *testing.T) {
	event := normalizeFields(t, map[string]any{"request": cloudflareFrontedRequest})

	if event.VendorEventID != "" {
		t.Errorf("VendorEventID = %q, want empty", event.VendorEventID)
	}
}
