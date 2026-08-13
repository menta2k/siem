package normalize

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/ingest"
	"github.com/menta2k/siem/internal/vendors"
)

// THE BUG THIS CATCHES, found in production after a green CI run. toRow copies the
// common-model event onto the stored row field by field, and a new field that is not
// added here is silently dropped between them — the adapter extracts it and the insert
// stores whatever it is handed, so both ends look correct in isolation.
//
// That is exactly how it escaped: the adapter test asserted on vendors.Event.JA4, and
// the storage test inserted a chdata.NormalizedEvent with JA4 already set. Neither
// crossed this seam, so 100% of Cloudflare events were written with an empty
// fingerprint while every test passed.
func TestToRowCarriesTheFingerprint(t *testing.T) {
	envelope := ingest.Envelope{
		TenantID:   uuid.New(),
		FeedID:     uuid.New(),
		EventID:    "cf-1",
		ReceivedAt: time.Unix(1786439000, 0).UTC(),
		Vendor:     vendors.Cloudflare,
	}
	event := vendors.Event{
		Vendor:    vendors.Cloudflare,
		EventTime: time.Unix(1786439000, 0).UTC(),
		Verdict:   vendors.VerdictAllowed,
		JA4:       "t13d1516h2_8daaf6152771_b0da82dd1658",
	}

	row := toRow(envelope, event)

	if row.JA4 != event.JA4 {
		t.Errorf("JA4 = %q, want %q — the fingerprint was dropped in translation",
			row.JA4, event.JA4)
	}
}

// Cloudflare sends the field on every record of a job that selects it but leaves it
// empty for roughly a quarter of them, so "no fingerprint" is an ordinary value and
// must round-trip as empty rather than as anything invented.
func TestToRowLeavesAnAbsentFingerprintEmpty(t *testing.T) {
	envelope := ingest.Envelope{
		TenantID:   uuid.New(),
		FeedID:     uuid.New(),
		EventID:    "cf-2",
		ReceivedAt: time.Unix(1786439000, 0).UTC(),
		Vendor:     vendors.Cloudflare,
	}
	event := vendors.Event{
		Vendor:    vendors.Cloudflare,
		EventTime: time.Unix(1786439000, 0).UTC(),
		Verdict:   vendors.VerdictAllowed,
	}

	if row := toRow(envelope, event); row.JA4 != "" {
		t.Errorf("JA4 = %q, want empty", row.JA4)
	}
}
