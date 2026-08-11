package normalize

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/ingest"
	"github.com/menta2k/siem/internal/vendors"
)

// A row records BOTH vendors, and for a DataDome verdict they differ.
//
// The event is attributed to datadome by the adapter, while the bytes arrived on a
// Cloudflare feed and are stored in raw_events under cloudflare. Storing only the first
// forced every reader to infer the second, and four of them inferred it wrongly: the
// payload lookup matched nothing, the field rebuild used the wrong adapter, a correlated
// record looked short of a raw event, and the lookup could not seek the sort key.
//
// The assertion is on the PAIR rather than on source_vendor alone, because the failure
// mode is the two collapsing into one value again.
func TestARowRecordsBothTheAttributedAndTheDeliveringVendor(t *testing.T) {
	envelope := ingest.Envelope{
		TenantID:   uuid.New(),
		FeedID:     uuid.New(),
		EventID:    "cf-worker-1",
		ReceivedAt: time.Unix(1786439000, 0).UTC(),
		// The FEED is Cloudflare's: that is what delivered the bytes.
		Vendor: vendors.Cloudflare,
	}
	// The ADAPTER attributed the event to DataDome.
	event := vendors.Event{
		Vendor:    vendors.DataDome,
		EventTime: time.Unix(1786439000, 0).UTC(),
		Verdict:   vendors.VerdictAllowed,
	}

	row := toRow(envelope, event)

	if row.Vendor != vendors.DataDome {
		t.Errorf("vendor = %q, want datadome — the attribution the adapter made",
			row.Vendor)
	}
	if row.SourceVendor != vendors.Cloudflare {
		t.Errorf("source_vendor = %q, want cloudflare — the feed the bytes arrived on. "+
			"Without it every reader has to guess, which is how the raw payload, the "+
			"parsed fields and the sort-key seek all broke at once",
			row.SourceVendor)
	}
	if row.Vendor == row.SourceVendor {
		t.Error("the two vendors collapsed into one value; that is the bug this column " +
			"exists to prevent")
	}
}

// Where they genuinely agree — an ordinary Cloudflare request, an F5 log — both carry the
// same value, and that is not a special case to be optimised away.
func TestTheVendorsAgreeWhenTheFeedIsAlsoTheSource(t *testing.T) {
	for _, vendor := range []string{vendors.Cloudflare, vendors.F5, vendors.Nginx} {
		t.Run(vendor, func(t *testing.T) {
			row := toRow(
				ingest.Envelope{Vendor: vendor, EventID: "e1"},
				vendors.Event{Vendor: vendor},
			)
			if row.Vendor != vendor || row.SourceVendor != vendor {
				t.Errorf("vendor=%q source_vendor=%q, want both %q",
					row.Vendor, row.SourceVendor, vendor)
			}
		})
	}
}
