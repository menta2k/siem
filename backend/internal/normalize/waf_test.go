package normalize

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/ingest"
	"github.com/menta2k/siem/internal/vendors"
)

// THE SEAM, AND THE FAILURE MODE IT GUARDS. toRow copies the common-model event onto
// the stored row field by field, so a new field is dropped between an adapter that
// extracted it and an insert that would have stored it — both ends correct in
// isolation, nothing written. That is exactly how JA4 shipped to production writing
// empty fingerprints on 100% of events with a green build.
//
// Asserting every field in one test rather than one per field is deliberate: the
// mistake is forgetting a line, and a test that checks only the fields somebody
// remembered cannot catch it.
func TestToRowCarriesTheWholeWAFDetail(t *testing.T) {
	envelope := ingest.Envelope{
		TenantID:   uuid.New(),
		FeedID:     uuid.New(),
		EventID:    "cf-waf-1",
		ReceivedAt: time.Unix(1786439000, 0).UTC(),
		Vendor:     vendors.Cloudflare,
	}
	event := vendors.Event{
		Vendor:    vendors.Cloudflare,
		EventTime: time.Unix(1786439000, 0).UTC(),
		Verdict:   vendors.VerdictMonitored,
		WAF: vendors.WAFDetail{
			AttackScore: 2,
			SQLiScore:   4,
			XSSScore:    98,
			RCEScore:    98,
			Action:      "log",
			Source:      "firewallManaged",
		},
	}

	row := toRow(envelope, event)

	checks := []struct {
		field string
		got   any
		want  any
	}{
		{"WAFAttackScore", row.WAFAttackScore, uint8(2)},
		{"WAFSQLiScore", row.WAFSQLiScore, uint8(4)},
		{"WAFXSSScore", row.WAFXSSScore, uint8(98)},
		{"WAFRCEScore", row.WAFRCEScore, uint8(98)},
		{"WAFAction", row.WAFAction, "log"},
		{"WAFSource", row.WAFSource, "firewallManaged"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v — dropped in translation", c.field, c.got, c.want)
		}
	}
}

// A vendor that reports no WAF detail must round-trip as zero rather than as anything
// invented. 0 is the "not scored" value the 1-99 range leaves free, and on this
// INVERTED scale a fabricated 0 would read as the strongest possible attack signal.
func TestToRowLeavesAnUnscoredEventAtZero(t *testing.T) {
	envelope := ingest.Envelope{
		TenantID:   uuid.New(),
		FeedID:     uuid.New(),
		EventID:    "f5-1",
		ReceivedAt: time.Unix(1786439000, 0).UTC(),
		Vendor:     vendors.F5,
	}
	event := vendors.Event{
		Vendor:    vendors.F5,
		EventTime: time.Unix(1786439000, 0).UTC(),
		Verdict:   vendors.VerdictBlocked,
	}

	row := toRow(envelope, event)

	if row.WAFAttackScore != 0 || row.WAFAction != "" || row.WAFSource != "" {
		t.Errorf("an unscored event carried WAF detail: score=%d action=%q source=%q",
			row.WAFAttackScore, row.WAFAction, row.WAFSource)
	}
}
