package correlate

import (
	"testing"

	"github.com/menta2k/siem/internal/correlate/group"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/vendors"
)

// geoEvent is a member reduced to the fields network attribution reads.
func geoEvent(vendor string, asn uint32, country string) group.Event {
	return group.Event{
		Ref: vendor,
		Row: chdata.NormalizedEvent{Vendor: vendor, ClientASN: asn, ClientCountry: country},
	}
}

func TestClientGeoPrefersTheVendorThatSeesTheClient(t *testing.T) {
	tests := []struct {
		name        string
		members     []group.Event
		wantASN     uint32
		wantCountry string
	}{
		{
			// The case this exists for. F5 is behind Cloudflare, so the network it
			// resolves is Cloudflare's edge; adopting it would attribute a Bulgarian
			// ISP's traffic to AS13335 on every four-vendor record.
			name: "cloudflare outranks an F5 report of the edge network",
			members: []group.Event{
				geoEvent(vendors.F5, 13335, "US"),
				geoEvent(vendors.Cloudflare, 8866, "BG"),
			},
			wantASN: 8866, wantCountry: "BG",
		},
		{
			// Order-independence is the point: the same members must produce the same
			// record whichever vendor's event was delivered first.
			name: "the same members in the other order agree",
			members: []group.Event{
				geoEvent(vendors.Cloudflare, 8866, "BG"),
				geoEvent(vendors.F5, 13335, "US"),
			},
			wantASN: 8866, wantCountry: "BG",
		},
		{
			// An edge ASN from a vendor behind the edge is dropped rather than demoted:
			// there is nothing better to fall back to and it is still wrong.
			name: "an F5 edge ASN is not used even when nobody else reports one",
			members: []group.Event{
				geoEvent(vendors.F5, 13335, "BG"),
			},
			wantASN: 0, wantCountry: "BG",
		},
		{
			// Cloudflare reporting its own network is a Worker subrequest, which really
			// did originate inside Cloudflare. Suppressing it would hide a fact.
			name: "cloudflare may report its own network",
			members: []group.Event{
				geoEvent(vendors.Cloudflare, 13335, "US"),
			},
			wantASN: 13335, wantCountry: "US",
		},
		{
			// Resolved independently: Cloudflare's country wins even though its ASN is
			// absent, and the ASN comes from the next vendor that has a usable one.
			name: "ASN and country come from different vendors when they have to",
			members: []group.Event{
				geoEvent(vendors.Cloudflare, 0, "BG"),
				geoEvent(vendors.DataDome, 29244, "DE"),
			},
			wantASN: 29244, wantCountry: "BG",
		},
		{
			// A vendor outside the trust order still contributes rather than being
			// silently ignored, so a new adapter is never worse than no adapter.
			name: "an unranked vendor is used as a last resort",
			members: []group.Event{
				geoEvent("newvendor", 64512, "FR"),
			},
			wantASN: 64512, wantCountry: "FR",
		},
		{
			name:    "no member reports anything",
			members: []group.Event{geoEvent(vendors.Nginx, 0, "")},
			wantASN: 0, wantCountry: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			asn, country := clientGeo(tc.members)

			if asn != tc.wantASN {
				t.Errorf("asn = %d, want %d", asn, tc.wantASN)
			}
			if country != tc.wantCountry {
				t.Errorf("country = %q, want %q", country, tc.wantCountry)
			}
		})
	}
}

func TestTrustASN(t *testing.T) {
	tests := []struct {
		vendor string
		asn    uint32
		want   bool
	}{
		{vendors.Cloudflare, 8866, true},
		{vendors.Cloudflare, 13335, true}, // its own network, genuinely
		{vendors.F5, 8866, true},          // a client network F5 got right
		{vendors.F5, 13335, false},        // the edge in front of it
		{vendors.DataDome, 13335, false},
		{vendors.Nginx, 0, false}, // absent, not wrong
	}

	for _, tc := range tests {
		if got := trustASN(tc.vendor, tc.asn); got != tc.want {
			t.Errorf("trustASN(%q, %d) = %v, want %v", tc.vendor, tc.asn, got, tc.want)
		}
	}
}
