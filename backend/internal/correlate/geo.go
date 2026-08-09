package correlate

import (
	"github.com/menta2k/siem/internal/correlate/group"
	"github.com/menta2k/siem/internal/vendors"
)

// Where the client's network attribution may be taken from, in decreasing order of
// trust. This is NOT the arrival order and must not be: the members of one record
// describe the same request seen at different points in the path, and only some of
// those points can see the client's own network.
//
//	Cloudflare terminates the client's TCP connection at the edge. Its ClientASN and
//	ClientCountry are resolved from the same address it logs as ClientIP, so they
//	describe the client by construction.
//
//	DataDome is handed the client address by the integration and resolves geo from it,
//	which is a step removed but still the client's address.
//
//	F5 and nginx sit BEHIND the CDN. Whatever their platform resolves describes the hop
//	they can see, and behind Cloudflare that hop is a Cloudflare edge address — so their
//	network attribution names Cloudflare's AS13335, not the client's ISP. F5 recovers the
//	real client IP from CF-Connecting-IP (see f5.resolveClientIP), but the appliance's own
//	geo fields are computed before that and are not re-derived from it.
var geoTrustOrder = []string{vendors.Cloudflare, vendors.DataDome, vendors.F5, vendors.Nginx}

// edgeASNs are networks that belong to a CDN or reverse proxy rather than to a client.
//
// A vendor sitting behind one of these reports the proxy's network as the client's. The
// vendor that OWNS the network is exempt: when Cloudflare reports AS13335 the request
// genuinely originated inside Cloudflare — a Worker subrequest is the ordinary case —
// and that is a fact about the traffic, not a misattribution.
//
// A short list on purpose. It exists to stop a specific, observed contamination, not to
// classify the internet; an unknown proxy's ASN is caught by the trust order above,
// which is what does the real work.
var edgeASNs = map[uint32]string{
	13335: vendors.Cloudflare,
}

// clientGeo picks the network attribution for a correlated record.
//
// Taking the first member that happened to report a value — which is what this used to
// do, in arrival order — lets whichever vendor's event landed first decide, so the same
// request could be attributed to the client's ISP or to the CDN in front of it depending
// on delivery timing. That is the kind of field an anomaly rule reads later, and a
// number that changes with delivery order is worse than no number at all.
//
// ASN and country are resolved INDEPENDENTLY: a vendor may report one without the other,
// and a record should take the best available of each rather than tying them together.
func clientGeo(members []group.Event) (asn uint32, country string) {
	asn = mostTrusted(members, func(m group.Event) (uint32, bool) {
		return m.Row.ClientASN, trustASN(m.Row.Vendor, m.Row.ClientASN)
	})
	country = mostTrusted(members, func(m group.Event) (string, bool) {
		return m.Row.ClientCountry, m.Row.ClientCountry != ""
	})
	return asn, country
}

// mostTrusted returns the value from the highest-ranked vendor that reports a usable one.
//
// Falls back to ANY member once the ranked vendors are exhausted: a vendor the trust
// order does not name still saw something, and dropping it would mean a newly added
// adapter silently contributes no geo at all until someone remembers to edit the list.
func mostTrusted[T any](members []group.Event, value func(group.Event) (T, bool)) T {
	for _, vendor := range geoTrustOrder {
		for _, m := range members {
			if m.Row.Vendor != vendor {
				continue
			}
			if v, ok := value(m); ok {
				return v
			}
		}
	}
	for _, m := range members {
		if v, ok := value(m); ok {
			return v
		}
	}

	var zero T
	return zero
}

// trustASN reports whether a vendor's ASN describes the client rather than the proxy in
// front of it.
func trustASN(vendor string, asn uint32) bool {
	if asn == 0 {
		return false
	}
	owner, isEdge := edgeASNs[asn]
	return !isEdge || owner == vendor
}
