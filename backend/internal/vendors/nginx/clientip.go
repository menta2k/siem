package nginx

import (
	"net"
	"strings"

	"github.com/menta2k/siem/internal/vendors"
)

// resolveClientIP determines the address the request actually came from.
//
// THE TRAP HERE IS remote_addr. nginx sits behind F5, which sits behind Cloudflare, so
// $remote_addr is the BIG-IP's address on every single request. Logging it as the
// client would make every nginx event report one of a handful of load-balancer
// addresses — search for a real client would return nothing, the top-sources panel
// would show the infrastructure, and the IP-based heuristic join would collapse all
// traffic onto one apparent source.
//
// Trust decreases down this list, and it mirrors the F5 adapter deliberately: the two
// sit at different points in the same chain and must agree about who the client is, or
// the same request is attributed to two different addresses depending on which vendor
// reported it.
//
//  1. CF-Connecting-IP, which Cloudflare OVERWRITES rather than appends — unspoofable
//     behind Cloudflare, and the same value Cloudflare's own logs carry.
//  2. The forwarded chain walked from the RIGHT, stopping at the first routable public
//     address that is not the peer.
//  3. Nothing. The peer is NOT used as a fallback, which is where this diverges from
//     F5: there the peer may genuinely be the client, whereas here it is always the
//     load balancer, and recording it would be worse than recording no address at all.
func resolveClientIP(fields map[string]any) net.IP {
	if ip := vendors.RoutableClientIP(
		vendors.AsString(fields["cf_connecting_ip"]),
	); ip != nil {
		return ip
	}

	forwarded := vendors.AsString(fields["x_forwarded_for"])
	peer := vendors.AsString(fields["remote_addr"])
	return vendors.LastUntrustedHop(forwarded, peer)
}

// cloudflareRayID extracts the join key from the CF-Ray header nginx logged.
//
// This is the whole reason an nginx event can join the others. Cloudflare sets CF-Ray
// on the request it sends to the origin, F5 passes it through, and nginx sees the same
// value F5 did — the ORIGIN FETCH's ray. That is exactly the identifier F5 keys on, so
// an nginx event lands in the group F5 is already in, and reaches Cloudflare and
// DataDome through the bridge the origin-fetch row provides.
//
// The header carries the id and the edge datacentre — `a2753242eef8d0ef-SOF` — but
// Cloudflare's own logs record only the id, so the suffix has to go or nothing matches.
func cloudflareRayID(fields map[string]any) string {
	value := strings.TrimSpace(vendors.AsString(fields["cf_ray"]))
	if value == "" {
		return ""
	}
	id, _, _ := strings.Cut(value, "-")
	return strings.TrimSpace(id)
}
