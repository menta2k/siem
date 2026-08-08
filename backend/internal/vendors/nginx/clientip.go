package nginx

import (
	"net"
	"strings"

	"github.com/menta2k/siem/internal/vendors"
)

// resolveClientIP determines the address the request actually came from.
//
// The order below is not the F5 adapter's, and the difference is deliberate — measured
// against real traffic from this deployment.
//
//  1. CF-Connecting-IP, which Cloudflare OVERWRITES rather than appends, so it cannot
//     be spoofed and matches Cloudflare's own logs by construction.
//
//  2. $remote_addr, but ONLY when it is a routable public address.
//
//     This is the one that matters. Cloudflare's Pseudo IPv4 feature synthesises an
//     address in reserved 240.0.0.0/4 when an IPv6 client reaches an IPv4 origin, and
//     on live traffic that was 36% of requests — 2,671 of 7,352 in ten minutes. Those
//     are correctly refused by step 1 as unroutable, and the real IPv6 client is sitting
//     in $remote_addr, put there by nginx's realip module.
//
//     Requiring it to be ROUTABLE is what makes this safe where realip is not
//     configured: $remote_addr is then the load balancer, whose LAN address is private
//     and therefore rejected, so the value is used only when it is plausibly a client.
//
// X-Forwarded-For is deliberately NOT consulted. Behind a CDN the rightmost hop is the
// CDN's own edge — walking the chain from the right returns Cloudflare's address on
// every request, which is exactly the bug this replaces: 708 events attributed to
// 162.158.60.172. Reading it from the LEFT is worse, since the header is append-only
// and its first entry is whatever the client typed.
//
// When neither source yields an address the event carries none. That is the honest
// answer, and far better than recording infrastructure as the client: the address
// drives search, the top-sources panel and the IP-based heuristic join, so a wrong one
// is worse than a missing one.
func resolveClientIP(fields map[string]any) net.IP {
	for _, name := range []string{"cf_connecting_ip", "remote_addr"} {
		if ip := vendors.RoutableClientIP(vendors.AsString(fields[name])); ip != nil {
			return ip
		}
	}
	return nil
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
