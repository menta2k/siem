package f5

import (
	"net"

	"github.com/menta2k/siem/internal/vendors"
)

// resolveClientIP determines the address the request actually came from.
//
// X-Forwarded-For is APPEND-ONLY. Each proxy adds the peer it received the request from,
// so whatever the client put in the header survives untouched at the FRONT of the chain.
// Reading the leftmost entry therefore reads an attacker-supplied string, and on live
// traffic it did: 27.7% of F5 events carried an address in reserved 240.0.0.0/4 that no
// host can hold, while Cloudflare's log of the same requests named the real client.
//
// That is not cosmetic. This address drives search, the top-sources panel and the IP-based
// heuristic join, so trusting the header lets an attacker attribute their traffic to any
// address they like and break its correlation at the same time.
//
// The order below is strictly decreasing trust:
//
//  1. CF-Connecting-IP, which Cloudflare OVERWRITES rather than appends — the only
//     unspoofable client address available behind Cloudflare, and the same value
//     Cloudflare puts in its own logs, so the vendors agree by construction.
//  2. The forwarded chain walked from the RIGHT, stopping at the first routable public
//     address: the closest hop we have actually observed rather than merely been told.
//  3. The connecting peer, which is always real even when it is only a proxy.
func resolveClientIP(fields map[string]any) net.IP {
	if ip := vendors.RoutableClientIP(
		headerFromRequest(vendors.AsString(fields["request"]), "cf-connecting-ip"),
	); ip != nil {
		return ip
	}

	peer := vendors.AsString(firstOf(fields, "ip_client", "src"))
	forwarded := vendors.AsString(fields["x_forwarded_for_header_value"])
	if ip := vendors.LastUntrustedHop(forwarded, peer); ip != nil {
		return ip
	}

	// Deliberately NOT filtered through routableClientIP: the connecting peer is an
	// address the appliance observed on a socket, so even a private one is a fact about
	// this event rather than a claim. Discarding it would leave the event with no client
	// at all.
	return vendors.ParseIP(peer)
}
