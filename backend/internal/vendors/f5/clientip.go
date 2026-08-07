package f5

import (
	"net"
	"slices"
	"strings"

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
	if ip := routableClientIP(
		headerFromRequest(vendors.AsString(fields["request"]), "cf-connecting-ip"),
	); ip != nil {
		return ip
	}

	peer := vendors.AsString(firstOf(fields, "ip_client", "src"))
	forwarded := vendors.AsString(fields["x_forwarded_for_header_value"])
	if ip := lastUntrustedHop(forwarded, peer); ip != nil {
		return ip
	}

	// Deliberately NOT filtered through routableClientIP: the connecting peer is an
	// address the appliance observed on a socket, so even a private one is a fact about
	// this event rather than a claim. Discarding it would leave the event with no client
	// at all.
	return vendors.ParseIP(peer)
}

// lastUntrustedHop walks the forwarded chain right to left and returns the first entry
// that could be an internet client.
//
// Right to left because trust decreases leftwards: the rightmost entry was written by the
// proxy nearest us, and every step further left was merely asserted by the hop before it.
//
// The peer is skipped because we KNOW it is a proxy: BIG-IP appends the address it
// received the connection from, so the same value appears both as ip_client and at the
// end of the chain. Without this the walk stops on the CDN edge — a perfectly routable
// public address that is nonetheless not the client — and every request through that edge
// collapses onto one apparent source.
//
// Private and reserved entries are skipped for the same reason: infrastructure hops and
// forgeries, never the client this event describes.
func lastUntrustedHop(forwarded, peer string) net.IP {
	if forwarded == "" {
		return nil
	}
	peerIP := vendors.ParseIP(strings.TrimSpace(peer))

	for _, hop := range slices.Backward(strings.Split(forwarded, ",")) {
		ip := routableClientIP(hop)
		if ip == nil || ip.Equal(peerIP) {
			continue
		}
		return ip
	}
	return nil
}

// routableClientIP parses an address and reports it only if a client could plausibly hold
// it on the public internet.
//
// The rejected classes are the ones that prove the value is not a client address:
// loopback, link-local, multicast, the unspecified address, private ranges — all
// infrastructure — plus anything outside assigned unicast space, which is where forged
// values land. Returning nil for these is what stops a spoofed header from being believed.
func routableClientIP(value string) net.IP {
	ip := vendors.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return nil
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsInterfaceLocalMulticast() {
		return nil
	}
	if isReserved(ip) {
		return nil
	}
	return ip
}

// reservedRanges are assigned to no one, so a packet cannot arrive from them.
//
// 240.0.0.0/4 is the one that matters in practice: it is where the forged values in live
// traffic landed, and IsGlobalUnicast reports true for it because Go excludes only the
// classes IANA marks specially, not the reserved block.
//
// The documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32)
// are deliberately NOT listed. They are equally impossible as real clients, but they are
// also the conventional stand-ins for public addresses in tests and examples, so treating
// them as forgeries would make this rule untestable against realistic fixtures for no
// gain against a real attacker — who would simply pick a different range.
var reservedRanges = []string{
	"240.0.0.0/4", // reserved for future use, never allocated
	"100::/64",    // IPv6 discard-only
}

// reservedNets is built once; parsing on every event would cost more than the lookup.
var reservedNets = func() []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(reservedRanges))
	for _, cidr := range reservedRanges {
		if _, network, err := net.ParseCIDR(cidr); err == nil {
			nets = append(nets, network)
		}
	}
	return nets
}()

func isReserved(ip net.IP) bool {
	for _, network := range reservedNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
