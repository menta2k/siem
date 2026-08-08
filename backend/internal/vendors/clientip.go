package vendors

import (
	"net"
	"slices"
	"strings"
)

// LastUntrustedHop walks a forwarded chain from the RIGHT and returns the first
// routable public address that is not the connecting peer.
//
// X-Forwarded-For is APPEND-ONLY. Each proxy adds the peer it received the request
// from, so whatever the client put in the header survives untouched at the FRONT of
// the chain. Reading the leftmost entry therefore reads an attacker-supplied string,
// and on live traffic it did: 27.7% of F5 events carried an address in reserved
// 240.0.0.0/4 that no host can hold, while Cloudflare's log of the same requests named
// the real client.
//
// That is not cosmetic. This address drives search, the top-sources panel and the
// IP-based heuristic join, so trusting the header lets an attacker attribute their
// traffic to any address they like and break its correlation at the same time.
//
// The peer is skipped because it is the edge itself — a public address that is
// nonetheless not the client, and every request through that edge would otherwise
// collapse onto one apparent source. Private and reserved entries are skipped for the
// same reason: infrastructure hops and forgeries, never the client.
//
// Shared by every adapter that sits behind a proxy. Duplicating it per vendor would
// mean fixing a spoofing bug in one place and leaving it open in another.
func LastUntrustedHop(forwarded, peer string) net.IP {
	if forwarded == "" {
		return nil
	}
	peerIP := ParseIP(strings.TrimSpace(peer))

	for _, hop := range slices.Backward(strings.Split(forwarded, ",")) {
		ip := RoutableClientIP(hop)
		if ip == nil || ip.Equal(peerIP) {
			continue
		}
		return ip
	}
	return nil
}

// RoutableClientIP parses an address and reports it only if a client could plausibly
// hold it on the public internet.
//
// The rejected classes are the ones that prove the value is not a client address:
// loopback, link-local, multicast, the unspecified address, private ranges — all
// infrastructure — plus anything outside assigned unicast space, which is where forged
// values land. Returning nil for these is what stops a spoofed header being believed.
func RoutableClientIP(value string) net.IP {
	ip := ParseIP(strings.TrimSpace(value))
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
// 240.0.0.0/4 is the one that matters in practice: it is where the forged values in
// live traffic landed, and IsGlobalUnicast reports true for it because Go excludes only
// the classes IANA marks specially, not the reserved block.
//
// The documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
// 2001:db8::/32) are deliberately NOT listed. They are equally impossible as real
// clients, but they are also the conventional stand-ins for public addresses in tests
// and examples, so treating them as forgeries would make this rule untestable against
// realistic fixtures for no gain against a real attacker — who would simply pick a
// different range.
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
