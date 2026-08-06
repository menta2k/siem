package vendors

import "net"

// sharedRanges are address blocks where many distinct clients commonly appear behind
// one address: RFC1918 private space (corporate NAT), carrier-grade NAT, and
// link-local ranges.
//
// This list is intentionally conservative. A false positive costs only a downgraded
// join confidence; a false negative lets the correlator assert a join it should have
// flagged as ambiguous, which is what SC-004's <1% false-join budget cannot absorb.
var sharedRanges = func() []*net.IPNet {
	cidrs := []string{
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"100.64.0.0/10",  // RFC6598 carrier-grade NAT — the big one for mobile traffic
		"169.254.0.0/16", // link-local
		"127.0.0.0/8",    // loopback
		"fc00::/7",       // IPv6 unique local
		"fe80::/10",      // IPv6 link-local
		"::1/128",        // IPv6 loopback
	}

	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		if _, network, err := net.ParseCIDR(cidr); err == nil {
			nets = append(nets, network)
		}
	}
	return nets
}()

// IsSharedIP reports whether an address is one many clients plausibly share.
//
// A true result downgrades a tier-2 correlation to low confidence rather than
// suppressing the join: the events probably do belong together, but the platform
// says so with appropriate uncertainty instead of asserting it (FR-015).
func IsSharedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, network := range sharedRanges {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
