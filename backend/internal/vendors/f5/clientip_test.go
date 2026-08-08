package f5

import (
	"testing"

	"github.com/menta2k/siem/internal/vendors"
)

// THE BUG THIS FIXES. X-Forwarded-For is APPEND-ONLY: every proxy adds the address it
// received the request from, and whatever the client sent arrives untouched at the front.
// So the leftmost entry is not "the original client" — it is the last thing an attacker
// typed into a header. Trusting it let 27.7% of live F5 events carry an address in
// reserved 240.0.0.0/4 that no host can hold, while Cloudflare's log of the very same
// requests reported the real client.
//
// This is worse than a display defect. The client address drives search, the top-sources
// panel, and the IP-based heuristic join, so an attacker could attribute their own traffic
// to any address they chose and break its correlation at the same time.
func TestASpoofedLeadingForwardedForIsNotTrusted(t *testing.T) {
	// Straight from production: 249.194.35.210 is in reserved space and was supplied by
	// the client; 162.158.210.42 is the Cloudflare edge that actually connected.
	fields := map[string]any{
		"ip_client":                    "162.158.210.42",
		"x_forwarded_for_header_value": "249.194.35.210, 162.158.210.42",
		"request": "GET / HTTP/1.1\\r\\nCF-Connecting-IP: " +
			"2a0d:3344:31e5:5a00:4043:b6b5:f617:3b3e\\r\\n",
	}

	got := resolveClientIP(fields)
	if got == nil {
		t.Fatal("resolveClientIP returned nil")
	}
	if got.String() == "249.194.35.210" {
		t.Fatal("the forged leftmost XFF entry was trusted as the client address")
	}
	if got.String() != "2a0d:3344:31e5:5a00:4043:b6b5:f617:3b3e" {
		t.Errorf("resolveClientIP = %q, want the CF-Connecting-IP address", got)
	}
}

// CF-Connecting-IP is preferred because Cloudflare OVERWRITES it on every request rather
// than appending — a client that sends its own is ignored. That makes it the only
// unspoofable client address available to a BIG-IP behind Cloudflare, and it is also
// exactly the address Cloudflare puts in its own logs, so the two vendors agree by
// construction rather than by luck.
func TestTheCloudflareConnectingIPWins(t *testing.T) {
	fields := map[string]any{
		"ip_client":                    "162.158.210.42",
		"x_forwarded_for_header_value": "203.0.113.9, 162.158.210.42",
		"request":                      "GET / HTTP/1.1\\r\\nCF-Connecting-IP: 198.51.100.7\\r\\n",
	}

	if got := resolveClientIP(fields); got == nil || got.String() != "198.51.100.7" {
		t.Errorf("resolveClientIP = %v, want 198.51.100.7 from CF-Connecting-IP", got)
	}
}

// Without Cloudflare there is still a correct answer, and it is not the leftmost entry.
// Walking the chain from the RIGHT and stopping at the first address that is not a known
// proxy yields the closest hop we have actually verified — everything further left was
// asserted by someone we have no reason to believe.
func TestTheChainIsWalkedFromTheRight(t *testing.T) {
	fields := map[string]any{
		"ip_client":                    "162.158.210.42",
		"x_forwarded_for_header_value": "10.0.0.1, 198.51.100.23, 162.158.210.42",
	}

	if got := resolveClientIP(fields); got == nil || got.String() != "198.51.100.23" {
		t.Errorf("resolveClientIP = %v, want 198.51.100.23 — the last untrusted hop", got)
	}
}

// A reserved or unroutable address cannot be a real client, so it is rejected wherever it
// appears rather than only at the head of the chain.
func TestUnroutableAddressesAreRejected(t *testing.T) {
	for name, value := range map[string]string{
		"reserved 240/4":  "249.194.35.210",
		"loopback":        "127.0.0.1",
		"unspecified":     "0.0.0.0",
		"link local":      "169.254.10.1",
		"multicast":       "224.0.0.1",
		"ipv6 loopback":   "::1",
		"ipv6 unassigned": "100::1",
	} {
		t.Run(name, func(t *testing.T) {
			if vendors.RoutableClientIP(value) != nil {
				t.Errorf("%q was accepted as a client address", value)
			}
		})
	}
}

// Private addresses are proxies or internal hops, never the internet client this event
// describes, so they are skipped in the chain rather than reported.
func TestPrivateHopsAreSkipped(t *testing.T) {
	fields := map[string]any{
		"x_forwarded_for_header_value": "203.0.113.5, 10.1.2.3, 192.168.1.1",
	}

	if got := resolveClientIP(fields); got == nil || got.String() != "203.0.113.5" {
		t.Errorf("resolveClientIP = %v, want 203.0.113.5 — private hops are not clients", got)
	}
}

// When every forwarded entry is unusable the connecting peer is still a real, observed
// address. Reporting nothing would drop the event's only verified fact.
func TestFallsBackToTheConnectingPeer(t *testing.T) {
	fields := map[string]any{
		"ip_client":                    "203.0.113.77",
		"x_forwarded_for_header_value": "249.1.2.3, 10.0.0.1",
	}

	if got := resolveClientIP(fields); got == nil || got.String() != "203.0.113.77" {
		t.Errorf("resolveClientIP = %v, want the ip_client fallback", got)
	}
}

// A BIG-IP with no proxy in front sends no XFF at all.
func TestTheConnectingPeerIsUsedWhenThereIsNoChain(t *testing.T) {
	fields := map[string]any{"ip_client": "198.51.100.200"}

	if got := resolveClientIP(fields); got == nil || got.String() != "198.51.100.200" {
		t.Errorf("resolveClientIP = %v, want 198.51.100.200", got)
	}
}

// Nothing usable anywhere must yield nil rather than a zero address, which would collapse
// every such event onto a single fake client in search and correlation.
func TestNoUsableAddressYieldsNil(t *testing.T) {
	if got := resolveClientIP(map[string]any{"x_forwarded_for_header_value": "10.0.0.1"}); got != nil {
		t.Errorf("resolveClientIP = %v, want nil", got)
	}
}

// End to end, on the shape the appliance actually emits.
func TestAnASMLineReportsTheRealClient(t *testing.T) {
	line := `support_id="2773644993843697603",request_status="blocked",` +
		`ip_client="162.158.210.42",method="GET",date_time="2026-08-07 11:53:41",` +
		`x_forwarded_for_header_value="249.194.35.210, 162.158.210.42",` +
		`uri="/",request="GET / HTTP/1.1\r\nCF-Connecting-IP: 198.51.100.7\r\nHost: app2.jobs.bg\r\n"`

	a := New()
	format, ok := a.Detect([]byte(line))
	if !ok {
		t.Fatal("Detect did not recognise the line")
	}
	records, err := a.Parse([]byte(line), format)
	if err != nil || len(records) != 1 {
		t.Fatalf("Parse: %v (%d records)", err, len(records))
	}

	event, err := a.Normalize(records[0])
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if event.ClientIP == nil || event.ClientIP.String() != "198.51.100.7" {
		t.Errorf("ClientIP = %v, want 198.51.100.7", event.ClientIP)
	}
}
