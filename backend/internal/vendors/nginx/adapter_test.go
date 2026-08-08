package nginx

import (
	"testing"

	"github.com/menta2k/siem/internal/vendors"
)

// A line in the log_format this adapter is deployed with. remote_addr is the BIG-IP,
// which is the whole point of the client-address handling below.
const accessLine = `{"time_iso8601":"2026-08-08T17:27:08+00:00",` +
	`"remote_addr":"10.1.111.20","cf_connecting_ip":"203.0.113.10",` +
	`"x_forwarded_for":"203.0.113.10, 162.158.210.42, 10.1.111.20",` +
	`"cf_ray":"a27fe3039e6f1216-SOF","host":"www.jobs.bg",` +
	`"request_uri":"/job/8564794?ref=search","request_method":"GET","status":200,` +
	`"user_agent":"Mozilla/5.0","server_name":"jobs","request_time":"0.042",` +
	`"upstream_status":"200","body_bytes_sent":18244}`

func normalizeOne(t *testing.T, payload string) vendors.Event {
	t.Helper()

	adapter := New()
	format, ok := adapter.Detect([]byte(payload))
	if !ok {
		t.Fatalf("Detect rejected the payload")
	}
	records, err := adapter.Parse([]byte(payload), format)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	event, err := adapter.Normalize(records[0])
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	return event
}

// THE JOIN. nginx sits behind F5, which sits behind Cloudflare, and the CF-Ray header
// travels the whole way — so nginx logs the ORIGIN FETCH's ray, exactly the identifier
// F5 keys on. That is what puts an nginx event in the group F5 is already in, and from
// there it reaches Cloudflare and DataDome through the bridge the origin-fetch row
// provides. Without the suffix stripped nothing matches, because Cloudflare's own logs
// record the bare id.
func TestTheRayIsTheJoinKeyAndLosesItsDatacentreSuffix(t *testing.T) {
	event := normalizeOne(t, accessLine)

	if event.VendorRequestID != "a27fe3039e6f1216" {
		t.Errorf("VendorRequestID = %q, want the bare ray — with the suffix it joins "+
			"nothing", event.VendorRequestID)
	}
	if event.Vendor != vendors.Nginx {
		t.Errorf("Vendor = %q, want nginx", event.Vendor)
	}
}

// THE TRAP. $remote_addr is the BIG-IP on every single request. Recording it as the
// client would make every nginx event report one load-balancer address: a search for a
// real client returns nothing, top sources shows the infrastructure, and the IP-based
// heuristic join collapses all traffic onto one apparent source.
func TestTheLoadBalancerIsNeverTheClient(t *testing.T) {
	event := normalizeOne(t, accessLine)

	if event.ClientIP == nil {
		t.Fatal("no client address resolved")
	}
	if got := event.ClientIP.String(); got != "203.0.113.10" {
		t.Errorf("ClientIP = %q, want the real client 203.0.113.10", got)
	}
	if event.ClientIP.String() == "10.1.111.20" {
		t.Error("the BIG-IP's address was recorded as the client")
	}
}

// CLOUDFLARE'S PSEUDO IPv4, and the bug it caused. When an IPv6 client reaches an IPv4
// origin Cloudflare synthesises a CF-Connecting-IP in reserved 240.0.0.0/4 — 36% of
// live requests on this deployment, 2,671 of 7,352 in ten minutes. The genuine IPv6
// client is in $remote_addr, put there by nginx's realip module.
//
// Refusing the pseudo address is right. Falling back to the forwarded chain was not:
// behind a CDN the rightmost hop is the CDN's own edge, so 708 events were attributed
// to Cloudflare's 162.158.60.172 instead of the people who made them.
func TestPseudoIPv4FallsBackToTheRealClient(t *testing.T) {
	line := `{"time_iso8601":"2026-08-08T17:27:08+00:00",` +
		`"cf_connecting_ip":"246.214.60.187",` +
		`"x_forwarded_for":"246.214.60.187, 172.71.148.23",` +
		`"remote_addr":"2a02:26f7:e180:da13:0:1000:0:f",` +
		`"cf_ray":"ray1-SOF","host":"www.jobs.bg","request_uri":"/","request_method":"GET",` +
		`"status":200}`

	event := normalizeOne(t, line)
	if event.ClientIP == nil {
		t.Fatal("no client resolved — the real IPv6 client was in remote_addr")
	}
	if got := event.ClientIP.String(); got != "2a02:26f7:e180:da13:0:1000:0:f" {
		t.Errorf("ClientIP = %q, want the IPv6 client from remote_addr", got)
	}
}

// The CDN's edge address must never be recorded as the client, whichever header it
// appears in. This is the specific regression: X-Forwarded-For's rightmost hop.
func TestTheCDNEdgeIsNeverTheClient(t *testing.T) {
	line := `{"time_iso8601":"2026-08-08T17:27:08+00:00",` +
		`"cf_connecting_ip":"246.214.60.187",` +
		`"x_forwarded_for":"246.214.60.187, 162.158.60.172",` +
		`"remote_addr":"10.1.111.20",` +
		`"cf_ray":"ray1","host":"www.jobs.bg","request_uri":"/","request_method":"GET",` +
		`"status":200}`

	got := normalizeOne(t, line).ClientIP
	if got != nil && got.String() == "162.158.60.172" {
		t.Error("Cloudflare's edge address was recorded as the client")
	}
	if got != nil {
		t.Errorf("ClientIP = %v, want none — nothing here is a client address", got)
	}
}

// Where realip is NOT configured, $remote_addr is the load balancer. Requiring the
// address to be routable is what keeps it out: a LAN address is private and refused,
// so the event carries no client rather than the infrastructure.
func TestNoClientIsBetterThanTheProxysAddress(t *testing.T) {
	line := `{"time_iso8601":"2026-08-08T17:27:08+00:00","remote_addr":"10.1.111.20",` +
		`"cf_ray":"ray1","host":"www.jobs.bg","request_uri":"/","request_method":"GET",` +
		`"status":200}`

	if got := normalizeOne(t, line).ClientIP; got != nil {
		t.Errorf("ClientIP = %v, want none — that address is the load balancer", got)
	}
}

// The observed status is always recorded, whatever the verdict resolves to. It is the
// origin's answer, and an analyst reading a record needs it even when it carries no
// security meaning. See verdict_test.go for how the verdict itself is decided.
func TestTheResponseStatusIsAlwaysRecorded(t *testing.T) {
	for _, status := range []string{"200", "403", "404", "429", "500"} {
		payload := `{"time_iso8601":"2026-08-08T17:27:08+00:00",` +
			`"cf_connecting_ip":"203.0.113.10","cf_ray":"ray1","host":"www.jobs.bg",` +
			`"request_uri":"/","request_method":"GET","status":` + status + `}`

		if got := normalizeOne(t, payload).HTTPStatus; got == 0 {
			t.Errorf("status %s was not recorded on the event", status)
		}
	}
}

func TestTheRequestIsSplitIntoPathAndQuery(t *testing.T) {
	event := normalizeOne(t, accessLine)

	if event.RequestPath != "/job/8564794" {
		t.Errorf("RequestPath = %q", event.RequestPath)
	}
	if event.RequestQuery != "ref=search" {
		t.Errorf("RequestQuery = %q", event.RequestQuery)
	}
	if event.RequestHost != "www.jobs.bg" {
		t.Errorf("RequestHost = %q", event.RequestHost)
	}
	if event.RequestMethod != "GET" {
		t.Errorf("RequestMethod = %q", event.RequestMethod)
	}
}

// A delivery is many lines. One unreadable line must not cost the rest of the batch.
func TestOneBadLineDoesNotSinkTheDelivery(t *testing.T) {
	adapter := New()
	payload := []byte(accessLine + "\nnot json at all\n" + accessLine)

	records, err := adapter.Parse(payload, vendors.FormatNDJSON)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("got %d records, want 3", len(records))
	}
	if records[1].Fields != nil {
		t.Error("the unparseable line produced fields")
	}
	if _, err := adapter.Normalize(records[1]); err == nil {
		t.Error("the unparseable line normalized without error, so it would never be " +
			"dead-lettered and the misconfiguration would stay invisible")
	}
	for _, i := range []int{0, 2} {
		if _, err := adapter.Normalize(records[i]); err != nil {
			t.Errorf("record %d failed alongside the bad line: %v", i, err)
		}
	}
}

// A plain-text combined-format line is rejected rather than guessed at. A visible
// dead-letter is a fixable misconfiguration; a guessed layout silently produces events
// with the wrong fields in them.
func TestTheCombinedTextFormatIsRejectedNotGuessed(t *testing.T) {
	line := `203.0.113.10 - - [08/Aug/2026:17:27:08 +0000] "GET /job/1 HTTP/1.1" 200 18244`

	if _, ok := New().Detect([]byte(line)); ok {
		t.Error("a plain-text access line was accepted — its fields would be guessed")
	}
}

// A line with no CF-Ray still becomes an event. It cannot join exactly, but a request
// that reached the origin is evidence worth keeping.
func TestALineWithoutARayIsStillAnEvent(t *testing.T) {
	line := `{"time_iso8601":"2026-08-08T17:27:08+00:00","cf_connecting_ip":"203.0.113.10",` +
		`"host":"www.jobs.bg","request_uri":"/","request_method":"GET","status":200}`

	event := normalizeOne(t, line)
	if event.VendorRequestID != "" {
		t.Errorf("VendorRequestID = %q, want empty", event.VendorRequestID)
	}
	if event.RequestHost != "www.jobs.bg" {
		t.Error("the event lost its host")
	}
}

// A missing timestamp is a rejection, not a silently invented time. An event dated now
// would sit in the wrong correlation window and never match its partners.
func TestAMissingTimestampIsRejected(t *testing.T) {
	line := `{"cf_ray":"ray1","host":"www.jobs.bg","request_uri":"/","request_method":"GET"}`

	adapter := New()
	records, err := adapter.Parse([]byte(line), vendors.FormatNDJSON)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := adapter.Normalize(records[0]); err == nil {
		t.Error("a line with no timestamp normalized successfully")
	}
}
