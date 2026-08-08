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

// X-Forwarded-For is append-only, so its LEFTMOST entry is attacker-controlled. With
// CF-Connecting-IP absent the chain must be read from the right, and a forged public
// address at the front must not win.
func TestAForgedForwardedForIsNotBelieved(t *testing.T) {
	line := `{"time_iso8601":"2026-08-08T17:27:08+00:00","remote_addr":"10.1.111.20",` +
		`"x_forwarded_for":"240.0.0.1, 198.18.5.6, 10.1.111.20",` +
		`"cf_ray":"ray1-SOF","host":"www.jobs.bg","request_uri":"/","request_method":"GET",` +
		`"status":200}`

	event := normalizeOne(t, line)
	if event.ClientIP != nil && event.ClientIP.String() == "240.0.0.1" {
		t.Error("a reserved 240.0.0.0/4 address was accepted as the client")
	}
}

// When there is nothing trustworthy, the event carries NO client rather than the load
// balancer's address. This is where nginx diverges from F5 on purpose: there the peer
// may genuinely be the client, here it is always infrastructure.
func TestNoClientIsBetterThanTheProxysAddress(t *testing.T) {
	line := `{"time_iso8601":"2026-08-08T17:27:08+00:00","remote_addr":"10.1.111.20",` +
		`"cf_ray":"ray1","host":"www.jobs.bg","request_uri":"/","request_method":"GET",` +
		`"status":200}`

	if got := normalizeOne(t, line).ClientIP; got != nil {
		t.Errorf("ClientIP = %v, want none — that address is the load balancer", got)
	}
}

// THE VERDICT REASONING. An nginx event only exists for a request every gate let
// through, so its presence IS the evidence it was allowed. Mapping the response status
// to a verdict would turn an application's 403 or 404 into a security judgement and
// manufacture disagreements against vendors that correctly allowed the request.
func TestTheResponseStatusIsNotAVerdict(t *testing.T) {
	for _, status := range []string{"200", "403", "404", "429", "500"} {
		line := `{"time_iso8601":"2026-08-08T17:27:08+00:00",` +
			`"cf_connecting_ip":"203.0.113.10","cf_ray":"ray1","host":"www.jobs.bg",` +
			`"request_uri":"/","request_method":"GET","status":` + status + `}`

		event := normalizeOne(t, line)
		if event.Verdict != vendors.VerdictAllowed {
			t.Errorf("status %s gave verdict %q, want allowed — the origin's response is "+
				"not a security decision", status, event.Verdict)
		}
		if event.HTTPStatus == 0 {
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
