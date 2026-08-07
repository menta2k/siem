package f5

import "testing"

// The exact `request` value BIG-IP ASM sends: a single-line log field carrying the whole
// HTTP request, with CRLF written as the literal two-character escapes \r\n so the
// request cannot break the log format.
const asmRequestField = `POST /search_form.php HTTP/1.1\r\n` +
	`x-forwarded-for: 79.132.17.66, 162.158.210.42\r\n` +
	`Host: app2.jobs.bg\r\n` +
	`Content-Type: application/x-www-form-urlencoded\r\n` +
	`CDN-Loop: cloudflare; loops=1\r\n`

// THE POINT OF ALL THIS. ASM has no selectable `host` field, so without reading the
// request there is no hostname — and hostname is the strongest heuristic join key.
// Every F5 event would silently fail to correlate with any other vendor.
func TestHostComesFromTheRawRequestWhenThereIsNoHostField(t *testing.T) {
	fields := map[string]any{"request": asmRequestField}

	if got := resolveHost(fields); got != "app2.jobs.bg" {
		t.Errorf("resolveHost = %q, want app2.jobs.bg — F5 events cannot join without it", got)
	}
}

// A real CRLF must work too: a different shipper may not escape it.
func TestARealCRLFRequestAlsoYieldsTheHost(t *testing.T) {
	fields := map[string]any{
		"request": "GET /a HTTP/1.1\r\nHost: shop.example.com\r\nAccept: */*\r\n",
	}

	if got := resolveHost(fields); got != "shop.example.com" {
		t.Errorf("resolveHost = %q, want shop.example.com", got)
	}
}

// An explicit field always wins; the request is only a fallback.
func TestAnExplicitHostFieldTakesPrecedence(t *testing.T) {
	fields := map[string]any{
		"host":    "explicit.example.com",
		"request": asmRequestField,
	}

	if got := resolveHost(fields); got != "explicit.example.com" {
		t.Errorf("resolveHost = %q, want the explicit field to win", got)
	}
}

// A port must be stripped, or the same request seen by a CDN on :443 never matches.
func TestThePortIsStrippedFromTheHostHeader(t *testing.T) {
	fields := map[string]any{"request": `GET / HTTP/1.1\r\nHost: shop.example.com:8443\r\n`}

	if got := resolveHost(fields); got != "shop.example.com" {
		t.Errorf("resolveHost = %q, want the port removed", got)
	}
}

// Header names are case-insensitive on the wire.
func TestTheHostHeaderIsMatchedCaseInsensitively(t *testing.T) {
	for _, header := range []string{"host", "HOST", "HoSt"} {
		fields := map[string]any{
			"request": `GET / HTTP/1.1\r\n` + header + `: Shop.Example.COM\r\n`,
		}
		// Lower-cased so it joins against another vendor reporting the same name in a
		// different case — hostnames are case-insensitive, join keys are not.
		if got := resolveHost(fields); got != "shop.example.com" {
			t.Errorf("header %q gave %q, want shop.example.com", header, got)
		}
	}
}

// A header merely CONTAINING "host" must not be mistaken for the Host header, or an
// event acquires a hostname that no other vendor will ever report.
func TestSimilarHeadersAreNotMistakenForHost(t *testing.T) {
	fields := map[string]any{
		"request": `GET / HTTP/1.1\r\nX-Forwarded-Host: attacker.example\r\n` +
			`Host: real.example.com\r\n`,
	}

	if got := resolveHost(fields); got != "real.example.com" {
		t.Errorf("resolveHost = %q, want real.example.com", got)
	}
}

func TestNoHostAnywhereYieldsEmpty(t *testing.T) {
	for name, fields := range map[string]map[string]any{
		"no request field": {},
		"empty request":    {"request": ""},
		"request with no host header": {
			"request": `GET / HTTP/1.1\r\nAccept: */*\r\n`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := resolveHost(fields); got != "" {
				t.Errorf("resolveHost = %q, want empty rather than a guess", got)
			}
		})
	}
}

// End to end on the shape production actually sends.
func TestAFullASMLineNormalizesWithAHost(t *testing.T) {
	line := `support_id="123",request_status="passed",ip_client="162.158.210.42",` +
		`x_forwarded_for_header_value="79.132.17.66, 162.158.210.42",method="POST",` +
		`date_time="2026-08-07 07:09:00",uri="/search_form.php",` +
		`request="` + asmRequestField + `"`

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

	if event.RequestHost != "app2.jobs.bg" {
		t.Errorf("RequestHost = %q, want app2.jobs.bg", event.RequestHost)
	}
	// The client IP must be the true client, not Cloudflare's edge, or the two vendors
	// disagree on who made the request and the heuristic join fails on that instead.
	if got := event.ClientIP.String(); got != "79.132.17.66" {
		t.Errorf("ClientIP = %q, want the true client from X-Forwarded-For", got)
	}
}
