package f5

import "testing"

// A real ASM `request` value from a BIG-IP behind Cloudflare. CF-Ray sits among the
// forwarded headers, ahead of most of the request, which is why it survives ASM's log
// truncation far more often than Host does.
const cloudflareFrontedRequest = `POST /search_form.php HTTP/1.1\r\n` +
	`x-forwarded-for: 79.132.17.66, 162.158.210.42\r\n` +
	`CF-Ray: a27533e76c55d101-SOF\r\n` +
	`Host: app2.jobs.bg\r\n` +
	`CDN-Loop: cloudflare; loops=1\r\n`

// THE POINT. Cloudflare's Logpush records the Ray ID without the edge-datacentre
// suffix, so the suffix has to go or the two vendors' values never match and the exact
// join silently degrades to the heuristic one.
func TestTheRayIDDropsTheDatacentreSuffix(t *testing.T) {
	fields := map[string]any{"request": cloudflareFrontedRequest}

	if got := resolveRequestID(fields); got != "a27533e76c55d101" {
		t.Errorf("resolveRequestID = %q, want the bare ray id — Cloudflare logs no suffix", got)
	}
}

// The ray is preferred over support_id precisely because it is SHARED. support_id is
// F5's own reference and no other vendor will ever report it, so an exact join on it
// can never fire.
func TestTheSharedRayBeatsF5sOwnSupportID(t *testing.T) {
	fields := map[string]any{
		"support_id": "2773644993865649202",
		"request":    cloudflareFrontedRequest,
	}

	if got := resolveRequestID(fields); got != "a27533e76c55d101" {
		t.Errorf("resolveRequestID = %q, want the ray — support_id joins with nothing", got)
	}
}

// A BIG-IP with no CDN in front, or a request truncated before CF-Ray, must still get
// an identifier rather than none.
func TestSupportIDIsUsedWhenThereIsNoRay(t *testing.T) {
	for name, fields := range map[string]map[string]any{
		"no request field": {"support_id": "12345"},
		"no cf-ray header": {
			"support_id": "12345",
			"request":    `GET / HTTP/1.1\r\nHost: shop.example.com\r\n`,
		},
		"truncated before cf-ray": {
			"support_id": "12345",
			"request":    `GET /a HTTP/1.1\r\nx-forwarded-for: 1.2.3.4`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := resolveRequestID(fields); got != "12345" {
				t.Errorf("resolveRequestID = %q, want the support_id fallback", got)
			}
		})
	}
}

func TestTheRayHeaderIsMatchedCaseInsensitively(t *testing.T) {
	for _, header := range []string{"CF-Ray", "cf-ray", "CF-RAY"} {
		fields := map[string]any{
			"request": `GET / HTTP/1.1\r\n` + header + `: abc123def456-LHR\r\n`,
		}
		if got := resolveRequestID(fields); got != "abc123def456" {
			t.Errorf("header %q gave %q, want abc123def456", header, got)
		}
	}
}

// A ray with no suffix must survive unchanged — the format is Cloudflare's to change.
func TestARayWithNoSuffixIsUnchanged(t *testing.T) {
	fields := map[string]any{"request": `GET / HTTP/1.1\r\nCF-Ray: a27533e76c55d101\r\n`}

	if got := resolveRequestID(fields); got != "a27533e76c55d101" {
		t.Errorf("resolveRequestID = %q, want the id unchanged", got)
	}
}

// Host and the ray are read from the same request without interfering.
func TestHostAndRayAreBothRecovered(t *testing.T) {
	fields := map[string]any{"request": cloudflareFrontedRequest}

	if got := resolveHost(fields); got != "app2.jobs.bg" {
		t.Errorf("resolveHost = %q, want app2.jobs.bg", got)
	}
	if got := resolveRequestID(fields); got != "a27533e76c55d101" {
		t.Errorf("resolveRequestID = %q, want the ray", got)
	}
}

// End to end: a full ASM line yields the identifier Cloudflare will also report, which
// is what turns this pair from a heuristic join into an exact one.
func TestAnASMLineYieldsTheCloudflareRayAsItsRequestID(t *testing.T) {
	line := `support_id="2773644993865649202",request_status="passed",` +
		`ip_client="162.158.210.42",method="POST",date_time="2026-08-07 07:09:00",` +
		`uri="/search_form.php",request="` + cloudflareFrontedRequest + `"`

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

	if event.VendorRequestID != "a27533e76c55d101" {
		t.Errorf("VendorRequestID = %q, want the Cloudflare ray", event.VendorRequestID)
	}
	// F5's own reference must remain on the event; it is what an operator quotes to F5
	// support, and the ray is no use to them.
	if got := event.RawExtra["support_id"]; got != "2773644993865649202" {
		t.Errorf("support_id = %q in RawExtra, want it preserved", got)
	}
}
