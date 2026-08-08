package nginx

import (
	"fmt"
	"testing"

	"github.com/menta2k/siem/internal/vendors"
)

// line builds an access log entry with a given status and upstream.
func line(status string, upstream string) string {
	return fmt.Sprintf(
		`{"time_iso8601":"2026-08-08T17:27:08+00:00","cf_connecting_ip":"203.0.113.10",`+
			`"cf_ray":"ray1","host":"www.jobs.bg","request_uri":"/x","request_method":"GET",`+
			`"status":%s,"upstream_addr":%q,"upstream_status":"%s"}`,
		status, upstream, statusIfProxied(upstream, status))
}

func statusIfProxied(upstream, status string) string {
	if upstream == "" || upstream == "-" {
		return "-"
	}
	return status
}

// THE RULE. What separates "the application answered" from "nginx refused" is whether
// the request ever reached upstream — NOT the status code.
//
// Using the status alone is actively harmful: a 302 is a login redirect, a 404 a
// missing page, a 401 an auth challenge, a 500 an application bug. All are ordinary
// outcomes for a request that WAS allowed through, and marking them as anything else
// would have each one disagreeing with three vendors that correctly allowed it —
// across the large share of any site's traffic that is redirects and 404s.
func TestTheApplicationsResponseIsAlwaysAllowed(t *testing.T) {
	for _, status := range []string{"200", "204", "301", "302", "401", "403", "404", "429", "500"} {
		event := normalizeOne(t, line(status, "10.1.111.50:8080"))
		if event.Verdict != vendors.VerdictAllowed {
			t.Errorf("status %s from the APPLICATION gave verdict %q, want allowed — "+
				"nginx passed the request through, which is all nginx decided",
				status, event.Verdict)
		}
	}
}

// nginx CAN refuse on its own — `deny`, `satisfy`, an access rule — and calling that
// allowed would hide a genuine block. It never reaches upstream, which is how it is
// told apart from an application's 403.
func TestNginxsOwn403IsABlock(t *testing.T) {
	event := normalizeOne(t, line("403", "-"))

	if event.Verdict != vendors.VerdictBlocked {
		t.Errorf("Verdict = %q, want blocked — nginx answered 403 without ever "+
			"consulting the application, so nginx refused the request", event.Verdict)
	}
}

// limit_req / limit_conn configured to answer 429. Rate limiting is distinct from a
// block in the common model, and the distinction is what an analyst reads.
func TestNginxsOwn429IsRateLimited(t *testing.T) {
	event := normalizeOne(t, line("429", "-"))

	if event.Verdict != vendors.VerdictRateLimited {
		t.Errorf("Verdict = %q, want rate_limited", event.Verdict)
	}
}

// THE SAME STATUS, OPPOSITE MEANINGS. This is the pair that justifies the whole
// design: a 403 the application returned is an authorization decision about a user, and
// a 403 nginx returned is a block. The status cannot tell them apart.
func TestA403FromTheAppAndFromNginxDiffer(t *testing.T) {
	fromApp := normalizeOne(t, line("403", "10.1.111.50:8080")).Verdict
	fromNginx := normalizeOne(t, line("403", "-")).Verdict

	if fromApp == fromNginx {
		t.Fatalf("both resolved to %q — an application's authorization decision and "+
			"nginx refusing the request are not the same event", fromApp)
	}
	if fromApp != vendors.VerdictAllowed || fromNginx != vendors.VerdictBlocked {
		t.Errorf("app=%q nginx=%q, want allowed and blocked", fromApp, fromNginx)
	}
}

// A 404 for a missing static file is served by nginx itself and is emphatically not a
// security decision. Treating every nginx-answered non-200 as a refusal would catch it.
func TestNginxsOwn404IsNotABlock(t *testing.T) {
	if got := normalizeOne(t, line("404", "-")).Verdict; got != vendors.VerdictAllowed {
		t.Errorf("Verdict = %q, want allowed — a missing file is not a block", got)
	}
}

// 503 is deliberately NOT read as rate limiting even though limit_req defaults to it.
// "No live upstreams" answers the same way, so the two are indistinguishable here, and
// reporting an origin outage as a security decision would be worse than missing a
// rate limit an operator can make unambiguous with limit_req_status 429.
func TestA503IsNotGuessedAsRateLimiting(t *testing.T) {
	if got := normalizeOne(t, line("503", "-")).Verdict; got != vendors.VerdictAllowed {
		t.Errorf("Verdict = %q, want allowed — 503 cannot be told apart from an "+
			"upstream outage", got)
	}
}

// nginx writes "-" rather than an empty string when there was no upstream, and a
// retried request produces a comma-separated list. Both must be read correctly or every
// request looks like nginx answered it.
func TestUpstreamPresenceIsDetectedInEveryForm(t *testing.T) {
	cases := map[string]bool{
		"10.1.111.50:8080":                   true,
		"10.1.111.50:8080, 10.1.111.51:8080": true,
		"-":                                  false,
		"":                                   false,
	}
	for upstream, reached := range cases {
		got := reachedUpstream(map[string]any{"upstream_addr": upstream})
		if got != reached {
			t.Errorf("upstream_addr %q: reachedUpstream = %v, want %v",
				upstream, got, reached)
		}
	}
}
