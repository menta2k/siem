package nginx

import (
	"strings"

	"github.com/menta2k/siem/internal/vendors"
)

// mapVerdict decides what nginx itself concluded about a request.
//
// THE DISCRIMINATOR IS WHO ANSWERED, NOT WHAT THE STATUS WAS.
//
// nginx is mostly the origin — the thing a request proceeds TO once every gate in front
// has let it through — and for those requests its verdict is `allowed`, because the
// event's existence is itself the evidence: Cloudflare, DataDome and F5 each terminate
// a request they refuse, so it never reaches the origin and no line is written.
//
// But nginx CAN refuse on its own: `deny`, `limit_req`, `limit_conn`, `satisfy`. Those
// are genuine security decisions and calling them allowed would hide a block.
//
// The status code cannot tell the two apart, and using it alone is actively harmful.
// A 302 is a login redirect, a 404 is a missing page, a 401 is an auth challenge, a 500
// is an application bug — all of them ordinary outcomes for a request that was allowed
// through. Treating "not 200" as not-allowed would mark every one of them as
// disagreeing with three vendors that correctly allowed it, and redirects and 404s are
// a large share of any site's traffic.
//
// What DOES separate them is whether the request ever reached the application. nginx
// records the upstream it proxied to, and leaves it empty when it answered by itself.
// So a refusal that never touched upstream is nginx's own decision, and a status
// returned by the application is the application's.
func mapVerdict(fields map[string]any) string {
	if reachedUpstream(fields) {
		// The application answered. Whatever it said — 200, 404, 403, 500 — nginx
		// passed the request through, which is the only thing nginx decided.
		return vendors.VerdictAllowed
	}

	switch vendors.ToStatus(fields["status"]) {
	case statusForbidden:
		// nginx answered 403 without consulting the application: `deny`, or an access
		// rule it evaluated itself. That is a block.
		return vendors.VerdictBlocked
	case statusTooManyRequests:
		// limit_req / limit_conn, configured to answer 429.
		return vendors.VerdictRateLimited
	default:
		// Everything else nginx answers on its own is a normal origin response: a 404
		// for a missing static file, a 304, a redirect from a `return` directive.
		//
		// 503 is deliberately NOT treated as rate limiting even though limit_req
		// defaults to it. "No live upstreams" answers 502/503 the same way, so the two
		// are indistinguishable here and guessing would report an outage as a security
		// decision. An operator who wants limit_req counted should configure
		// limit_req_status 429, which is unambiguous.
		return vendors.VerdictAllowed
	}
}

// Statuses nginx returns when refusing a request itself.
const (
	statusForbidden       = 403
	statusTooManyRequests = 429
)

// reachedUpstream reports whether nginx proxied the request to the application.
//
// nginx writes "-" rather than leaving the variable empty when there was no upstream,
// and a request retried across several upstreams produces a comma-separated list — so
// any real address in the field means the application saw the request.
func reachedUpstream(fields map[string]any) bool {
	for _, name := range []string{"upstream_addr", "upstream_status"} {
		value := strings.TrimSpace(vendors.AsString(fields[name]))
		if value == "" || value == "-" {
			continue
		}
		return true
	}
	return false
}
