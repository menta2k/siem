package f5

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/menta2k/siem/internal/vendors"
)

// requestStatusVerdicts maps ASM's request_status onto the common model.
//
// ASM reports a narrower vocabulary than the other two vendors, so severity and
// policy context do the rest of the work in mapVerdict below.
var requestStatusVerdicts = map[string]string{
	"blocked": vendors.VerdictBlocked,
	"passed":  vendors.VerdictAllowed,
	// "alerted" means the policy matched but is in transparent/staging mode: the
	// request was NOT allowed on its merits, it was let through because enforcement
	// was off. Mapping it to allowed would manufacture false disagreements against a
	// vendor that genuinely blocked the same request.
	"alerted": vendors.VerdictMonitored,
}

// rateLimitViolations identify a block that was actually rate limiting, which the
// common model distinguishes because an analyst reads them very differently.
var rateLimitViolations = []string{
	"rate limit", "brute force", "anomaly", "flood", "dos",
}

// Normalize maps an F5 record onto the common event model. Pure and deterministic.
func (a *Adapter) Normalize(record vendors.RawRecord) (vendors.Event, error) {
	if record.Fields == nil {
		return vendors.Event{}, fmt.Errorf("%w: record did not decode", vendors.ErrUnparseable)
	}

	eventTime, original, err := parseEventTime(record.Fields)
	if err != nil {
		return vendors.Event{}, err
	}

	clientIP := resolveClientIP(record.Fields)
	path, query := resolveURI(record.Fields)

	event := vendors.Event{
		Vendor:            vendors.F5,
		VendorAccount:     vendors.AsString(firstOf(record.Fields, "virtual_server", "http_class_name")),
		VendorRequestID:   resolveRequestID(record.Fields),
		EventTime:         eventTime,
		EventTimeOriginal: original,

		ClientIP:       clientIP,
		ClientIPShared: vendors.IsSharedIP(clientIP),
		ClientCountry:  strings.ToUpper(vendors.AsString(record.Fields["geo_location"])),

		// Only genuine Host-header sources. `virtual_server` is deliberately NOT one:
		// it is a BIG-IP object path like /Common/vs_shop_https, and using it as the
		// host makes every F5 event unjoinable — no other vendor reports that string —
		// while also making a hostname search silently miss all F5 traffic. It is
		// recorded as VendorAccount, which is what it actually is.
		RequestHost:  resolveHost(record.Fields),
		RequestPath:  path,
		RequestQuery: query,
		RequestMethod: strings.ToUpper(
			vendors.AsString(firstOf(record.Fields, "method", "requestMethod"))),
		UserAgent:  vendors.AsString(record.Fields["user_agent"]),
		HTTPStatus: vendors.ToStatus(firstOf(record.Fields, "response_code", "cn1")),

		VerdictReason: vendors.AsString(firstOf(record.Fields, "attack_type", "name")),
		RuleID:        vendors.AsString(firstOf(record.Fields, "policy_name", "signature_id")),
		RuleIDs:       vendors.AsStringSlice(record.Fields["violations"]),

		// ASM's violation_rating is a threat score, not a bot score.
		ScoreKind: vendors.ScoreKindNone,
	}

	if rating, ok := vendors.AsFloat32(record.Fields["violation_rating"]); ok {
		event.Score = &rating
		event.ScoreKind = vendors.ScoreKindThreat
	}

	event.RawExtra, event.UnknownFields = collectExtra(record.Fields)
	event.Verdict = mapVerdict(record.Fields, &event)

	return event, nil
}

func parseEventTime(fields map[string]any) (eventTime time.Time, original string, err error) {
	value := firstOf(fields, "date_time", "rt", "start", "timestamp")
	if value == nil {
		return time.Time{}, "", fmt.Errorf("field date_time: timestamp is absent")
	}

	parsed, raw, parseErr := vendors.ParseTime(value)
	if parseErr != nil {
		return time.Time{}, raw, fmt.Errorf("field date_time: %w", parseErr)
	}
	return parsed, raw, nil
}

// resolveClientIP prefers the true client address over the connecting one.
//
// When BIG-IP sits behind another proxy, ip_client is that proxy. The
// X-Forwarded-For value is the actual client and is what the other two vendors
// report, so preferring it is what makes cross-vendor correlation line up at all.
func resolveClientIP(fields map[string]any) net.IP {
	if xff := vendors.AsString(fields["x_forwarded_for_header_value"]); xff != "" {
		// XFF may be a chain; the leftmost entry is the original client.
		first, _, _ := strings.Cut(xff, ",")
		if ip := vendors.ParseIP(first); ip != nil {
			return ip
		}
	}
	return vendors.ParseIP(vendors.AsString(firstOf(fields, "ip_client", "src")))
}

// resolveHost finds the HTTP Host header.
//
// BIG-IP ASM has no selectable `host` log field — an operator cannot add one, because
// ASM carries the Host header inside the full `request` field instead. Reading only a
// dedicated field therefore leaves RequestHost empty for every BIG-IP event, and that
// single gap defeats the product: hostname is the strongest heuristic join key, so F5
// events silently never correlate with any other vendor, and a hostname search misses
// all F5 traffic without saying so.
//
// `virtual_server` and `http_class_name` are NOT substitutes. They look like hostnames
// but are BIG-IP object paths — `/Common/jobs_bg_ASP1` — and joining on them would
// match nothing while appearing to work.
func resolveHost(fields map[string]any) string {
	if host := vendors.AsString(
		firstOf(fields, "host", "http_host", "hostname", "request_host")); host != "" {
		return host
	}
	host := headerFromRequest(vendors.AsString(fields["request"]), "host")
	// A Host header may carry a port; the join key is the name alone, or an F5 event on
	// :443 would never match the same request seen by a CDN.
	if trimmed, _, ok := strings.Cut(host, ":"); ok {
		host = trimmed
	}
	return strings.ToLower(strings.TrimSpace(host))
}

// resolveRequestID picks the identifier that can join this event to another vendor's.
//
// When Cloudflare fronts BIG-IP it passes its Ray ID through as the CF-Ray request
// header, and that value IS Cloudflare's own request identifier — so using it makes the
// two vendors' records of the same request join EXACTLY (tier 1) rather than by the
// heuristic shape-and-time match.
//
// Measured on live traffic, this is not a marginal improvement: CF-Ray is present on
// ~99% of ASM events and matched a Cloudflare event 200 times out of 200, while the Host
// header the heuristic join depends on survives ASM's log truncation only ~20% of the
// time. It is also immune to clock skew between the appliances, which a time-windowed
// heuristic is not.
//
// Falls back to support_id where there is no CF-Ray — a BIG-IP with no CDN in front, or
// a truncated request. support_id is never lost either way: collectExtra keeps every
// field, so F5's own support reference stays on the event.
func resolveRequestID(fields map[string]any) string {
	if ray := cloudflareRayID(vendors.AsString(fields["request"])); ray != "" {
		return ray
	}
	return vendors.AsString(firstOf(fields, "support_id", "cs3"))
}

// cloudflareRayID extracts the Ray ID from a CF-Ray header.
//
// The header carries the id and the edge datacentre — `a2753242eef8d0ef-SOF` — but
// Cloudflare's own logs record only the id, so the suffix has to go or the two values
// never match.
func cloudflareRayID(request string) string {
	value := headerFromRequest(request, "cf-ray")
	if value == "" {
		return ""
	}
	id, _, _ := strings.Cut(value, "-")
	return strings.TrimSpace(id)
}

// headerFromRequest returns a named header's value from a raw HTTP request.
//
// The line separators arrive BOTH ways: as real CRLF, and as the literal two-character
// escapes `\r\n` that ASM writes so a request never breaks the single-line log format.
// Handling only one of them works in a unit test and fails against the appliance.
func headerFromRequest(request, name string) string {
	if request == "" {
		return ""
	}

	// Normalise the escaped form first so one scan covers both.
	normalized := strings.NewReplacer("\\r\\n", "\n", "\\n", "\n", "\r\n", "\n").Replace(request)

	for _, line := range strings.Split(normalized, "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found || !strings.EqualFold(strings.TrimSpace(key), name) {
			continue
		}
		return strings.TrimSpace(value)
	}
	return ""
}

func resolveURI(fields map[string]any) (path, query string) {
	uri := vendors.AsString(firstOf(fields, "uri", "request"))
	path, query = vendors.SplitURI(uri)

	// ASM reports the query separately when configured to.
	if q := vendors.AsString(fields["query_string"]); q != "" {
		query = q
	}
	return path, query
}

// mapVerdict resolves the verdict from request_status, refining a block into rate
// limiting where the violation says so.
func mapVerdict(fields map[string]any, event *vendors.Event) string {
	status := strings.ToLower(strings.TrimSpace(
		vendors.AsString(firstOf(fields, "request_status", "outcome"))))

	verdict, ok := requestStatusVerdicts[status]
	if !ok {
		if event.RawExtra == nil {
			event.RawExtra = map[string]string{}
		}
		event.RawExtra["unmapped_request_status"] = status
		return vendors.VerdictUnknown
	}

	if verdict == vendors.VerdictBlocked && isRateLimit(fields) {
		return vendors.VerdictRateLimited
	}
	return verdict
}

func isRateLimit(fields map[string]any) bool {
	haystack := strings.ToLower(
		vendors.AsString(fields["violations"]) + " " +
			vendors.AsString(fields["attack_type"]) + " " +
			vendors.AsString(fields["sub_violations"]))

	for _, needle := range rateLimitViolations {
		if strings.Contains(haystack, needle) {
			return true
		}
	}
	return false
}

// firstOf returns the first present, non-empty value among the given keys.
//
// F5's field names differ between ASM JSON, CEF, and Distributed Cloud, so most
// lookups need a fallback chain rather than a single key.
func firstOf(fields map[string]any, keys ...string) any {
	for _, key := range keys {
		if value, ok := fields[key]; ok && vendors.AsString(value) != "" {
			return value
		}
	}
	return nil
}

func collectExtra(fields map[string]any) (extra map[string]string, unknown []string) {
	extra = make(map[string]string, len(fields))

	for key, value := range fields {
		if !knownFields[key] && !isCEFHeaderField(key) {
			unknown = append(unknown, key)
		}
		if rendered := vendors.AsString(value); rendered != "" {
			extra[key] = rendered
		}
	}
	return extra, unknown
}

// isCEFHeaderField reports whether a key came from the CEF header rather than the
// vendor's own schema, so CEF plumbing is not reported as schema drift.
func isCEFHeaderField(key string) bool {
	switch key {
	case "cef_version", "device_vendor", "device_product", "device_version",
		"signature_id", "name", "severity", "src", "dst", "spt", "dpt",
		"requestMethod", "request", "cn1", "cs1", "cs2", "cs3", "cs4", "cs5", "cs6",
		"deviceExternalId", "response_code", "policy_name", "request_status",
		"support_id", "violations":
		return true
	default:
		return false
	}
}
