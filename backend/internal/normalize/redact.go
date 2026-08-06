package normalize

import (
	"strings"

	"github.com/menta2k/siem/internal/vendors"
)

// redactedPlaceholder replaces a masked value.
//
// A fixed marker rather than an empty string, so an analyst can tell "this field was
// redacted by policy" from "this vendor did not report it" — the two lead to very
// different conclusions during an investigation.
const redactedPlaceholder = "[REDACTED]"

// redactableFields names the common-model fields a tenant may mask. Anything outside
// this set is either structural (timestamps, ids) or already non-identifying.
var redactableFields = map[string]bool{
	"user_agent":    true,
	"request_query": true,
	"request_path":  true,
	"client_ip":     true,
	"raw_extra":     true,
}

// Redact applies a tenant's masking policy, returning a NEW event.
//
// Masking happens here, before the row is built, so a redacted value is never written
// in readable form anywhere — not to normalized_events, not to the correlation
// stream (FR-037). The raw_events copy deliberately still holds the original bytes:
// redaction governs the derived, queryable view, while the vendor's evidence is
// retained under the tenant's retention policy and deleted with it.
//
// The input event is not modified.
func Redact(event vendors.Event, policy []string) vendors.Event {
	if len(policy) == 0 {
		return event
	}

	masked := make(map[string]bool, len(policy))
	for _, field := range policy {
		masked[strings.ToLower(strings.TrimSpace(field))] = true
	}

	redacted := event

	// Values removed from the common model must also be scrubbed from RawExtra.
	//
	// Every adapter copies the vendor's native fields into RawExtra, so masking only
	// the common-model field leaves the original readable under its vendor name —
	// ClientRequestUserAgent, ua, user_agent. Collecting the values here and matching
	// on them below closes that leak whatever the vendor calls the field.
	var leaked []string

	if masked["user_agent"] && redacted.UserAgent != "" {
		leaked = append(leaked, redacted.UserAgent)
		redacted.UserAgent = redactedPlaceholder
	}
	if masked["request_query"] && redacted.RequestQuery != "" {
		leaked = append(leaked, redacted.RequestQuery)
		redacted.RequestQuery = redactedPlaceholder
	}
	if masked["request_path"] && redacted.RequestPath != "" {
		leaked = append(leaked, redacted.RequestPath)
		redacted.RequestPath = redactedPlaceholder
	}
	if masked["client_ip"] {
		if redacted.ClientIP != nil {
			leaked = append(leaked, redacted.ClientIP.String())
		}
		// The address is dropped entirely rather than replaced with a marker, since
		// the column is typed. Correlation on this tenant degrades to host+path, which
		// is the accepted cost of the policy.
		redacted.ClientIP = nil
	}

	redacted.RawExtra = redactExtra(event.RawExtra, masked, leaked)

	return redacted
}

// redactExtra masks vendor-specific fields, returning a new map so the caller's is
// left untouched.
//
// Masking is by key AND by value: `leaked` carries the values already removed from
// the common model, and any RawExtra entry holding one of them is masked too,
// regardless of what the vendor named it. Matching on value over-masks slightly in
// the rare case a redacted string legitimately appears elsewhere — the safe direction
// for a privacy control.
func redactExtra(
	extra map[string]string, masked map[string]bool, leaked []string,
) map[string]string {
	if len(extra) == 0 {
		return extra
	}

	out := make(map[string]string, len(extra))
	for key, value := range extra {
		lowered := strings.ToLower(key)
		// A tenant may name a vendor field directly, or mask the whole extras map.
		if masked["raw_extra"] || masked[lowered] || containsValue(leaked, value) {
			out[key] = redactedPlaceholder
			continue
		}
		out[key] = value
	}
	return out
}

// containsValue reports whether a RawExtra value carries something already redacted.
func containsValue(leaked []string, value string) bool {
	if value == "" {
		return false
	}
	for _, secret := range leaked {
		// Substring rather than equality: a vendor may store the value inside a
		// composite field, such as a full request line containing the path.
		if secret != "" && strings.Contains(value, secret) {
			return true
		}
	}
	return false
}

// RedactableFields lists the fields a tenant may configure for masking, so the admin
// UI offers a validated set rather than free text that silently does nothing.
func RedactableFields() []string {
	fields := make([]string, 0, len(redactableFields))
	for name := range redactableFields {
		fields = append(fields, name)
	}
	return fields
}

// ValidRedactionField reports whether a policy entry names something maskable.
//
// A tenant that types "password" expecting protection, and gets silence, is worse off
// than one told the field is not maskable.
func ValidRedactionField(name string) bool {
	return redactableFields[strings.ToLower(strings.TrimSpace(name))]
}
