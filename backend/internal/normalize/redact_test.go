package normalize

import (
	"net"
	"strings"
	"testing"

	"github.com/menta2k/siem/internal/vendors"
)

func sampleEvent() vendors.Event {
	return vendors.Event{
		Vendor:        vendors.Cloudflare,
		ClientIP:      net.ParseIP("203.0.113.45"),
		UserAgent:     "Mozilla/5.0 (secret-device-id-12345)",
		RequestPath:   "/account/settings",
		RequestQuery:  "token=abc123&email=user@example.com",
		RequestHost:   "shop.example.com",
		RequestMethod: "GET",
		RawExtra: map[string]string{
			"SessionCookie": "sess=deadbeef",
			"CacheStatus":   "hit",
		},
	}
}

func TestRedactWithEmptyPolicyIsANoOp(t *testing.T) {
	event := sampleEvent()

	got := Redact(event, nil)

	if got.UserAgent != event.UserAgent || got.RequestQuery != event.RequestQuery {
		t.Error("Redact() with no policy altered the event")
	}
}

// A redacted value must never survive into the derived view (FR-037).
func TestRedactMasksConfiguredFields(t *testing.T) {
	tests := []struct {
		name   string
		policy []string
		check  func(*testing.T, vendors.Event)
	}{
		{
			name:   "user agent",
			policy: []string{"user_agent"},
			check: func(t *testing.T, e vendors.Event) {
				if e.UserAgent != redactedPlaceholder {
					t.Errorf("UserAgent = %q, want it masked", e.UserAgent)
				}
			},
		},
		{
			name:   "query string",
			policy: []string{"request_query"},
			check: func(t *testing.T, e vendors.Event) {
				if e.RequestQuery != redactedPlaceholder {
					t.Errorf("RequestQuery = %q, want it masked", e.RequestQuery)
				}
			},
		},
		{
			name:   "client ip",
			policy: []string{"client_ip"},
			check: func(t *testing.T, e vendors.Event) {
				if e.ClientIP != nil {
					t.Errorf("ClientIP = %v, want it dropped", e.ClientIP)
				}
			},
		},
		{
			name:   "all vendor extras",
			policy: []string{"raw_extra"},
			check: func(t *testing.T, e vendors.Event) {
				for key, value := range e.RawExtra {
					if value != redactedPlaceholder {
						t.Errorf("RawExtra[%q] = %q, want it masked", key, value)
					}
				}
			},
		},
		{
			name:   "a single vendor extra by name",
			policy: []string{"sessioncookie"},
			check: func(t *testing.T, e vendors.Event) {
				if e.RawExtra["SessionCookie"] != redactedPlaceholder {
					t.Error("the named vendor field was not masked")
				}
				if e.RawExtra["CacheStatus"] != "hit" {
					t.Error("an unnamed vendor field was masked")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.check(t, Redact(sampleEvent(), tt.policy))
		})
	}
}

// The placeholder distinguishes "masked by policy" from "the vendor did not report
// it" — during an investigation those lead to very different conclusions.
func TestRedactedFieldIsDistinguishableFromAbsent(t *testing.T) {
	event := sampleEvent()
	event.RequestQuery = "" // genuinely absent

	got := Redact(event, []string{"request_query", "user_agent"})

	if got.RequestQuery != "" {
		t.Errorf("RequestQuery = %q, want an absent field left empty", got.RequestQuery)
	}
	if got.UserAgent != redactedPlaceholder {
		t.Errorf("UserAgent = %q, want the masked marker", got.UserAgent)
	}
}

// Redact must not mutate the caller's event, or the unredacted original would be
// destroyed for any other consumer holding it.
func TestRedactDoesNotMutateInput(t *testing.T) {
	event := sampleEvent()
	originalUA := event.UserAgent
	originalExtra := event.RawExtra["SessionCookie"]

	_ = Redact(event, []string{"user_agent", "raw_extra", "client_ip"})

	if event.UserAgent != originalUA {
		t.Error("Redact() mutated the caller's UserAgent")
	}
	if event.RawExtra["SessionCookie"] != originalExtra {
		t.Error("Redact() mutated the caller's RawExtra map")
	}
	if event.ClientIP == nil {
		t.Error("Redact() mutated the caller's ClientIP")
	}
}

func TestRedactPolicyIgnoresCaseAndWhitespace(t *testing.T) {
	got := Redact(sampleEvent(), []string{"  USER_AGENT  "})

	if got.UserAgent != redactedPlaceholder {
		t.Errorf("UserAgent = %q, want the policy matched case-insensitively", got.UserAgent)
	}
}

// A tenant that configures "password" expecting protection, and gets silence, is
// worse off than one told the field is not maskable.
func TestValidRedactionField(t *testing.T) {
	for _, field := range RedactableFields() {
		if !ValidRedactionField(field) {
			t.Errorf("ValidRedactionField(%q) = false for an advertised field", field)
		}
	}
	for _, field := range []string{"password", "verdict", "event_time", "", "nonsense"} {
		if ValidRedactionField(field) {
			t.Errorf("ValidRedactionField(%q) = true for a field that is not maskable", field)
		}
	}
}

func TestRedactableFieldsIsNotEmpty(t *testing.T) {
	if len(RedactableFields()) == 0 {
		t.Error("RedactableFields() is empty; the admin UI would offer nothing")
	}
}

// Regression: masking the common-model field alone left the original readable under
// the vendor's own name in RawExtra. Every adapter copies its native fields there, so
// a redacted user agent survived as ClientRequestUserAgent / ua / user_agent.
func TestRedactionScrubsVendorNativeCopiesOfTheSameValue(t *testing.T) {
	const secret = "Mozilla/5.0 (secret-device-id-12345)"

	event := sampleEvent()
	event.UserAgent = secret
	event.RawExtra = map[string]string{
		"ClientRequestUserAgent": secret,            // Cloudflare's name for it
		"ua":                     secret,            // DataDome's name for it
		"user_agent":             secret,            // F5's name for it
		"RequestLine":            "GET / " + secret, // embedded in a composite field
		"CacheStatus":            "hit",             // unrelated, must survive
	}

	got := Redact(event, []string{"user_agent"})

	for key, value := range got.RawExtra {
		if key == "CacheStatus" {
			continue
		}
		if strings.Contains(value, "secret-device-id") {
			t.Errorf("RawExtra[%q] = %q still carries the redacted value", key, value)
		}
	}
	if got.RawExtra["CacheStatus"] != "hit" {
		t.Error("an unrelated vendor field was masked")
	}
}

// The same leak applies to the client address.
func TestRedactionScrubsVendorNativeCopiesOfClientIP(t *testing.T) {
	event := sampleEvent()
	event.RawExtra = map[string]string{
		"ClientIP":  "203.0.113.45",
		"ip_client": "203.0.113.45",
		"country":   "DE",
	}

	got := Redact(event, []string{"client_ip"})

	if got.ClientIP != nil {
		t.Error("ClientIP was not dropped")
	}
	for _, key := range []string{"ClientIP", "ip_client"} {
		if got.RawExtra[key] != redactedPlaceholder {
			t.Errorf("RawExtra[%q] = %q still carries the address", key, got.RawExtra[key])
		}
	}
	if got.RawExtra["country"] != "DE" {
		t.Error("an unrelated field was masked")
	}
}
