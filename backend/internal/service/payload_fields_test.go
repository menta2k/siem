package service

import (
	"testing"

	"github.com/menta2k/siem/internal/vendors"
	"github.com/menta2k/siem/internal/vendors/cloudflare"
	"github.com/menta2k/siem/internal/vendors/f5"
)

func testRegistry(t *testing.T) *vendors.Registry {
	t.Helper()
	registry, err := vendors.NewRegistry(cloudflare.New(), f5.New())
	if err != nil {
		t.Fatalf("build registry: %v", err)
	}
	return registry
}

// THE POINT OF THE WHOLE CHANGE. raw_extra was a parsed copy of bytes raw_events already
// held in full, and the copy cost four times the original -- 12.79 GiB against 3.08 GiB --
// because Map interleaves keys and values per row while the payload column compresses
// whole blocks of similar JSON together. Rebuilding it on read for the one event being
// inspected replaces a per-row cost paid by every event ever ingested.
func TestRawExtraIsRebuiltFromThePayload(t *testing.T) {
	payload := []byte(`{"ClientIP":"203.0.113.9","ClientRequestHost":"shop.example.com",` +
		`"EdgeStartTimestamp":"2026-08-07T11:00:00Z","EdgeResponseStatus":200,` +
		`"RayID":"a27533e76c55d101","BotScore":42}`)

	extra, _ := payloadFields(testRegistry(t), "cloudflare", payload, nil)
	if len(extra) == 0 {
		t.Fatal("rebuilt raw_extra is empty, so the detail view lost the vendor fields")
	}
	if got := extra["BotScore"]; got != "42" {
		t.Errorf("BotScore = %q, want 42", got)
	}
}

// Redaction has to be RE-APPLIED on read. The stored copy was masked before it was
// written, so serving an unmasked rebuild would quietly undo the tenant's policy on the
// very field they asked to hide.
func TestTheTenantsRedactionPolicyIsReapplied(t *testing.T) {
	payload := []byte(`{"ClientIP":"203.0.113.9","ClientRequestHost":"shop.example.com",` +
		`"EdgeStartTimestamp":"2026-08-07T11:00:00Z","EdgeResponseStatus":200,` +
		`"ClientRequestUserAgent":"secret-agent/1.0"}`)

	extra, _ := payloadFields(testRegistry(t), "cloudflare", payload, []string{"user_agent"})

	for key, value := range extra {
		if value == "secret-agent/1.0" {
			t.Errorf("field %q returned the unmasked user agent despite the redaction policy", key)
		}
	}
}

// Unknown fields come from the SAME parse, which is why moving them off every search row
// costs nothing here: the work was already being done for raw_extra.
func TestUnknownFieldsComeFromTheSameParse(t *testing.T) {
	line := `support_id="123",request_status="passed",ip_client="203.0.113.4",` +
		`method="GET",date_time="2026-08-07 11:53:41",uri="/",` +
		`some_future_asm_field="surprise"`

	_, unknown := payloadFields(testRegistry(t), "f5", []byte(line), nil)

	found := false
	for _, name := range unknown {
		if name == "some_future_asm_field" {
			found = true
		}
	}
	if !found {
		t.Errorf("unknown fields %v do not name the unrecognised field, so schema drift "+
			"is invisible on the detail view", unknown)
	}
}

// A payload that cannot be re-parsed must not fail the read. The normalized row is still
// the answer to the analyst's question, and raw_payload is returned beside this — so
// degrading to empty is strictly better than turning a detail view into an error.
func TestAnUnparseablePayloadDegradesRatherThanFails(t *testing.T) {
	for name, payload := range map[string][]byte{
		"empty":    {},
		"garbage":  []byte("\x00\x01not a log line at all"),
		"trimmed":  []byte(`{"ClientIP":`),
		"unknown ": []byte(`{"whatever":1}`),
	} {
		t.Run(name, func(t *testing.T) {
			// Must not panic, and must yield nothing usable rather than partial junk.
			extra, unknown := payloadFields(testRegistry(t), "cloudflare", payload, nil)
			if len(extra) != 0 || len(unknown) != 0 {
				t.Errorf("%s produced extra=%v unknown=%v, want both empty", name, extra, unknown)
			}
		})
	}
}

// Retention is what makes the whole scheme safe, and an expired payload is the case where
// it stops being: the row outlives the bytes it was derived from. It must read as absent
// rather than as an error.
func TestAMissingPayloadYieldsNothing(t *testing.T) {
	extra, unknown := payloadFields(testRegistry(t), "cloudflare", nil, nil)
	if len(extra) != 0 || len(unknown) != 0 {
		t.Errorf("a missing payload produced extra=%v unknown=%v, want both empty", extra, unknown)
	}
}

// An unknown vendor cannot be parsed by anything, and must not take the read down.
func TestAnUnknownVendorIsNotAnError(t *testing.T) {
	extra, unknown := payloadFields(testRegistry(t), "not-a-vendor", []byte(`{}`), nil)
	if len(extra) != 0 || len(unknown) != 0 {
		t.Errorf("an unknown vendor produced extra=%v unknown=%v, want both empty", extra, unknown)
	}
}
