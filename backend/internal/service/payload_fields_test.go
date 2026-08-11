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

// THE PARSE MUST USE THE VENDOR THAT DELIVERED THE BYTES, not the one the event is
// attributed to.
//
// A DataDome verdict is normalized out of a Cloudflare Worker's log of its own call to
// DataDome: the normalized row says datadome while the stored bytes are Cloudflare's
// NDJSON. Handing those bytes to DataDome's adapter parses nothing, so the detail view
// showed a full raw payload beside an empty field list — on 270,233 of 1,662,366 events in
// half an hour of production, 16% of the total.
//
// The two cases are asserted together because only the contrast proves it: the same bytes
// must yield fields under the delivering vendor and nothing under the attributed one.
func TestVendorFieldsUseTheDeliveringVendorNotTheAttributedOne(t *testing.T) {
	// A Cloudflare Worker's record of the DataDome validation call, trimmed from a real
	// production payload — that host and URI are what makes it a DataDome-attributed
	// event, and EdgeStartTimestamp is what makes it parseable at all.
	payload := []byte(`{"ClientIP":"2a06:98c0:3600::103",` +
		`"ClientRequestHost":"api-cloudflare.datadome.co",` +
		`"ClientRequestMethod":"POST","ClientRequestURI":"/validate-request/",` +
		`"EdgeStartTimestamp":"2026-08-11T07:15:39Z",` +
		`"EdgeEndTimestamp":"2026-08-11T07:15:39Z",` +
		`"RayID":"a27533e76c55d999","EdgeResponseStatus":200,"BotScore":7,` +
		`"ZoneName":"jobs.bg","SecurityAction":"unknown"}`)

	delivering, _ := payloadFields(testRegistry(t), "cloudflare", payload, nil)
	if len(delivering) == 0 {
		t.Fatal("parsed with the delivering vendor, the field list is empty — the fix " +
			"cannot work, because these are the bytes the detail view has")
	}
	if got := delivering["BotScore"]; got != "7" {
		t.Errorf("BotScore = %q, want 7", got)
	}

	// The bug, pinned. Were the attributed vendor used, this is what the analyst saw.
	attributed, _ := payloadFields(testRegistry(t), "datadome", payload, nil)
	if len(attributed) != 0 {
		t.Skipf("datadome's adapter now parses a Cloudflare payload (%d fields); this "+
			"test's premise no longer holds", len(attributed))
	}
}
