package cloudflare

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/menta2k/siem/internal/vendors"
)

// fixture loads a corpus file. The corpus is the contract: if a vendor's real output
// changes, the fixture changes and these tests are what notice.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "..", "test", "fixtures", "cloudflare", name)
	data, err := os.ReadFile(path) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

// parseFixture is the common load-detect-parse sequence.
func parseFixture(t *testing.T, name string) []vendors.RawRecord {
	t.Helper()
	a := New()
	payload := fixture(t, name)

	format, ok := a.Detect(payload)
	if !ok {
		t.Fatalf("Detect() did not recognize fixture %s", name)
	}
	records, err := a.Parse(payload, format)
	if err != nil {
		t.Fatalf("Parse(%s) error = %v", name, err)
	}
	return records
}

func TestVendorName(t *testing.T) {
	if got := New().Vendor(); got != vendors.Cloudflare {
		t.Errorf("Vendor() = %q, want %q", got, vendors.Cloudflare)
	}
}

func TestDetect(t *testing.T) {
	a := New()
	tests := []struct {
		name    string
		payload []byte
		want    vendors.Format
		ok      bool
	}{
		{"ndjson", []byte(`{"RayID":"a"}` + "\n" + `{"RayID":"b"}`), vendors.FormatNDJSON, true},
		{"single object", []byte(`{"RayID":"a"}`), vendors.FormatNDJSON, true},
		{"json array", []byte(`[{"RayID":"a"}]`), vendors.FormatJSON, true},
		{"empty", []byte(``), vendors.FormatUnknown, false},
		{"whitespace only", []byte("  \n\t "), vendors.FormatUnknown, false},
		{"not json", []byte(`CEF:0|F5|ASM|`), vendors.FormatUnknown, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := a.Detect(tt.payload)
			if ok != tt.ok || (tt.ok && got != tt.want) {
				t.Errorf("Detect() = (%q, %v), want (%q, %v)", got, ok, tt.want, tt.ok)
			}
		})
	}
}

// Logpush can deliver gzipped, so the adapter must handle it transparently.
func TestDetectAndParseGzip(t *testing.T) {
	a := New()
	plain := fixture(t, "valid.ndjson")

	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	if _, err := w.Write(plain); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	format, ok := a.Detect(compressed.Bytes())
	if !ok {
		t.Fatal("Detect() did not recognize a gzipped delivery")
	}
	records, err := a.Parse(compressed.Bytes(), format)
	if err != nil {
		t.Fatalf("Parse() on gzip error = %v", err)
	}
	if len(records) != 5 {
		t.Errorf("Parse() returned %d records from the gzipped fixture, want 5", len(records))
	}
}

func TestParseValidFixture(t *testing.T) {
	records := parseFixture(t, "valid.ndjson")
	if len(records) != 5 {
		t.Fatalf("Parse() returned %d records, want 5", len(records))
	}
	for i, r := range records {
		if r.Fields == nil {
			t.Errorf("record %d has no decoded fields", i)
		}
		if len(r.Bytes) == 0 {
			t.Errorf("record %d did not retain its original bytes", i)
		}
	}
}

// The scanner reuses its buffer; records must own their bytes or they all end up
// holding the last line.
func TestParseRecordsOwnTheirBytes(t *testing.T) {
	records := parseFixture(t, "valid.ndjson")

	first := string(records[0].Bytes)
	last := string(records[len(records)-1].Bytes)

	if first == last {
		t.Fatal("all records share the same bytes; the scanner buffer was not copied")
	}
	if !strings.Contains(first, "8d1f2a3b4c5d6e7f") {
		t.Errorf("first record bytes = %q, want the first RayID", first)
	}
}

// The full verdict mapping table. Correlation's disagreement detection is only as
// good as this, so every action is pinned.
func TestVerdictMapping(t *testing.T) {
	a := New()
	tests := []struct {
		action string
		want   string
	}{
		{"block", vendors.VerdictBlocked},
		{"drop", vendors.VerdictBlocked},
		{"challenge", vendors.VerdictChallenged},
		{"jschallenge", vendors.VerdictChallenged},
		{"managed_challenge", vendors.VerdictChallenged},
		{"connectionClose", vendors.VerdictRateLimited},
		{"allow", vendors.VerdictAllowed},
		{"log", vendors.VerdictAllowed},
		{"skip", vendors.VerdictAllowed},
		{"unknown", vendors.VerdictAllowed},
		{"", vendors.VerdictAllowed},
		// Staging: the rule matched but was not enforced. Must NOT read as allowed,
		// or it manufactures a false disagreement against a vendor that blocked.
		{"simulate", vendors.VerdictMonitored},
		// An action Cloudflare adds tomorrow.
		{"quantum_shield", vendors.VerdictUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			payload := []byte(`{"RayID":"x","EdgeStartTimestamp":"2026-08-06T12:00:00Z",` +
				`"ClientIP":"203.0.113.1","ClientRequestHost":"h","ClientRequestURI":"/",` +
				`"ClientRequestMethod":"GET","SecurityAction":"` + tt.action + `"}`)

			records, err := a.Parse(payload, vendors.FormatNDJSON)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			event, err := a.Normalize(records[0])
			if err != nil {
				t.Fatalf("Normalize() error = %v", err)
			}
			if event.Verdict != tt.want {
				t.Errorf("action %q mapped to %q, want %q", tt.action, event.Verdict, tt.want)
			}
		})
	}
}

// An unmapped action must be preserved, not discarded, so an operator can see what
// the vendor actually said.
func TestUnmappedActionIsPreserved(t *testing.T) {
	a := New()
	payload := []byte(`{"RayID":"x","EdgeStartTimestamp":"2026-08-06T12:00:00Z",` +
		`"ClientIP":"203.0.113.1","ClientRequestHost":"h","ClientRequestURI":"/",` +
		`"ClientRequestMethod":"GET","SecurityAction":"brand_new_action"}`)

	records, _ := a.Parse(payload, vendors.FormatNDJSON)
	event, err := a.Normalize(records[0])
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if event.Verdict != vendors.VerdictUnknown {
		t.Errorf("Verdict = %q, want %q", event.Verdict, vendors.VerdictUnknown)
	}
	if event.RawExtra["unmapped_security_action"] != "brand_new_action" {
		t.Errorf("the unmapped action was not preserved: %v", event.RawExtra)
	}
}

func TestNormalizeFullRecord(t *testing.T) {
	records := parseFixture(t, "valid.ndjson")
	a := New()

	event, err := a.Normalize(records[0])
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	checks := []struct {
		field string
		got   any
		want  any
	}{
		{"Vendor", event.Vendor, vendors.Cloudflare},
		{"VendorRequestID", event.VendorRequestID, "8d1f2a3b4c5d6e7f"},
		{"VendorAccount", event.VendorAccount, "example.com"},
		{"ClientIP", event.ClientIP.String(), "203.0.113.45"},
		{"ClientASN", event.ClientASN, uint32(64512)},
		{"ClientCountry", event.ClientCountry, "DE"},
		{"RequestHost", event.RequestHost, "shop.example.com"},
		{"RequestPath", event.RequestPath, "/api/checkout"},
		{"RequestQuery", event.RequestQuery, "step=2"},
		{"RequestMethod", event.RequestMethod, "POST"},
		{"HTTPStatus", event.HTTPStatus, uint16(403)},
		{"Verdict", event.Verdict, vendors.VerdictBlocked},
		{"VerdictReason", event.VerdictReason, "SQLi attempt in body"},
		{"RuleID", event.RuleID, "100015"},
		{"ScoreKind", event.ScoreKind, vendors.ScoreKindNone},
	}

	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.field, c.got, c.want)
		}
	}

	if event.EventTime.Format("2006-01-02T15:04:05Z") != "2026-08-06T12:00:00Z" {
		t.Errorf("EventTime = %v, want 2026-08-06T12:00:00Z", event.EventTime)
	}
	if event.EventTimeOriginal == "" {
		t.Error("EventTimeOriginal was not preserved")
	}
	if len(event.RuleIDs) != 2 {
		t.Errorf("RuleIDs = %v, want 2 entries", event.RuleIDs)
	}
}

// Contract obligation 2: a missing optional field must not reject the record.
func TestNormalizeToleratesMissingOptionalFields(t *testing.T) {
	records := parseFixture(t, "missing_optional.ndjson")

	event, err := New().Normalize(records[0])
	if err != nil {
		t.Fatalf("Normalize() rejected a record with missing optional fields: %v", err)
	}

	if event.VendorRequestID != "aa11bb22cc33dd44" {
		t.Errorf("VendorRequestID = %q, want it populated", event.VendorRequestID)
	}
	if event.HTTPStatus != 0 {
		t.Errorf("HTTPStatus = %d, want 0 for an absent field", event.HTTPStatus)
	}
	if event.ClientCountry != "" {
		t.Errorf("ClientCountry = %q, want empty for an absent field", event.ClientCountry)
	}
	if event.Verdict != vendors.VerdictAllowed {
		t.Errorf("Verdict = %q, want allowed when no action was reported", event.Verdict)
	}
}

// Contract obligation 3: unknown fields are preserved and reported, never fatal.
func TestNormalizeReportsUnknownFields(t *testing.T) {
	records := parseFixture(t, "unknown_fields.ndjson")

	event, err := New().Normalize(records[0])
	if err != nil {
		t.Fatalf("Normalize() failed on a record with unknown fields: %v", err)
	}

	unknown := strings.Join(event.UnknownFields, ",")
	for _, want := range []string{"BrandNewFieldV2", "AnotherUnexpectedField"} {
		if !strings.Contains(unknown, want) {
			t.Errorf("UnknownFields = %v, want it to include %q", event.UnknownFields, want)
		}
	}
	if event.RawExtra["BrandNewFieldV2"] != "surprise" {
		t.Errorf("the unknown field's value was not preserved: %v", event.RawExtra)
	}
	// A known field must not be reported as drift, or the warning is useless noise.
	if strings.Contains(unknown, "RayID") {
		t.Error("a known field was reported as unknown")
	}
}

// Contract obligation 1 (partial): a malformed line yields a record with no fields,
// so the caller can dead-letter it individually rather than losing the batch.
func TestParseIsolatesMalformedLines(t *testing.T) {
	records := parseFixture(t, "malformed.ndjson")
	a := New()

	var decoded, failed int
	for _, r := range records {
		if _, err := a.Normalize(r); err != nil {
			failed++
			continue
		}
		decoded++
	}

	if failed == 0 {
		t.Error("no record failed; the malformed fixture should produce failures")
	}
	if len(records) < 3 {
		t.Errorf("Parse() returned %d records, want every line preserved for dead-lettering",
			len(records))
	}
}

func TestNormalizeRejectsBadTimestamp(t *testing.T) {
	a := New()
	payload := []byte(`{"RayID":"x","EdgeStartTimestamp":"not-a-timestamp",` +
		`"ClientIP":"203.0.113.1","ClientRequestHost":"h","ClientRequestURI":"/"}`)

	records, _ := a.Parse(payload, vendors.FormatNDJSON)
	if _, err := a.Normalize(records[0]); err == nil {
		t.Error("Normalize() accepted an unparseable timestamp")
	} else if !strings.Contains(err.Error(), "EdgeStartTimestamp") {
		t.Errorf("error = %q, want it to name the offending field", err)
	}
}

// Logpush emits epoch nanoseconds when configured to, so both encodings must work.
func TestNormalizeAcceptsEpochNanoseconds(t *testing.T) {
	records := parseFixture(t, "epoch_nanos.ndjson")

	event, err := New().Normalize(records[0])
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if event.EventTime.Year() != 2026 {
		t.Errorf("EventTime = %v, want a 2026 timestamp from epoch nanoseconds", event.EventTime)
	}
}

// Contract obligation 4: Normalize is pure. Same input, same output — which is what
// makes the correlation replay corpus meaningful.
func TestNormalizeIsDeterministic(t *testing.T) {
	records := parseFixture(t, "valid.ndjson")
	a := New()

	first, err := a.Normalize(records[0])
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	second, err := a.Normalize(records[0])
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if first.VendorRequestID != second.VendorRequestID ||
		!first.EventTime.Equal(second.EventTime) ||
		first.Verdict != second.Verdict ||
		first.RequestPath != second.RequestPath {
		t.Error("Normalize() is not deterministic across calls")
	}
}

// Attacker-controlled strings must survive normalization as inert data — escaping is
// the render boundary's job, and mangling them here would corrupt the evidence.
func TestNormalizePreservesAttackerControlledStringsVerbatim(t *testing.T) {
	records := parseFixture(t, "xss.ndjson")

	event, err := New().Normalize(records[0])
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if event.UserAgent != `<img src=x onerror=alert(1)>` {
		t.Errorf("UserAgent = %q, want the payload preserved verbatim", event.UserAgent)
	}
	if !strings.Contains(event.VerdictReason, "<svg/onload=") {
		t.Errorf("VerdictReason = %q, want the payload preserved", event.VerdictReason)
	}
}

// NAT and carrier-grade ranges must be flagged, since that is what downgrades a
// tier-2 join to low confidence.
func TestSharedIPDetection(t *testing.T) {
	a := New()
	tests := []struct {
		ip     string
		shared bool
	}{
		{"203.0.113.45", false},
		{"10.20.30.40", true},
		{"192.168.1.1", true},
		{"172.16.5.5", true},
		{"100.64.12.9", true}, // carrier-grade NAT — the common mobile case
		{"8.8.8.8", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			payload := []byte(`{"RayID":"x","EdgeStartTimestamp":"2026-08-06T12:00:00Z",` +
				`"ClientIP":"` + tt.ip + `","ClientRequestHost":"h","ClientRequestURI":"/",` +
				`"ClientRequestMethod":"GET","SecurityAction":"allow"}`)

			records, _ := a.Parse(payload, vendors.FormatNDJSON)
			event, err := a.Normalize(records[0])
			if err != nil {
				t.Fatalf("Normalize() error = %v", err)
			}
			if event.ClientIPShared != tt.shared {
				t.Errorf("ClientIPShared for %s = %v, want %v", tt.ip, event.ClientIPShared, tt.shared)
			}
		})
	}
}

func TestParseRejectsEmptyDelivery(t *testing.T) {
	if _, err := New().Parse([]byte("  \n  \n"), vendors.FormatNDJSON); err == nil {
		t.Error("Parse() accepted a delivery containing no records")
	}
}

func TestNormalizeRejectsUndecodableRecord(t *testing.T) {
	_, err := New().Normalize(vendors.RawRecord{Bytes: []byte("garbage"), Fields: nil})
	if err == nil {
		t.Error("Normalize() accepted a record that never decoded")
	}
}

// recordFrom builds a single Logpush record from a JSON object, for the cases that turn
// on one field rather than on a whole fixture.
func recordFrom(t *testing.T, line string) vendors.RawRecord {
	t.Helper()
	a := New()

	format, ok := a.Detect([]byte(line))
	if !ok {
		t.Fatal("Detect() did not recognize the record")
	}
	records, err := a.Parse([]byte(line), format)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("Parse() returned %d records, want 1", len(records))
	}
	return records[0]
}

// ja4Record is a minimal Logpush line carrying a fingerprint.
const ja4Record = `{"RayID":"8f1a2b3c4d5e6f70","EdgeStartTimestamp":"2026-08-13T10:00:00Z",` +
	`"ClientIP":"203.0.113.10","ClientRequestHost":"example.com",` +
	`"ClientRequestURI":"/login","ClientRequestMethod":"POST",` +
	`"EdgeResponseStatus":200,"SecurityAction":"allow",` +
	`"JA4":"t13d1516h2_8daaf6152771_b0da82dd1658"}`

// The fingerprint is what an analyst pivots on when an attacker rotates addresses and
// user agents but not their TLS stack, so it has to reach the common model rather than
// stay buried in the vendor's own fields.
func TestNormalizeExtractsJA4(t *testing.T) {
	event, err := New().Normalize(recordFrom(t, ja4Record))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	const want = "t13d1516h2_8daaf6152771_b0da82dd1658"
	if event.JA4 != want {
		t.Errorf("JA4 = %q, want %q", event.JA4, want)
	}
}

// THE DRIFT FALSE POSITIVE THIS CLOSES. JA4 was not in knownFields, so every record of
// a Logpush job configured to send it was reported as carrying an unknown field. That is
// a permanent warning on a correctly-configured feed, and a schema-drift signal that is
// always on is one an operator learns to ignore.
func TestJA4IsNotReportedAsSchemaDrift(t *testing.T) {
	event, err := New().Normalize(recordFrom(t, ja4Record))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	for _, field := range event.UnknownFields {
		if field == "JA4" {
			t.Errorf("JA4 was reported as drift: UnknownFields = %v", event.UnknownFields)
		}
	}
}

// A vendor that reports no fingerprint must normalize to an empty one rather than fail.
// Cloudflare only emits JA4 when the Logpush job selects it, so absence is the ordinary
// case, not an error.
func TestNormalizeToleratesAMissingJA4(t *testing.T) {
	records := parseFixture(t, "valid.ndjson")

	event, err := New().Normalize(records[0])
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if event.JA4 != "" {
		t.Errorf("JA4 = %q, want empty for a record that carries none", event.JA4)
	}
}
