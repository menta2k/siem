package f5

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/menta2k/siem/internal/vendors"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "..", "test", "fixtures", "f5", name)
	data, err := os.ReadFile(path) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

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
	if got := New().Vendor(); got != vendors.F5 {
		t.Errorf("Vendor() = %q, want %q", got, vendors.F5)
	}
}

// All three encodings appear in real BIG-IP deployments, so all three must be
// recognized without the customer reconfiguring their logging.
func TestDetectAllThreeEncodings(t *testing.T) {
	a := New()
	tests := []struct {
		name    string
		fixture string
		want    vendors.Format
	}{
		{"json array", "valid.json", vendors.FormatJSON},
		{"ndjson", "valid.ndjson", vendors.FormatNDJSON},
		{"cef", "valid.cef", vendors.FormatCEF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := a.Detect(fixture(t, tt.fixture))
			if !ok {
				t.Fatalf("Detect() did not recognize %s", tt.fixture)
			}
			if got != tt.want {
				t.Errorf("Detect() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetectSyslogKeyValue(t *testing.T) {
	line := []byte(`Aug  6 12:00:00 bigip01 ASM: support_id=123456 ip_client=203.0.113.9 ` +
		`method=GET uri=/ request_status=passed`)

	got, ok := New().Detect(line)
	if !ok || got != vendors.FormatSyslog {
		t.Errorf("Detect() = (%q, %v), want (syslog, true)", got, ok)
	}
}

func TestDetectRejectsUnrecognized(t *testing.T) {
	a := New()
	for _, payload := range [][]byte{nil, []byte(""), []byte("   "), []byte("hello world")} {
		if _, ok := a.Detect(payload); ok {
			t.Errorf("Detect(%q) reported recognized, want false", payload)
		}
	}
}

func TestNormalizeJSONRecord(t *testing.T) {
	records := parseFixture(t, "valid.json")
	if len(records) != 3 {
		t.Fatalf("Parse() returned %d records, want 3", len(records))
	}

	event, err := New().Normalize(records[0])
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	checks := []struct {
		field string
		got   any
		want  any
	}{
		{"Vendor", event.Vendor, vendors.F5},
		{"VendorRequestID", event.VendorRequestID, "5847392018374652"},
		{"ClientIP", event.ClientIP.String(), "203.0.113.45"},
		{"ClientCountry", event.ClientCountry, "DE"},
		{"RequestPath", event.RequestPath, "/api/checkout"},
		{"RequestQuery", event.RequestQuery, "step=2"},
		{"RequestMethod", event.RequestMethod, "POST"},
		{"HTTPStatus", event.HTTPStatus, uint16(403)},
		{"Verdict", event.Verdict, vendors.VerdictBlocked},
		{"VerdictReason", event.VerdictReason, "SQL-Injection"},
		{"RuleID", event.RuleID, "prod_waf_policy"},
		{"ScoreKind", event.ScoreKind, vendors.ScoreKindThreat},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.field, c.got, c.want)
		}
	}

	if event.Score == nil || *event.Score != 5 {
		t.Errorf("Score = %v, want 5 (violation_rating)", event.Score)
	}
	// violations is a semicolon-delimited string in ASM output.
	if len(event.RuleIDs) != 2 {
		t.Errorf("RuleIDs = %v, want the 2 violations split out", event.RuleIDs)
	}
}

// The verdict table. "alerted" is the one that matters most: it means the policy was
// in transparent mode, not that the request was judged safe.
func TestVerdictMapping(t *testing.T) {
	a := New()
	tests := []struct {
		name       string
		status     string
		violations string
		want       string
	}{
		{"blocked", "blocked", "", vendors.VerdictBlocked},
		{"passed", "passed", "", vendors.VerdictAllowed},
		{"alerted is monitored not allowed", "alerted", "", vendors.VerdictMonitored},
		{"blocked by rate limit", "blocked", "Brute Force attack detected", vendors.VerdictRateLimited},
		{"blocked by anomaly", "blocked", "HTTP protocol anomaly", vendors.VerdictRateLimited},
		{"unmapped status", "quarantined", "", vendors.VerdictUnknown},
		{"empty status", "", "", vendors.VerdictUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := []byte(`[{"support_id":"1","date_time":"2026-08-06 12:00:00",` +
				`"ip_client":"203.0.113.1","method":"GET","uri":"/",` +
				`"request_status":"` + tt.status + `","violations":"` + tt.violations + `"}]`)

			records, err := a.Parse(payload, vendors.FormatJSON)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			event, err := a.Normalize(records[0])
			if err != nil {
				t.Fatalf("Normalize() error = %v", err)
			}
			if event.Verdict != tt.want {
				t.Errorf("status %q verdict = %q, want %q", tt.status, event.Verdict, tt.want)
			}
		})
	}
}

// CEF is what BIG-IP emits by default in many deployments, and the cs1..cs6 slots
// must resolve to their labelled names rather than reaching the model as "cs3".
func TestNormalizeCEFRecord(t *testing.T) {
	records := parseFixture(t, "valid.cef")
	if len(records) != 2 {
		t.Fatalf("Parse() returned %d CEF records, want 2", len(records))
	}

	event, err := New().Normalize(records[0])
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if event.VendorRequestID != "5847392018374652" {
		t.Errorf("VendorRequestID = %q, want the cs3/support_id value resolved by label",
			event.VendorRequestID)
	}
	if event.ClientIP == nil || event.ClientIP.String() != "203.0.113.45" {
		t.Errorf("ClientIP = %v, want 203.0.113.45 from src=", event.ClientIP)
	}
	if event.RequestMethod != "POST" {
		t.Errorf("RequestMethod = %q, want POST", event.RequestMethod)
	}
	if event.HTTPStatus != 403 {
		t.Errorf("HTTPStatus = %d, want 403 from cn1", event.HTTPStatus)
	}
	if event.Verdict != vendors.VerdictBlocked {
		t.Errorf("Verdict = %q, want blocked from the cs2/request_status label", event.Verdict)
	}
	if event.RuleID != "prod_waf_policy" {
		t.Errorf("RuleID = %q, want the cs1/policy_name value", event.RuleID)
	}
}

// CEF values commonly contain spaces. Splitting naively on whitespace would truncate
// most of the useful fields.
func TestCEFExtensionHandlesMultiWordValues(t *testing.T) {
	line := []byte(`CEF:0|F5|ASM|13.1.0|Sig|SQL-Injection|8|` +
		`src=203.0.113.1 cs4=Attack signature detected in body cs4Label=violations ` +
		`requestMethod=GET`)

	records, err := New().Parse(line, vendors.FormatCEF)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	fields := records[0].Fields
	if fields == nil {
		t.Fatal("the CEF line did not decode")
	}

	got, _ := fields["violations"].(string)
	if got != "Attack signature detected in body" {
		t.Errorf("violations = %q, want the full multi-word value", got)
	}
}

// When BIG-IP sits behind another proxy, ip_client is that proxy. Preferring
// X-Forwarded-For is what makes F5's client address line up with the other vendors'.
func TestClientIPPrefersForwardedFor(t *testing.T) {
	payload := []byte(`[{"support_id":"1","date_time":"2026-08-06 12:00:00",` +
		`"ip_client":"10.0.0.7","x_forwarded_for_header_value":"203.0.113.99, 10.0.0.7",` +
		`"method":"GET","uri":"/","request_status":"passed"}]`)

	records, err := New().Parse(payload, vendors.FormatJSON)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	event, err := New().Normalize(records[0])
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if event.ClientIP.String() != "203.0.113.99" {
		t.Errorf("ClientIP = %v, want the leftmost X-Forwarded-For entry, not the proxy",
			event.ClientIP)
	}
	if event.ClientIPShared {
		t.Error("ClientIPShared = true for a public address")
	}
}

func TestNormalizeToleratesMissingOptionalFields(t *testing.T) {
	records := parseFixture(t, "missing_optional.json")

	event, err := New().Normalize(records[0])
	if err != nil {
		t.Fatalf("Normalize() rejected a minimal record: %v", err)
	}
	if event.VendorRequestID != "7047392018374652" {
		t.Errorf("VendorRequestID = %q, want it populated", event.VendorRequestID)
	}
	if event.HTTPStatus != 0 {
		t.Errorf("HTTPStatus = %d, want 0 when absent", event.HTTPStatus)
	}
	if event.Score != nil {
		t.Errorf("Score = %v, want nil when violation_rating is absent", event.Score)
	}
}

func TestNormalizeReportsUnknownFields(t *testing.T) {
	records := parseFixture(t, "unknown_fields.json")

	event, err := New().Normalize(records[0])
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	unknown := strings.Join(event.UnknownFields, ",")
	for _, want := range []string{"brand_new_f5_field", "another_new_one"} {
		if !strings.Contains(unknown, want) {
			t.Errorf("UnknownFields = %v, want it to include %q", event.UnknownFields, want)
		}
	}
	if strings.Contains(unknown, "support_id") {
		t.Error("a known field was reported as schema drift")
	}
}

// Carrier-grade NAT and RFC1918 ranges must be flagged: this is what downgrades a
// tier-2 join to low confidence instead of asserting a false match.
func TestNATAddressesAreFlaggedAsShared(t *testing.T) {
	records := parseFixture(t, "nat.json")
	a := New()

	for i, r := range records {
		event, err := a.Normalize(r)
		if err != nil {
			t.Fatalf("Normalize(%d) error = %v", i, err)
		}
		if !event.ClientIPShared {
			t.Errorf("record %d with IP %v was not flagged as shared", i, event.ClientIP)
		}
	}
}

// BIG-IP resolves network attribution from the connection it terminates, which behind
// Cloudflare is a Cloudflare edge address. An asn field here therefore names the CDN, not
// the client, and mapping it would attribute an ISP's traffic to AS13335 — so it stays
// unmapped and is kept in RawExtra instead, where it is visible without being claimed.
func TestASNIsNotAdoptedFromTheAppliance(t *testing.T) {
	payload := []byte(`[{"support_id":"1","date_time":"2026-08-09T12:00:00Z",` +
		`"ip_client":"203.0.113.1","method":"GET","uri":"/","asn":"13335",` +
		`"geo_location":"BG","request_status":"passed"}]`)

	records, err := New().Parse(payload, vendors.FormatJSON)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	event, err := New().Normalize(records[0])
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if event.ClientASN != 0 {
		t.Errorf("ClientASN = %d, want 0: the appliance sees the CDN's network, not the client's",
			event.ClientASN)
	}
	// Kept rather than discarded — an operator investigating still gets to see it.
	if got := event.RawExtra["asn"]; got != "13335" {
		t.Errorf("RawExtra[asn] = %q, want %q", got, "13335")
	}
	// The country IS mapped: ASM resolves it per-request and production shows it
	// tracking the real client population rather than the edge.
	if event.ClientCountry != "BG" {
		t.Errorf("ClientCountry = %q, want %q", event.ClientCountry, "BG")
	}
}

func TestNormalizeRejectsMissingTimestamp(t *testing.T) {
	payload := []byte(`[{"support_id":"1","ip_client":"203.0.113.1","method":"GET","uri":"/"}]`)

	records, err := New().Parse(payload, vendors.FormatJSON)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if _, err := New().Normalize(records[0]); err == nil {
		t.Error("Normalize() accepted a record with no timestamp")
	}
}

func TestParseRejectsMalformedPayload(t *testing.T) {
	if _, err := New().Parse(fixture(t, "malformed.json"), vendors.FormatJSON); err == nil {
		t.Error("Parse() accepted a malformed JSON array")
	}
}

func TestNormalizeIsDeterministic(t *testing.T) {
	records := parseFixture(t, "valid.json")
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
		first.Verdict != second.Verdict {
		t.Error("Normalize() is not deterministic across calls")
	}
}

func TestNormalizeRejectsUndecodableRecord(t *testing.T) {
	if _, err := New().Normalize(vendors.RawRecord{Bytes: []byte("junk")}); err == nil {
		t.Error("Normalize() accepted a record that never decoded")
	}
}

// F5's ndjson variant must produce the same shape as its JSON array variant.
func TestNDJSONMatchesJSONShape(t *testing.T) {
	records := parseFixture(t, "valid.ndjson")

	event, err := New().Normalize(records[0])
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if event.VendorRequestID != "6947392018374652" {
		t.Errorf("VendorRequestID = %q, want it populated from ndjson", event.VendorRequestID)
	}
	if event.Verdict != vendors.VerdictAllowed {
		t.Errorf("Verdict = %q, want allowed", event.Verdict)
	}
}

// A CEF line with no timestamp cannot be correlated — correlation is time-windowed —
// so it is rejected and dead-lettered with a clear reason rather than being stored
// with a guessed time that would silently produce wrong joins.
func TestCEFWithoutTimestampIsRejectedNotGuessed(t *testing.T) {
	records := parseFixture(t, "cef_no_timestamp.cef")
	if len(records) != 1 {
		t.Fatalf("Parse() returned %d records, want 1", len(records))
	}
	if records[0].Fields == nil {
		t.Fatal("the line should still decode; only normalization should fail")
	}

	_, err := New().Normalize(records[0])
	if err == nil {
		t.Fatal("Normalize() accepted a CEF record with no timestamp")
	}
	if !strings.Contains(err.Error(), "date_time") {
		t.Errorf("error = %q, want it to name the missing field so the dead-letter "+
			"reason is actionable", err)
	}
}
