package datadome

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/menta2k/siem/internal/vendors"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "..", "test", "fixtures", "datadome", name)
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
	if got := New().Vendor(); got != vendors.DataDome {
		t.Errorf("Vendor() = %q, want %q", got, vendors.DataDome)
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
		{"json array", []byte(`[{"requestid":"a"}]`), vendors.FormatJSON, true},
		{"ndjson", []byte(`{"requestid":"a"}`), vendors.FormatNDJSON, true},
		{"empty", []byte(``), vendors.FormatUnknown, false},
		{"not json", []byte(`CEF:0|F5|`), vendors.FormatUnknown, false},
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

func TestNormalizeFullRecord(t *testing.T) {
	records := parseFixture(t, "valid.json")
	if len(records) != 4 {
		t.Fatalf("Parse() returned %d records, want 4", len(records))
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
		{"Vendor", event.Vendor, vendors.DataDome},
		{"VendorRequestID", event.VendorRequestID, "01J8XKQ2M4N7P9R3T5V6W8Y0AB"},
		{"VendorAccount", event.VendorAccount, "acct_9f2b"},
		{"ClientIP", event.ClientIP.String(), "203.0.113.45"},
		{"ClientASN", event.ClientASN, uint32(64512)},
		{"ClientCountry", event.ClientCountry, "DE"},
		{"RequestHost", event.RequestHost, "shop.example.com"},
		{"RequestPath", event.RequestPath, "/api/checkout"},
		{"RequestQuery", event.RequestQuery, "step=2"},
		{"RequestMethod", event.RequestMethod, "POST"},
		{"HTTPStatus", event.HTTPStatus, uint16(403)},
		{"Verdict", event.Verdict, vendors.VerdictBlocked},
		{"RuleID", event.RuleID, "scrapy"},
		{"ScoreKind", event.ScoreKind, vendors.ScoreKindBot},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.field, c.got, c.want)
		}
	}

	if event.VerdictReason != "scrapy (Scraper)" {
		t.Errorf("VerdictReason = %q, want the bot name and family combined", event.VerdictReason)
	}
}

// The score must be normalized to 0..1. Comparing DataDome's raw 95 against F5's
// violation_rating of 5 would be meaningless, and the score_conflict threshold is
// expressed on the normalized scale.
func TestBotScoreIsNormalizedToUnitScale(t *testing.T) {
	records := parseFixture(t, "valid.json")
	a := New()

	tests := []struct {
		index int
		want  float32
	}{
		{0, 0.95},
		{1, 0.12},
		{2, 0.78},
		{3, 0.88},
	}

	for _, tt := range tests {
		event, err := a.Normalize(records[tt.index])
		if err != nil {
			t.Fatalf("Normalize(%d) error = %v", tt.index, err)
		}
		if event.Score == nil {
			t.Fatalf("record %d has no score", tt.index)
		}
		if diff := *event.Score - tt.want; diff > 0.001 || diff < -0.001 {
			t.Errorf("record %d score = %v, want %v on the 0..1 scale",
				tt.index, *event.Score, tt.want)
		}
		if *event.Score < 0 || *event.Score > 1 {
			t.Errorf("record %d score %v is outside the unit scale", tt.index, *event.Score)
		}
	}
}

func TestVerdictMapping(t *testing.T) {
	a := New()
	tests := []struct {
		action string
		isBot  string
		want   string
	}{
		{"BLOCK", "true", vendors.VerdictBlocked},
		{"HARDBLOCK", "true", vendors.VerdictBlocked},
		{"CAPTCHA", "true", vendors.VerdictChallenged},
		{"DEVICE_CHECK", "true", vendors.VerdictUnknown}, // not in the table; must not guess
		{"ALLOW", "false", vendors.VerdictAllowed},
		// Monitoring mode: a bot was identified but not acted on. Must NOT read as
		// allowed, or the disagreements the product exists to surface are hidden.
		{"MONITOR", "true", vendors.VerdictMonitored},
		{"", "true", vendors.VerdictMonitored}, // no action, bot flagged
		{"", "false", vendors.VerdictAllowed},  // no action, not a bot
		{"TELEPORT", "false", vendors.VerdictUnknown},
	}

	for _, tt := range tests {
		name := tt.action
		if name == "" {
			name = "empty/isbot=" + tt.isBot
		}
		t.Run(name, func(t *testing.T) {
			payload := []byte(`[{"requestid":"x","timestamp":1786017600000,` +
				`"ip":"203.0.113.1","host":"h","uri":"/","method":"GET",` +
				`"action":"` + tt.action + `","isbot":` + tt.isBot + `}]`)

			records, err := a.Parse(payload, vendors.FormatJSON)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			event, err := a.Normalize(records[0])
			if err != nil {
				t.Fatalf("Normalize() error = %v", err)
			}
			if event.Verdict != tt.want {
				t.Errorf("action %q verdict = %q, want %q", tt.action, event.Verdict, tt.want)
			}
		})
	}
}

// Module-level enrichment sends X-DataDome-* header names rather than plain keys.
// Both shapes appear in real integrations and must normalize identically.
func TestHeaderStyleFieldNames(t *testing.T) {
	records := parseFixture(t, "header_style.json")

	event, err := New().Normalize(records[0])
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if event.VendorRequestID != "01J8XKQ2M4N7P9R3T5V6W8Y0EA" {
		t.Errorf("VendorRequestID = %q, want it read from the X-DataDome-* name",
			event.VendorRequestID)
	}
	if event.RuleID != "curl" {
		t.Errorf("RuleID = %q, want the bot name from the header-style field", event.RuleID)
	}
	if event.Verdict != vendors.VerdictBlocked {
		t.Errorf("Verdict = %q, want blocked", event.Verdict)
	}
}

func TestNormalizeToleratesMissingOptionalFields(t *testing.T) {
	records := parseFixture(t, "missing_optional.json")

	event, err := New().Normalize(records[0])
	if err != nil {
		t.Fatalf("Normalize() rejected a minimal record: %v", err)
	}
	if event.VendorRequestID != "01J8XKQ2M4N7P9R3T5V6W8Y0CA" {
		t.Errorf("VendorRequestID = %q, want it populated", event.VendorRequestID)
	}
	if event.Score != nil {
		t.Errorf("Score = %v, want nil when botscore is absent", event.Score)
	}
	if event.ScoreKind != vendors.ScoreKindNone {
		t.Errorf("ScoreKind = %q, want none when no score was reported", event.ScoreKind)
	}
	if event.HTTPStatus != 0 {
		t.Errorf("HTTPStatus = %d, want 0 when absent", event.HTTPStatus)
	}
}

func TestNormalizeReportsUnknownFields(t *testing.T) {
	records := parseFixture(t, "unknown_fields.json")

	event, err := New().Normalize(records[0])
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	unknown := strings.Join(event.UnknownFields, ",")
	for _, want := range []string{"brandnewsignal", "devicefingerprintv3"} {
		if !strings.Contains(strings.ToLower(unknown), want) {
			t.Errorf("UnknownFields = %v, want it to include %q", event.UnknownFields, want)
		}
	}
	if strings.Contains(unknown, "requestid") {
		t.Error("a known field was reported as schema drift")
	}
}

// DataDome sends epoch milliseconds.
func TestNormalizeParsesEpochMilliseconds(t *testing.T) {
	records := parseFixture(t, "valid.json")

	event, err := New().Normalize(records[0])
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if event.EventTime.Year() != 2026 {
		t.Errorf("EventTime = %v, want a 2026 timestamp from epoch millis", event.EventTime)
	}
	if event.EventTimeOriginal == "" {
		t.Error("EventTimeOriginal was not preserved")
	}
}

func TestNormalizeRejectsMissingTimestamp(t *testing.T) {
	payload := []byte(`[{"requestid":"x","ip":"203.0.113.1","host":"h","uri":"/"}]`)

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
		t.Error("Parse() accepted a malformed payload")
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
		first.Verdict != second.Verdict || *first.Score != *second.Score {
		t.Error("Normalize() is not deterministic across calls")
	}
}

func TestNDJSONVariant(t *testing.T) {
	records := parseFixture(t, "valid.ndjson")

	event, err := New().Normalize(records[0])
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if event.VendorRequestID != "01J8XKQ2M4N7P9R3T5V6W8Y0BA" {
		t.Errorf("VendorRequestID = %q, want it populated from ndjson", event.VendorRequestID)
	}
}

func TestNormalizeRejectsUndecodableRecord(t *testing.T) {
	if _, err := New().Normalize(vendors.RawRecord{Bytes: []byte("junk")}); err == nil {
		t.Error("Normalize() accepted a record that never decoded")
	}
}

// The MONITOR case is what produces score_conflict disagreements: every vendor
// allowed the request, but DataDome scored it as a bot.
func TestMonitoredHighScoreIsPreservedForConflictDetection(t *testing.T) {
	records := parseFixture(t, "valid.json")

	event, err := New().Normalize(records[3]) // the MONITOR record
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if event.Verdict != vendors.VerdictMonitored {
		t.Errorf("Verdict = %q, want monitored", event.Verdict)
	}
	if event.Score == nil || *event.Score < 0.8 {
		t.Errorf("Score = %v, want a high score preserved so score_conflict can fire",
			event.Score)
	}
}
