package cloudflare

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
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
//
// This table used to say "managed_challenge", matching a map key that Cloudflare's
// camelCase could never lowercase into — so the test and the code agreed with each
// other and both were wrong about what the vendor actually sends. The value here is now
// the one taken off the wire, and TestEverySecurityActionSeenInProductionMaps below
// checks the whole vocabulary against a real traffic sample rather than against
// whatever the table happens to claim.
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
		{"managedChallenge", vendors.VerdictChallenged},
		{"connectionClose", vendors.VerdictRateLimited},
		{"allow", vendors.VerdictAllowed},
		{"log", vendors.VerdictMonitored},
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

// productionFields is the exact key set of a Logpush record taken from production.
//
// THE REGRESSION THIS PINS. knownFields was written against a minimal job and never
// grew with it: a real record carries 59 fields and the map recognised 20, so 39 were
// classed as drift on every single event. It stayed invisible only because the counter
// behind the drift warning had no producer — connecting that up without fixing this
// would have lit a permanent 100%-drift alarm on a correctly-configured feed.
//
// Listing the fields literally, rather than deriving them, is the point: this test only
// keeps its value if adding a field to the job means changing this list on purpose.
var productionFields = []string{
	"BotDetectionIDs", "BotDetectionTags", "BotScore", "BotScoreSrc", "BotTags",
	"cache_ratio_1h", "ClientASN", "ClientCity", "ClientCountry", "ClientLatitude",
	"ClientLongitude", "ClientRequestHost", "ClientRequestMethod", "ClientRequestURI",
	"ContentScanObjResults", "ContentScanObjTypes", "EdgeCFConnectingO2O", "EdgeColoCode",
	"EdgeColoID", "EdgeEndTimestamp", "EdgePathingSrc", "EdgePathingStatus",
	"EdgeResponseBytes", "EdgeResponseStatus", "EdgeServerIP", "EdgeStartTimestamp",
	"h2h3_ratio_1h", "heuristic_ratio_1h", "ips_quantile_1h", "ips_rank_1h", "JA3Hash",
	"JA4", "JA4Signals", "JSDetectionPassed", "MatchedRules", "ParentRayID",
	"paths_rank_1h", "RayID", "reqs_quantile_1h", "reqs_rank_1h", "rules", "rulesetId",
	"rulesetVersion", "SecurityAction", "SecurityActions", "SecurityRuleDescription",
	"SecurityRuleID", "SecurityRuleIDs", "SecuritySources", "SmartRouteColoID",
	"uas_rank_1h", "UpperTierColoID", "WAFAttackScore", "WAFFlags", "WAFMatchedVar",
	"WAFRCEAttackScore", "WAFSQLiAttackScore", "WAFXSSAttackScore", "WorkerStatus",
	"ZoneName",
}

func TestAProductionRecordReportsNoSchemaDrift(t *testing.T) {
	fields := make(map[string]any, len(productionFields))
	for _, name := range productionFields {
		fields[name] = "value"
	}
	fields["EdgeStartTimestamp"] = "2026-08-13T10:00:00Z"
	fields["SecurityAction"] = "allow"
	fields["EdgeResponseStatus"] = 200

	payload, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("encode payload: %v", err)
	}

	event, err := New().Normalize(recordFrom(t, string(payload)))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if len(event.UnknownFields) != 0 {
		t.Errorf("a correctly-configured feed reported %d drifting fields: %v",
			len(event.UnknownFields), event.UnknownFields)
	}
}

// The opposite guarantee, and the reason the list above is not simply "everything".
// Drift has to still fire for a field nobody has declared, or the warning is worthless.
func TestAGenuinelyNewFieldStillReportsDrift(t *testing.T) {
	payload := `{"RayID":"8f1a2b3c4d5e6f70","EdgeStartTimestamp":"2026-08-13T10:00:00Z",` +
		`"SecurityAction":"allow","EdgeResponseStatus":200,"SomethingNobodyDeclared":"x"}`

	event, err := New().Normalize(recordFrom(t, payload))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	var saw bool
	for _, f := range event.UnknownFields {
		if f == "SomethingNobodyDeclared" {
			saw = true
		}
	}
	if !saw {
		t.Errorf("an undeclared field was not reported as drift: %v", event.UnknownFields)
	}
}

// productionSecurityActions is every SecurityAction value observed in production over a
// three-hour window, with the share of traffic each carried.
//
// THE BUG THIS PINS. The map held "managed_challenge" with an underscore, while the
// lookup lowercases Cloudflare's camelCase to "managedchallenge" — a key nothing could
// ever produce. Managed challenge is Cloudflare's default challenge action, so 21,000
// requests in three hours were recorded with NO VERDICT. A challenged request that
// reads as `unknown` is invisible to disagreement detection, which is the whole reason
// these vendors are correlated.
//
// Listed with real counts rather than invented values, because the failure was that the
// table did not match what the vendor actually sends. A test built from the same
// imagination that wrote the table would have agreed with it.
func TestEverySecurityActionSeenInProductionMaps(t *testing.T) {
	tests := []struct {
		action string
		want   string
		share  string
	}{
		{"", vendors.VerdictAllowed, "2,000,746 — no security action taken"},
		{"skip", vendors.VerdictAllowed, "590,239"},
		{"managedChallenge", vendors.VerdictChallenged, "21,023"},
		{"allow", vendors.VerdictAllowed, "922"},
		{"managedChallengeBypassed", vendors.VerdictChallenged, "407"},
		{"managedChallengeNonInteractiveSolved", vendors.VerdictChallenged, "203"},
		{"managedChallengeInteractiveSolved", vendors.VerdictChallenged, "16"},
		{"log", vendors.VerdictMonitored, "1"},
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			payload := `{"RayID":"8f1a2b3c4d5e6f70","EdgeStartTimestamp":"2026-08-13T10:00:00Z",` +
				`"EdgeResponseStatus":200,"SecurityAction":"` + tt.action + `"}`

			event, err := New().Normalize(recordFrom(t, payload))
			if err != nil {
				t.Fatalf("Normalize() error = %v", err)
			}
			if event.Verdict != tt.want {
				t.Errorf("verdict = %q, want %q (seen on %s requests)",
					event.Verdict, tt.want, tt.share)
			}
			if event.Verdict == vendors.VerdictUnknown {
				t.Error("a real production action produced no verdict at all")
			}
		})
	}
}

// The camelCase forms Cloudflare actually sends must survive the lowercasing, which is
// the specific mechanism that broke. Asserting on the normalized key alone would have
// passed against the underscore.
func TestChallengeActionsMapInTheCasingCloudflareSends(t *testing.T) {
	for _, action := range []string{
		"managedChallenge", "MANAGEDCHALLENGE", "managedchallenge", " managedChallenge ",
	} {
		payload := `{"RayID":"r","EdgeStartTimestamp":"2026-08-13T10:00:00Z",` +
			`"EdgeResponseStatus":200,"SecurityAction":"` + action + `"}`

		event, err := New().Normalize(recordFrom(t, payload))
		if err != nil {
			t.Fatalf("Normalize(%q) error = %v", action, err)
		}
		if event.Verdict != vendors.VerdictChallenged {
			t.Errorf("SecurityAction %q gave verdict %q, want challenged", action, event.Verdict)
		}
	}
}

// An action nobody has mapped must still be reported as unknown and kept verbatim, or
// the next vocabulary change is silently mapped to something wrong instead of showing up.
func TestAnUnmappedActionIsStillReportedAsUnknown(t *testing.T) {
	payload := `{"RayID":"r","EdgeStartTimestamp":"2026-08-13T10:00:00Z",` +
		`"EdgeResponseStatus":200,"SecurityAction":"someFutureAction"}`

	event, err := New().Normalize(recordFrom(t, payload))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if event.Verdict != vendors.VerdictUnknown {
		t.Errorf("verdict = %q, want unknown", event.Verdict)
	}
	if event.RawExtra["unmapped_security_action"] != "somefutureaction" {
		t.Errorf("the original action was not preserved: %v", event.RawExtra)
	}
}

// A verbatim production record for a managed-rule detection in log mode — the exact
// shape ruleset tuning reads. Values are the ones observed on jobs.bg.
const wafDetectionRecord = `{"RayID":"8f1a2b3c4d5e6f70",` +
	`"EdgeStartTimestamp":"2026-08-13T10:00:00Z","ClientIP":"203.0.113.10",` +
	`"ClientRequestHost":"www.jobs.bg","ClientRequestURI":"/?a=%27or%201=1%27",` +
	`"ClientRequestMethod":"GET","EdgeResponseStatus":200,` +
	`"SecurityAction":"log","SecurityActions":["log"],` +
	`"SecurityRuleDescription":"SQLi - Equation - URI",` +
	`"SecurityRuleID":"46b937649a424b7ead90f6d0e1149ea6",` +
	`"SecurityRuleIDs":["46b937649a424b7ead90f6d0e1149ea6"],` +
	`"SecuritySources":["firewallManaged"],` +
	`"WAFAttackScore":2,"WAFFlags":"0","WAFMatchedVar":"",` +
	`"WAFRCEAttackScore":98,"WAFSQLiAttackScore":4,"WAFXSSAttackScore":98}`

// THE SCALE IS INVERTED and everything downstream depends on reading it that way:
// 1 is certainly an attack, 99 certainly clean. This record is a real SQL injection —
// overall 2, driven by the SQLi sub-score of 4, while RCE and XSS sit at 98 because it
// is not those things. Getting the direction wrong would rank the cleanest traffic as
// the most dangerous.
func TestWAFScoresAreExtractedOnTheirInvertedScale(t *testing.T) {
	event, err := New().Normalize(recordFrom(t, wafDetectionRecord))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	checks := []struct {
		field string
		got   uint8
		want  uint8
	}{
		{"AttackScore", event.WAF.AttackScore, 2},
		{"SQLiScore", event.WAF.SQLiScore, 4},
		{"XSSScore", event.WAF.XSSScore, 98},
		{"RCEScore", event.WAF.RCEScore, 98},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.field, c.got, c.want)
		}
	}

	if event.WAF.Source != "firewallManaged" {
		t.Errorf("source = %q, want firewallManaged — it decides how the rule is tuned",
			event.WAF.Source)
	}
	// Verbatim, in Cloudflare's casing, so it matches what the dashboard shows.
	if event.WAF.Action != "log" {
		t.Errorf("action = %q, want log", event.WAF.Action)
	}
}

// A LOGGED DETECTION IS NOT AN ALLOWED REQUEST. The rule matched and was deliberately
// not enforced, which is what `monitored` means. Under `allowed` it was
// indistinguishable from clean traffic, and the question tuning asks — what is
// Cloudflare catching but not acting on — had no answer.
func TestALoggedDetectionIsMonitoredNotAllowed(t *testing.T) {
	event, err := New().Normalize(recordFrom(t, wafDetectionRecord))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if event.Verdict != vendors.VerdictMonitored {
		t.Errorf("verdict = %q, want monitored", event.Verdict)
	}
	// The rule identity still has to survive, or the detection cannot be attributed.
	if event.RuleID != "46b937649a424b7ead90f6d0e1149ea6" {
		t.Errorf("rule id = %q", event.RuleID)
	}
	if event.VerdictReason != "SQLi - Equation - URI" {
		t.Errorf("rule description = %q", event.VerdictReason)
	}
}

// A record from a zone with no WAF omits the fields entirely, and that must read as
// "not scored" rather than as 0. On this inverted scale a fabricated 0 is the strongest
// attack signal there is, so every unscored request would top the tuning report.
func TestAnAbsentScoreIsNotZeroTheAttackValue(t *testing.T) {
	payload := `{"RayID":"r","EdgeStartTimestamp":"2026-08-13T10:00:00Z",` +
		`"EdgeResponseStatus":200,"SecurityAction":"allow"}`

	event, err := New().Normalize(recordFrom(t, payload))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if event.WAF.AttackScore != 0 {
		t.Errorf("AttackScore = %d, want 0 meaning unscored", event.WAF.AttackScore)
	}
	if event.WAF.Source != "" || event.WAF.Action != "allow" {
		t.Errorf("unexpected WAF detail: %+v", event.WAF)
	}
}

// A value outside the documented 1-99 range is not a score. Clamping to 0 keeps the
// "unscored" meaning intact rather than letting a malformed 255 rank as clean.
func TestAnOutOfRangeScoreIsTreatedAsUnscored(t *testing.T) {
	payload := `{"RayID":"r","EdgeStartTimestamp":"2026-08-13T10:00:00Z",` +
		`"EdgeResponseStatus":200,"SecurityAction":"allow","WAFAttackScore":255}`

	event, err := New().Normalize(recordFrom(t, payload))
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if event.WAF.AttackScore != 0 {
		t.Errorf("AttackScore = %d, want 0 for an out-of-range value", event.WAF.AttackScore)
	}
}
