package f5

import "testing"

// The exact shape a BIG-IP Logging Profile emits with Storage Format: Field-Value Pairs.
// This is the line that arrived in production and was rejected as having no timestamp.
const asmLine = `unit_hostname="bigip1.local",policy_name="/Common/shop_policy",` +
	`violations="Illegal length,HTTP protocol compliance failed",support_id="1827399125",` +
	`request_status="blocked",response_code="0",ip_client="198.51.100.9",method="POST",` +
	`date_time="2026-08-07 07:09:00",severity="Critical",attack_type="SQL-Injection",` +
	`geo_location="BG",uri="/login",host="shop.example.com",user_agent="Mozilla/5.0 (X11)"`

func TestFieldValuePairsParsesRealASMOutput(t *testing.T) {
	fields := parseFieldValuePairs(asmLine)

	want := map[string]string{
		"support_id":     "1827399125",
		"request_status": "blocked",
		"ip_client":      "198.51.100.9",
		"method":         "POST",
		"host":           "shop.example.com",
		"uri":            "/login",
		"attack_type":    "SQL-Injection",
		// A space inside a quoted value. The CEF parser split this into fragments, and
		// the record was then rejected for an absent timestamp it plainly contained.
		"date_time": "2026-08-07 07:09:00",
		// Commas inside a quoted value: `violations` routinely holds several names, and
		// splitting on the comma would truncate it to the first.
		"violations": "Illegal length,HTTP protocol compliance failed",
		"user_agent": "Mozilla/5.0 (X11)",
	}

	for key, expected := range want {
		if got := fields[key]; got != expected {
			t.Errorf("%s = %q, want %q", key, got, expected)
		}
	}
}

// A shipper may preserve the syslog header. The parser must find the pairs regardless.
func TestALeadingSyslogHeaderIsIgnored(t *testing.T) {
	withHeader := `<134>Aug  7 07:09:00 bigip1 ASM:` + asmLine

	fields := parseFieldValuePairs(withHeader)

	if got := fields["support_id"]; got != "1827399125" {
		t.Errorf("support_id = %q with a syslog header present, want the id", got)
	}
	if got := fields["date_time"]; got != "2026-08-07 07:09:00" {
		t.Errorf("date_time = %q with a syslog header present", got)
	}
}

func TestQuotesInsideValuesSurvive(t *testing.T) {
	for name, line := range map[string]string{
		"backslash escaped": `uri="/a\"b",support_id="1"`,
		"doubled":           `uri="/a""b",support_id="1"`,
	} {
		t.Run(name, func(t *testing.T) {
			fields := parseFieldValuePairs(line)
			if got := fields["uri"]; got != `/a"b` {
				t.Errorf("uri = %q, want %q", got, `/a"b`)
			}
			if got := fields["support_id"]; got != "1" {
				t.Errorf("the pair after an escaped quote was lost: support_id = %q", got)
			}
		})
	}
}

// An = inside a value must not be read as the start of a new pair — query strings are
// full of them, and a mis-split there silently corrupts the request path.
func TestAnEqualsInsideAValueDoesNotSplitIt(t *testing.T) {
	fields := parseFieldValuePairs(`uri="/search?q=1&id=2",support_id="9"`)

	if got := fields["uri"]; got != "/search?q=1&id=2" {
		t.Errorf("uri = %q, want the whole query string", got)
	}
	if got := fields["support_id"]; got != "9" {
		t.Errorf("support_id = %q, want 9", got)
	}
}

// Truncation is normal on a syslog transport with a length limit. A partial record still
// carries an id and a timestamp, which beats discarding the event entirely.
func TestAnUnterminatedQuoteStillYieldsWhatWasRead(t *testing.T) {
	fields := parseFieldValuePairs(`support_id="123",date_time="2026-08-07 07:09:00",uri="/lo`)

	if got := fields["support_id"]; got != "123" {
		t.Errorf("support_id = %q, want 123", got)
	}
	if got := fields["uri"]; got != "/lo" {
		t.Errorf("uri = %q, want the truncated fragment", got)
	}
}

func TestUnquotedValuesStillParse(t *testing.T) {
	fields := parseFieldValuePairs(`support_id=123,method=POST`)

	if fields["support_id"] != "123" || fields["method"] != "POST" {
		t.Errorf("unquoted pairs mis-parsed: %v", fields)
	}
}
