package wirefilter

import (
	"encoding/base64"
	"strings"
	"testing"
)

// F5's transcript of the real upload: quotes percent-encoded, line breaks written as the
// two characters backslash-n, and cut off after a bounded prefix.
const f5Transcript = `POST /js_file.php?subm=1&ajax=1 HTTP/1.1\r\n` +
	`Host: app2.jobs.bg\r\n` +
	`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryX\r\n` +
	`Referer: https://app2.jobs.bg/js_file_list.php\r\n` +
	`Cookie: JOBSSESSID=abc; datadome=xyz\r\n` +
	`User-Agent: Mozilla/5.0 (Linux; Android 13)\r\n` +
	`\r\n` +
	`------WebKitFormBoundaryX\r\n` +
	`Content-Disposition: form-data; name=%22file%22; filename=%22test.html%22\r\n` +
	`Content-Type: text/html\r\n\r\n<!DOCTYPE html>`

func captured() CapturedRequest {
	return CapturedRequest{
		EventID:  "f5-event",
		Host:     "app2.jobs.bg",
		Method:   "POST",
		Path:     "/js_file.php",
		Query:    "subm=1&ajax=1",
		ClientIP: "87.243.106.179",
		Raw:      f5Transcript,
	}
}

func body(t *testing.T, r Request) string {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(r.FieldsBase64["http.request.body.raw"])
	if err != nil {
		t.Fatalf("decode body: %v", err)
	}
	return string(decoded)
}

// THE ONE THAT DECIDES EVERYTHING. F5 must percent-encode quotes, because the transcript
// lives inside request="..." in a syslog line. A multipart body is nothing BUT quotes, so an
// expression matching filename="test.html" would never match the escaped form — and the
// tester would confidently report that a correct rule does not work, which is the exact
// failure it was built to end.
func TestQuotesAreRestoredBeforeEvaluation(t *testing.T) {
	got := body(t, captured().Fields())

	if !strings.Contains(got, `filename="test.html"`) {
		t.Errorf("body still holds F5's escaping, so a filename expression cannot match: %q", got)
	}
	if strings.Contains(got, "%22") {
		t.Error("the percent-encoded quotes survived into the body")
	}
}

// The header block and the body are separated by the blank line the HTTP format defines.
// Getting this wrong would put the request headers inside the body, where a body expression
// would match text the edge never sees there.
func TestTheBodyStartsAfterTheHeaders(t *testing.T) {
	got := body(t, captured().Fields())

	if strings.Contains(got, "Host: app2.jobs.bg") {
		t.Error("the request headers leaked into the body")
	}
	if !strings.HasPrefix(got, "------WebKitFormBoundaryX") {
		t.Errorf("the body does not begin at the multipart boundary: %q", got)
	}
}

// F5's transcript is a prefix by construction and nothing in it says how much was cut, so
// every body is marked truncated. Without that, a miss would be reported as certain when the
// deciding bytes may simply not be here.
func TestEveryCapturedBodyIsMarkedTruncated(t *testing.T) {
	if !captured().Fields().BodyTruncated {
		t.Error("the body is not marked truncated, so a miss would be reported as certain")
	}
}

func TestHeadersAreReadCaseInsensitively(t *testing.T) {
	fields := captured().Fields().Fields

	if fields["http.referer"] != "https://app2.jobs.bg/js_file_list.php" {
		t.Errorf("referer = %q", fields["http.referer"])
	}
	if !strings.Contains(fields["http.cookie"], "JOBSSESSID=abc") {
		t.Errorf("cookie = %q", fields["http.cookie"])
	}
}

// The normalized columns are exact — parsed at ingest rather than recovered from a
// transcript — so they win. The transcript fills only what they do not carry.
func TestNormalizedFieldsWinAndTheTranscriptFillsTheGaps(t *testing.T) {
	request := captured()
	request.UserAgent = "" // not recorded as a column for this vendor
	fields := request.Fields().Fields

	if fields["http.request.uri"] != "/js_file.php?subm=1&ajax=1" {
		t.Errorf("uri = %q, want path and query joined", fields["http.request.uri"])
	}
	if fields["http.user_agent"] != "Mozilla/5.0 (Linux; Android 13)" {
		t.Errorf("user agent = %q, want it recovered from the header", fields["http.user_agent"])
	}
}

// A path with no query must not gain a trailing question mark: http.request.uri is compared
// with eq as often as with contains.
func TestAQuerylessRequestKeepsABarePath(t *testing.T) {
	request := captured()
	request.Query = ""

	if got := request.Fields().Fields["http.request.uri"]; got != "/js_file.php" {
		t.Errorf("uri = %q, want the bare path", got)
	}
}

// An address that was never captured must not be sent as one: the evaluator would compare it
// against a real address and answer with confidence.
func TestAnAbsentClientAddressIsOmitted(t *testing.T) {
	request := captured()
	request.ClientIP = ""

	if _, present := request.Fields().Fields["ip.src"]; present {
		t.Error("an empty client address was sent as a field")
	}
}

// A transcript cut off inside the headers has no body at all, and must not be handed one.
func TestATruncatedHeaderBlockYieldsNoBody(t *testing.T) {
	request := captured()
	request.Raw = `POST /js_file.php HTTP/1.1\r\nHost: app2.jobs.bg\r\nCookie: a=b`

	if got := body(t, request.Fields()); got != "" {
		t.Errorf("body = %q, want empty when the transcript never reached one", got)
	}
}

// An event with no transcript at all still produces a usable field set: the normalized
// columns are enough for an expression that reads the path or the method.
func TestNoTranscriptStillYieldsTheNormalizedFields(t *testing.T) {
	request := captured()
	request.Raw = ""

	fields := request.Fields().Fields
	if fields["http.request.uri.path"] != "/js_file.php" || fields["http.host"] != "app2.jobs.bg" {
		t.Errorf("fields = %v, want the normalized columns", fields)
	}
}
