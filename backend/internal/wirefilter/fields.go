package wirefilter

import (
	"strings"
)

// Building the field set an expression is evaluated against.
//
// The honest difficulty here is that the evidence is F5's LOG of a request, not the request
// Cloudflare saw. F5 records a bounded prefix and percent-encodes the quotes inside it, so
// what arrives is a faithful but partial transcript. Every decision below is about not
// overstating what that transcript proves.

// CapturedRequest is one stored request as the platform can reconstruct it.
type CapturedRequest struct {
	// EventID keys the verdict back to the row the operator clicked.
	EventID string
	// The normalized fields, which are exact: they were parsed at ingest, not recovered.
	Host   string
	Method string
	Path   string
	Query  string
	// ClientIP is the address as text; an unparseable one is dropped rather than guessed.
	ClientIP  string
	UserAgent string
	// Raw is the vendor's transcript of the request — headers and as much body as it kept.
	Raw string
}

// f5QuoteEscape is how F5 writes a double quote inside the request it logs.
//
// It has to: the whole transcript sits inside request="..." in a syslog line, so a literal
// quote would end the field. Undoing it is what turns the transcript back into the bytes
// the edge actually saw — and a multipart body is nothing BUT quotes, so an expression
// matching filename="x.html" would never match the escaped form.
const f5QuoteEscape = "%22"

// Fields renders one captured request into what the evaluator takes.
//
// The body is marked truncated ALWAYS, because F5's transcript is a prefix by construction
// and nothing in it says how much was cut. Claiming otherwise would let a body expression's
// miss read as certain when the deciding bytes may simply not be here.
func (c CapturedRequest) Fields() Request {
	headers, body := splitRequest(c.Raw)

	fields := map[string]string{
		"http.host":              c.Host,
		"http.request.method":    c.Method,
		"http.request.uri.path":  c.Path,
		"http.request.uri.query": c.Query,
		"http.request.uri":       uri(c.Path, c.Query),
		"http.user_agent":        c.UserAgent,
		"http.referer":           header(headers, "referer"),
		"http.cookie":            header(headers, "cookie"),
	}
	if c.ClientIP != "" {
		fields["ip.src"] = c.ClientIP
	}
	// The user agent from the transcript wins when the normalized row has none: some
	// vendors do not record it as a column, and the header is the same value.
	if fields["http.user_agent"] == "" {
		fields["http.user_agent"] = header(headers, "user-agent")
	}

	request := Request{ID: c.EventID, Fields: fields}
	request.SetBody([]byte(body), true)
	return request
}

// uri joins the path and query the way Cloudflare's http.request.uri holds them.
func uri(path, query string) string {
	if query == "" {
		return path
	}
	return path + "?" + query
}

// splitRequest divides the transcript into its header block and whatever body followed.
//
// The blank line between them is the HTTP message format itself, so this is not a heuristic
// — but the transcript is a prefix, so a request cut off mid-headers has no body at all and
// must not be treated as having an empty one. The caller marks every body truncated for
// that reason.
func splitRequest(raw string) (headers, body string) {
	decoded := strings.ReplaceAll(raw, f5QuoteEscape, `"`)
	// F5 writes the line breaks as the two characters backslash-n. Left alone, the whole
	// transcript is one line and neither the header split nor a header lookup can work.
	decoded = strings.ReplaceAll(decoded, `\r\n`, "\r\n")
	decoded = strings.ReplaceAll(decoded, `\n`, "\n")

	for _, separator := range []string{"\r\n\r\n", "\n\n"} {
		if head, rest, found := strings.Cut(decoded, separator); found {
			return head, rest
		}
	}
	return decoded, ""
}

// header reads one header out of the transcript, case-insensitively as HTTP requires.
func header(headers, name string) string {
	want := strings.ToLower(name) + ":"
	for _, line := range strings.Split(headers, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(strings.ToLower(line), want) {
			return strings.TrimSpace(line[len(want):])
		}
	}
	return ""
}
