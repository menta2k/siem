package crs

import (
	"strconv"
	"strings"
)

// Turning a vendor's LOG of a request back into a request.
//
// The evidence is F5's transcript, not the bytes on the wire: the whole thing sits inside
// request="..." in a syslog line, so F5 percent-encodes the quotes and writes the line
// breaks as the two characters backslash-n, and it keeps only a bounded prefix. Undoing
// that is what makes the transcript evaluable at all — and the prefix is why every body
// coming out of here is marked truncated.
//
// internal/wirefilter does the same unescaping for Cloudflare expressions. If this PoC
// graduates, that decoding is the piece the two should share; it is duplicated here on
// purpose so the PoC cannot break the working path.

// Request is one captured request, in the shape a rule engine needs.
type Request struct {
	Method string
	URI    string
	Proto  string
	// Headers keeps the transcript's order and repetitions: CRS has rules about both.
	Headers [][2]string
	Body    []byte
	// BodyTruncated is true whenever the body may be a prefix, which for an F5
	// transcript is always. A rule that did not match an incomplete body has not been
	// answered — it has been left unanswered, and the result says so.
	BodyTruncated bool
	// BodyDeclared is the length the request itself claimed, from Content-Length.
	//
	// The gap between this and len(Body) is the whole reason a local reading can differ
	// from the edge's: an upload declaring 124 KB of which the log kept 900 bytes has not
	// been evaluated in any meaningful sense, and only these two numbers side by side
	// make that visible instead of leaving "no rule matched" to be read as "clean".
	BodyDeclared int
	ClientIP     string
}

// f5QuoteEscape is how F5 writes a double quote inside the request it logs.
const f5QuoteEscape = "%22"

// ParseTranscript reads a vendor transcript into a request.
//
// It is deliberately lenient. A transcript cut off mid-headers is still worth evaluating —
// the URI and the headers that survived carry most of what CRS reads in phase 1 — so a
// short one yields a request with no body rather than an error.
func ParseTranscript(raw string) (Request, bool) {
	decoded := decodeTranscript(raw)
	if strings.TrimSpace(decoded) == "" {
		return Request{}, false
	}

	head, body := split(decoded)
	lines := strings.Split(head, "\n")

	method, uri, proto, ok := requestLine(lines[0])
	if !ok {
		return Request{}, false
	}

	request := Request{
		Method:        method,
		URI:           uri,
		Proto:         proto,
		Headers:       headers(lines[1:]),
		Body:          []byte(body),
		BodyTruncated: true,
	}
	request.BodyDeclared = declaredLength(request.Headers)
	return request, true
}

// decodeTranscript undoes the escaping the syslog envelope forced on the request.
func decodeTranscript(raw string) string {
	decoded := strings.ReplaceAll(raw, f5QuoteEscape, `"`)
	decoded = strings.ReplaceAll(decoded, `\r\n`, "\r\n")
	decoded = strings.ReplaceAll(decoded, `\n`, "\n")
	return decoded
}

// split divides the transcript at the blank line the HTTP message format defines.
func split(decoded string) (head, body string) {
	for _, separator := range []string{"\r\n\r\n", "\n\n"} {
		if h, rest, found := strings.Cut(decoded, separator); found {
			return h, rest
		}
	}
	return decoded, ""
}

// requestLine reads "POST /path?q=1 HTTP/1.1".
//
// The protocol is optional because CRS reads it — rule 920430 enforces allowed versions —
// and a transcript that omits it must not be given one it never had.
func requestLine(line string) (method, uri, proto string, ok bool) {
	fields := strings.Fields(strings.TrimRight(line, "\r"))
	if len(fields) < 2 {
		return "", "", "", false
	}
	if len(fields) > 2 {
		proto = fields[2]
	}
	return fields[0], fields[1], proto, true
}

// headers reads the header block, keeping order and duplicates.
func headers(lines []string) [][2]string {
	out := make([][2]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		name, value, found := strings.Cut(line, ":")
		if !found || strings.TrimSpace(name) == "" {
			// A folded continuation or a line cut in half by the transcript's bound.
			// Dropping it is honest; guessing what it continued is not.
			continue
		}
		out = append(out, [2]string{strings.TrimSpace(name), strings.TrimSpace(value)})
	}
	return out
}

// declaredLength reads Content-Length, which is what the request claimed to be carrying.
func declaredLength(headers [][2]string) int {
	for _, header := range headers {
		if !strings.EqualFold(header[0], "content-length") {
			continue
		}
		if length, err := strconv.Atoi(strings.TrimSpace(header[1])); err == nil {
			return length
		}
	}
	return 0
}
