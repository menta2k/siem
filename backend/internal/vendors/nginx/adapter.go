// Package nginx adapts nginx access logs to the common event model.
//
// nginx is the ORIGIN, not a security vendor, and that difference runs through every
// decision here. Cloudflare, DataDome and F5 each decide whether a request may proceed;
// nginx is what proceeds to. It completes the picture the other three describe — the
// request reached the application, and this is what the application returned — and its
// value is confirming that a request survived every gate, not adding a fourth opinion
// about whether it should have.
//
// The log format is JSON, configured on the nginx side. Parsing the combined format
// with a regex would work until the first operator added a field, and the fields this
// adapter needs (CF-Ray, the forwarded client address) are not in the default format
// anyway — so a purpose-built log_format is required regardless, and JSON makes it
// unambiguous.
package nginx

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/menta2k/siem/internal/vendors"
)

// maxLineBytes bounds a single log line, which is untrusted input.
const maxLineBytes = 1 << 20 // 1 MiB

// knownFields are the fields this adapter maps or deliberately ignores. Anything else
// is reported as drift so a log_format change is visible rather than silent.
var knownFields = map[string]bool{
	"time": true, "timestamp": true, "time_iso8601": true,
	"cf_ray": true, "cf_connecting_ip": true, "x_forwarded_for": true,
	"remote_addr": true, "host": true, "request_uri": true, "request_method": true,
	"status": true, "user_agent": true, "server_name": true,
	// Timing and size fields: useful context, no security meaning.
	"request_time": true, "upstream_response_time": true, "upstream_addr": true,
	"upstream_status": true, "body_bytes_sent": true, "request_length": true,
	"scheme": true, "server_protocol": true, "referer": true,
}

// Adapter implements vendors.Adapter for nginx.
type Adapter struct{}

// New constructs the adapter.
func New() *Adapter { return &Adapter{} }

// Vendor returns the vendor name.
func (a *Adapter) Vendor() string { return vendors.Nginx }

// Detect identifies the payload as newline-delimited JSON objects.
func (a *Adapter) Detect(payload []byte) (vendors.Format, bool) {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return vendors.FormatUnknown, false
	}
	switch trimmed[0] {
	case '[':
		return vendors.FormatJSON, true
	case '{':
		return vendors.FormatNDJSON, true
	default:
		// Deliberately NOT falling back to the combined text format. A line this
		// adapter cannot read is dead-lettered with its bytes intact, which is a
		// visible, fixable misconfiguration — guessing at a text layout would produce
		// events with silently wrong fields instead.
		return vendors.FormatUnknown, false
	}
}

// Parse splits a delivery into records, keeping each record's original bytes.
func (a *Adapter) Parse(payload []byte, format vendors.Format) ([]vendors.RawRecord, error) {
	if format == vendors.FormatJSON {
		return parseJSONArray(payload)
	}
	return parseNDJSON(payload)
}

func parseJSONArray(body []byte) ([]vendors.RawRecord, error) {
	var raw []json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("%w: json array: %w", vendors.ErrUnparseable, err)
	}
	records := make([]vendors.RawRecord, 0, len(raw))
	for _, item := range raw {
		records = append(records, decodeRecord(item))
	}
	return records, nil
}

func parseNDJSON(body []byte) ([]vendors.RawRecord, error) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64<<10), maxLineBytes)

	var records []vendors.RawRecord
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		// The scanner reuses its buffer, so the bytes must be copied before they are
		// retained, or every record ends up holding the last line.
		owned := make([]byte, len(line))
		copy(owned, line)
		records = append(records, decodeRecord(owned))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%w: reading ndjson: %w", vendors.ErrUnparseable, err)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("%w: delivery contained no records", vendors.ErrUnparseable)
	}
	return records, nil
}

// decodeRecord decodes one line, leaving Fields nil when it will not parse so the
// caller can dead-letter that line alone rather than the whole delivery.
func decodeRecord(raw []byte) vendors.RawRecord {
	record := vendors.RawRecord{Bytes: raw, Format: vendors.FormatNDJSON}

	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		return record
	}
	record.Fields = fields
	return record
}

// Normalize maps an nginx access log line onto the common event model.
func (a *Adapter) Normalize(record vendors.RawRecord) (vendors.Event, error) {
	if record.Fields == nil {
		return vendors.Event{}, fmt.Errorf("%w: record is not valid json", vendors.ErrUnparseable)
	}

	eventTime, original, err := vendors.ParseTime(
		firstOf(record.Fields, "time_iso8601", "time", "timestamp"))
	if err != nil {
		return vendors.Event{}, fmt.Errorf("field time_iso8601: %w", err)
	}

	uri := vendors.AsString(record.Fields["request_uri"])
	path, query := vendors.SplitURI(uri)
	clientIP := resolveClientIP(record.Fields)

	event := vendors.Event{
		Vendor:            vendors.Nginx,
		VendorAccount:     vendors.AsString(record.Fields["server_name"]),
		VendorRequestID:   cloudflareRayID(record.Fields),
		EventTime:         eventTime,
		EventTimeOriginal: original,

		ClientIP:       clientIP,
		ClientIPShared: vendors.IsSharedIP(clientIP),

		RequestHost:   strings.ToLower(strings.TrimSpace(vendors.AsString(record.Fields["host"]))),
		RequestPath:   path,
		RequestQuery:  query,
		RequestMethod: strings.ToUpper(vendors.AsString(record.Fields["request_method"])),
		UserAgent:     vendors.AsString(record.Fields["user_agent"]),
		HTTPStatus:    vendors.ToStatus(record.Fields["status"]),

		// See mapVerdict: nginx is usually the origin, but it can refuse on its own,
		// and what separates the two is whether the request reached the application —
		// not the status code, which says what the APPLICATION concluded.
		Verdict:   mapVerdict(record.Fields),
		ScoreKind: vendors.ScoreKindNone,
	}

	event.RawExtra, event.UnknownFields = collectExtra(record.Fields)
	return event, nil
}

// collectExtra preserves unmapped fields and reports genuinely unrecognized ones.
func collectExtra(fields map[string]any) (extra map[string]string, unknown []string) {
	extra = make(map[string]string, len(fields))
	for key, value := range fields {
		text := vendors.AsString(value)
		if text == "" {
			continue
		}
		extra[key] = text
		if !knownFields[key] {
			unknown = append(unknown, key)
		}
	}
	return extra, unknown
}

// firstOf returns the first present, non-empty value among the named fields.
func firstOf(fields map[string]any, names ...string) any {
	for _, name := range names {
		if value, ok := fields[name]; ok && vendors.AsString(value) != "" {
			return value
		}
	}
	return nil
}
