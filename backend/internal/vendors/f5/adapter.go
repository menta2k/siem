// Package f5 adapts F5 BIG-IP ASM and F5 Distributed Cloud deliveries to the common
// event model.
//
// F5 is the awkward vendor of the three. BIG-IP ASM commonly emits CEF or delimited
// syslog rather than JSON, depending on how remote logging was configured, and all
// three encodings appear in real deployments. The adapter accepts them all and
// normalizes to the same shape, because telling a customer to reconfigure their
// logging before they can onboard is not a real answer.
//
// `support_id` is F5's per-request identifier and the basis of tier-1 correlation.
package f5

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/menta2k/siem/internal/vendors"
)

const maxLineBytes = 4 << 20

// knownFields are the ASM fields this adapter maps or knowingly carries.
var knownFields = map[string]bool{
	"support_id": true, "date_time": true, "ip_client": true, "method": true,
	"uri": true, "query_string": true, "protocol": true, "response_code": true,
	"request_status": true, "severity": true, "attack_type": true,
	"policy_name": true, "violations": true, "violation_rating": true,
	"sub_violations": true, "geo_location": true, "user_agent": true,
	"unit_hostname": true, "management_ip_address": true, "virtual_server": true,
	"x_forwarded_for_header_value": true, "http_class_name": true,
	"dest_port": true, "src_port": true, "session_id": true, "username": true,
	"request": true, "response": true, "outcome": true, "outcome_reason": true,
}

// Adapter implements vendors.Adapter for F5.
type Adapter struct{}

// New constructs the adapter.
func New() *Adapter { return &Adapter{} }

// Vendor returns the vendor name.
func (a *Adapter) Vendor() string { return vendors.F5 }

// Detect distinguishes F5's three encodings.
func (a *Adapter) Detect(payload []byte) (vendors.Format, bool) {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return vendors.FormatUnknown, false
	}

	switch {
	case trimmed[0] == '[':
		return vendors.FormatJSON, true
	case trimmed[0] == '{':
		return vendors.FormatNDJSON, true
	case bytes.HasPrefix(trimmed, []byte("CEF:")):
		return vendors.FormatCEF, true
	case bytes.Contains(trimmed, []byte("support_id=")) ||
		bytes.Contains(trimmed, []byte("ip_client=")):
		// A delimited syslog line carrying key=value pairs.
		return vendors.FormatSyslog, true
	default:
		return vendors.FormatUnknown, false
	}
}

// Parse splits a delivery into records according to the detected format.
func (a *Adapter) Parse(payload []byte, format vendors.Format) ([]vendors.RawRecord, error) {
	switch format {
	case vendors.FormatJSON:
		return parseJSONArray(payload)
	case vendors.FormatNDJSON:
		return parseLines(payload, decodeJSONRecord)
	case vendors.FormatCEF:
		return parseLines(payload, decodeCEFRecord)
	case vendors.FormatSyslog:
		return parseLines(payload, decodeSyslogRecord)
	case vendors.FormatUnknown:
		return nil, fmt.Errorf("%w: unrecognized f5 payload", vendors.ErrUnparseable)
	default:
		return nil, fmt.Errorf("%w: unsupported format %q", vendors.ErrUnparseable, format)
	}
}

func parseJSONArray(payload []byte) ([]vendors.RawRecord, error) {
	var raw []json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("%w: json array: %w", vendors.ErrUnparseable, err)
	}

	records := make([]vendors.RawRecord, 0, len(raw))
	for _, item := range raw {
		records = append(records, decodeJSONRecord(item))
	}
	return records, nil
}

// parseLines splits a payload into lines and decodes each with the given decoder.
func parseLines(
	payload []byte, decode func([]byte) vendors.RawRecord,
) ([]vendors.RawRecord, error) {
	scanner := bufio.NewScanner(bytes.NewReader(payload))
	scanner.Buffer(make([]byte, 0, 64<<10), maxLineBytes)

	var records []vendors.RawRecord
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		// The scanner reuses its buffer; records must own their bytes.
		owned := make([]byte, len(line))
		copy(owned, line)
		records = append(records, decode(owned))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%w: reading lines: %w", vendors.ErrUnparseable, err)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("%w: delivery contained no records", vendors.ErrUnparseable)
	}
	return records, nil
}

func decodeJSONRecord(raw []byte) vendors.RawRecord {
	record := vendors.RawRecord{Bytes: raw, Format: vendors.FormatNDJSON}

	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		return record
	}
	record.Fields = fields
	return record
}

// decodeCEFRecord parses an ArcSight CEF line.
//
// The header is pipe-delimited with backslash escaping; the extension is a
// space-separated key=value list where values may contain spaces. F5 carries the
// interesting fields in cs1..cs6 with matching cs1Label..cs6Label pairs, which are
// resolved to their labelled names so downstream code never sees "cs3".
func decodeCEFRecord(raw []byte) vendors.RawRecord {
	record := vendors.RawRecord{Bytes: raw, Format: vendors.FormatCEF}

	line := string(raw)
	if !strings.HasPrefix(line, "CEF:") {
		return record
	}

	header, extension, found := splitCEFHeader(line)
	if !found {
		return record
	}

	fields := make(map[string]any, len(header)+8)
	for k, v := range header {
		fields[k] = v
	}
	for k, v := range parseCEFExtension(extension) {
		fields[k] = v
	}

	record.Fields = resolveCEFLabels(fields)
	return record
}

// splitCEFHeader extracts the seven fixed header fields and returns the remainder.
func splitCEFHeader(line string) (map[string]string, string, bool) {
	// CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension
	parts := splitUnescaped(line, '|', 8)
	if len(parts) < 8 {
		return nil, "", false
	}

	return map[string]string{
		"cef_version":    strings.TrimPrefix(parts[0], "CEF:"),
		"device_vendor":  parts[1],
		"device_product": parts[2],
		"device_version": parts[3],
		"signature_id":   parts[4],
		"name":           parts[5],
		"severity":       parts[6],
	}, parts[7], true
}

// splitUnescaped splits on sep, honouring backslash escapes, up to n parts.
func splitUnescaped(s string, sep byte, n int) []string {
	var parts []string
	var current strings.Builder
	var escaped bool

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case escaped:
			current.WriteByte(c)
			escaped = false
		case c == '\\':
			escaped = true
		case c == sep && len(parts) < n-1:
			parts = append(parts, current.String())
			current.Reset()
		default:
			current.WriteByte(c)
		}
	}
	return append(parts, current.String())
}

// parseCEFExtension parses the key=value tail.
//
// Values may contain spaces, so a token is only treated as a new key when it contains
// '=' and the text before it looks like an identifier. Splitting naively on spaces
// would truncate every multi-word value, which is most of the useful ones.
func parseCEFExtension(extension string) map[string]string {
	fields := map[string]string{}
	tokens := strings.Fields(extension)

	var currentKey string
	var currentValue strings.Builder

	flush := func() {
		if currentKey != "" {
			fields[currentKey] = currentValue.String()
		}
		currentValue.Reset()
	}

	for _, token := range tokens {
		key, value, isPair := strings.Cut(token, "=")
		if isPair && isIdentifier(key) {
			flush()
			currentKey = key
			currentValue.WriteString(value)
			continue
		}
		if currentKey == "" {
			continue
		}
		currentValue.WriteByte(' ')
		currentValue.WriteString(token)
	}
	flush()

	return fields
}

func isIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		isAlnum := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !isAlnum && r != '_' && r != '.' && r != '-' {
			return false
		}
	}
	return true
}

// resolveCEFLabels rewrites cs1/cs1Label pairs into named fields, so the rest of the
// adapter works with meaningful names rather than positional slots.
func resolveCEFLabels(fields map[string]any) map[string]any {
	resolved := make(map[string]any, len(fields))

	for key, value := range fields {
		if strings.HasSuffix(key, "Label") {
			continue // consumed below
		}
		if label, ok := fields[key+"Label"].(string); ok && label != "" {
			resolved[normalizeLabel(label)] = value
			continue
		}
		resolved[key] = value
	}
	return resolved
}

// normalizeLabel maps a CEF label onto the ASM field name it corresponds to.
func normalizeLabel(label string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(label), " ", "_"))
}

// decodeSyslogRecord parses a delimited syslog line of key=value pairs.
func decodeSyslogRecord(raw []byte) vendors.RawRecord {
	record := vendors.RawRecord{Bytes: raw, Format: vendors.FormatSyslog}

	line := string(raw)

	// BIG-IP ASM's Field-Value Pairs format first, CEF's space-separated extension as
	// the fallback. They are distinguished by `="`, which only the quoted format has.
	// Reading ASM output with the CEF parser splits every value containing a space —
	// date_time and violations always do — and the record then fails on an absent
	// timestamp it plainly contains.
	parse := parseCEFExtension
	if strings.Contains(line, `="`) {
		parse = parseFieldValuePairs
	}

	fields := map[string]any{}
	for k, v := range parse(line) {
		fields[k] = v
	}
	if len(fields) == 0 {
		return record
	}
	record.Fields = fields
	return record
}

// Compile-time check that the adapter satisfies the contract.
var _ vendors.Adapter = (*Adapter)(nil)
