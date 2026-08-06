// Package datadome adapts DataDome Logs Enrichment deliveries to the common event
// model.
//
// DataDome is the bot-detection vendor of the three: it contributes a bot score
// rather than a WAF rule verdict, which is what makes score_conflict disagreements
// possible — every vendor allowed the request, but DataDome scored it as automated.
//
// Field names arrive in two shapes depending on integration: plain keys from the log
// export, and X-DataDome-* header names from module-level enrichment. Both appear in
// real deployments, so both are read.
package datadome

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/menta2k/siem/internal/vendors"
)

const maxLineBytes = 4 << 20

// botScoreMax is DataDome's score ceiling. Scores are normalized to 0..1 so the
// platform can compare them against thresholds without knowing vendor scales.
const botScoreMax = 100.0

// knownFields covers both naming shapes.
var knownFields = map[string]bool{
	"requestid": true, "timestamp": true, "ip": true, "host": true, "uri": true,
	"method": true, "status": true, "ua": true, "botscore": true, "isbot": true,
	"botname": true, "family": true, "action": true, "country": true, "asn": true,
	"accountid": true, "referer": true, "requestmodulename": true, "serverside": true,
	"x-datadome-requestid": true, "x-datadome-isbot": true, "x-datadome-botname": true,
	"x-datadome-family": true, "x-datadome-botscore": true, "x-datadome-action": true,
}

// actionVerdicts maps DataDome's action vocabulary onto the common model.
var actionVerdicts = map[string]string{
	"block":       vendors.VerdictBlocked,
	"hardblock":   vendors.VerdictBlocked,
	"captcha":     vendors.VerdictChallenged,
	"devicecheck": vendors.VerdictChallenged,
	"challenge":   vendors.VerdictChallenged,
	"ratelimit":   vendors.VerdictRateLimited,
	"allow":       vendors.VerdictAllowed,
	"pass":        vendors.VerdictAllowed,
	// Monitoring mode: DataDome identified a bot but was configured not to act. This
	// is NOT an allow — treating it as one would hide the very disagreements the
	// platform exists to surface.
	"monitor": vendors.VerdictMonitored,
	"protect": vendors.VerdictMonitored,
}

// Adapter implements vendors.Adapter for DataDome.
type Adapter struct{}

// New constructs the adapter.
func New() *Adapter { return &Adapter{} }

// Vendor returns the vendor name.
func (a *Adapter) Vendor() string { return vendors.DataDome }

// Detect identifies the payload encoding.
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
		return vendors.FormatUnknown, false
	}
}

// Parse splits a delivery into records.
func (a *Adapter) Parse(payload []byte, format vendors.Format) ([]vendors.RawRecord, error) {
	if format == vendors.FormatJSON {
		var raw []json.RawMessage
		if err := json.Unmarshal(payload, &raw); err != nil {
			return nil, fmt.Errorf("%w: json array: %w", vendors.ErrUnparseable, err)
		}
		records := make([]vendors.RawRecord, 0, len(raw))
		for _, item := range raw {
			records = append(records, decodeRecord(item))
		}
		return records, nil
	}

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

func decodeRecord(raw []byte) vendors.RawRecord {
	record := vendors.RawRecord{Bytes: raw, Format: vendors.FormatNDJSON}

	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		return record
	}
	// Keys are lowercased so the plain and X-DataDome-* shapes resolve identically.
	normalized := make(map[string]any, len(fields))
	for key, value := range fields {
		normalized[strings.ToLower(key)] = value
	}
	record.Fields = normalized
	return record
}

// Normalize maps a DataDome record onto the common event model. Pure and
// deterministic.
func (a *Adapter) Normalize(record vendors.RawRecord) (vendors.Event, error) {
	if record.Fields == nil {
		return vendors.Event{}, fmt.Errorf("%w: record is not valid json", vendors.ErrUnparseable)
	}

	eventTime, original, err := vendors.ParseTime(firstOf(record.Fields, "timestamp", "ts", "date"))
	if err != nil {
		return vendors.Event{}, fmt.Errorf("field timestamp: %w", err)
	}

	path, query := vendors.SplitURI(vendors.AsString(record.Fields["uri"]))
	clientIP := vendors.ParseIP(vendors.AsString(record.Fields["ip"]))

	event := vendors.Event{
		Vendor:        vendors.DataDome,
		VendorAccount: vendors.AsString(record.Fields["accountid"]),
		VendorRequestID: vendors.AsString(
			firstOf(record.Fields, "requestid", "x-datadome-requestid")),
		EventTime:         eventTime,
		EventTimeOriginal: original,

		ClientIP:       clientIP,
		ClientIPShared: vendors.IsSharedIP(clientIP),
		ClientASN:      vendors.AsUint32(record.Fields["asn"]),
		ClientCountry:  strings.ToUpper(vendors.AsString(record.Fields["country"])),

		RequestHost:   vendors.AsString(record.Fields["host"]),
		RequestPath:   path,
		RequestQuery:  query,
		RequestMethod: strings.ToUpper(vendors.AsString(record.Fields["method"])),
		UserAgent:     vendors.AsString(record.Fields["ua"]),
		HTTPStatus:    vendors.ToStatus(record.Fields["status"]),

		VerdictReason: buildReason(record.Fields),
		RuleID: vendors.AsString(
			firstOf(record.Fields, "botname", "x-datadome-botname")),
		ScoreKind: vendors.ScoreKindNone,
	}

	// The bot score is DataDome's whole contribution to correlation, so it is
	// normalized to 0..1 rather than left on the vendor's 0..100 scale. Comparing a
	// raw 95 against an F5 violation_rating of 5 would be meaningless.
	if raw, ok := vendors.AsFloat32(firstOf(record.Fields, "botscore", "x-datadome-botscore")); ok {
		normalized := raw / botScoreMax
		event.Score = &normalized
		event.ScoreKind = vendors.ScoreKindBot
	}

	event.RawExtra, event.UnknownFields = collectExtra(record.Fields)
	event.Verdict = mapVerdict(record.Fields, &event)

	return event, nil
}

// buildReason combines the bot name and family into a readable explanation.
func buildReason(fields map[string]any) string {
	name := vendors.AsString(firstOf(fields, "botname", "x-datadome-botname"))
	family := vendors.AsString(firstOf(fields, "family", "x-datadome-family"))

	switch {
	case name != "" && family != "":
		return fmt.Sprintf("%s (%s)", name, family)
	case name != "":
		return name
	default:
		return family
	}
}

func mapVerdict(fields map[string]any, event *vendors.Event) string {
	action := strings.ToLower(strings.TrimSpace(
		vendors.AsString(firstOf(fields, "action", "x-datadome-action"))))

	if verdict, ok := actionVerdicts[action]; ok {
		return verdict
	}
	if action == "" {
		// No action reported at all: fall back to the bot flag, which every
		// integration sets. Reporting unknown here would make most records useless.
		if isBot(fields) {
			return vendors.VerdictMonitored
		}
		return vendors.VerdictAllowed
	}

	if event.RawExtra == nil {
		event.RawExtra = map[string]string{}
	}
	event.RawExtra["unmapped_action"] = action
	return vendors.VerdictUnknown
}

func isBot(fields map[string]any) bool {
	switch v := firstOf(fields, "isbot", "x-datadome-isbot").(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true") || v == "1"
	default:
		return false
	}
}

func firstOf(fields map[string]any, keys ...string) any {
	for _, key := range keys {
		if value, ok := fields[key]; ok && vendors.AsString(value) != "" {
			return value
		}
	}
	return nil
}

func collectExtra(fields map[string]any) (extra map[string]string, unknown []string) {
	extra = make(map[string]string, len(fields))

	for key, value := range fields {
		if !knownFields[key] {
			unknown = append(unknown, key)
		}
		if rendered := vendors.AsString(value); rendered != "" {
			extra[key] = rendered
		}
	}
	return extra, unknown
}

// Compile-time check that the adapter satisfies the contract.
var _ vendors.Adapter = (*Adapter)(nil)
