// Package cloudflare adapts Cloudflare Logpush deliveries to the common event model.
//
// Logpush emits newline-delimited JSON from the `http_requests` dataset, optionally
// gzipped. The `RayID` field is the reason tier-1 correlation is possible at all:
// customers commonly propagate it into F5 and DataDome logs, which gives an exact
// join key rather than a heuristic one.
package cloudflare

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/menta2k/siem/internal/vendors"
)

// maxLineBytes bounds a single NDJSON line. A delivery is untrusted input, and an
// unbounded line would let one malformed record exhaust memory.
const maxLineBytes = 4 << 20 // 4 MiB

// knownFields are the Logpush fields this adapter maps or deliberately ignores.
// Anything outside this set is reported as an unknown field and drives the
// schema-drift warning (FR-012).
var knownFields = map[string]bool{
	"RayID": true, "EdgeStartTimestamp": true, "EdgeEndTimestamp": true,
	"ClientIP": true, "ClientASN": true, "ClientCountry": true,
	"ClientRequestHost": true, "ClientRequestURI": true, "ClientRequestMethod": true,
	"ClientRequestUserAgent": true, "ClientRequestPath": true,
	"EdgeResponseStatus": true, "EdgeResponseBytes": true,
	"SecurityAction": true, "SecurityRuleID": true, "SecurityRuleIDs": true,
	"SecurityRuleDescription": true, "SecuritySources": true, "SecurityActions": true,
	"SecurityLevel": true, "ZoneName": true, "ZoneID": true,
	// Performance and cache fields are known but carry no security meaning; they are
	// preserved in RawExtra without being reported as drift.
	"CacheCacheStatus": true, "CacheResponseStatus": true, "OriginResponseStatus": true,
	"ClientRequestProtocol": true, "ClientSSLProtocol": true, "EdgeColoCode": true,
	// The TLS client fingerprint, mapped onto the common model rather than only
	// preserved.
	"JA4": true,

	// ---------------------------------------------------------------- the rest of a
	// real Logpush job.
	//
	// THIS LIST WAS WRITTEN AGAINST A MINIMAL JOB AND NEVER GREW WITH IT. A production
	// record carries 59 fields and this map recognised 20, so 39 of them were counted as
	// drift on EVERY event. That did not show up only because the counter behind the
	// warning had no producer; wiring it up without this would have lit a permanent
	// 100%-drift alarm on a correctly-configured feed, which is the fastest way to teach
	// an operator to ignore it.
	//
	// Declared known, not mapped. "Known" here means the field is a documented part of
	// the dataset and its absence from the common model is a decision, not a surprise —
	// which is exactly what drift has to mean to be worth alerting on.

	// Bot Management. NOT MAPPED, and the most valuable thing in this list: the adapter
	// still says the dataset carries no bot score, which was true of the job it was
	// written for and is not true of this one. Mapping BotScore onto the common model's
	// bot score is a real change to correlation and disagreement detection, so it is
	// deliberately left as its own piece of work rather than smuggled in here.
	"BotScore": true, "BotScoreSrc": true, "BotTags": true,
	"BotDetectionIDs": true, "BotDetectionTags": true, "JSDetectionPassed": true,

	// WAF scoring and the variable that matched. Also unmapped, for the same reason.
	"WAFAttackScore": true, "WAFSQLiAttackScore": true, "WAFXSSAttackScore": true,
	"WAFRCEAttackScore": true, "WAFFlags": true, "WAFMatchedVar": true,
	"MatchedRules": true, "rules": true, "rulesetId": true, "rulesetVersion": true,

	// Client geo, beyond the country the common model already carries.
	"ClientCity": true, "ClientLatitude": true, "ClientLongitude": true,

	// Edge routing and topology: which colo, which tier, which path. Operational
	// context with no security meaning.
	"EdgeColoID": true, "EdgeServerIP": true, "EdgePathingSrc": true,
	"EdgePathingStatus": true, "EdgeCFConnectingO2O": true, "UpperTierColoID": true,
	"SmartRouteColoID": true, "WorkerStatus": true, "ParentRayID": true,

	// Content scanning results.
	"ContentScanObjResults": true, "ContentScanObjTypes": true,

	// The other TLS fingerprints alongside JA4.
	"JA3Hash": true, "JA4Signals": true,

	// The custom-field header maps. Present on every event once a custom field is
	// declared, and empty on most of them — an empty map is the vendor saying "the
	// header was not on this request", not a missing field.
	"RequestHeaders": true, "ResponseHeaders": true,

	// Per-client rolling ratios and ranks this deployment adds to its job. Not part of
	// the stock dataset, which is precisely why they must be declared: an operator's own
	// custom fields are the one thing that is definitely not a vendor schema change.
	"cache_ratio_1h": true, "h2h3_ratio_1h": true, "heuristic_ratio_1h": true,
	"ips_quantile_1h": true, "ips_rank_1h": true, "paths_rank_1h": true,
	"reqs_quantile_1h": true, "reqs_rank_1h": true, "uas_rank_1h": true,
}

// securityActionVerdicts maps Cloudflare's action vocabulary onto the common model.
//
// This table is the most correctness-sensitive mapping in the adapter: correlation's
// disagreement detection is only as good as it is. Every row is covered by a test.
var securityActionVerdicts = map[string]string{
	"block":                vendors.VerdictBlocked,
	"drop":                 vendors.VerdictBlocked,
	"challenge":            vendors.VerdictChallenged,
	"jschallenge":          vendors.VerdictChallenged,
	"interactivechallenge": vendors.VerdictChallenged,

	// MANAGED CHALLENGE, and the key that never matched anything.
	//
	// The lookup lowercases Cloudflare's camelCase, so "managedChallenge" arrives as
	// "managedchallenge" — while this map held "managed_challenge" with an underscore
	// no lowercasing could ever produce. Every other challenge key in this table is
	// already in the concatenated form for exactly that reason; this one was written
	// in snake_case and silently matched nothing.
	//
	// The cost was not cosmetic. Managed challenge is Cloudflare's default challenge
	// action — 21,000 requests in three hours on this deployment — and all of them were
	// recorded with no verdict at all. A challenged request that reads as `unknown` is
	// invisible to disagreement detection, which is the entire purpose of correlating
	// these vendors: Cloudflare challenging what F5 allowed is precisely the case the
	// platform exists to surface, and it could not be seen.
	"managedchallenge": vendors.VerdictChallenged,

	// The outcomes of a managed challenge. All three record that the challenge engine
	// ACTED on the request, which is what SecurityAction reports; whether the visitor
	// then solved it, and how, is the result rather than a different action. Mapping
	// the solved variants to `allowed` would erase the fact that Cloudflare found the
	// request suspicious enough to challenge while another vendor waved it through.
	//
	// The exact string is preserved in RawExtra either way, so the distinction between
	// issued, solved and bypassed is never lost — only summarised.
	"managedchallengeinteractivesolved":    vendors.VerdictChallenged,
	"managedchallengenoninteractivesolved": vendors.VerdictChallenged,
	"managedchallengebypassed":             vendors.VerdictChallenged,
	"connectionclose":                      vendors.VerdictRateLimited,
	"ratelimit":                            vendors.VerdictRateLimited,
	"allow":                                vendors.VerdictAllowed,

	// LOG IS NOT ALLOWED. The rule matched and was deliberately not enforced, which is
	// exactly what `monitored` means — the same verdict "simulate" already maps to. It
	// sat under `allowed` alongside skip and bypass, which made a detection-only rule
	// indistinguishable from clean traffic and left the platform unable to answer the
	// one question ruleset tuning asks: what is Cloudflare catching but not acting on.
	//
	// This moves existing numbers. The verdict-mix panel shifts, and a Cloudflare
	// `monitored` against an F5 `blocked` now registers as a disagreement — correctly,
	// because that is precisely the case worth looking at.
	"log": vendors.VerdictMonitored,

	"skip":   vendors.VerdictAllowed,
	"bypass": vendors.VerdictAllowed,
	// "simulate" is a staging action: the rule matched but was not enforced. It maps
	// to monitored, not allowed, so it does not manufacture a false disagreement
	// against a vendor that genuinely blocked the same request.
	"simulate": vendors.VerdictMonitored,
	// "unknown" is what Cloudflare emits when no security action was taken at all.
	"unknown": vendors.VerdictAllowed,
	"":        vendors.VerdictAllowed,
}

// Adapter implements vendors.Adapter for Cloudflare.
type Adapter struct{}

// New constructs the adapter.
func New() *Adapter { return &Adapter{} }

// Vendor returns the vendor name.
func (a *Adapter) Vendor() string { return vendors.Cloudflare }

// Detect identifies the payload encoding, transparently handling gzip.
func (a *Adapter) Detect(payload []byte) (vendors.Format, bool) {
	body := payload
	if isGzip(payload) {
		decompressed, err := decompress(payload)
		if err != nil {
			return vendors.FormatUnknown, false
		}
		body = decompressed
	}

	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return vendors.FormatUnknown, false
	}
	switch trimmed[0] {
	case '[':
		return vendors.FormatJSON, true
	case '{':
		// One object or many, newline-separated. NDJSON handles both.
		return vendors.FormatNDJSON, true
	default:
		return vendors.FormatUnknown, false
	}
}

// Parse splits a delivery into records, keeping each record's original bytes.
//
// A malformed line yields a record with no Fields rather than failing the batch: one
// bad line must not cost a customer the other 49,999 (Acceptance Scenario 1.4).
func (a *Adapter) Parse(payload []byte, format vendors.Format) ([]vendors.RawRecord, error) {
	body := payload
	if isGzip(payload) {
		decompressed, err := decompress(payload)
		if err != nil {
			return nil, fmt.Errorf("%w: gzip: %w", vendors.ErrUnparseable, err)
		}
		body = decompressed
	}

	if format == vendors.FormatJSON {
		return parseJSONArray(body)
	}
	return parseNDJSON(body)
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
		// retained. Without this every record would end up holding the last line.
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

// decodeRecord decodes one record, leaving Fields nil when it will not parse so the
// caller can dead-letter it individually.
func decodeRecord(raw []byte) vendors.RawRecord {
	record := vendors.RawRecord{Bytes: raw, Format: vendors.FormatNDJSON}

	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		return record
	}
	record.Fields = fields
	return record
}

// Normalize maps a Logpush record onto the common event model.
//
// It is pure: no clock, no network, no shared state. Same input, same output — which
// is what makes the correlation replay corpus meaningful.
func (a *Adapter) Normalize(record vendors.RawRecord) (vendors.Event, error) {
	if record.Fields == nil {
		return vendors.Event{}, fmt.Errorf("%w: record is not valid json", vendors.ErrUnparseable)
	}

	// Checked before anything else: this record is not a request at all, it is the
	// DataDome Worker's call to its protection API, and the fields below would describe
	// that call rather than the visitor who caused it.
	if isDataDomeCall(record.Fields) {
		event, err := normalizeDataDomeCall(record.Fields)
		if err != nil {
			return vendors.Event{}, fmt.Errorf("field EdgeStartTimestamp: %w", err)
		}
		return event, nil
	}
	return normalizeRequest(record.Fields)
}

// normalizeRequest maps an ordinary Cloudflare request onto the common model.
func normalizeRequest(fields map[string]any) (vendors.Event, error) {
	record := vendors.RawRecord{Fields: fields}

	eventTime, original, err := vendors.ParseTime(record.Fields["EdgeStartTimestamp"])
	if err != nil {
		return vendors.Event{}, fmt.Errorf("field EdgeStartTimestamp: %w", err)
	}

	uri := vendors.AsString(record.Fields["ClientRequestURI"])
	path, query := vendors.SplitURI(uri)
	if path == "" {
		path = vendors.AsString(record.Fields["ClientRequestPath"])
	}

	clientIP := vendors.ParseIP(vendors.AsString(record.Fields["ClientIP"]))

	event := vendors.Event{
		Vendor:          vendors.Cloudflare,
		VendorAccount:   vendors.AsString(record.Fields["ZoneName"]),
		VendorRequestID: vendors.AsString(record.Fields["RayID"]),
		// A Worker subrequest is a second Cloudflare row for the SAME user request,
		// and it is the only place the hops are tied together: F5 receives this row's
		// own ray, while DataDome's verdict is reachable only through the parent's.
		// Recording both is what lets one correlated record hold all three verdicts.
		LinkedRequestID:   parentRay(record.Fields),
		EventTime:         eventTime,
		EventTimeOriginal: original,

		ClientIP:       clientIP,
		ClientIPShared: vendors.IsSharedIP(clientIP),
		ClientASN:      vendors.AsUint32(record.Fields["ClientASN"]),
		ClientCountry:  strings.ToUpper(vendors.AsString(record.Fields["ClientCountry"])),

		RequestHost:   vendors.AsString(record.Fields["ClientRequestHost"]),
		RequestPath:   path,
		RequestQuery:  query,
		RequestMethod: strings.ToUpper(vendors.AsString(record.Fields["ClientRequestMethod"])),
		UserAgent:     vendors.AsString(record.Fields["ClientRequestUserAgent"]),
		HTTPStatus:    vendors.ToStatus(record.Fields["EdgeResponseStatus"]),
		JA4:           vendors.AsString(record.Fields["JA4"]),
		WAF:           wafDetail(record.Fields),

		VerdictReason: vendors.AsString(record.Fields["SecurityRuleDescription"]),
		RuleID:        vendors.AsString(record.Fields["SecurityRuleID"]),
		RuleIDs:       vendors.AsStringSlice(record.Fields["SecurityRuleIDs"]),
		// Cloudflare's http_requests dataset carries no bot or threat score.
		ScoreKind: vendors.ScoreKindNone,
	}

	// Order matters: RawExtra must be populated BEFORE mapVerdict, which appends the
	// original action to it when it cannot be mapped. Doing it the other way round
	// silently discards that value.
	event.RawExtra, event.UnknownFields = collectExtra(record.Fields)
	event.Verdict = mapVerdict(record.Fields, &event)

	return event, nil
}

// mapVerdict resolves the security action, recording anything unmapped rather than
// discarding it.
func mapVerdict(fields map[string]any, event *vendors.Event) string {
	action := strings.ToLower(strings.TrimSpace(vendors.AsString(fields["SecurityAction"])))

	if verdict, ok := securityActionVerdicts[action]; ok {
		return verdict
	}
	// An action this adapter does not know is reported as unknown, with the original
	// kept so an operator can see what the vendor actually said (FR-009).
	if event.RawExtra == nil {
		event.RawExtra = map[string]string{}
	}
	event.RawExtra["unmapped_security_action"] = action
	return vendors.VerdictUnknown
}

// wafDetail reads Cloudflare's WAF scoring and rule-engine attribution.
//
// The scores are 1-99 with LOW MEANING ATTACK, which is the opposite direction to every
// other score in the platform. They are carried on their own struct for that reason;
// see the note on vendors.WAFDetail.
func wafDetail(fields map[string]any) vendors.WAFDetail {
	return vendors.WAFDetail{
		AttackScore: wafScore(fields["WAFAttackScore"]),
		SQLiScore:   wafScore(fields["WAFSQLiAttackScore"]),
		XSSScore:    wafScore(fields["WAFXSSAttackScore"]),
		RCEScore:    wafScore(fields["WAFRCEAttackScore"]),

		// The action verbatim, in Cloudflare's own casing. mapVerdict lowercases its
		// copy for the lookup; this one is what an operator reads back and matches
		// against the Cloudflare dashboard, so it is not normalised.
		Action: vendors.AsString(fields["SecurityAction"]),
		// FIRST source only. The field is an array and in practice carries one entry;
		// where it carries more, the first is the engine that produced the action, and
		// storing a list would make the column ungroupable for no gain.
		Source: firstOfSlice(vendors.AsStringSlice(fields["SecuritySources"])),
	}
}

// wafScore narrows a score to the range the vendor actually emits.
//
// 1-100, NOT the 1-99 the documentation describes. Cloudflare sends 100 for a request
// it considers definitively clean — on this deployment that is the single most common
// value, 31% of all requests — and a bound of 99 silently reclassified every one of
// them as "not scored". The observed evidence beats the published range.
//
// Anything outside 1-100 becomes 0, meaning "not scored". A missing field must not read
// as score 0: on this INVERTED scale 0 would be the strongest possible attack signal,
// so every unscored request would top a report sorted by severity.
func wafScore(value any) uint8 {
	score := vendors.AsUint32(value)
	if score == 0 || score > 100 {
		return 0
	}
	return uint8(score)
}

// firstOfSlice returns the first entry, or empty for none.
func firstOfSlice(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// collectExtra preserves unmapped fields and reports genuinely unrecognized ones.
func collectExtra(fields map[string]any) (extra map[string]string, unknown []string) {
	extra = make(map[string]string, len(fields))

	for key, value := range fields {
		if !knownFields[key] {
			unknown = append(unknown, key)
		}
		// Everything is preserved, known or not (FR-010). Mapped fields are cheap to
		// duplicate and having the original available settles "did we read it right".
		if rendered := vendors.AsString(value); rendered != "" {
			extra[key] = rendered
		}
	}
	return extra, unknown
}

func isGzip(payload []byte) bool {
	return len(payload) > 2 && payload[0] == 0x1f && payload[1] == 0x8b
}

func decompress(payload []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("open gzip reader: %w", err)
	}
	defer func() { _ = reader.Close() }()

	// Bounded so a decompression bomb cannot exhaust memory.
	limited := io.LimitReader(reader, 256<<20)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}
	return body, nil
}

// Compile-time check that the adapter satisfies the contract.
var _ vendors.Adapter = (*Adapter)(nil)
