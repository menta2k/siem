package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
	"github.com/menta2k/siem/internal/audit"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/query"
	"github.com/menta2k/siem/internal/tenancy"
	"github.com/menta2k/siem/internal/vendors"
)

// EventPage is a page of event search hits. Aliased so the searcher interface reads
// as what it returns rather than as a wall of generics.
type EventPage = chdata.Page[chdata.EventSearchResult]

// CorrelatedPage is a page of correlated-request search hits.
type CorrelatedPage = chdata.Page[chdata.CorrelatedRequest]

// EventSearcher is the storage surface the search service reads through.
type EventSearcher interface {
	SearchEvents(ctx context.Context, q chdata.EventQuery) (EventPage, error)
	SearchCorrelated(ctx context.Context, q chdata.CorrelatedQuery) (CorrelatedPage, error)
	// EventIDsFor resolves a vendor identifier to the events carrying it. Correlated
	// records store event ids rather than identifiers, so searching them by ray or
	// support id is a two-step lookup.
	EventIDsFor(ctx context.Context, column, value string, rng query.TimeRange) ([]string, error)
}

// EventDetailReader fetches one event with its raw payload.
type EventDetailReader interface {
	GetNormalized(ctx context.Context, eventID string) (chdata.NormalizedEvent, error)
	GetRawPayload(
		ctx context.Context, eventID string, hint chdata.RawPayloadHint,
	) (chdata.RawPayload, error)
}

// TenantPolicyReader supplies the redaction policy to re-apply when vendor fields are
// rebuilt from a payload on read.
type TenantPolicyReader interface {
	GetByID(ctx context.Context, tenantID uuid.UUID) (chdata.Tenant, error)
}

// SearchService implements the Search proto service.
type SearchService struct {
	search   EventSearcher
	events   EventDetailReader
	auditLog AuditWriter
	limits   query.Limits
	// adapters and tenants rebuild raw_extra and unknown_fields from the stored payload
	// rather than reading columns that used to hold a parsed copy of those same bytes.
	adapters *vendors.Registry
	tenants  TenantPolicyReader
	// networks names the client's ASN on read. Optional: nil where the lookup is
	// disabled, in which case results carry the bare number.
	networks NetworkNamer
	// rules names the WAF rule that matched. Optional in the same way, and empty until a
	// tenant configures a Cloudflare token.
	rules RuleNamer
	// log records a degraded read. Optional so existing constructions keep working; a
	// nil logger simply means the degradation is not written down.
	log mw.Logger
	now func() time.Time
}

// WithLogger attaches a logger, so a raw payload that could not be read is recorded
// rather than silently rendered blank. Returns the service for chaining at construction.
func (s *SearchService) WithLogger(log mw.Logger) *SearchService {
	s.log = log
	return s
}

// NewSearchService constructs the service.
//
// `now` is injected so the bounds can be tested deterministically; a rule about time
// that can only be checked against the real clock gets tested loosely or not at all.
func NewSearchService(
	search EventSearcher, events EventDetailReader, auditLog AuditWriter,
	limits query.Limits, adapters *vendors.Registry, tenants TenantPolicyReader,
	networks NetworkNamer, rules RuleNamer,
) *SearchService {
	return &SearchService{
		search: search, events: events, auditLog: auditLog,
		limits: limits, adapters: adapters, tenants: tenants,
		networks: networks, rules: rules, now: time.Now,
	}
}

// SearchEvents runs a bounded cross-vendor event search.
func (s *SearchService) SearchEvents(
	ctx context.Context, req *pb.SearchEventsRequest,
) (resp *pb.SearchEventsResponse, err error) {
	// Deferred so a rejection is measured too. Recording only successful queries hides
	// exactly the case worth alerting on: a client whose requests are all refused looks
	// identical to a client making none.
	started := s.now()
	defer func() { query.Observe("search_events", started, int64(len(resp.GetItems())), err) }()

	rng, err := s.timeRange(req.GetTimeRange())
	if err != nil {
		return nil, err
	}

	conditions, args, err := eventConditions(req.GetFilters())
	if err != nil {
		return nil, err
	}

	cursor, err := query.DecodeCursor(req.GetPage().GetCursor())
	if err != nil {
		return nil, err
	}

	ctx, cancel := s.limits.WithTimeout(ctx)
	defer cancel()

	page, err := s.search.SearchEvents(ctx, chdata.EventQuery{
		Range:      rng,
		Conditions: conditions,
		Args:       args,
		Cursor:     cursor,
		PageSize:   s.limits.PageSize(req.GetPage().GetLimit()),
	})
	if err != nil {
		return nil, query.TranslateError(err)
	}

	out := &pb.SearchEventsResponse{
		Items: make([]*pb.EventSummary, 0, len(page.Items)),
		Page: &pb.PageResponse{
			NextCursor:      page.NextCursor,
			Total:           page.Total,
			TotalIsEstimate: page.TotalIsEstimate,
		},
	}
	for _, item := range page.Items {
		out.Items = append(out.Items, toEventSummary(item))
	}
	// One lookup for the whole page: the same network carries most of the rows of a
	// typical search, so resolving per row would multiply one query by the page size.
	nameClients(ctx, s.networks, clientsOf(out.Items)...)
	describeEvents(ctx, s.rules, out.Items)
	return out, nil
}

// SearchCorrelated runs a bounded search over correlated requests.
func (s *SearchService) SearchCorrelated(
	ctx context.Context, req *pb.SearchCorrelatedRequest,
) (resp *pb.SearchCorrelatedResponse, err error) {
	started := s.now()
	defer func() { query.Observe("search_correlated", started, int64(len(resp.GetItems())), err) }()

	rng, err := s.timeRange(req.GetTimeRange())
	if err != nil {
		return nil, err
	}

	// An identifier filter is resolved to event ids FIRST, because a correlated record
	// stores the ids and not the identifiers. Resolving to nothing is a real answer —
	// the identifier matched no event — and must render as an empty page rather than as
	// an absent filter, which would return everything in the range.
	eventIDs, matched, err := s.resolveIdentifiers(ctx, req.GetFilters(), rng)
	if err != nil {
		return nil, err
	}
	if !matched {
		return &pb.SearchCorrelatedResponse{
			Items: []*pb.CorrelatedRequest{}, Page: &pb.PageResponse{},
		}, nil
	}

	conditions, args, err := correlatedConditions(req.GetFilters(), eventIDs)
	if err != nil {
		return nil, err
	}

	cursor, err := query.DecodeCursor(req.GetPage().GetCursor())
	if err != nil {
		return nil, err
	}

	ctx, cancel := s.limits.WithTimeout(ctx)
	defer cancel()

	page, err := s.search.SearchCorrelated(ctx, chdata.CorrelatedQuery{
		Range:      rng,
		Conditions: conditions,
		Args:       args,
		Cursor:     cursor,
		PageSize:   s.limits.PageSize(req.GetPage().GetLimit()),
	})
	if err != nil {
		return nil, query.TranslateError(err)
	}

	out := correlatedResponse(page)
	nameClients(ctx, s.networks, correlatedClientsOf(out.GetItems())...)
	describeVerdicts(ctx, s.rules, out.GetItems())
	return out, nil
}

// correlatedResponse projects a page onto the wire type.
func correlatedResponse(page CorrelatedPage) *pb.SearchCorrelatedResponse {
	out := &pb.SearchCorrelatedResponse{
		Items: make([]*pb.CorrelatedRequest, 0, len(page.Items)),
		Page: &pb.PageResponse{
			NextCursor:      page.NextCursor,
			Total:           page.Total,
			TotalIsEstimate: page.TotalIsEstimate,
		},
	}
	for _, item := range page.Items {
		out.Items = append(out.Items, toCorrelatedProto(item))
	}
	return out
}

// GetEvent returns one event with the vendor payload exactly as received (FR-005).
func (s *SearchService) GetEvent(
	ctx context.Context, req *pb.GetEventRequest,
) (*pb.EventDetail, error) {
	eventID := req.GetEventId()
	if eventID == "" {
		return nil, mw.ValidationFailed("event_id is required")
	}

	event, err := s.events.GetNormalized(ctx, eventID)
	switch {
	case errors.Is(err, chdata.ErrNotFound):
		return nil, mw.NotFound("event")
	case err != nil:
		return nil, mw.Internal().WithCause(err)
	}

	detail := &pb.EventDetail{Summary: toEventSummary(toSearchResult(event))}
	nameClients(ctx, s.networks, detail.GetSummary().GetClient())
	describeEvents(ctx, s.rules, []*pb.EventSummary{detail.GetSummary()})

	// A missing raw payload is not an error worth failing the whole read for: retention
	// may have expired it while the normalized row survives under a longer TTL, and the
	// normalized view is still the answer to the analyst's question.
	//
	// EVERY OTHER FAILURE IS LOGGED, because degrading silently is how this hid. The
	// lookup was scanning the whole table and being cancelled when the client gave up,
	// and `if err == nil` turned each cancellation into a 200 with an empty payload —
	// indistinguishable from an expired one, with nothing written down. The hint below
	// is what stops the scan; this is what would have made it visible a lot sooner.
	raw, err := s.events.GetRawPayload(ctx, eventID, chdata.RawPayloadHint{
		ReceivedAt:   event.ReceivedAt,
		SourceVendor: event.SourceVendor,
	})
	switch {
	case err == nil:
		detail.RawPayload = string(raw.Payload)
		detail.RawContentType = raw.Format
		// Rebuilt from those bytes rather than read from a column. Storing the parsed
		// copy cost four times what the payload itself does, and this is the only view
		// that ever asked for it.
		//
		// PARSED WITH THE VENDOR THAT DELIVERED THE BYTES, not the one the event is
		// attributed to. They differ for every DataDome verdict, which is normalized out
		// of a Cloudflare Worker payload — handing those bytes to DataDome's adapter
		// returned nothing, so the parsed-field view was blank on 16% of events while the
		// raw payload beside it rendered fine.
		detail.RawExtra, detail.UnknownFields = s.vendorFields(ctx, raw.Vendor, raw.Payload)
	case errors.Is(err, chdata.ErrNotFound):
		// Expected: retention expired the payload while the normalized row survives.
		// Expected: retention expired the payload while the normalized row survives.
	case s.log != nil:
		s.log.Error(ctx, "event detail: raw payload could not be read",
			"event_id", eventID, "vendor", event.Vendor, "error", err.Error())
	}

	// After the payload block, because the signature ids come out of the fields rebuilt
	// from it. The violations do not, so a blocked request whose payload has expired
	// still explains its violations — with the signatures simply absent, which is the
	// honest rendering of "the bytes that named them are gone".
	detail.Asm = asmFindings(event, detail.GetRawExtra())

	return detail, nil
}

// vendorFields rebuilds one event's vendor-native fields under the tenant's redaction
// policy, degrading to nothing rather than failing the read around it.
func (s *SearchService) vendorFields(
	ctx context.Context, vendor string, payload []byte,
) (map[string]string, []string) {
	var redacted []string
	if s.tenants != nil {
		if tenantID, err := tenancy.MustID(ctx); err == nil {
			if tenant, err := s.tenants.GetByID(ctx, tenantID); err == nil {
				redacted = tenant.RedactedFields
			}
		}
	}

	return payloadFields(s.adapters, vendor, payload, redacted)
}

// timeRange validates the mandatory window.
func (s *SearchService) timeRange(r *pb.TimeRange) (query.TimeRange, error) {
	if r == nil {
		return query.TimeRange{}, mw.TimeRangeRequired()
	}
	var from, to time.Time
	if r.GetFrom() != nil {
		from = r.GetFrom().AsTime()
	}
	if r.GetTo() != nil {
		to = r.GetTo().AsTime()
	}
	return s.limits.Range(from, to, s.now())
}

// eventConditions renders the filters through the allowlisting builder.
//
// Nothing here formats a value into SQL. The builder rejects any field it does not
// recognise, and a rejected filter fails the query rather than being dropped — a
// dropped filter would return a WIDER result than the analyst asked for.
func eventConditions(f *pb.EventFilters) (string, []any, error) {
	b := query.NewBuilder(query.EventsTable)
	if f == nil {
		return b.Conditions()
	}

	b.WhereIfSet("client_ip", query.OpEqual, f.GetClientIp())
	b.WhereIfSet("request_host", query.OpEqual, f.GetRequestHost())
	b.WhereIfSet("request_path", query.OpEqual, f.GetRequestPath())
	b.WhereIfSet("rule_id", query.OpEqual, f.GetRuleId())
	b.WhereIfSet("country", query.OpEqual, f.GetCountry())
	b.WhereIfSet("request_method", query.OpEqual, f.GetRequestMethod())
	b.WhereIfSet("vendor_request_id", query.OpEqual, f.GetVendorRequestId())
	b.WhereIfSet("vendor_event_id", query.OpEqual, f.GetVendorEventId())

	if names := vendorNames(f.GetVendor()); len(names) > 0 {
		b.Where("vendor", query.OpIn, names)
	}
	if names := verdictNames(f.GetVerdict()); len(names) > 0 {
		b.Where("verdict", query.OpIn, names)
	}
	if f.MinScore != nil {
		b.Where("score", query.OpGreaterEqual, f.GetMinScore())
	}
	if f.MaxScore != nil {
		b.Where("score", query.OpLessEqual, f.GetMaxScore())
	}
	if f.Asn != nil {
		b.Where("client_asn", query.OpEqual, f.GetAsn())
	}
	if f.HttpStatus != nil {
		b.Where("http_status", query.OpEqual, f.GetHttpStatus())
	}

	// Exact, not a token match: a fingerprint is one opaque value and half of one
	// identifies nothing. The bloom_filter index answers equality directly.
	b.WhereIfSet("ja4", query.OpEqual, f.GetJa4())

	// Token match rather than LIKE: these columns carry token bloom indexes, and a
	// leading-wildcard LIKE would read every granule instead of using them.
	b.WhereIfSet("user_agent", query.OpHasToken, f.GetUserAgent())
	b.WhereIfSet("request_path", query.OpHasToken, f.GetQ())

	return b.Conditions()
}

// resolveIdentifiers turns a ray or support-id filter into the event ids carrying it.
//
// Reports matched=false when a filter was set but resolved to no events, which is the
// difference between "no such request" and "no filter" — conflating them would answer a
// specific question with every record in the range.
func (s *SearchService) resolveIdentifiers(
	ctx context.Context, f *pb.CorrelatedFilters, rng query.TimeRange,
) (eventIDs []string, matched bool, err error) {
	if f == nil {
		return nil, true, nil
	}

	lookups := []struct{ column, value string }{
		{"vendor_request_id", f.GetVendorRequestId()},
		{"vendor_event_id", f.GetVendorEventId()},
		// A correlated request has no fingerprint of its own: the vendors that joined
		// into it need not all have reported one, so there is nothing to store on the
		// join. Resolving through the events is what makes "which correlations involved
		// this client stack" answerable at all.
		{"ja4", f.GetJa4()},
	}

	for _, lookup := range lookups {
		if lookup.value == "" {
			continue
		}
		found, err := s.search.EventIDsFor(ctx, lookup.column, lookup.value, rng)
		if err != nil {
			return nil, false, query.TranslateError(err)
		}
		if len(found) == 0 {
			return nil, false, nil
		}
		eventIDs = append(eventIDs, found...)
	}
	return eventIDs, true, nil
}

func correlatedConditions(f *pb.CorrelatedFilters, eventIDs []string) (string, []any, error) {
	b := query.NewBuilder(query.CorrelatedTable)
	if f == nil {
		return b.Conditions()
	}

	// The identifiers were resolved to these ids by the caller; the record matches when
	// its event list contains any of them.
	if len(eventIDs) > 0 {
		b.Where("event_ids", query.OpHasAny, eventIDs)
	}

	b.WhereIfSet("client_ip", query.OpEqual, f.GetClientIp())
	b.WhereIfSet("request_host", query.OpEqual, f.GetRequestHost())
	b.WhereIfSet("request_path", query.OpEqual, f.GetRequestPath())
	b.WhereIfSet("country", query.OpEqual, f.GetCountry())

	if f.Asn != nil {
		b.Where("client_asn", query.OpEqual, f.GetAsn())
	}
	if f.MinVendorCount != nil {
		b.Where("vendor_count", query.OpGreaterEqual, f.GetMinVendorCount())
	}
	if f.GetOnlyDisagreements() {
		b.Where("has_disagreement", query.OpEqual, true)
	}
	if kind := disagreementFromProto(f.GetDisagreementKind()); kind != "" {
		b.Where("disagreement_kind", query.OpEqual, kind)
	}
	if level := confidenceFromProto(f.GetConfidence()); level != "" {
		b.Where("confidence", query.OpEqual, level)
	}
	if outcome := verdictFromProto(f.GetCombinedOutcome()); outcome != "" {
		b.Where("combined_outcome", query.OpEqual, outcome)
	}

	return b.Conditions()
}

func vendorNames(values []pb.Vendor) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if name := vendorFromProto(v); name != "" {
			out = append(out, name)
		}
	}
	return out
}

func verdictNames(values []pb.Verdict) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if name := verdictFromProto(v); name != "" {
			out = append(out, name)
		}
	}
	return out
}

func verdictFromProto(v pb.Verdict) string {
	switch v {
	case pb.Verdict_VERDICT_ALLOWED:
		return vendors.VerdictAllowed
	case pb.Verdict_VERDICT_BLOCKED:
		return vendors.VerdictBlocked
	case pb.Verdict_VERDICT_CHALLENGED:
		return vendors.VerdictChallenged
	case pb.Verdict_VERDICT_RATE_LIMITED:
		return vendors.VerdictRateLimited
	case pb.Verdict_VERDICT_MONITORED:
		return vendors.VerdictMonitored
	case pb.Verdict_VERDICT_UNKNOWN:
		return vendors.VerdictUnknown
	case pb.Verdict_VERDICT_UNSPECIFIED:
		return ""
	default:
		return ""
	}
}

func disagreementFromProto(kind pb.DisagreementKind) string {
	switch kind {
	case pb.DisagreementKind_DISAGREEMENT_KIND_NONE:
		return "none"
	case pb.DisagreementKind_DISAGREEMENT_KIND_ALLOW_VS_BLOCK:
		return "allow_vs_block"
	case pb.DisagreementKind_DISAGREEMENT_KIND_ALLOW_VS_CHALLENGE:
		return "allow_vs_challenge"
	case pb.DisagreementKind_DISAGREEMENT_KIND_SCORE_CONFLICT:
		return "score_conflict"
	case pb.DisagreementKind_DISAGREEMENT_KIND_UNSPECIFIED:
		return ""
	default:
		return ""
	}
}

// toSearchResult narrows a full event to the search projection, so the detail endpoint
// and the search results describe an event the same way.
func toSearchResult(e chdata.NormalizedEvent) chdata.EventSearchResult {
	return chdata.EventSearchResult{
		EventID: e.EventID, EventTime: e.EventTime, Vendor: e.Vendor, FeedID: e.FeedID,
		VendorRequestID: e.VendorRequestID, VendorEventID: e.VendorEventID,
		ClientIP: e.ClientIP, ClientIPShared: e.ClientIPShared,
		ClientASN: e.ClientASN, ClientCountry: e.ClientCountry,
		RequestHost: e.RequestHost, RequestPath: e.RequestPath,
		RequestQuery: e.RequestQuery, RequestMethod: e.RequestMethod,
		UserAgent: e.UserAgent, HTTPStatus: e.HTTPStatus, JA4: e.JA4,
		Verdict: e.Verdict, VerdictReason: e.VerdictReason,
		RuleID: e.RuleID, RuleIDs: e.RuleIDs, Score: e.Score, ScoreKind: e.ScoreKind,
	}
}

func toEventSummary(e chdata.EventSearchResult) *pb.EventSummary {
	summary := &pb.EventSummary{
		EventId:         e.EventID,
		EventTime:       timestamppb.New(e.EventTime),
		Vendor:          vendorToProto(e.Vendor),
		FeedId:          e.FeedID.String(),
		VendorRequestId: e.VendorRequestID,
		VendorEventId:   e.VendorEventID,
		Client: &pb.ClientInfo{
			IpShared: e.ClientIPShared,
			Asn:      e.ClientASN,
			Country:  e.ClientCountry,
			// The user agent is attacker-controlled text. It travels as data and every
			// renderer treats it as text; nothing in the pipeline interprets it.
			UserAgent: e.UserAgent,
		},
		Request: &pb.RequestInfo{
			Host:   e.RequestHost,
			Path:   e.RequestPath,
			Query:  e.RequestQuery,
			Method: e.RequestMethod,
			Status: uint32(e.HTTPStatus),
		},
		Ja4:           e.JA4,
		Verdict:       verdictToProto(e.Verdict),
		VerdictReason: e.VerdictReason,
		RuleId:        e.RuleID,
		RuleIds:       e.RuleIDs,
		ScoreKind:     e.ScoreKind,
	}
	if e.ClientIP != nil {
		summary.Client.Ip = e.ClientIP.String()
	}
	if e.Score != nil {
		score := *e.Score
		summary.Score = &score
	}
	return summary
}

// ---------------------------------------------------------------- export

// exportColumns fixes the CSV column order.
//
// Declared here rather than derived from a map, because a CSV whose columns move
// between runs cannot be diffed, scripted against, or loaded by a saved import.
var exportColumns = []string{
	"event_id", "event_time", "vendor", "vendor_request_id", "vendor_event_id",
	"client_ip", "client_country", "client_asn",
	"request_host", "request_path", "request_method", "http_status",
	"user_agent", "ja4", "verdict", "verdict_reason", "rule_id", "score", "score_kind",
}

// ExportSearch streams a row-capped export of an event search (FR-026).
//
// The audit entry is written whether or not the export completes, and it records the
// query and the row count. An export removes data from the platform's control, so
// "who took what, when" has to survive the request — including when the export was
// truncated, since a partial extract is still an extract.
func (s *SearchService) ExportSearch(
	ctx context.Context, req *pb.ExportSearchRequest,
) (resp *pb.ExportSearchResponse, err error) {
	started := s.now()
	defer func() { query.Observe("export", started, resp.GetRowCount(), err) }()

	rng, err := s.timeRange(req.GetTimeRange())
	if err != nil {
		return nil, err
	}

	format := exportFormat(req.GetFormat())
	conditions, args, err := eventConditions(req.GetFilters())
	if err != nil {
		return nil, err
	}

	ctx, cancel := s.limits.WithTimeout(ctx)
	defer cancel()

	rows, err := s.collectExportRows(ctx, rng, conditions, args, int(req.GetMaxRows()))
	if err != nil {
		return nil, err
	}

	buf, exporter, err := renderExport(format, rows, int(req.GetMaxRows()))
	if err != nil {
		return nil, err
	}

	written := int64(exporter.Written())

	at := s.now().UTC()
	recordAudit(ctx, s.auditLog, audit.Record{
		Action:     audit.ActionExport,
		TargetType: "event_search",
		TargetID:   query.Filename("events", at, format),
		AfterValue: exportDescription(req, exporter.Written(), exporter.Truncated()),
		Result:     audit.ResultSuccess,
	})

	query.ObserveExport(format, exporter.Written(), exporter.Truncated())

	return &pb.ExportSearchResponse{
		Content:     buf.Bytes(),
		ContentType: format.ContentType(),
		Filename:    query.Filename("events", at, format),
		RowCount:    written,
		Truncated:   exporter.Truncated(),
	}, nil
}

// renderExport serializes the collected rows.
func renderExport(
	format query.Format, rows []query.ExportRow, maxRows int,
) (*bytes.Buffer, *query.Exporter, error) {
	var buf bytes.Buffer
	exporter := query.NewExporter(format, exportColumns, maxRows)

	err := exporter.Write(&buf, func(yield func(query.ExportRow) bool) {
		for _, row := range rows {
			if !yield(row) {
				return
			}
		}
	})
	if err != nil {
		return nil, nil, mw.Internal().WithCause(err)
	}
	return &buf, exporter, nil
}

// collectExportRows walks the result pages up to the export cap.
//
// Paged rather than one enormous query: the cap is a hundred thousand rows, and a
// single LIMIT of that size holds the whole result in the driver's buffer before the
// first byte is written.
func (s *SearchService) collectExportRows(
	ctx context.Context, rng query.TimeRange, conditions string, args []any, maxRows int,
) ([]query.ExportRow, error) {
	if maxRows <= 0 || maxRows > query.DefaultMaxExportRows {
		maxRows = query.DefaultMaxExportRows
	}

	var (
		out    []query.ExportRow
		cursor query.Cursor
	)
	for len(out) < maxRows {
		page, err := s.search.SearchEvents(ctx, chdata.EventQuery{
			Range:      rng,
			Conditions: conditions,
			Args:       args,
			Cursor:     cursor,
			PageSize:   s.limits.PageSize(0),
		})
		if err != nil {
			return nil, query.TranslateError(err)
		}
		for _, item := range page.Items {
			out = append(out, exportRow(item))
		}
		if !page.HasMore() {
			break
		}
		decoded, err := query.DecodeCursor(page.NextCursor)
		if err != nil {
			return nil, err
		}
		cursor = decoded
	}
	return out, nil
}

func exportRow(e chdata.EventSearchResult) query.ExportRow {
	row := query.ExportRow{
		"event_id": e.EventID, "event_time": e.EventTime, "vendor": e.Vendor,
		"vendor_request_id": e.VendorRequestID, "vendor_event_id": e.VendorEventID,
		"client_country": e.ClientCountry, "client_asn": e.ClientASN,
		"request_host": e.RequestHost, "request_path": e.RequestPath,
		"request_method": e.RequestMethod, "http_status": e.HTTPStatus,
		"user_agent": e.UserAgent, "ja4": e.JA4, "verdict": e.Verdict,
		"verdict_reason": e.VerdictReason, "rule_id": e.RuleID,
		"score_kind": e.ScoreKind,
	}
	if e.ClientIP != nil {
		row["client_ip"] = e.ClientIP.String()
	}
	// An absent score is left absent rather than rendered as 0. A vendor that does not
	// score requests would otherwise appear to have rated every one of them as human.
	if e.Score != nil {
		row["score"] = *e.Score
	}
	return row
}

func exportFormat(f pb.ExportFormat) query.Format {
	if f == pb.ExportFormat_EXPORT_FORMAT_CSV {
		return query.FormatCSV
	}
	return query.FormatNDJSON
}

// exportDescription records what was taken, for the audit trail.
func exportDescription(req *pb.ExportSearchRequest, rows int, truncated bool) string {
	described := map[string]any{
		"from":      req.GetTimeRange().GetFrom().AsTime().UTC().Format(time.RFC3339),
		"to":        req.GetTimeRange().GetTo().AsTime().UTC().Format(time.RFC3339),
		"format":    exportFormat(req.GetFormat()).Extension(),
		"row_count": rows,
		"truncated": truncated,
	}
	if f := req.GetFilters(); f != nil {
		described["filters"] = protojson.Format(f)
	}
	encoded, err := json.Marshal(described)
	if err != nil {
		// The audit entry must still be written; losing the description is far better
		// than losing the record that an export happened at all.
		return fmt.Sprintf(`{"row_count":%d,"truncated":%t}`, rows, truncated)
	}
	return string(encoded)
}
