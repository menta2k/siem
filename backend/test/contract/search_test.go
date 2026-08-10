//go:build contract

package contract

import (
	"context"
	"encoding/csv"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
	"github.com/menta2k/siem/internal/audit"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/query"
	"github.com/menta2k/siem/internal/service"
	"github.com/menta2k/siem/internal/vendors"
	"github.com/menta2k/siem/internal/vendors/cloudflare"
	"github.com/menta2k/siem/internal/vendors/f5"
)

var searchNow = time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)

// ---------------------------------------------------------------- stubs

// stubSearch records the query it received, so the tests can assert on what the
// service actually asked storage for rather than only on what it returned.
type stubSearch struct {
	events     []chdata.EventSearchResult
	pageSize   int32
	lastQuery  chdata.EventQuery
	lastCursor query.Cursor
	calls      int
}

func (s *stubSearch) SearchEvents(
	_ context.Context, q chdata.EventQuery,
) (service.EventPage, error) {
	s.lastQuery = q
	s.lastCursor = q.Cursor
	s.calls++
	s.pageSize = q.PageSize

	page := service.EventPage{Items: s.events}
	page.Total = int64(len(s.events))
	return page, nil
}

func (s *stubSearch) SearchCorrelated(
	_ context.Context, _ chdata.CorrelatedQuery,
) (service.CorrelatedPage, error) {
	page := service.CorrelatedPage{Items: []chdata.CorrelatedRequest{fullRecord()}}
	page.Total = 1
	return page, nil
}

// EventIDsFor resolves a ray or support id to the events carrying it. The stub answers
// with the ids it was primed with, so a lookup either resolves or finds nothing —
// enough for a shape contract, and the resolution itself is exercised against real
// storage in the integration suite.
func (s *stubSearch) EventIDsFor(
	_ context.Context, _, _ string, _ query.TimeRange,
) ([]string, error) {
	ids := make([]string, 0, len(s.events))
	for _, e := range s.events {
		ids = append(ids, e.EventID)
	}
	return ids, nil
}

type stubEvents struct {
	event   chdata.NormalizedEvent
	err     error
	payload []byte
}

func (s stubEvents) GetNormalized(context.Context, string) (chdata.NormalizedEvent, error) {
	return s.event, s.err
}

func (s stubEvents) GetRawPayload(context.Context, string) ([]byte, string, error) {
	return s.payload, "application/json", nil
}

// stubTenants supplies the redaction policy the service re-applies when it rebuilds a
// vendor's fields from the raw payload. A contract test asserts the SHAPE of a response,
// so an empty policy is the right answer here: redaction is asserted where it belongs, in
// service.TestTheTenantsRedactionPolicyIsReapplied.
type stubTenants struct{ tenant chdata.Tenant }

func (s stubTenants) GetByID(context.Context, uuid.UUID) (chdata.Tenant, error) {
	return s.tenant, nil
}

type stubAudit struct{ records []audit.Record }

func (s *stubAudit) Append(_ context.Context, r audit.Record) (audit.Entry, error) {
	s.records = append(s.records, r)
	return audit.Entry{}, nil
}

func sampleEvent(id string, at time.Time) chdata.EventSearchResult {
	score := float32(0.42)
	return chdata.EventSearchResult{
		EventID: id, EventTime: at, Vendor: vendors.Cloudflare,
		VendorRequestID: "ray-" + id,
		ClientIP:        net.ParseIP("203.0.113.10"), ClientCountry: "DE", ClientASN: 64512,
		RequestHost: "shop.example.com", RequestPath: "/checkout",
		RequestMethod: "GET", HTTPStatus: 200,
		UserAgent: "curl/8.0", Verdict: vendors.VerdictAllowed,
		RuleID: "waf-1", Score: &score, ScoreKind: vendors.ScoreKindBot,
	}
}

func newSearchService(t *testing.T, stub *stubSearch) (*service.SearchService, *stubAudit) {
	t.Helper()
	auditLog := &stubAudit{}

	// The adapter registry and the tenant policy are what let the service rebuild a
	// vendor's own fields from the raw payload instead of storing a second parsed copy
	// of them. Both are REQUIRED by the constructor, so a contract test that omitted
	// them stopped compiling — which is the gate working: the response shape it pins is
	// derived through exactly this path.
	registry, err := vendors.NewRegistry(cloudflare.New(), f5.New())
	if err != nil {
		t.Fatalf("build adapter registry: %v", err)
	}

	// Nil namers: this suite pins the response SHAPE, and the ASN owner and rule name are
	// optional decoration on it. Naming itself is asserted in the service tests.
	return service.NewSearchService(
		stub, stubEvents{}, auditLog, query.DefaultLimits(), registry, stubTenants{},
		nil, nil,
	), auditLog
}

func validRange() *pb.TimeRange {
	return &pb.TimeRange{
		From: timestamppb.New(searchNow.Add(-time.Hour)),
		To:   timestamppb.New(searchNow),
	}
}

// ---------------------------------------------------------------- contract

func TestSearchEndpointsArePublished(t *testing.T) {
	spec := loadGeneratedSpec(t)

	cases := map[string]string{
		"/api/v1/search/events":     "Search_SearchEvents",
		"/api/v1/search/correlated": "Search_SearchCorrelated",
		"/api/v1/search/export":     "Search_ExportSearch",
	}
	for path, operationID := range cases {
		operation, ok := spec.Paths[path]["post"]
		if !ok {
			t.Errorf("%s POST is not in the generated contract", path)
			continue
		}
		if operation.OperationID != operationID {
			t.Errorf("%s operationId = %q, want %q", path, operation.OperationID, operationID)
		}
	}

	if _, ok := spec.Paths["/api/v1/events/{eventId}"]["get"]; !ok {
		t.Error("/api/v1/events/{eventId} GET is not in the generated contract")
	}
}

func TestEventSummaryMatchesTheDocumentedSchema(t *testing.T) {
	spec := loadGeneratedSpec(t)
	stub := &stubSearch{events: []chdata.EventSearchResult{sampleEvent("e1", searchNow)}}
	svc, _ := newSearchService(t, stub)

	resp, err := svc.SearchEvents(context.Background(), &pb.SearchEventsRequest{
		TimeRange: validRange(),
	})
	if err != nil {
		t.Fatalf("SearchEvents: %v", err)
	}
	if len(resp.GetItems()) != 1 {
		t.Fatalf("got %d items, want 1", len(resp.GetItems()))
	}

	body := encode(t, resp.GetItems()[0])
	documented, ok := spec.Components.Schemas["EventSummary"]
	if !ok {
		t.Fatal("EventSummary is not in the generated components")
	}

	for name := range body {
		if _, present := documented.Properties[name]; !present {
			t.Errorf("handler emitted %q, which the contract does not document", name)
		}
	}
	for _, required := range []string{
		"eventId", "eventTime", "vendor", "client", "request", "verdict",
	} {
		if _, present := body[required]; !present {
			t.Errorf("the contract documents %q but the handler did not emit it", required)
		}
	}
}

// An unbounded scan reads every partition the tenant owns. It is rejected, not queued.
func TestSearchRequiresATimeRange(t *testing.T) {
	svc, _ := newSearchService(t, &stubSearch{})

	for name, req := range map[string]*pb.SearchEventsRequest{
		"no range at all": {},
		"no from":         {TimeRange: &pb.TimeRange{To: timestamppb.New(searchNow)}},
		"no to":           {TimeRange: &pb.TimeRange{From: timestamppb.New(searchNow)}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := svc.SearchEvents(context.Background(), req)
			if err == nil {
				t.Fatal("an unbounded search was accepted")
			}
			if got := mw.AsError(err).Code; got != mw.CodeTimeRangeRequired {
				t.Errorf("code = %q, want %q", got, mw.CodeTimeRangeRequired)
			}
		})
	}
}

func TestSearchRejectsAnOversizedRange(t *testing.T) {
	svc, _ := newSearchService(t, &stubSearch{})

	_, err := svc.SearchEvents(context.Background(), &pb.SearchEventsRequest{
		TimeRange: &pb.TimeRange{
			From: timestamppb.New(searchNow.AddDate(-5, 0, 0)),
			To:   timestamppb.New(searchNow),
		},
	})
	if err == nil {
		t.Fatal("a five-year range was accepted")
	}
	if got := mw.AsError(err).Code; got != mw.CodeTimeRangeTooLarge {
		t.Errorf("code = %q, want %q", got, mw.CodeTimeRangeTooLarge)
	}
}

func TestSearchCapsThePageSize(t *testing.T) {
	stub := &stubSearch{}
	svc, _ := newSearchService(t, stub)

	_, err := svc.SearchEvents(context.Background(), &pb.SearchEventsRequest{
		TimeRange: validRange(),
		Page:      &pb.PageRequest{Limit: 1_000_000},
	})
	if err != nil {
		t.Fatalf("SearchEvents: %v", err)
	}
	if stub.pageSize > query.DefaultMaxRows {
		t.Errorf("page size = %d, want it capped at %d", stub.pageSize, query.DefaultMaxRows)
	}
}

func TestMalformedCursorIsRejectedBySearch(t *testing.T) {
	svc, _ := newSearchService(t, &stubSearch{})

	_, err := svc.SearchEvents(context.Background(), &pb.SearchEventsRequest{
		TimeRange: validRange(),
		Page:      &pb.PageRequest{Cursor: "!!!not-a-cursor!!!"},
	})
	if err == nil {
		t.Fatal("a malformed cursor was accepted")
	}
	if got := mw.AsError(err).Code; got != mw.CodeCursorInvalid {
		t.Errorf("code = %q, want %q", got, mw.CodeCursorInvalid)
	}
}

// A filter the builder does not recognise must fail the query. Dropping it would
// return a WIDER result than the analyst asked for, with nothing to signal it.
func TestFiltersReachTheQueryAsBoundParameters(t *testing.T) {
	stub := &stubSearch{}
	svc, _ := newSearchService(t, stub)

	_, err := svc.SearchEvents(context.Background(), &pb.SearchEventsRequest{
		TimeRange: validRange(),
		Filters: &pb.EventFilters{
			RequestHost: "shop.example.com",
			Verdict:     []pb.Verdict{pb.Verdict_VERDICT_BLOCKED},
			RuleId:      "'; DROP TABLE normalized_events; --",
		},
	})
	if err != nil {
		t.Fatalf("SearchEvents: %v", err)
	}

	if strings.Contains(stub.lastQuery.Conditions, "DROP TABLE") ||
		strings.Contains(stub.lastQuery.Conditions, "shop.example.com") {
		t.Fatalf("a filter value reached the SQL: %s", stub.lastQuery.Conditions)
	}
	if got := strings.Count(stub.lastQuery.Conditions, "?"); got != len(stub.lastQuery.Args) {
		t.Errorf("%d placeholders but %d args", got, len(stub.lastQuery.Args))
	}
}

// The paging fields live on PageResponse, not duplicated onto the response body: two
// places stating the same count is two places to keep in step.
func TestPagingFieldsAreOnThePageResponse(t *testing.T) {
	stub := &stubSearch{events: []chdata.EventSearchResult{sampleEvent("e1", searchNow)}}
	svc, _ := newSearchService(t, stub)

	resp, err := svc.SearchEvents(context.Background(), &pb.SearchEventsRequest{
		TimeRange: validRange(),
	})
	if err != nil {
		t.Fatalf("SearchEvents: %v", err)
	}

	if resp.GetPage() == nil {
		t.Fatal("no page response")
	}
	// One page, no next cursor: the count is exact and must not claim to be an estimate.
	if resp.GetPage().GetTotalIsEstimate() {
		t.Error("a single complete page was reported as an estimate")
	}
	if resp.GetPage().GetTotal() != 1 {
		t.Errorf("total = %d, want 1", resp.GetPage().GetTotal())
	}
}

// ---------------------------------------------------------------- export

func TestExportIsAudited(t *testing.T) {
	stub := &stubSearch{events: []chdata.EventSearchResult{sampleEvent("e1", searchNow)}}
	svc, auditLog := newSearchService(t, stub)

	resp, err := svc.ExportSearch(context.Background(), &pb.ExportSearchRequest{
		TimeRange: validRange(),
		Format:    pb.ExportFormat_EXPORT_FORMAT_CSV,
		MaxRows:   100,
	})
	if err != nil {
		t.Fatalf("ExportSearch: %v", err)
	}

	if len(auditLog.records) != 1 {
		t.Fatalf("%d audit entries, want 1 — an export removes data from the platform",
			len(auditLog.records))
	}
	entry := auditLog.records[0]
	if entry.Action != audit.ActionExport {
		t.Errorf("action = %q, want %q", entry.Action, audit.ActionExport)
	}
	if !strings.Contains(entry.AfterValue, "row_count") {
		t.Errorf("the audit entry does not record the row count: %s", entry.AfterValue)
	}
	if resp.GetRowCount() != 1 {
		t.Errorf("row_count = %d, want 1", resp.GetRowCount())
	}
}

func TestExportProducesTheRequestedFormat(t *testing.T) {
	stub := &stubSearch{events: []chdata.EventSearchResult{sampleEvent("e1", searchNow)}}
	svc, _ := newSearchService(t, stub)

	csvResp, err := svc.ExportSearch(context.Background(), &pb.ExportSearchRequest{
		TimeRange: validRange(), Format: pb.ExportFormat_EXPORT_FORMAT_CSV, MaxRows: 10,
	})
	if err != nil {
		t.Fatalf("ExportSearch: %v", err)
	}
	if !strings.HasPrefix(csvResp.GetContentType(), "text/csv") {
		t.Errorf("content type = %q, want text/csv", csvResp.GetContentType())
	}
	if !strings.HasSuffix(csvResp.GetFilename(), ".csv") {
		t.Errorf("filename = %q, want a .csv suffix", csvResp.GetFilename())
	}

	records, err := csv.NewReader(strings.NewReader(string(csvResp.GetContent()))).ReadAll()
	if err != nil {
		t.Fatalf("the export is not valid CSV: %v", err)
	}
	if len(records) != 2 {
		t.Errorf("%d CSV rows, want a header and one record", len(records))
	}

	ndjsonResp, err := svc.ExportSearch(context.Background(), &pb.ExportSearchRequest{
		TimeRange: validRange(), Format: pb.ExportFormat_EXPORT_FORMAT_NDJSON, MaxRows: 10,
	})
	if err != nil {
		t.Fatalf("ExportSearch: %v", err)
	}
	if ndjsonResp.GetContentType() != "application/x-ndjson" {
		t.Errorf("content type = %q, want application/x-ndjson", ndjsonResp.GetContentType())
	}
}

func TestExportRequiresATimeRange(t *testing.T) {
	svc, auditLog := newSearchService(t, &stubSearch{})

	if _, err := svc.ExportSearch(context.Background(),
		&pb.ExportSearchRequest{}); err == nil {
		t.Fatal("an unbounded export was accepted")
	}
	if len(auditLog.records) != 0 {
		t.Error("a rejected export wrote an audit entry for an export that never happened")
	}
}

// A truncated export must say so. A partial extract that looks complete leads an
// analyst to conclude the attack ended at whatever row the cap fell on.
func TestTruncatedExportIsFlagged(t *testing.T) {
	events := make([]chdata.EventSearchResult, 20)
	for i := range events {
		events[i] = sampleEvent(string(rune('a'+i)), searchNow)
	}
	stub := &stubSearch{events: events}
	svc, _ := newSearchService(t, stub)

	resp, err := svc.ExportSearch(context.Background(), &pb.ExportSearchRequest{
		TimeRange: validRange(),
		Format:    pb.ExportFormat_EXPORT_FORMAT_NDJSON,
		MaxRows:   5,
	})
	if err != nil {
		t.Fatalf("ExportSearch: %v", err)
	}
	if !resp.GetTruncated() {
		t.Error("an export that hit its cap was not flagged as truncated")
	}
	if resp.GetRowCount() != 5 {
		t.Errorf("row_count = %d, want 5", resp.GetRowCount())
	}
}

// ---------------------------------------------------------------- dashboards

func TestDashboardEndpointsArePublished(t *testing.T) {
	spec := loadGeneratedSpec(t)

	for _, path := range []string{
		"/api/v1/dashboards/overview",
		"/api/v1/dashboards/rules",
		"/api/v1/dashboards/sources",
		"/api/v1/dashboards/disagreements",
		"/api/v1/dashboards/feed-health",
	} {
		operation, ok := spec.Paths[path]["get"]
		if !ok {
			t.Errorf("%s GET is not in the generated contract", path)
			continue
		}
		// Every panel takes the same range, so a range change moves them together.
		var hasFrom, hasTo bool
		for _, param := range operation.Parameters {
			switch param.Name {
			case "timeRange.from":
				hasFrom = true
			case "timeRange.to":
				hasTo = true
			}
		}
		if !hasFrom || !hasTo {
			t.Errorf("%s does not accept the shared time range", path)
		}
	}
}
