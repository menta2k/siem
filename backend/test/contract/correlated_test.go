//go:build contract

package contract

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/service"
	"github.com/menta2k/siem/internal/vendors"
)

// ---------------------------------------------------------------- generated contract

// generatedSpec is the subset of the GENERATED OpenAPI document these tests read.
//
// The generated document — not a hand-written copy of it — because that is what the
// frontend client is built from. Asserting against anything else would let the API and
// the client drift while the test stayed green.
type generatedSpec struct {
	Paths map[string]map[string]struct {
		OperationID string `yaml:"operationId"`
		Parameters  []struct {
			Name string `yaml:"name"`
			In   string `yaml:"in"`
		} `yaml:"parameters"`
		Responses map[string]struct {
			Content map[string]struct {
				Schema map[string]any `yaml:"schema"`
			} `yaml:"content"`
		} `yaml:"responses"`
	} `yaml:"paths"`
	Components struct {
		Schemas map[string]struct {
			Properties map[string]struct {
				Type   string   `yaml:"type"`
				Format string   `yaml:"format"`
				Enum   []string `yaml:"enum"`
			} `yaml:"properties"`
		} `yaml:"schemas"`
	} `yaml:"components"`
}

func loadGeneratedSpec(t *testing.T) generatedSpec {
	t.Helper()

	path := filepath.Join("..", "..", "api", "openapi.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var spec generatedSpec
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return spec
}

// ---------------------------------------------------------------- stub store

type stubCorrelated struct {
	record chdata.CorrelatedRequest
	err    error
}

func (s stubCorrelated) Get(context.Context, uuid.UUID) (chdata.CorrelatedRequest, error) {
	return s.record, s.err
}

func (s stubCorrelated) List(
	context.Context, chdata.CorrelatedFilter,
) ([]chdata.CorrelatedRequest, error) {
	if s.err != nil {
		return nil, s.err
	}
	return []chdata.CorrelatedRequest{s.record}, nil
}

var contractCorrelationID = uuid.MustParse("6b3f1b6e-9f1a-4f3e-8f0a-5b9c2d1e7a44")

// fullRecord populates every field, so a missing mapping shows up as an absent key
// rather than hiding behind a zero value that the encoder would omit anyway.
func fullRecord() chdata.CorrelatedRequest {
	at := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)

	return chdata.CorrelatedRequest{
		TenantID:       uuid.New(),
		CorrelationID:  contractCorrelationID,
		WindowStart:    at,
		FirstEventTime: at,
		LastEventTime:  at.Add(2 * time.Second),
		Vendors:        []string{vendors.Cloudflare, vendors.F5},
		VendorCount:    2,
		EventIDs:       []string{"cf-1", "f5-1"},
		ClientIP:       net.ParseIP("203.0.113.10"),
		ClientIPShared: true,
		ClientASN:      64512,
		ClientCountry:  "DE",
		RequestHost:    "shop.example.com",
		RequestPath:    "/checkout",
		RequestMethod:  "GET",
		Verdicts: map[string]string{
			vendors.Cloudflare: vendors.VerdictAllowed,
			vendors.F5:         vendors.VerdictBlocked,
		},
		RuleIDs: map[string]string{vendors.F5: "prod_waf_policy"},
		Scores:  map[string]float32{vendors.Cloudflare: 0.91},

		CombinedOutcome:  vendors.VerdictBlocked,
		HasDisagreement:  true,
		DisagreementKind: "allow_vs_block",

		JoinSignals:    []string{"ip_host_path_method", "time_window"},
		JoinTier:       2,
		Confidence:     "low",
		CandidateCount: 3,

		Version: 2,
		Amended: true,
	}
}

func encode(t *testing.T, msg proto.Message) map[string]any {
	t.Helper()

	// The same marshaller the HTTP transport uses, so what is asserted is what a client
	// actually receives — field naming included.
	raw, err := protojson.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return decoded
}

// ---------------------------------------------------------------- the tests

func TestCorrelatedEndpointIsPublished(t *testing.T) {
	spec := loadGeneratedSpec(t)

	const path = "/api/v1/correlated/{correlationId}"
	operation, ok := spec.Paths[path]["get"]
	if !ok {
		t.Fatalf("%s GET is not in the generated contract", path)
	}
	if operation.OperationID != "Correlation_GetCorrelatedRequest" {
		t.Errorf("operationId = %q, want Correlation_GetCorrelatedRequest — the generated "+
			"client's method name is derived from it", operation.OperationID)
	}

	response, ok := operation.Responses["200"]
	if !ok {
		t.Fatal("no 200 response documented")
	}
	schema := response.Content["application/json"].Schema
	if got := schema["$ref"]; got != "#/components/schemas/CorrelatedRequest" {
		t.Errorf("200 schema = %v, want a CorrelatedRequest reference", got)
	}

	if _, ok := spec.Paths["/api/v1/correlated"]["get"]; !ok {
		t.Error("/api/v1/correlated GET (the listing) is not in the generated contract")
	}
}

// The handler's actual output must carry every field the contract advertises.
func TestCorrelatedResponseMatchesTheDocumentedSchema(t *testing.T) {
	spec := loadGeneratedSpec(t)
	svc := service.NewCorrelationService(stubCorrelated{record: fullRecord()})

	resp, err := svc.GetCorrelatedRequest(context.Background(),
		&pb.GetCorrelatedRequestRequest{CorrelationId: contractCorrelationID.String()})
	if err != nil {
		t.Fatalf("GetCorrelatedRequest: %v", err)
	}
	body := encode(t, resp)

	documented, ok := spec.Components.Schemas["CorrelatedRequest"]
	if !ok {
		t.Fatal("CorrelatedRequest is not in the generated components")
	}

	for name := range documented.Properties {
		if _, present := body[name]; !present {
			t.Errorf("contract documents %q but the handler did not emit it", name)
		}
	}
	for name := range body {
		if _, present := documented.Properties[name]; !present {
			t.Errorf("handler emitted %q, which the contract does not document", name)
		}
	}
}

// Enums must serialize as strings. As integers the generated TypeScript client types
// them as `number`, and every consumer ends up hard-coding ordinals that a proto
// reordering would silently invalidate.
func TestCorrelatedEnumsSerializeAsStrings(t *testing.T) {
	svc := service.NewCorrelationService(stubCorrelated{record: fullRecord()})

	resp, err := svc.GetCorrelatedRequest(context.Background(),
		&pb.GetCorrelatedRequestRequest{CorrelationId: contractCorrelationID.String()})
	if err != nil {
		t.Fatalf("GetCorrelatedRequest: %v", err)
	}
	body := encode(t, resp)

	for _, field := range []string{"combinedOutcome", "disagreementKind", "confidence"} {
		if _, isString := body[field].(string); !isString {
			t.Errorf("%s = %v (%T), want a string", field, body[field], body[field])
		}
	}

	signals, ok := body["joinSignals"].([]any)
	if !ok || len(signals) == 0 {
		t.Fatalf("joinSignals = %v, want a non-empty array", body["joinSignals"])
	}
	for _, signal := range signals {
		if _, isString := signal.(string); !isString {
			t.Errorf("joinSignals entry %v is %T, want a string", signal, signal)
		}
	}
}

// The join provenance is the point of the endpoint (FR-015, FR-024): an analyst who
// cannot see WHY two events were joined cannot act on the record.
func TestCorrelatedResponseCarriesJoinProvenance(t *testing.T) {
	svc := service.NewCorrelationService(stubCorrelated{record: fullRecord()})

	resp, err := svc.GetCorrelatedRequest(context.Background(),
		&pb.GetCorrelatedRequestRequest{CorrelationId: contractCorrelationID.String()})
	if err != nil {
		t.Fatalf("GetCorrelatedRequest: %v", err)
	}

	if resp.GetJoinTier() != 2 {
		t.Errorf("joinTier = %d, want 2", resp.GetJoinTier())
	}
	if resp.GetConfidence() != pb.Confidence_CONFIDENCE_LOW {
		t.Errorf("confidence = %v, want low", resp.GetConfidence())
	}
	if resp.GetCandidateCount() != 3 {
		t.Errorf("candidateCount = %d, want 3", resp.GetCandidateCount())
	}
	if len(resp.GetJoinSignals()) != 2 {
		t.Errorf("joinSignals = %v, want both signals", resp.GetJoinSignals())
	}
	if len(resp.GetEventIds()) != 2 {
		t.Errorf("eventIds = %v, want links to both contributing events", resp.GetEventIds())
	}
	if !resp.GetAmended() || resp.GetVersion() != 2 {
		t.Errorf("amended=%v version=%d, want the amendment history preserved",
			resp.GetAmended(), resp.GetVersion())
	}
}

// Per-vendor detail is what makes a disagreement actionable; a flattened summary would
// tell an analyst that vendors disagreed without saying which said what.
func TestCorrelatedResponseKeepsPerVendorDetail(t *testing.T) {
	svc := service.NewCorrelationService(stubCorrelated{record: fullRecord()})

	resp, err := svc.GetCorrelatedRequest(context.Background(),
		&pb.GetCorrelatedRequestRequest{CorrelationId: contractCorrelationID.String()})
	if err != nil {
		t.Fatalf("GetCorrelatedRequest: %v", err)
	}

	byVendor := map[pb.Vendor]*pb.VendorVerdict{}
	for _, v := range resp.GetVendorVerdicts() {
		byVendor[v.GetVendor()] = v
	}

	cf, ok := byVendor[pb.Vendor_VENDOR_CLOUDFLARE]
	if !ok {
		t.Fatalf("no Cloudflare verdict in %v", resp.GetVendorVerdicts())
	}
	if cf.GetVerdict() != pb.Verdict_VERDICT_ALLOWED {
		t.Errorf("cloudflare verdict = %v, want allowed", cf.GetVerdict())
	}
	if cf.Score == nil || *cf.Score != 0.91 {
		t.Errorf("cloudflare score = %v, want 0.91", cf.Score)
	}

	f5, ok := byVendor[pb.Vendor_VENDOR_F5]
	if !ok {
		t.Fatalf("no F5 verdict in %v", resp.GetVendorVerdicts())
	}
	if f5.GetVerdict() != pb.Verdict_VERDICT_BLOCKED {
		t.Errorf("f5 verdict = %v, want blocked", f5.GetVerdict())
	}
	if f5.GetRuleId() != "prod_waf_policy" {
		t.Errorf("f5 rule id = %q, want prod_waf_policy", f5.GetRuleId())
	}
}

// Ordering must be stable: a response that reshuffles itself between identical calls
// is unusable for diffing and for caching alike.
func TestVendorVerdictOrderIsStable(t *testing.T) {
	svc := service.NewCorrelationService(stubCorrelated{record: fullRecord()})

	var first []pb.Vendor
	for i := range 20 {
		resp, err := svc.GetCorrelatedRequest(context.Background(),
			&pb.GetCorrelatedRequestRequest{CorrelationId: contractCorrelationID.String()})
		if err != nil {
			t.Fatalf("GetCorrelatedRequest: %v", err)
		}

		order := make([]pb.Vendor, 0, len(resp.GetVendorVerdicts()))
		for _, v := range resp.GetVendorVerdicts() {
			order = append(order, v.GetVendor())
		}

		if i == 0 {
			first = order
			continue
		}
		for j := range order {
			if order[j] != first[j] {
				t.Fatalf("call %d returned vendors in a different order: %v vs %v",
					i, order, first)
			}
		}
	}
}

func TestMalformedCorrelationIDIsRejected(t *testing.T) {
	svc := service.NewCorrelationService(stubCorrelated{record: fullRecord()})

	_, err := svc.GetCorrelatedRequest(context.Background(),
		&pb.GetCorrelatedRequestRequest{CorrelationId: "not-a-uuid"})
	if err == nil {
		t.Fatal("a malformed correlation id was accepted")
	}
	if got := mw.AsError(err).HTTPStatus(); got != 400 {
		t.Errorf("status = %d, want 400", got)
	}
}

func TestUnknownCorrelationIDIsNotFound(t *testing.T) {
	svc := service.NewCorrelationService(stubCorrelated{err: chdata.ErrCorrelatedNotFound})

	_, err := svc.GetCorrelatedRequest(context.Background(),
		&pb.GetCorrelatedRequestRequest{CorrelationId: contractCorrelationID.String()})
	if err == nil {
		t.Fatal("an unknown correlation id returned a record")
	}
	if got := mw.AsError(err).HTTPStatus(); got != 404 {
		t.Errorf("status = %d, want 404", got)
	}
}

// An unbounded correlated scan reads every partition the tenant has ever written, so
// it is rejected rather than queued.
func TestListRequiresATimeRange(t *testing.T) {
	svc := service.NewCorrelationService(stubCorrelated{record: fullRecord()})

	_, err := svc.ListCorrelatedRequests(context.Background(),
		&pb.ListCorrelatedRequestsRequest{})
	if err == nil {
		t.Fatal("an unbounded listing was accepted")
	}
	if got := mw.AsError(err).HTTPStatus(); got != 400 {
		t.Errorf("status = %d, want 400", got)
	}
}
