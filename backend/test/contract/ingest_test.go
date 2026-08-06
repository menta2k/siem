//go:build contract

// Package contract verifies that handlers actually behave the way the published
// contract says they do.
//
// These tests exist because a contract document nobody executes is a wish. They load
// api/ingest.openapi.yaml, drive the real handler, and fail when a status code,
// response shape, or required header stops matching what is documented — which is the
// only thing that keeps a hand-authored contract honest.
package contract

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/data/stream"
	"github.com/menta2k/siem/internal/ingest"
	"github.com/menta2k/siem/internal/ingest/dedup"
	"github.com/menta2k/siem/internal/ingest/receiver"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/vendors"
	"github.com/menta2k/siem/internal/vendors/cloudflare"
	"github.com/menta2k/siem/internal/vendors/datadome"
	"github.com/menta2k/siem/internal/vendors/f5"
)

// ---------------------------------------------------------------- contract document

// spec is the subset of OpenAPI these tests assert against.
type spec struct {
	Paths map[string]struct {
		Post struct {
			OperationID string `yaml:"operationId"`
			Responses   map[string]struct {
				Description string `yaml:"description"`
				Headers     map[string]struct {
					Schema map[string]any `yaml:"schema"`
				} `yaml:"headers"`
				Content map[string]struct {
					Schema map[string]any `yaml:"schema"`
				} `yaml:"content"`
			} `yaml:"responses"`
		} `yaml:"post"`
	} `yaml:"paths"`
	Components struct {
		Schemas map[string]struct {
			Required   []string       `yaml:"required"`
			Properties map[string]any `yaml:"properties"`
		} `yaml:"schemas"`
	} `yaml:"components"`
}

const ingestPath = "/ingest/v1/{vendor}/{feed_id}"

func loadSpec(t *testing.T) spec {
	t.Helper()

	path := filepath.Join("..", "..", "api", "ingest.openapi.yaml")
	data, err := os.ReadFile(path) //nolint:gosec // repository-relative path
	if err != nil {
		t.Fatalf("read contract: %v", err)
	}

	var s spec
	if err := yaml.Unmarshal(data, &s); err != nil {
		t.Fatalf("parse contract: %v", err)
	}
	if _, ok := s.Paths[ingestPath]; !ok {
		t.Fatalf("the contract does not document %s", ingestPath)
	}
	return s
}

// documentsStatus reports whether the contract declares a response for this status.
func documentsStatus(t *testing.T, s spec, status int) bool {
	t.Helper()
	_, ok := s.Paths[ingestPath].Post.Responses[strconv.Itoa(status)]
	return ok
}

func requiresHeader(t *testing.T, s spec, status int, header string) bool {
	t.Helper()
	resp, ok := s.Paths[ingestPath].Post.Responses[strconv.Itoa(status)]
	if !ok {
		return false
	}
	_, has := resp.Headers[header]
	return has
}

// ---------------------------------------------------------------- harness

const (
	feedToken = "contract-feed-token-abcdefghijklmnop"
	goodEvent = `{"RayID":"contract-1","EdgeStartTimestamp":"2026-08-06T12:00:00Z",` +
		`"ClientIP":"203.0.113.10","ClientRequestHost":"shop.example.com",` +
		`"ClientRequestURI":"/checkout","ClientRequestMethod":"POST",` +
		`"EdgeResponseStatus":403,"SecurityAction":"block"}`
)

type stubFeeds struct{ feed chdata.Feed }

func (s *stubFeeds) GetForIngest(context.Context, uuid.UUID) (chdata.Feed, error) {
	return s.feed, nil
}

type stubSecrets struct{}

func (stubSecrets) Resolve(_ context.Context, ref string) (string, error) {
	if ref == "ref-token" {
		return feedToken, nil
	}
	return "", nil
}

var errBrokerDown = errors.New("all brokers unreachable")

type stubProducer struct {
	mu   sync.Mutex
	fail bool
}

func (p *stubProducer) Publish(context.Context, string, []stream.Record) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail {
		return errBrokerDown
	}
	return nil
}

type stubCounter struct {
	mu     sync.Mutex
	counts map[string]int64
}

func (c *stubCounter) IncrBy(
	_ context.Context, key string, delta int64, _ time.Duration,
) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counts[key] += delta
	return c.counts[key], nil
}

func (c *stubCounter) Exists(_ context.Context, keys ...string) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var count int64
	for _, key := range keys {
		if c.counts[key] > 0 {
			count++
		}
	}
	return count, nil
}

func (c *stubCounter) Set(_ context.Context, key, _ string, _ time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counts[key] = 1
	return nil
}

type stubHealth struct{}

func (stubHealth) Record(context.Context, ingest.HealthSample) {}

type harness struct {
	handler  http.Handler
	feedID   uuid.UUID
	producer *stubProducer
	feeds    *stubFeeds
}

func newHarness(t *testing.T, quotaEventsPerSec uint32) *harness {
	t.Helper()

	feedID := uuid.New()
	feeds := &stubFeeds{feed: chdata.Feed{
		TenantID: uuid.New(), ID: feedID, Vendor: vendors.Cloudflare,
		Name: "contract", Delivery: chdata.DeliveryPush, Enabled: true,
		CredentialRef: "ref-token", QuotaEventsPerSec: quotaEventsPerSec,
	}}
	producer := &stubProducer{}
	counter := &stubCounter{counts: map[string]int64{}}

	registry, err := vendors.NewRegistry(cloudflare.New(), f5.New(), datadome.New())
	if err != nil {
		t.Fatalf("NewRegistry(): %v", err)
	}

	r := receiver.New(feeds, stubSecrets{}, registry,
		ingest.NewPublisher(producer, "raw", "dlq"),
		dedup.New(counter, time.Minute),
		ingest.NewQuotaEnforcer(counter),
		stubHealth{}, mw.NewLogger("error", "json"),
		receiver.Options{MaxBodyBytes: 1 << 20, MaxBatchEvents: 10})

	return &harness{r.Handler(), feedID, producer, feeds}
}

func (h *harness) post(
	t *testing.T, body string, mutate ...func(*http.Request),
) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/ingest/v1/cloudflare/"+h.feedID.String(), strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+feedToken)
	for _, m := range mutate {
		m(req)
	}

	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec
}

// ---------------------------------------------------------------- assertions

// assertMatchesSchema checks a response body against a named contract schema.
func assertMatchesSchema(t *testing.T, s spec, schemaName string, body []byte) {
	t.Helper()

	schema, ok := s.Components.Schemas[schemaName]
	if !ok {
		t.Fatalf("the contract has no schema named %q", schemaName)
	}

	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("response is not JSON: %v (body=%s)", err, body)
	}

	for _, field := range schema.Required {
		if _, present := decoded[field]; !present {
			t.Errorf("response is missing required field %q from schema %s (body=%s)",
				field, schemaName, body)
		}
	}
	// An undocumented field is a contract violation in the other direction: a client
	// generated from this document would silently drop it.
	for field := range decoded {
		if _, documented := schema.Properties[field]; !documented {
			t.Errorf("response carries field %q which schema %s does not document",
				field, schemaName)
		}
	}
}

// ---------------------------------------------------------------- tests

func TestContractDocumentsEveryStatusTheHandlerReturns(t *testing.T) {
	s := loadSpec(t)

	// Each case drives the handler into one documented outcome. If the handler starts
	// returning something the contract does not declare, this fails.
	tests := []struct {
		name   string
		status int
		run    func(t *testing.T) *httptest.ResponseRecorder
	}{
		{"accepted", http.StatusAccepted, func(t *testing.T) *httptest.ResponseRecorder {
			return newHarness(t, 0).post(t, goodEvent)
		}},
		{"partial", http.StatusMultiStatus, func(t *testing.T) *httptest.ResponseRecorder {
			return newHarness(t, 0).post(t,
				goodEvent+"\n"+`{"RayID":"bad","EdgeStartTimestamp":"nope"}`)
		}},
		{"unparseable", http.StatusBadRequest, func(t *testing.T) *httptest.ResponseRecorder {
			return newHarness(t, 0).post(t, "not json at all")
		}},
		{"bad credential", http.StatusUnauthorized, func(t *testing.T) *httptest.ResponseRecorder {
			return newHarness(t, 0).post(t, goodEvent, func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer wrong")
			})
		}},
		{"feed mismatch", http.StatusForbidden, func(t *testing.T) *httptest.ResponseRecorder {
			h := newHarness(t, 0)
			h.feeds.feed.Vendor = vendors.DataDome
			return h.post(t, goodEvent)
		}},
		{"disabled feed", http.StatusNotFound, func(t *testing.T) *httptest.ResponseRecorder {
			h := newHarness(t, 0)
			h.feeds.feed.Enabled = false
			return h.post(t, goodEvent)
		}},
		{"batch too large", http.StatusRequestEntityTooLarge,
			func(t *testing.T) *httptest.ResponseRecorder {
				lines := make([]string, 0, 20)
				for range 20 {
					lines = append(lines, goodEvent)
				}
				return newHarness(t, 0).post(t, strings.Join(lines, "\n"))
			}},
		{"quota exceeded", http.StatusTooManyRequests, func(t *testing.T) *httptest.ResponseRecorder {
			h := newHarness(t, 1)
			h.post(t, goodEvent)
			return h.post(t, goodEvent+"\n"+goodEvent)
		}},
		{"broker down", http.StatusServiceUnavailable, func(t *testing.T) *httptest.ResponseRecorder {
			h := newHarness(t, 0)
			h.producer.fail = true
			return h.post(t, goodEvent)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := tt.run(t)

			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d (body=%s)", rec.Code, tt.status, rec.Body.String())
			}
			if !documentsStatus(t, s, rec.Code) {
				t.Fatalf("the handler returned %d, which api/ingest.openapi.yaml does not document",
					rec.Code)
			}

			schemaName := "Error"
			if rec.Code < 300 {
				schemaName = "Outcome"
			}
			assertMatchesSchema(t, s, schemaName, rec.Body.Bytes())
		})
	}
}

// A retryable status without Retry-After invites an immediate retry, which makes the
// overload worse. The contract declares the header; the handler must send it.
func TestRetryAfterIsSentWhereTheContractRequiresIt(t *testing.T) {
	s := loadSpec(t)

	tests := []struct {
		name   string
		status int
		run    func(t *testing.T) *httptest.ResponseRecorder
	}{
		{"quota exceeded", http.StatusTooManyRequests, func(t *testing.T) *httptest.ResponseRecorder {
			h := newHarness(t, 1)
			h.post(t, goodEvent)
			return h.post(t, goodEvent+"\n"+goodEvent)
		}},
		{"broker down", http.StatusServiceUnavailable, func(t *testing.T) *httptest.ResponseRecorder {
			h := newHarness(t, 0)
			h.producer.fail = true
			return h.post(t, goodEvent)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !requiresHeader(t, s, tt.status, "Retry-After") {
				t.Skipf("the contract does not declare Retry-After on %d", tt.status)
			}

			rec := tt.run(t)
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d", rec.Code, tt.status)
			}
			if rec.Header().Get("Retry-After") == "" {
				t.Errorf("no Retry-After on %d, but the contract declares it", tt.status)
			}
		})
	}
}

// The rejection reason codes are part of the contract: a vendor branches on them.
func TestRejectionReasonCodesAreDocumented(t *testing.T) {
	s := loadSpec(t)

	rejectionSchema, ok := s.Components.Schemas["Rejection"]
	if !ok {
		t.Fatal("the contract has no Rejection schema")
	}
	reasonProp, ok := rejectionSchema.Properties["reason_code"].(map[string]any)
	if !ok {
		t.Fatal("the Rejection schema does not describe reason_code")
	}
	rawEnum, ok := reasonProp["enum"].([]any)
	if !ok {
		t.Fatal("reason_code has no enum; a vendor could not branch on it safely")
	}

	documented := map[string]bool{}
	for _, value := range rawEnum {
		if s, ok := value.(string); ok {
			documented[s] = true
		}
	}

	// Every code the implementation can emit must appear in the contract.
	implemented := []ingest.RejectionCode{
		ingest.ReasonParseError, ingest.ReasonSchemaUnknown, ingest.ReasonQuotaExceeded,
		ingest.ReasonTimestampOutOfRange, ingest.ReasonTenantUnknown, ingest.ReasonPayloadTooLarge,
	}
	for _, code := range implemented {
		if !documented[string(code)] {
			t.Errorf("the handler can emit %q but the contract does not document it", code)
		}
	}
}

// A 207 body must identify which record failed and why, or a vendor cannot act on it.
func TestPartialFailureIdentifiesTheFailedRecord(t *testing.T) {
	s := loadSpec(t)
	h := newHarness(t, 0)

	rec := h.post(t, goodEvent+"\n"+`{"RayID":"bad","EdgeStartTimestamp":"nope"}`)
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("status = %d, want 207 (body=%s)", rec.Code, rec.Body.String())
	}

	var outcome struct {
		Rejected []map[string]any `json:"rejected"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &outcome); err != nil {
		t.Fatalf("decode outcome: %v", err)
	}
	if len(outcome.Rejected) != 1 {
		t.Fatalf("rejected = %d entries, want 1", len(outcome.Rejected))
	}

	rejectionSchema := s.Components.Schemas["Rejection"]
	for _, field := range rejectionSchema.Required {
		if _, present := outcome.Rejected[0][field]; !present {
			t.Errorf("the rejection is missing required field %q", field)
		}
	}
}

// The error envelope is what clients branch on, so its code must be stable and its
// message must never carry internal detail.
func TestErrorEnvelopeIsStableAndSafe(t *testing.T) {
	h := newHarness(t, 0)
	h.producer.fail = true

	rec := h.post(t, goodEvent)

	var envelope struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}

	if envelope.Code != mw.CodeBrokerUnavailable {
		t.Errorf("code = %q, want %q", envelope.Code, mw.CodeBrokerUnavailable)
	}
	if strings.Contains(strings.ToLower(envelope.Message), "broker") {
		t.Errorf("message = %q names internal infrastructure", envelope.Message)
	}
}

// Every documented status must be reachable. A status the handler can never return is
// a promise to vendors that the implementation does not keep.
func TestEveryDocumentedStatusIsCoveredByATest(t *testing.T) {
	s := loadSpec(t)

	exercised := map[string]bool{
		"202": true, "207": true, "400": true, "401": true,
		"403": true, "404": true, "413": true, "429": true, "503": true,
	}

	for status := range s.Paths[ingestPath].Post.Responses {
		if !exercised[status] {
			t.Errorf("the contract documents status %s but no test drives the handler "+
				"into it — it may be unreachable", status)
		}
	}
}
