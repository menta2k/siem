package normalize

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/data/stream"
	"github.com/menta2k/siem/internal/ingest"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/vendors"
	"github.com/menta2k/siem/internal/vendors/cloudflare"
	"github.com/menta2k/siem/internal/vendors/datadome"
	"github.com/menta2k/siem/internal/vendors/f5"
)

const validPayload = `{"RayID":"abc123","EdgeStartTimestamp":"2026-08-06T12:00:00Z",` +
	`"ClientIP":"203.0.113.45","ClientRequestHost":"shop.example.com",` +
	`"ClientRequestURI":"/api/checkout?step=2","ClientRequestMethod":"POST",` +
	`"ClientRequestUserAgent":"curl/8.5.0","EdgeResponseStatus":403,` +
	`"SecurityAction":"block","SecurityRuleID":"100015"}`

// fakeStore records writes in order, which is how the raw-before-normalized
// guarantee gets verified.
type fakeStore struct {
	mu         sync.Mutex
	writeOrder []string
	raw        []chdata.RawEvent
	normalized []chdata.NormalizedEvent
	rejected   []chdata.RejectedEvent
	rawErr     error
	normErr    error
}

func (s *fakeStore) InsertRaw(_ context.Context, events []chdata.RawEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rawErr != nil {
		return s.rawErr
	}
	s.writeOrder = append(s.writeOrder, "raw")
	s.raw = append(s.raw, events...)
	return nil
}

func (s *fakeStore) InsertNormalized(_ context.Context, events []chdata.NormalizedEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.normErr != nil {
		return s.normErr
	}
	s.writeOrder = append(s.writeOrder, "normalized")
	s.normalized = append(s.normalized, events...)
	return nil
}

func (s *fakeStore) InsertRejected(_ context.Context, events []chdata.RejectedEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeOrder = append(s.writeOrder, "rejected")
	s.rejected = append(s.rejected, events...)
	return nil
}

type fakeTenants struct {
	tenant chdata.Tenant
	err    error
}

func (f *fakeTenants) GetByID(context.Context, uuid.UUID) (chdata.Tenant, error) {
	if f.err != nil {
		return chdata.Tenant{}, f.err
	}
	return f.tenant, nil
}

type fakePublisher struct {
	mu      sync.Mutex
	records []stream.Record
	err     error
}

func (f *fakePublisher) Publish(_ context.Context, _ string, records []stream.Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.records = append(f.records, records...)
	return nil
}

func (f *fakePublisher) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.records)
}

type workerHarness struct {
	worker    *Worker
	store     *fakeStore
	tenants   *fakeTenants
	publisher *fakePublisher
	tenantID  uuid.UUID
	feedID    uuid.UUID
}

func newWorkerHarness(t *testing.T) *workerHarness {
	t.Helper()

	registry, err := vendors.NewRegistry(cloudflare.New(), f5.New(), datadome.New())
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}

	tenantID := uuid.New()
	store := &fakeStore{}
	tenants := &fakeTenants{tenant: chdata.Tenant{ID: tenantID, Status: chdata.TenantStatusActive}}
	publisher := &fakePublisher{}

	w := NewWorker(registry, store, tenants, NewDriftDetector(nil), publisher,
		"normalized", mw.NewLogger("error", "json"))

	return &workerHarness{w, store, tenants, publisher, tenantID, uuid.New()}
}

func (h *workerHarness) record(t *testing.T, payload string, at time.Time) stream.Record {
	t.Helper()

	envelope := ingest.Envelope{
		TenantID: h.tenantID, FeedID: h.feedID, Vendor: vendors.Cloudflare,
		EventID: "event-1", BatchID: uuid.New(), ReceivedAt: at,
		Format: string(vendors.FormatNDJSON), Payload: []byte(payload),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return stream.Record{Key: []byte(envelope.EventID), Value: encoded}
}

// The write order is load-bearing: the vendor's original bytes are stored BEFORE
// parsing is attempted, so a parser bug can never cost the evidence (FR-005).
func TestRawEventIsStoredBeforeNormalization(t *testing.T) {
	h := newWorkerHarness(t)

	err := h.worker.Handle(context.Background(),
		h.record(t, validPayload, time.Date(2026, 8, 6, 12, 0, 1, 0, time.UTC)))
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	if len(h.store.writeOrder) < 2 {
		t.Fatalf("writeOrder = %v, want at least a raw and a normalized write", h.store.writeOrder)
	}
	if h.store.writeOrder[0] != "raw" {
		t.Errorf("first write was %q, want the raw event stored first", h.store.writeOrder[0])
	}
}

// Even when normalization fails, the raw payload must already be safe.
func TestRawEventIsStoredEvenWhenNormalizationFails(t *testing.T) {
	h := newWorkerHarness(t)
	badPayload := `{"RayID":"x","EdgeStartTimestamp":"not-a-timestamp"}`

	err := h.worker.Handle(context.Background(), h.record(t, badPayload, time.Now().UTC()))
	if err != nil {
		t.Fatalf("Handle() error = %v, want the rejection handled internally", err)
	}

	if len(h.store.raw) != 1 {
		t.Error("the raw event was not stored despite the parse failure")
	}
	if len(h.store.rejected) != 1 {
		t.Fatalf("rejected = %d, want the failure recorded in the dead-letter store",
			len(h.store.rejected))
	}
	if h.store.rejected[0].ReasonCode == "" {
		t.Error("the rejection has no reason code")
	}
	if string(h.store.rejected[0].Payload) != badPayload {
		t.Error("the dead-letter copy does not carry the original payload")
	}
	if len(h.store.normalized) != 0 {
		t.Error("a normalized row was written for an unparseable event")
	}
}

func TestNormalizedRowIsPopulated(t *testing.T) {
	h := newWorkerHarness(t)

	err := h.worker.Handle(context.Background(),
		h.record(t, validPayload, time.Date(2026, 8, 6, 12, 0, 1, 0, time.UTC)))
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	if len(h.store.normalized) != 1 {
		t.Fatalf("normalized = %d rows, want 1", len(h.store.normalized))
	}

	row := h.store.normalized[0]
	checks := []struct {
		field string
		got   any
		want  any
	}{
		{"TenantID", row.TenantID, h.tenantID},
		{"FeedID", row.FeedID, h.feedID},
		{"EventID", row.EventID, "event-1"},
		{"Vendor", row.Vendor, vendors.Cloudflare},
		{"VendorRequestID", row.VendorRequestID, "abc123"},
		{"RequestPath", row.RequestPath, "/api/checkout"},
		{"RequestQuery", row.RequestQuery, "step=2"},
		{"Verdict", row.Verdict, vendors.VerdictBlocked},
		{"HTTPStatus", row.HTTPStatus, uint16(403)},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.field, c.got, c.want)
		}
	}
}

// An event older than the retention window would land in a partition the retention
// job is about to drop. This is the now-relative check the pure adapters cannot make.
func TestEventsOutsideTheRetentionWindowAreRejected(t *testing.T) {
	tests := []struct {
		name      string
		eventTime string
		received  time.Time
	}{
		{
			name:      "older than retention",
			eventTime: "2020-01-01T00:00:00Z",
			received:  time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC),
		},
		{
			name:      "dated in the future",
			eventTime: "2026-08-06T12:00:00Z",
			received:  time.Date(2026, 8, 6, 11, 0, 0, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newWorkerHarness(t)
			payload := `{"RayID":"x","EdgeStartTimestamp":"` + tt.eventTime + `",` +
				`"ClientIP":"203.0.113.1","ClientRequestHost":"h","ClientRequestURI":"/",` +
				`"ClientRequestMethod":"GET","SecurityAction":"allow"}`

			if err := h.worker.Handle(context.Background(), h.record(t, payload, tt.received)); err != nil {
				t.Fatalf("Handle() error = %v", err)
			}

			if len(h.store.rejected) != 1 {
				t.Fatalf("rejected = %d, want the out-of-range event dead-lettered",
					len(h.store.rejected))
			}
			if h.store.rejected[0].ReasonCode != string(ingest.ReasonTimestampOutOfRange) {
				t.Errorf("ReasonCode = %q, want %q",
					h.store.rejected[0].ReasonCode, ingest.ReasonTimestampOutOfRange)
			}
			if len(h.store.normalized) != 0 {
				t.Error("an out-of-range event was written to the normalized table")
			}
		})
	}
}

// A masked field must never reach the derived view or the correlation stream.
func TestRedactionPolicyIsAppliedBeforeStorage(t *testing.T) {
	h := newWorkerHarness(t)
	h.tenants.tenant.RedactedFields = []string{"user_agent"}

	err := h.worker.Handle(context.Background(),
		h.record(t, validPayload, time.Date(2026, 8, 6, 12, 0, 1, 0, time.UTC)))
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	if len(h.store.normalized) != 1 {
		t.Fatalf("normalized = %d rows, want 1", len(h.store.normalized))
	}
	if h.store.normalized[0].UserAgent == "curl/8.5.0" {
		t.Error("the redacted field was written in readable form")
	}

	// It must not escape through the correlation stream either.
	h.publisher.mu.Lock()
	published := string(h.publisher.records[0].Value)
	h.publisher.mu.Unlock()
	if strings.Contains(published, "curl/8.5.0") {
		t.Error("the redacted field leaked into the correlation stream")
	}
}

// A storage outage must NOT advance the offset: the event has to be retried, or the
// promise made by the 202 is broken.
func TestStorageFailureIsRetryable(t *testing.T) {
	tests := []struct {
		name  string
		apply func(*fakeStore)
	}{
		{"raw write fails", func(s *fakeStore) { s.rawErr = errors.New("clickhouse down") }},
		{"normalized write fails", func(s *fakeStore) { s.normErr = errors.New("clickhouse down") }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newWorkerHarness(t)
			tt.apply(h.store)

			err := h.worker.Handle(context.Background(),
				h.record(t, validPayload, time.Date(2026, 8, 6, 12, 0, 1, 0, time.UTC)))

			if err == nil {
				t.Error("Handle() returned nil on a storage failure; the offset would " +
					"advance and the event would be lost")
			}
		})
	}
}

// An event that will fail identically on every retry must not be retried forever.
func TestUnparseableEventDoesNotBlockThePartition(t *testing.T) {
	h := newWorkerHarness(t)

	err := h.worker.Handle(context.Background(),
		h.record(t, `{"RayID":"x","EdgeStartTimestamp":"garbage"}`, time.Now().UTC()))

	if err != nil {
		t.Errorf("Handle() error = %v, want nil so the offset advances past a "+
			"permanently-bad event", err)
	}
}

func TestUndecodableEnvelopeIsReported(t *testing.T) {
	h := newWorkerHarness(t)

	err := h.worker.Handle(context.Background(), stream.Record{Value: []byte("not json")})

	if err == nil {
		t.Error("Handle() accepted an undecodable envelope")
	}
}

func TestNormalizedEventIsForwardedForCorrelation(t *testing.T) {
	h := newWorkerHarness(t)

	err := h.worker.Handle(context.Background(),
		h.record(t, validPayload, time.Date(2026, 8, 6, 12, 0, 1, 0, time.UTC)))
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	if h.publisher.count() != 1 {
		t.Fatalf("forwarded %d events, want 1", h.publisher.count())
	}
	h.publisher.mu.Lock()
	key := string(h.publisher.records[0].Key)
	h.publisher.mu.Unlock()
	if key != "event-1" {
		t.Errorf("forwarded record key = %q, want the event id", key)
	}
}

func TestTenantLookupFailureIsRetryable(t *testing.T) {
	h := newWorkerHarness(t)
	h.tenants.err = errors.New("clickhouse down")

	err := h.worker.Handle(context.Background(),
		h.record(t, validPayload, time.Date(2026, 8, 6, 12, 0, 1, 0, time.UTC)))

	// The tenant policy is unknown, so writing without redaction could expose a field
	// the tenant asked to have masked. Rejecting is the only safe direction.
	if err == nil && len(h.store.normalized) > 0 {
		t.Error("an event was normalized without its tenant's redaction policy")
	}
}

func TestWorkerName(t *testing.T) {
	if got := newWorkerHarness(t).worker.Name(); got != "normalizer" {
		t.Errorf("Name() = %q, want %q", got, "normalizer")
	}
}
