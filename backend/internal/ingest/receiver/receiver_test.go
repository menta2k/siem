package receiver

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/data/stream"
	"github.com/menta2k/siem/internal/ingest"
	"github.com/menta2k/siem/internal/ingest/dedup"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/vendors"
	"github.com/menta2k/siem/internal/vendors/cloudflare"
	"github.com/menta2k/siem/internal/vendors/datadome"
	"github.com/menta2k/siem/internal/vendors/f5"
)

const (
	testToken   = "feed-token-abcdefghijklmnopqrstuvwxyz"
	testPayload = `{"RayID":"abc123","EdgeStartTimestamp":"2026-08-06T12:00:00Z",` +
		`"ClientIP":"203.0.113.1","ClientRequestHost":"shop.example.com",` +
		`"ClientRequestURI":"/","ClientRequestMethod":"GET","SecurityAction":"allow"}`
)

// ---------------------------------------------------------------- fakes

type fakeFeeds struct {
	feed chdata.Feed
	err  error
}

func (f *fakeFeeds) GetForIngest(context.Context, uuid.UUID) (chdata.Feed, error) {
	if f.err != nil {
		return chdata.Feed{}, f.err
	}
	return f.feed, nil
}

type fakeSecrets struct {
	values map[string]string
	err    error
}

func (f *fakeSecrets) Resolve(_ context.Context, ref string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.values[ref], nil
}

// fakeProducer records what was published and can be made to fail, which is how the
// durability contract gets tested.
type fakeProducer struct {
	mu        sync.Mutex
	published map[string][]stream.Record
	err       error
}

func newFakeProducer() *fakeProducer {
	return &fakeProducer{published: map[string][]stream.Record{}}
}

func (f *fakeProducer) Publish(_ context.Context, topic string, records []stream.Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.published[topic] = append(f.published[topic], records...)
	return nil
}

func (f *fakeProducer) count(topic string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.published[topic])
}

type memCounter struct {
	mu     sync.Mutex
	counts map[string]int64
	err    error
}

func newMemCounter() *memCounter { return &memCounter{counts: map[string]int64{}} }

func (m *memCounter) IncrBy(
	_ context.Context, key string, delta int64, _ time.Duration,
) (int64, error) {
	if m.err != nil {
		return 0, m.err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counts[key] += delta
	return m.counts[key], nil
}

func (m *memCounter) Exists(_ context.Context, keys ...string) (int64, error) {
	if m.err != nil {
		return 0, m.err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var count int64
	for _, key := range keys {
		if m.counts[key] > 0 {
			count++
		}
	}
	return count, nil
}

func (m *memCounter) Set(_ context.Context, key, _ string, _ time.Duration) error {
	if m.err != nil {
		return m.err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counts[key] = 1
	return nil
}

type recordedHealth struct {
	mu      sync.Mutex
	samples []ingest.HealthSample
}

func (r *recordedHealth) Record(_ context.Context, s ingest.HealthSample) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.samples = append(r.samples, s)
}

func (r *recordedHealth) last() (ingest.HealthSample, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.samples) == 0 {
		return ingest.HealthSample{}, false
	}
	return r.samples[len(r.samples)-1], true
}

// ---------------------------------------------------------------- harness

type harness struct {
	receiver *Receiver
	feeds    *fakeFeeds
	secrets  *fakeSecrets
	producer *fakeProducer
	counter  *memCounter
	health   *recordedHealth
	feedID   uuid.UUID
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	feedID, tenantID := uuid.New(), uuid.New()
	feeds := &fakeFeeds{feed: chdata.Feed{
		TenantID: tenantID, ID: feedID, Vendor: vendors.Cloudflare,
		Name: "cf-prod", Delivery: chdata.DeliveryPush, Enabled: true,
		CredentialRef: "ref-token", QuotaEventsPerSec: 5000, QuotaBytesPerDay: 1 << 30,
	}}
	secrets := &fakeSecrets{values: map[string]string{"ref-token": testToken}}
	producer := newFakeProducer()
	counter := newMemCounter()
	health := &recordedHealth{}

	registry, err := vendors.NewRegistry(cloudflare.New(), f5.New(), datadome.New())
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}

	r := New(
		feeds, secrets, registry,
		ingest.NewPublisher(producer, "raw", "dlq"),
		dedup.New(counter, time.Minute),
		ingest.NewQuotaEnforcer(counter),
		health, mw.NewLogger("error", "json"),
		Options{MaxBodyBytes: 1 << 20, MaxBatchEvents: 100},
	)

	return &harness{r, feeds, secrets, producer, counter, health, feedID}
}

// deliver posts a payload and returns the response.
func (h *harness) deliver(
	t *testing.T, body string, mutate ...func(*http.Request),
) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/ingest/v1/cloudflare/"+h.feedID.String(), strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken)
	for _, m := range mutate {
		m(req)
	}

	rec := httptest.NewRecorder()
	h.receiver.Handler().ServeHTTP(rec, req)
	return rec
}

func decodeOutcome(t *testing.T, rec *httptest.ResponseRecorder) ingest.Outcome {
	t.Helper()
	var outcome ingest.Outcome
	if err := json.Unmarshal(rec.Body.Bytes(), &outcome); err != nil {
		t.Fatalf("decode outcome: %v (body=%s)", err, rec.Body.String())
	}
	return outcome
}

// ---------------------------------------------------------------- tests

func TestAcceptedDeliveryReturns202(t *testing.T) {
	h := newHarness(t)

	rec := h.deliver(t, testPayload)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (body=%s)", rec.Code, rec.Body.String())
	}
	outcome := decodeOutcome(t, rec)
	if outcome.Accepted != 1 {
		t.Errorf("Accepted = %d, want 1", outcome.Accepted)
	}
	if h.producer.count("raw") != 1 {
		t.Errorf("published %d records, want 1", h.producer.count("raw"))
	}
}

// THE contract. A broker failure must never produce a 2xx: acknowledging an event the
// broker did not commit loses it permanently, whereas a 503 makes the vendor retry
// and deduplication absorbs the duplicate (Constitution Principle II).
func TestBrokerFailureReturns503NotSuccess(t *testing.T) {
	h := newHarness(t)
	h.producer.err = errors.New("all brokers unreachable")

	rec := h.deliver(t, testPayload)

	if rec.Code < 400 {
		t.Fatalf("status = %d — a failed durable commit must NEVER return a success status",
			rec.Code)
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 so the vendor retries", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got == "" {
		t.Error("no Retry-After header; a 503 without one invites an immediate retry")
	}

	var envelope mw.Error
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	if envelope.Code != mw.CodeBrokerUnavailable {
		t.Errorf("code = %q, want %q", envelope.Code, mw.CodeBrokerUnavailable)
	}
	// The broker's internal failure detail must not reach the vendor.
	if strings.Contains(envelope.Message, "unreachable") {
		t.Errorf("message = %q leaks internal detail", envelope.Message)
	}
}

// A malformed line must not cost the customer the rest of the batch.
func TestMalformedLinesAreDeadLetteredNotFatal(t *testing.T) {
	h := newHarness(t)
	const malformed = `{"RayID":"broken","EdgeStartTimestamp":"not-a-time"}`
	body := testPayload + "\n" + malformed + "\n" + testPayload

	rec := h.deliver(t, body)

	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("status = %d, want 207 (body=%s)", rec.Code, rec.Body.String())
	}
	outcome := decodeOutcome(t, rec)
	if len(outcome.Rejected) != 1 {
		t.Fatalf("Rejected = %v, want exactly the 1 malformed line", outcome.Rejected)
	}
	if outcome.Rejected[0].Index != 1 {
		t.Errorf("rejected index = %d, want 1 so the vendor can identify the record",
			outcome.Rejected[0].Index)
	}
	if outcome.Rejected[0].ReasonCode == "" {
		t.Error("the rejection has no reason code; a dead-letter reason must be actionable")
	}
	// The other two lines are identical, so one is also a duplicate — what matters is
	// that the good lines were committed and the bad one was parked.
	if h.producer.count("raw") == 0 {
		t.Error("no events were committed despite valid lines in the batch")
	}
	if h.producer.count("dlq") != 1 {
		t.Errorf("dead-lettered %d records, want 1", h.producer.count("dlq"))
	}
}

// FR-004: a replayed batch is suppressed and the count is reported.
func TestReplayedDeliveryReportsDuplicates(t *testing.T) {
	h := newHarness(t)

	if rec := h.deliver(t, testPayload); rec.Code != http.StatusAccepted {
		t.Fatalf("first delivery status = %d", rec.Code)
	}
	rec := h.deliver(t, testPayload)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("replay status = %d, want 202 — a retry is not an error", rec.Code)
	}
	outcome := decodeOutcome(t, rec)
	if outcome.DuplicatesSuppressed != 1 {
		t.Errorf("DuplicatesSuppressed = %d, want 1", outcome.DuplicatesSuppressed)
	}
	if outcome.Accepted != 0 {
		t.Errorf("Accepted = %d, want 0 on a full replay", outcome.Accepted)
	}
	if h.producer.count("raw") != 1 {
		t.Errorf("published %d records total, want 1 — the replay was re-committed",
			h.producer.count("raw"))
	}
}

func TestAuthenticationFailures(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"no header", func(r *http.Request) { r.Header.Del("Authorization") }},

		{"wrong token", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer wrong-token-value")
		}},
		{"wrong scheme", func(r *http.Request) {
			r.Header.Set("Authorization", "Basic "+testToken)
		}},
		{"empty bearer", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer ")
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			rec := h.deliver(t, testPayload, tt.mutate)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rec.Code)
			}
			if h.producer.count("raw") != 0 {
				t.Error("events were committed despite failed authentication")
			}
		})
	}
}

// A failed credential is how an expired token surfaces to the operator, rather than
// as silent traffic loss.
func TestFailedAuthenticationIsRecordedInFeedHealth(t *testing.T) {
	h := newHarness(t)

	h.deliver(t, testPayload, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer wrong-token-value")
	})

	sample, ok := h.health.last()
	if !ok {
		t.Fatal("no health sample was recorded for a failed authentication")
	}
	if sample.CredentialValid {
		t.Error("CredentialValid = true after a failed authentication")
	}
}

// A token valid for one feed must not be usable against another vendor's endpoint.
func TestVendorFeedMismatchIsRejected(t *testing.T) {
	h := newHarness(t)
	h.feeds.feed.Vendor = vendors.DataDome // the URL still says cloudflare

	rec := h.deliver(t, testPayload)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for a vendor/feed mismatch", rec.Code)
	}
}

func TestDisabledFeedIsRejected(t *testing.T) {
	h := newHarness(t)
	h.feeds.feed.Enabled = false

	if rec := h.deliver(t, testPayload); rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for a disabled feed", rec.Code)
	}
}

func TestUnknownFeedIsRejected(t *testing.T) {
	h := newHarness(t)
	h.feeds.err = chdata.ErrNotFound

	if rec := h.deliver(t, testPayload); rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// HMAC signing: a valid token alone is not sufficient when signing is configured.
func TestSignatureVerification(t *testing.T) {
	const signingSecret = "hmac-signing-secret"

	sign := func(body string) string {
		mac := hmac.New(sha256.New, []byte(signingSecret))
		mac.Write([]byte(body))
		return hex.EncodeToString(mac.Sum(nil))
	}

	tests := []struct {
		name      string
		signature string
		want      int
	}{
		{"valid signature", sign(testPayload), http.StatusAccepted},
		{"valid with prefix", "sha256=" + sign(testPayload), http.StatusAccepted},
		{"wrong signature", sign("different body"), http.StatusUnauthorized},
		{"missing signature", "", http.StatusUnauthorized},
		{"garbage signature", "not-a-signature", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.feeds.feed.SigningSecretRef = "ref-signing"
			h.secrets.values["ref-signing"] = signingSecret

			rec := h.deliver(t, testPayload, func(r *http.Request) {
				if tt.signature != "" {
					r.Header.Set("X-Signature", tt.signature)
				}
			})

			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d (body=%s)", rec.Code, tt.want, rec.Body.String())
			}
		})
	}
}

// Backpressure must be explicit: a 429 with Retry-After, not a silent drop and not
// unbounded buffering (FR-007).
func TestQuotaExceededReturns429WithRetryAfter(t *testing.T) {
	h := newHarness(t)
	h.feeds.feed.QuotaEventsPerSec = 1

	// The first delivery consumes the whole per-second allowance.
	if rec := h.deliver(t, testPayload); rec.Code != http.StatusAccepted {
		t.Fatalf("first delivery status = %d", rec.Code)
	}

	rec := h.deliver(t, testPayload+"\n"+testPayload)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 (body=%s)", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After on a 429; the vendor has no idea when to come back")
	}
}

// Losing a customer's logs because Redis is down would be worse than briefly
// over-accepting, and the storage layer still deduplicates.
func TestQuotaAndDedupFailOpen(t *testing.T) {
	h := newHarness(t)
	h.counter.err = errors.New("redis unavailable")

	rec := h.deliver(t, testPayload)

	if rec.Code != http.StatusAccepted {
		t.Errorf("status = %d, want 202 — quota and dedup must fail open", rec.Code)
	}
	if h.producer.count("raw") != 1 {
		t.Error("the event was not committed while Redis was unavailable")
	}
}

func TestOversizedBodyIsRejected(t *testing.T) {
	h := newHarness(t)
	huge := strings.Repeat("x", 2<<20) // exceeds the 1 MiB test limit

	if rec := h.deliver(t, huge); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
}

func TestOversizedBatchIsRejected(t *testing.T) {
	h := newHarness(t)
	lines := make([]string, 0, 150)
	for range 150 { // exceeds the 100-event test limit
		lines = append(lines, testPayload)
	}

	rec := h.deliver(t, strings.Join(lines, "\n"))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413 for a batch over the event cap", rec.Code)
	}
}

func TestEmptyBodyIsRejected(t *testing.T) {
	h := newHarness(t)
	if rec := h.deliver(t, ""); rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// An unreadable batch envelope is a 400, not a 503: retrying the same bytes will fail
// identically, so telling the vendor to retry would loop forever.
func TestUnparseableBatchIsClientErrorNotRetryable(t *testing.T) {
	h := newHarness(t)

	rec := h.deliver(t, "this is not json at all")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if h.producer.count("raw") != 0 {
		t.Error("events were committed from an unparseable batch")
	}
}

func TestSuccessfulDeliveryRecordsHealth(t *testing.T) {
	h := newHarness(t)

	h.deliver(t, testPayload)

	sample, ok := h.health.last()
	if !ok {
		t.Fatal("no health sample was recorded")
	}
	if sample.EventsReceived != 1 {
		t.Errorf("EventsReceived = %d, want 1", sample.EventsReceived)
	}
	if !sample.CredentialValid {
		t.Error("CredentialValid = false on a successful delivery")
	}
	if sample.BytesReceived == 0 {
		t.Error("BytesReceived = 0; byte volume drives the daily quota")
	}
}

// The envelope carries the vendor's bytes verbatim, so the raw payload can be stored
// exactly as received (FR-005).
func TestPublishedEnvelopePreservesRawPayload(t *testing.T) {
	h := newHarness(t)

	h.deliver(t, testPayload)

	h.producer.mu.Lock()
	records := h.producer.published["raw"]
	h.producer.mu.Unlock()

	if len(records) != 1 {
		t.Fatalf("published %d records, want 1", len(records))
	}

	var envelope ingest.Envelope
	if err := json.Unmarshal(records[0].Value, &envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if string(envelope.Payload) != testPayload {
		t.Errorf("payload was altered in transit:\n got %q\nwant %q",
			envelope.Payload, testPayload)
	}
	if envelope.EventID == "" {
		t.Error("the envelope carries no event id, so deduplication cannot work")
	}
	// Partitioning on the event id keeps redeliveries of one event together.
	if string(records[0].Key) != envelope.EventID {
		t.Error("the record key is not the event id")
	}
}

func TestInvalidFeedIDIsRejected(t *testing.T) {
	h := newHarness(t)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/ingest/v1/cloudflare/not-a-uuid", strings.NewReader(testPayload))
	req.Header.Set("Authorization", "Bearer "+testToken)

	rec := httptest.NewRecorder()
	h.receiver.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestUnknownVendorIsRejected(t *testing.T) {
	h := newHarness(t)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/ingest/v1/akamai/"+h.feedID.String(), strings.NewReader(testPayload))
	req.Header.Set("Authorization", "Bearer "+testToken)

	rec := httptest.NewRecorder()
	h.receiver.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for an unregistered vendor", rec.Code)
	}
}

// Regression: a failed durable commit must NOT mark events as seen, or the vendor's
// retry after the 503 is suppressed as a duplicate and the events are lost for good.
func TestFailedCommitDoesNotSuppressTheRetry(t *testing.T) {
	h := newHarness(t)
	h.producer.err = errors.New("all brokers unreachable")

	if rec := h.deliver(t, testPayload); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("first attempt = %d, want 503", rec.Code)
	}

	// The broker recovers and the vendor retries the same batch.
	h.producer.err = nil
	rec := h.deliver(t, testPayload)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("retry = %d, want 202 (body=%s)", rec.Code, rec.Body.String())
	}
	outcome := decodeOutcome(t, rec)
	if outcome.Accepted != 1 {
		t.Errorf("Accepted = %d on the retry, want 1 — the failed attempt suppressed "+
			"the retry and the event would be lost permanently", outcome.Accepted)
	}
	if outcome.DuplicatesSuppressed != 0 {
		t.Errorf("DuplicatesSuppressed = %d, want 0; nothing was ever committed",
			outcome.DuplicatesSuppressed)
	}
	if h.producer.count("raw") != 1 {
		t.Errorf("published %d records, want 1", h.producer.count("raw"))
	}
}
