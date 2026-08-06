package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/data/stream"
	"github.com/menta2k/siem/internal/vendors"
	"github.com/menta2k/siem/internal/vendors/cloudflare"
)

type recordingProducer struct {
	mu        sync.Mutex
	byTopic   map[string][]stream.Record
	err       error
	failAfter int
	calls     int
}

func newRecordingProducer() *recordingProducer {
	return &recordingProducer{byTopic: map[string][]stream.Record{}, failAfter: -1}
}

func (p *recordingProducer) Publish(
	_ context.Context, topic string, records []stream.Record,
) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.err != nil {
		return p.err
	}
	if p.failAfter >= 0 && p.calls > p.failAfter {
		return errors.New("broker unavailable")
	}
	p.byTopic[topic] = append(p.byTopic[topic], records...)
	return nil
}

func (p *recordingProducer) records(topic string) []stream.Record {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]stream.Record{}, p.byTopic[topic]...)
}

func testEnvelopes(n int) []Envelope {
	out := make([]Envelope, 0, n)
	for i := range n {
		out = append(out, Envelope{
			TenantID: uuid.New(), FeedID: uuid.New(), Vendor: vendors.Cloudflare,
			EventID: "event-" + string(rune('a'+i)), BatchID: uuid.New(),
			ReceivedAt: time.Now().UTC(), Format: "ndjson",
			Payload: []byte(`{"RayID":"x"}`),
		})
	}
	return out
}

func TestPublishBatchCommitsEveryEnvelope(t *testing.T) {
	producer := newRecordingProducer()
	p := NewPublisher(producer, "raw", "dlq")

	if err := p.PublishBatch(context.Background(), testEnvelopes(3)); err != nil {
		t.Fatalf("PublishBatch() error = %v", err)
	}
	if got := len(producer.records("raw")); got != 3 {
		t.Errorf("committed %d records, want 3", got)
	}
}

// A partial success is treated as total failure on purpose: acknowledging the events
// that made it and silently losing the rest breaks the promise every 202 makes.
func TestPublishBatchFailsWholesaleOnBrokerError(t *testing.T) {
	producer := newRecordingProducer()
	producer.err = errors.New("all brokers unreachable")
	p := NewPublisher(producer, "raw", "dlq")

	err := p.PublishBatch(context.Background(), testEnvelopes(50))

	if err == nil {
		t.Fatal("PublishBatch() returned nil on a broker failure; the caller would " +
			"answer 202 for events that were never committed")
	}
	if got := len(producer.records("raw")); got != 0 {
		t.Errorf("recorded %d committed records despite the failure", got)
	}
}

func TestPublishBatchWithNoEnvelopesIsANoOp(t *testing.T) {
	producer := newRecordingProducer()
	producer.err = errors.New("should not be called")

	err := NewPublisher(producer, "raw", "dlq").PublishBatch(context.Background(), nil)
	if err != nil {
		t.Errorf("PublishBatch(nil) = %v, want nil", err)
	}
}

// Partitioning on the event id keeps every redelivery of one event on the same
// partition, so ordering and deduplication behave predictably.
func TestPublishedRecordIsKeyedByEventID(t *testing.T) {
	producer := newRecordingProducer()
	envelopes := testEnvelopes(1)

	if err := NewPublisher(producer, "raw", "dlq").
		PublishBatch(context.Background(), envelopes); err != nil {
		t.Fatalf("PublishBatch() error = %v", err)
	}

	records := producer.records("raw")
	if string(records[0].Key) != envelopes[0].EventID {
		t.Errorf("record key = %q, want the event id %q", records[0].Key, envelopes[0].EventID)
	}
	for _, header := range []string{"tenant_id", "feed_id", "vendor", "batch_id"} {
		if records[0].Headers[header] == "" {
			t.Errorf("header %q is missing; a consumer would have to parse the payload "+
				"to route the record", header)
		}
	}
}

func TestPublishedEnvelopeRoundTrips(t *testing.T) {
	producer := newRecordingProducer()
	envelopes := testEnvelopes(1)

	if err := NewPublisher(producer, "raw", "dlq").
		PublishBatch(context.Background(), envelopes); err != nil {
		t.Fatalf("PublishBatch() error = %v", err)
	}

	var decoded Envelope
	if err := json.Unmarshal(producer.records("raw")[0].Value, &decoded); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if decoded.EventID != envelopes[0].EventID {
		t.Errorf("EventID = %q, want %q", decoded.EventID, envelopes[0].EventID)
	}
	if string(decoded.Payload) != string(envelopes[0].Payload) {
		t.Error("the payload did not survive the round trip")
	}
}

func TestPublishRejectionsParksOnTheDeadLetterTopic(t *testing.T) {
	producer := newRecordingProducer()
	envelopes := testEnvelopes(3)
	rejections := []Rejection{
		{Index: 1, ReasonCode: ReasonParseError, ReasonDetail: "bad timestamp"},
	}

	err := NewPublisher(producer, "raw", "dlq").
		PublishRejections(context.Background(), envelopes, rejections)
	if err != nil {
		t.Fatalf("PublishRejections() error = %v", err)
	}

	records := producer.records("dlq")
	if len(records) != 1 {
		t.Fatalf("parked %d records, want 1", len(records))
	}
	if records[0].Headers["reason_code"] != string(ReasonParseError) {
		t.Errorf("reason_code = %q, want %q",
			records[0].Headers["reason_code"], ReasonParseError)
	}
	if records[0].Headers["reason_detail"] == "" {
		t.Error("no reason detail; the dead-letter entry would not be actionable")
	}
}

// An out-of-range index must be skipped rather than panicking: the rejection list is
// built separately from the envelope list and could drift.
func TestPublishRejectionsIgnoresOutOfRangeIndices(t *testing.T) {
	producer := newRecordingProducer()

	err := NewPublisher(producer, "raw", "dlq").PublishRejections(
		context.Background(), testEnvelopes(2),
		[]Rejection{{Index: 99}, {Index: -1}, {Index: 0, ReasonCode: ReasonParseError}})
	if err != nil {
		t.Fatalf("PublishRejections() error = %v", err)
	}

	if got := len(producer.records("dlq")); got != 1 {
		t.Errorf("parked %d records, want only the in-range one", got)
	}
}

func TestPublishRejectionsWithNothingRejectedIsANoOp(t *testing.T) {
	producer := newRecordingProducer()
	producer.err = errors.New("should not be called")

	err := NewPublisher(producer, "raw", "dlq").
		PublishRejections(context.Background(), testEnvelopes(1), nil)
	if err != nil {
		t.Errorf("PublishRejections() with no rejections = %v, want nil", err)
	}
}

func TestBuildEnvelopesSeparatesUsableFromRejected(t *testing.T) {
	adapter := cloudflare.New()
	payload := []byte(`{"RayID":"good","EdgeStartTimestamp":"2026-08-06T12:00:00Z",` +
		`"ClientIP":"203.0.113.1","ClientRequestHost":"h","ClientRequestURI":"/",` +
		`"ClientRequestMethod":"GET","SecurityAction":"allow"}` + "\n" +
		`{"RayID":"bad","EdgeStartTimestamp":"not-a-time"}`)

	records, err := adapter.Parse(payload, vendors.FormatNDJSON)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	meta := EnvelopeMeta{
		TenantID: uuid.New(), FeedID: uuid.New(), BatchID: uuid.New(),
		ReceivedAt:  time.Now().UTC(),
		IdentityFor: func(requestID string, raw []byte) string { return requestID + string(raw[:4]) },
	}

	envelopes, rejections := BuildEnvelopes(adapter, records, meta)

	// Every record gets an envelope, including the bad one, so its position is
	// preserved and the dead-letter copy retains the original bytes.
	if len(envelopes) != 2 {
		t.Fatalf("built %d envelopes, want one per record", len(envelopes))
	}
	if len(rejections) != 1 {
		t.Fatalf("reported %d rejections, want 1", len(rejections))
	}
	if rejections[0].Index != 1 {
		t.Errorf("rejection index = %d, want 1", rejections[0].Index)
	}
	if rejections[0].ReasonCode != ReasonTimestampOutOfRange &&
		rejections[0].ReasonCode != ReasonParseError {
		t.Errorf("ReasonCode = %q, want a specific parse or timestamp reason",
			rejections[0].ReasonCode)
	}
}

func TestOutcomeHasRejections(t *testing.T) {
	if (Outcome{}).HasRejections() {
		t.Error("HasRejections() = true for an outcome with none")
	}
	if !(Outcome{Rejected: []Rejection{{}}}).HasRejections() {
		t.Error("HasRejections() = false despite a rejection")
	}
}

// ---------------------------------------------------------------- quota

type stubCounter struct {
	mu     sync.Mutex
	counts map[string]int64
	err    error
}

func newStubCounter() *stubCounter { return &stubCounter{counts: map[string]int64{}} }

func (s *stubCounter) IncrBy(
	_ context.Context, key string, delta int64, _ time.Duration,
) (int64, error) {
	if s.err != nil {
		return 0, s.err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts[key] += delta
	return s.counts[key], nil
}

// Quotas are expressed in events, not requests: one 50,000-event delivery must not
// consume the same budget as a single event.
func TestEventQuotaCountsEventsNotRequests(t *testing.T) {
	counter := newStubCounter()
	q := NewQuotaEnforcer(counter)
	ctx := context.Background()

	// A single delivery of 200 events against a 100/sec limit must be refused.
	decision, err := q.Check(ctx, "feed-1", 200, 1024, 100, 0)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if decision.Allowed {
		t.Error("a 200-event delivery was allowed against a 100 events/sec limit")
	}
	if decision.RetryAfter <= 0 {
		t.Error("no RetryAfter on a refusal; the vendor has no idea when to come back")
	}
	if decision.Reason == "" {
		t.Error("no reason given for the refusal")
	}
}

func TestEventQuotaAllowsWithinLimit(t *testing.T) {
	q := NewQuotaEnforcer(newStubCounter())

	decision, err := q.Check(context.Background(), "feed-1", 50, 1024, 100, 0)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !decision.Allowed {
		t.Error("a 50-event delivery was refused against a 100 events/sec limit")
	}
}

// The daily byte budget must accumulate across deliveries, not reset each request.
func TestByteQuotaAccumulatesAcrossDeliveries(t *testing.T) {
	q := NewQuotaEnforcer(newStubCounter())
	ctx := context.Background()
	const limit = 1000

	for i := range 10 {
		decision, err := q.Check(ctx, "feed-1", 1, 150, 0, limit)
		if err != nil {
			t.Fatalf("Check() %d error = %v", i, err)
		}
		if !decision.Allowed && i < 6 {
			t.Fatalf("delivery %d refused too early; only %d bytes had accumulated",
				i, (i+1)*150)
		}
		if !decision.Allowed {
			return // correctly refused once the running total passed the limit
		}
	}
	t.Error("the daily byte budget never ran out; the counter is not accumulating")
}

// A Redis outage must not stop a customer's log ingestion.
func TestQuotaFailsOpenOnCounterError(t *testing.T) {
	counter := newStubCounter()
	counter.err = errors.New("redis unavailable")
	q := NewQuotaEnforcer(counter)

	decision, err := q.Check(context.Background(), "feed-1", 100, 1024, 10, 100)

	if err == nil {
		t.Error("Check() hid a counter failure; the caller cannot log the degradation")
	}
	if !decision.Allowed {
		t.Error("the delivery was refused because the counter was unavailable; " +
			"quotas must fail open")
	}
}

func TestZeroQuotaMeansUnlimited(t *testing.T) {
	counter := newStubCounter()
	counter.err = errors.New("should not be consulted")

	decision, err := NewQuotaEnforcer(counter).Check(context.Background(), "f", 1e6, 1e9, 0, 0)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !decision.Allowed {
		t.Error("an unconfigured quota refused a delivery")
	}
}
