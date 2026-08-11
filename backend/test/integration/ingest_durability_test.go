//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
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
	"github.com/menta2k/siem/internal/ingest/filter"
	"github.com/menta2k/siem/internal/ingest/receiver"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/normalize"
	"github.com/menta2k/siem/internal/tenancy"
	"github.com/menta2k/siem/internal/vendors"
	"github.com/menta2k/siem/internal/vendors/cloudflare"
	"github.com/menta2k/siem/internal/vendors/datadome"
	"github.com/menta2k/siem/internal/vendors/f5"
	"github.com/menta2k/siem/test/support"
)

const ingestToken = "integration-feed-token-abcdefghijklmnop"

// cloudflareEvent builds a distinct valid event.
func cloudflareEvent(rayID string) string {
	return fmt.Sprintf(`{"RayID":%q,"EdgeStartTimestamp":%q,"ClientIP":"203.0.113.10",`+
		`"ClientRequestHost":"shop.example.com","ClientRequestURI":"/checkout",`+
		`"ClientRequestMethod":"POST","EdgeResponseStatus":403,"SecurityAction":"block"}`,
		rayID, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339))
}

// ---------------------------------------------------------------- harness

type liveSecrets struct{}

func (liveSecrets) Resolve(_ context.Context, ref string) (string, error) {
	if ref == "ref-token" {
		return ingestToken, nil
	}
	return "", nil
}

type liveHealth struct{ aggregator *ingest.HealthAggregator }

func (h liveHealth) Record(ctx context.Context, s ingest.HealthSample) {
	h.aggregator.Record(ctx, s)
}

// brokerToggle wraps the real producer so a test can simulate a broker outage without
// stopping the container — which keeps the test fast and deterministic.
type brokerToggle struct {
	inner *stream.Producer
	down  bool
}

func (b *brokerToggle) Publish(ctx context.Context, topic string, records []stream.Record) error {
	if b.down {
		return fmt.Errorf("simulated broker outage")
	}
	return b.inner.Publish(ctx, topic, records)
}

type ingestHarness struct {
	fixture  *support.Fixture
	handler  http.Handler
	ctx      context.Context
	feed     chdata.Feed
	broker   *brokerToggle
	registry *vendors.Registry
	health   *ingest.HealthAggregator
	// Each test publishes to its OWN topics. The consumer starts at the beginning of
	// a topic by design, so sharing topics across the package would make every drain
	// replay every earlier test's events.
	topicRaw string
	topicDLQ string
}

func newIngestHarness(t *testing.T, quotaEventsPerSec uint32) *ingestHarness {
	t.Helper()

	f, ctx := support.SharedTenant(t, "ingest")

	feed, err := f.Feeds.Create(ctx, chdata.Feed{
		Vendor: vendors.Cloudflare, Name: "cf-" + uuid.NewString()[:8],
		Delivery: chdata.DeliveryPush, Enabled: true, CredentialRef: "ref-token",
		QuotaEventsPerSec: quotaEventsPerSec,
	})
	if err != nil {
		t.Fatalf("create feed: %v", err)
	}

	registry, err := vendors.NewRegistry(cloudflare.New(), f5.New(), datadome.New())
	if err != nil {
		t.Fatalf("NewRegistry(): %v", err)
	}

	suffix := uuid.NewString()[:8]
	topicRaw := "test.raw." + suffix
	topicDLQ := "test.dlq." + suffix

	topicCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := f.EnsureTopics(topicCtx, topicRaw, topicDLQ); err != nil {
		t.Fatalf("create test topics: %v", err)
	}

	broker := &brokerToggle{inner: f.Producer}
	health := ingest.NewHealthAggregator(f.Health)

	r := receiver.New(f.Feeds, liveSecrets{}, registry,
		ingest.NewPublisher(broker, topicRaw, topicDLQ),
		dedup.New(f.Redis, time.Minute),
		ingest.NewQuotaEnforcer(f.Redis),
		filter.NewCache(f.Tenants, filter.DefaultCacheTTL),
		liveHealth{health}, mw.NewLogger("error", "json"),
		receiver.Options{MaxBodyBytes: 1 << 20, MaxBatchEvents: 1000})

	return &ingestHarness{f, r.Handler(), ctx, feed, broker, registry, health, topicRaw, topicDLQ}
}

func (h *ingestHarness) deliver(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/ingest/v1/cloudflare/"+h.feed.ID.String(), strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+ingestToken)

	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec
}

func (h *ingestHarness) outcome(t *testing.T, rec *httptest.ResponseRecorder) ingest.Outcome {
	t.Helper()
	var outcome ingest.Outcome
	if err := json.Unmarshal(rec.Body.Bytes(), &outcome); err != nil {
		t.Fatalf("decode outcome: %v (body=%s)", err, rec.Body.String())
	}
	return outcome
}

// drain consumes the raw topic and runs the normalization worker over it, so a test
// can assert on what actually reached storage rather than on what was published.
func (h *ingestHarness) drain(t *testing.T, expect int) {
	t.Helper()

	worker := normalize.NewWorker(h.registry, h.fixture.Events, h.fixture.Tenants,
		normalize.NewDriftDetector(nil), nil, "", mw.NewLogger("error", "json"))

	h.consume(t, h.topicRaw, expect, worker.Handle)
}

// consume reads `expect` records from a topic and runs `handle` over each.
func (h *ingestHarness) consume(
	t *testing.T, topic string, expect int, handle func(context.Context, stream.Record) error,
) {
	t.Helper()

	consumer, err := stream.NewConsumer(h.fixture.RedpandaConf(),
		"drain-"+uuid.NewString()[:8], []string{topic}, nil)
	if err != nil {
		t.Fatalf("create consumer: %v", err)
	}
	defer consumer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	var (
		mu      sync.Mutex
		handled int
	)
	reached := make(chan struct{})
	var once sync.Once
	done := make(chan struct{})

	go func() {
		defer close(done)
		_ = consumer.Run(ctx, func(runCtx context.Context, record stream.Record) error {
			// The handler must NOT cancel the run context: franz-go dispatches the
			// rest of the fetched batch with that same context, and every remaining
			// record would then fail its ClickHouse write with "context canceled".
			if err := handle(runCtx, record); err != nil {
				t.Logf("worker: %v", err)
			}
			mu.Lock()
			handled++
			enough := handled >= expect
			mu.Unlock()
			if enough {
				once.Do(func() { close(reached) })
			}
			return nil
		})
	}()

	select {
	case <-reached:
		cancel() // stop the consumer only once the whole batch has been handled
	case <-time.After(45 * time.Second):
		cancel()
	}

	select {
	case <-done:
	case <-time.After(50 * time.Second):
		t.Fatal("draining the raw topic timed out")
	}

	mu.Lock()
	final := handled
	mu.Unlock()
	if final < expect {
		t.Fatalf("drained %d events from %s, want %d", final, topic, expect)
	}
}

// drainDLQ consumes the dead-letter topic and runs the dead-letter worker over it, so
// a test can assert on the rejected_events rows an operator would actually see.
func (h *ingestHarness) drainDLQ(t *testing.T, expect int) {
	t.Helper()
	h.consume(t, h.topicDLQ, expect,
		normalize.NewDeadLetterWorker(h.fixture.Events, mw.NewLogger("error", "json")).Handle)
}

// ---------------------------------------------------------------- tests

// SC-001: nothing acknowledged may be lost. An event answered with 202 must be
// present in the durable queue and reach storage.
func TestAcknowledgedEventsReachStorage(t *testing.T) {
	h := newIngestHarness(t, 0)

	const count = 25
	lines := make([]string, 0, count)
	for i := range count {
		lines = append(lines, cloudflareEvent(fmt.Sprintf("ray-%03d", i)))
	}

	rec := h.deliver(t, strings.Join(lines, "\n"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (body=%s)", rec.Code, rec.Body.String())
	}
	if got := h.outcome(t, rec).Accepted; got != count {
		t.Fatalf("Accepted = %d, want %d", got, count)
	}

	h.drain(t, count)
	h.fixture.Sync(t, "raw_events")

	if got := h.fixture.CountRows(h.ctx, t, "raw_events", ""); got != count {
		t.Errorf("raw_events holds %d rows, want %d — acknowledged events were lost", got, count)
	}
	if got := h.fixture.CountRows(h.ctx, t, "normalized_events", "FINAL"); got != count {
		t.Errorf("normalized_events holds %d rows, want %d", got, count)
	}
}

// THE durability contract, against a real broker. A publish failure must surface as
// 503 and NOTHING may be persisted, so a vendor retry is safe.
func TestBrokerOutageReturns503AndPersistsNothing(t *testing.T) {
	h := newIngestHarness(t, 0)
	h.broker.down = true

	rec := h.deliver(t, cloudflareEvent("outage-1"))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 — a failed durable commit must never be a 2xx "+
			"(body=%s)", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After; the vendor has no idea when to come back")
	}

	// Recovery: the same batch retried after the broker returns must succeed AND be
	// accepted — not suppressed as a duplicate of the attempt that never committed.
	h.broker.down = false
	rec = h.deliver(t, cloudflareEvent("outage-1"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("retry after recovery = %d, want 202 (body=%s)", rec.Code, rec.Body.String())
	}
	if got := h.outcome(t, rec).Accepted; got != 1 {
		t.Fatalf("Accepted = %d on the retry, want 1 — the failed attempt suppressed "+
			"the retry and the event would be lost permanently", got)
	}

	h.drain(t, 1)
	h.fixture.Sync(t, "raw_events")

	if got := h.fixture.CountRows(h.ctx, t, "raw_events", ""); got != 1 {
		t.Errorf("raw_events holds %d rows, want exactly 1 — the failed attempt should "+
			"have persisted nothing", got)
	}
}

// FR-004: a replayed batch is suppressed and reported, and storage does not grow.
func TestReplayIsDeduplicatedEndToEnd(t *testing.T) {
	h := newIngestHarness(t, 0)

	const count = 10
	lines := make([]string, 0, count)
	for i := range count {
		lines = append(lines, cloudflareEvent(fmt.Sprintf("replay-%03d", i)))
	}
	batch := strings.Join(lines, "\n")

	first := h.deliver(t, batch)
	if first.Code != http.StatusAccepted {
		t.Fatalf("first delivery = %d, want 202", first.Code)
	}

	second := h.deliver(t, batch)
	if second.Code != http.StatusAccepted {
		t.Fatalf("replay = %d, want 202 — a retry is not an error", second.Code)
	}

	outcome := h.outcome(t, second)
	if outcome.DuplicatesSuppressed != count {
		t.Errorf("DuplicatesSuppressed = %d, want %d", outcome.DuplicatesSuppressed, count)
	}
	if outcome.Accepted != 0 {
		t.Errorf("Accepted = %d on a full replay, want 0", outcome.Accepted)
	}

	h.drain(t, count)
	h.fixture.Sync(t, "normalized_events")

	if got := h.fixture.CountRows(h.ctx, t, "normalized_events", "FINAL"); got != count {
		t.Errorf("normalized_events holds %d rows after a replay, want %d", got, count)
	}
}

// Even if a duplicate escapes the ingest window, ReplacingMergeTree must collapse it.
// This is the second layer of deduplication and the one that guarantees correctness.
func TestStorageLayerDeduplicatesIdenticalEventIDs(t *testing.T) {
	h := newIngestHarness(t, 0)

	feedID := h.feed.ID
	eventID := normalize.EventID(feedID, "storage-dedup", []byte("x"))
	now := time.Now().UTC()

	tenantID, err := tenancy.MustID(h.ctx)
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}

	row := chdata.NormalizedEvent{
		TenantID: tenantID, EventID: eventID, EventTime: now, ReceivedAt: now,
		Vendor: vendors.Cloudflare, FeedID: feedID, VendorRequestID: "storage-dedup",
		RequestHost: "h", RequestPath: "/", RequestMethod: "GET",
		Verdict: vendors.VerdictAllowed, ScoreKind: vendors.ScoreKindNone,
		IngestVersion: 1,
	}

	// Write the same identity three times, as three separate redeliveries would.
	for i := range 3 {
		row.IngestVersion = uint64(i + 1)
		if err := h.fixture.Events.InsertNormalized(h.ctx, []chdata.NormalizedEvent{row}); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}

	h.fixture.Sync(t, "normalized_events")

	if got := h.fixture.CountRows(h.ctx, t, "normalized_events", "FINAL"); got != 1 {
		t.Errorf("normalized_events holds %d rows for one event id, want 1 — "+
			"ReplacingMergeTree did not collapse the redeliveries", got)
	}
}

// FR-005: the vendor's original bytes must be recoverable exactly as delivered.
func TestRawPayloadIsPreservedByteForByte(t *testing.T) {
	h := newIngestHarness(t, 0)
	payload := cloudflareEvent("verbatim-1")

	if rec := h.deliver(t, payload); rec.Code != http.StatusAccepted {
		t.Fatalf("delivery = %d, want 202", rec.Code)
	}
	h.drain(t, 1)
	h.fixture.Sync(t, "raw_events")

	// Derived exactly as the pipeline derives it — per (feed, vendor, request id). See
	// the note in TestRedactionPolicyIsEnforcedAtStorage.
	eventID := normalize.EventIDFor(h.feed.ID, vendors.Cloudflare, "verbatim-1", []byte(payload))

	stored, err := h.fixture.Events.GetRawPayload(h.ctx, eventID, chdata.RawPayloadHint{})
	if err != nil {
		t.Fatalf("GetRawPayload(): %v", err)
	}
	if string(stored.Payload) != payload {
		t.Errorf("the stored payload differs from what was delivered:\n got %q\nwant %q",
			stored.Payload, payload)
	}
	if stored.Format == "" {
		t.Error("the payload format was not recorded")
	}
	// The delivering vendor travels with the bytes, because it is what any parse of them
	// must use. It is not always the vendor the event is attributed to.
	if stored.Vendor != vendors.Cloudflare {
		t.Errorf("raw vendor = %q, want %q", stored.Vendor, vendors.Cloudflare)
	}
}

// FR-007: backpressure is explicit. A quota refusal must not persist anything.
func TestQuotaRefusalPersistsNothing(t *testing.T) {
	h := newIngestHarness(t, 1)

	if rec := h.deliver(t, cloudflareEvent("quota-1")); rec.Code != http.StatusAccepted {
		t.Fatalf("first delivery = %d, want 202", rec.Code)
	}

	rec := h.deliver(t, cloudflareEvent("quota-2")+"\n"+cloudflareEvent("quota-3"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 (body=%s)", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After on a 429")
	}

	h.drain(t, 1)
	h.fixture.Sync(t, "raw_events")

	if got := h.fixture.CountRows(h.ctx, t, "raw_events", ""); got != 1 {
		t.Errorf("raw_events holds %d rows, want only the 1 accepted event", got)
	}
}

// Feed health is what makes a working feed distinguishable from a dead one.
func TestDeliveryIsReflectedInFeedHealth(t *testing.T) {
	h := newIngestHarness(t, 0)

	if rec := h.deliver(t, cloudflareEvent("health-1")); rec.Code != http.StatusAccepted {
		t.Fatalf("delivery = %d, want 202", rec.Code)
	}
	if err := h.health.Flush(h.ctx); err != nil {
		t.Fatalf("flush health: %v", err)
	}
	h.fixture.Sync(t, "feed_health")

	health, err := h.fixture.Health.GetFeedHealth(h.ctx, h.feed.ID)
	if err != nil {
		t.Fatalf("GetFeedHealth(): %v", err)
	}

	if health.EventsReceived1h != 1 {
		t.Errorf("EventsReceived1h = %d, want 1", health.EventsReceived1h)
	}
	if !health.CredentialValid {
		t.Error("CredentialValid = false after a successful delivery")
	}
	if health.Silent {
		t.Error("Silent = true for a feed that just delivered")
	}
	if health.LastEventAt.IsZero() {
		t.Error("LastEventAt was not recorded")
	}
}
