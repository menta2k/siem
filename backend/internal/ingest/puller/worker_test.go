package puller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/ingest"
	"github.com/menta2k/siem/internal/ingest/dedup"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/vendors"
	"github.com/menta2k/siem/internal/vendors/cloudflare"
)

// ---------------------------------------------------------------- fakes

type fakeFeedStore struct {
	mu         sync.Mutex
	feeds      []chdata.Feed
	watermarks []string
	setErr     error
	listErr    error
}

func (f *fakeFeedStore) ListPullFeeds(context.Context) ([]chdata.Feed, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.feeds, nil
}

func (f *fakeFeedStore) SetWatermark(_ context.Context, feedID uuid.UUID, watermark string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.setErr != nil {
		return f.setErr
	}
	f.watermarks = append(f.watermarks, watermark)
	for i := range f.feeds {
		if f.feeds[i].ID == feedID {
			f.feeds[i].PullWatermark = watermark
		}
	}
	return nil
}

func (f *fakeFeedStore) committed() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.watermarks...)
}

// recordingPublisher tracks publish order and can be made to fail on a chosen batch,
// which is how the watermark ordering rule gets tested.
type recordingPublisher struct {
	mu        sync.Mutex
	published []string
	failOn    int
	calls     int
}

func (p *recordingPublisher) PublishBatch(_ context.Context, envelopes []ingest.Envelope) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.failOn > 0 && p.calls == p.failOn {
		return errors.New("broker unavailable")
	}
	for _, e := range envelopes {
		p.published = append(p.published, e.EventID)
	}
	return nil
}

func (p *recordingPublisher) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.published)
}

// stubSource returns a fixed set of batches, recording the watermark it was asked to
// resume from.
type stubSource struct {
	batches       []Batch
	err           error
	seenWatermark string
	calls         int
}

func (s *stubSource) Vendor() string { return vendors.Cloudflare }

func (s *stubSource) Fetch(_ context.Context, _ Config, watermark string) ([]Batch, error) {
	s.calls++
	s.seenWatermark = watermark
	return s.batches, s.err
}

type memStore struct {
	mu   sync.Mutex
	seen map[string]bool
}

func newMemStore() *memStore { return &memStore{seen: map[string]bool{}} }

func (m *memStore) Exists(_ context.Context, keys ...string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var count int64
	for _, key := range keys {
		if m.seen[key] {
			count++
		}
	}
	return count, nil
}

// Batched forms over the same map, so the puller's dedup behaves identically whether it
// asks for one key or a thousand.
func (m *memStore) ExistsMany(
	_ context.Context, keys []string,
) (map[string]bool, error) {
	present := make(map[string]bool, len(keys))
	for _, key := range keys {
		if m.seen[key] {
			present[key] = true
		}
	}
	return present, nil
}

func (m *memStore) SetMany(
	_ context.Context, keys []string, _ string, _ time.Duration,
) error {
	for _, key := range keys {
		m.seen[key] = true
	}
	return nil
}

func (m *memStore) Set(_ context.Context, key, _ string, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seen[key] = true
	return nil
}

type nopHealth struct{}

func (nopHealth) Record(context.Context, ingest.HealthSample) {}

type stubSecrets struct{ err error }

func (s stubSecrets) Resolve(context.Context, string) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	return "token", nil
}

// ---------------------------------------------------------------- harness

func cloudflarePayload(rayID string) []byte {
	return []byte(fmt.Sprintf(
		`{"RayID":%q,"EdgeStartTimestamp":%q,"ClientIP":"203.0.113.1",`+
			`"ClientRequestHost":"h","ClientRequestURI":"/","ClientRequestMethod":"GET",`+
			`"SecurityAction":"allow"}`,
		rayID, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)))
}

type harness struct {
	worker    *Worker
	feeds     *fakeFeedStore
	source    *stubSource
	publisher *recordingPublisher
	feedID    uuid.UUID
}

func newHarness(t *testing.T, batches []Batch) *harness {
	t.Helper()

	feedID := uuid.New()
	feeds := &fakeFeedStore{feeds: []chdata.Feed{{
		TenantID: uuid.New(), ID: feedID, Vendor: vendors.Cloudflare,
		Delivery: chdata.DeliveryPull, Enabled: true, CredentialRef: "ref",
		PullConfig: `{"endpoint":"https://store.example","bucket":"logs","interval_seconds":30}`,
	}}}

	source := &stubSource{batches: batches}
	publisher := &recordingPublisher{}

	adapters, err := vendors.NewRegistry(cloudflare.New())
	if err != nil {
		t.Fatalf("NewRegistry(): %v", err)
	}

	w := NewWorker(feeds, NewRegistry(source), adapters, publisher,
		dedup.New(newMemStore(), time.Minute), stubSecrets{},
		nil, // no ingest filters configured
		nopHealth{}, mw.NewLogger("error", "json"))

	return &harness{w, feeds, source, publisher, feedID}
}

// ---------------------------------------------------------------- tests

// THE ordering rule: a watermark advances only AFTER the batch is durably committed.
func TestWatermarkAdvancesOnlyAfterCommit(t *testing.T) {
	h := newHarness(t, []Batch{
		{Payload: cloudflarePayload("a"), Watermark: "obj-001", Label: "obj-001"},
		{Payload: cloudflarePayload("b"), Watermark: "obj-002", Label: "obj-002"},
		{Payload: cloudflarePayload("c"), Watermark: "obj-003", Label: "obj-003"},
	})

	if err := h.worker.PollDue(context.Background()); err != nil {
		t.Fatalf("PollDue() error = %v", err)
	}

	if got := h.feeds.committed(); len(got) != 3 {
		t.Fatalf("watermarks = %v, want one per committed batch", got)
	}
	if h.publisher.count() != 3 {
		t.Errorf("published %d events, want 3", h.publisher.count())
	}
}

// A commit failure must leave the watermark BEFORE the failed batch, so the next poll
// re-fetches it. Advancing first would lose the batch permanently.
func TestFailedCommitDoesNotAdvanceTheWatermark(t *testing.T) {
	h := newHarness(t, []Batch{
		{Payload: cloudflarePayload("a"), Watermark: "obj-001", Label: "obj-001"},
		{Payload: cloudflarePayload("b"), Watermark: "obj-002", Label: "obj-002"},
		{Payload: cloudflarePayload("c"), Watermark: "obj-003", Label: "obj-003"},
	})
	h.publisher.failOn = 2 // the second batch fails to commit

	err := h.worker.PollDue(context.Background())
	if err == nil {
		t.Fatal("PollDue() returned nil despite a failed durable commit")
	}

	committed := h.feeds.committed()
	if len(committed) != 1 || committed[0] != "obj-001" {
		t.Errorf("watermarks = %v, want only obj-001 — the watermark must not pass a "+
			"batch that was never committed", committed)
	}
}

// Processing stops at the first failure. Committing a later batch while the watermark
// still points before this one would make the next poll re-commit everything between.
func TestProcessingStopsAtTheFirstFailure(t *testing.T) {
	h := newHarness(t, []Batch{
		{Payload: cloudflarePayload("a"), Watermark: "obj-001"},
		{Payload: cloudflarePayload("b"), Watermark: "obj-002"},
		{Payload: cloudflarePayload("c"), Watermark: "obj-003"},
	})
	h.publisher.failOn = 2

	_ = h.worker.PollDue(context.Background())

	// Only the first batch's event was published; the third was never attempted.
	if h.publisher.count() != 1 {
		t.Errorf("published %d events, want only the 1 from the batch before the failure",
			h.publisher.count())
	}
}

// The next poll resumes from the last committed watermark, not from the start.
func TestPollResumesFromTheStoredWatermark(t *testing.T) {
	h := newHarness(t, []Batch{
		{Payload: cloudflarePayload("a"), Watermark: "obj-001"},
	})

	if err := h.worker.PollDue(context.Background()); err != nil {
		t.Fatalf("first PollDue() error = %v", err)
	}

	h.worker.lastPolled = map[uuid.UUID]time.Time{}
	h.source.batches = nil

	if err := h.worker.PollDue(context.Background()); err != nil {
		t.Fatalf("second PollDue() error = %v", err)
	}
	if h.source.seenWatermark != "obj-001" {
		t.Errorf("resumed from watermark %q, want %q",
			h.source.seenWatermark, "obj-001")
	}
}

// A partial fetch failure must still commit what arrived — otherwise the same data is
// re-fetched on every poll while the vendor stays unhealthy — AND report the error.
func TestPartialFetchCommitsWhatArrivedAndReportsTheError(t *testing.T) {
	h := newHarness(t, []Batch{
		{Payload: cloudflarePayload("a"), Watermark: "obj-001"},
		{Payload: cloudflarePayload("b"), Watermark: "obj-002"},
	})
	h.source.err = errors.New("vendor returned 503 on page 3")

	err := h.worker.PollDue(context.Background())

	if err == nil {
		t.Error("PollDue() swallowed a fetch failure; a vendor outage must stay visible")
	}
	if got := h.feeds.committed(); len(got) != 2 {
		t.Errorf("watermarks = %v, want both fetched batches committed despite the "+
			"later failure", got)
	}
}

// An unreadable object must not stall the feed forever: the watermark advances past it
// so the backlog keeps draining.
func TestUnparseableBatchAdvancesPastItself(t *testing.T) {
	h := newHarness(t, []Batch{
		{Payload: []byte("not json at all"), Watermark: "obj-001", Label: "obj-001"},
		{Payload: cloudflarePayload("b"), Watermark: "obj-002", Label: "obj-002"},
	})

	if err := h.worker.PollDue(context.Background()); err != nil {
		t.Fatalf("PollDue() error = %v", err)
	}

	committed := h.feeds.committed()
	if len(committed) != 2 {
		t.Errorf("watermarks = %v, want the bad object skipped and the good one "+
			"committed — a poison object must not stall the feed", committed)
	}
	if h.publisher.count() != 1 {
		t.Errorf("published %d events, want only the 1 readable batch", h.publisher.count())
	}
}

// A redelivered batch is suppressed, so a replay after a crash does not double-count.
func TestReplayedBatchIsDeduplicated(t *testing.T) {
	batches := []Batch{{Payload: cloudflarePayload("a"), Watermark: "obj-001"}}
	h := newHarness(t, batches)

	if err := h.worker.PollDue(context.Background()); err != nil {
		t.Fatalf("first PollDue() error = %v", err)
	}
	h.worker.lastPolled = map[uuid.UUID]time.Time{}

	// The same object is fetched again, as it would be after a crash before the
	// watermark was persisted.
	if err := h.worker.PollDue(context.Background()); err != nil {
		t.Fatalf("second PollDue() error = %v", err)
	}

	if h.publisher.count() != 1 {
		t.Errorf("published %d events across a replay, want 1", h.publisher.count())
	}
}

// A feed is not polled again until its interval has elapsed.
func TestFeedIsNotPolledBeforeItsInterval(t *testing.T) {
	h := newHarness(t, []Batch{{Payload: cloudflarePayload("a"), Watermark: "obj-001"}})

	if err := h.worker.PollDue(context.Background()); err != nil {
		t.Fatalf("PollDue() error = %v", err)
	}
	if err := h.worker.PollDue(context.Background()); err != nil {
		t.Fatalf("PollDue() error = %v", err)
	}

	if h.source.calls != 1 {
		t.Errorf("fetched %d times, want 1 — the 30s interval had not elapsed", h.source.calls)
	}
}

// A credential that will not resolve must fail the poll rather than fetching
// unauthenticated, which would return an opaque 401 the operator has to guess at.
func TestUnresolvableCredentialFailsThePoll(t *testing.T) {
	h := newHarness(t, []Batch{{Payload: cloudflarePayload("a"), Watermark: "obj-001"}})
	h.worker.secrets = stubSecrets{err: errors.New("no such secret")}

	if err := h.worker.PollDue(context.Background()); err == nil {
		t.Error("PollDue() succeeded despite an unresolvable credential")
	}
	if h.source.calls != 0 {
		t.Error("the source was fetched without a credential")
	}
}

func TestMisconfiguredFeedIsReportedNotSkippedSilently(t *testing.T) {
	h := newHarness(t, nil)
	h.feeds.feeds[0].PullConfig = "{}"

	if err := h.worker.PollDue(context.Background()); err == nil {
		t.Error("PollDue() succeeded for a feed with no pull configuration")
	}
}

// ---------------------------------------------------------------- config

// A one-second interval against a vendor API is indistinguishable from an attack.
func TestIntervalIsClamped(t *testing.T) {
	tests := []struct {
		name    string
		seconds int
		want    time.Duration
	}{
		{"unset falls back", 0, DefaultInterval},
		{"negative falls back", -5, DefaultInterval},
		{"one second is raised to the floor", 1, MinInterval},
		{"a day is lowered to the ceiling", 86400, MaxInterval},
		{"a sane value passes through", 120, 2 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (Config{IntervalSeconds: tt.seconds}).Interval(); got != tt.want {
				t.Errorf("Interval() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseConfigRejectsUnusableConfiguration(t *testing.T) {
	tests := []struct{ name, raw string }{
		{"empty", ""},
		{"empty object", "{}"},
		{"not json", "endpoint=foo"},
		{"no endpoint", `{"bucket":"logs"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseConfig(tt.raw); err == nil {
				t.Errorf("ParseConfig(%q) accepted an unusable configuration", tt.raw)
			}
		})
	}
}

func TestParseConfigAcceptsValidConfiguration(t *testing.T) {
	cfg, err := ParseConfig(
		`{"endpoint":"https://r2.example","bucket":"logs","prefix":"cf/","interval_seconds":60}`)
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if cfg.Bucket != "logs" || cfg.Prefix != "cf/" {
		t.Errorf("Config = %+v, want the bucket and prefix parsed", cfg)
	}
	if cfg.Interval() != time.Minute {
		t.Errorf("Interval() = %v, want 1m", cfg.Interval())
	}
}

// A credential must never reach a log through a URL.
func TestRedactURLStripsCredentials(t *testing.T) {
	got := redactURL("https://user:pass@api.example/v1/logs?token=secret123&from=x")

	for _, forbidden := range []string{"secret123", "pass", "token"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("redactURL() = %q still carries %q", got, forbidden)
		}
	}
	if !strings.Contains(got, "api.example") {
		t.Errorf("redactURL() = %q, want the host retained for diagnosis", got)
	}
}
