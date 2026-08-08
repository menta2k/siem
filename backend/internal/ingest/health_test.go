package ingest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

type fakeHealthStore struct {
	mu   sync.Mutex
	rows []FeedHealthRow
	err  error
}

func (f *fakeHealthStore) InsertFeedHealth(_ context.Context, rows []FeedHealthRow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.rows = append(f.rows, rows...)
	return nil
}

func (f *fakeHealthStore) snapshot() []FeedHealthRow {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]FeedHealthRow{}, f.rows...)
}

func newTestAggregator(store HealthStore, now func() time.Time) *HealthAggregator {
	a := NewHealthAggregator(store)
	if now != nil {
		a.now = now
	}
	return a
}

// Per-delivery writes would put a ClickHouse insert on the hot path of every vendor
// request. Samples must accumulate in memory and flush as one row per minute.
func TestSamplesAccumulateIntoOneRowPerMinute(t *testing.T) {
	store := &fakeHealthStore{}
	minute := time.Date(2026, 8, 6, 12, 30, 0, 0, time.UTC)
	a := newTestAggregator(store, func() time.Time { return minute.Add(17 * time.Second) })

	tenant, feed := uuid.New(), uuid.New()
	for range 5 {
		a.Record(context.Background(), HealthSample{
			TenantID: tenant, FeedID: feed,
			EventsReceived: 100, EventsRejected: 2, DuplicatesSuppressed: 3,
			BytesReceived: 1024, CredentialValid: true,
		})
	}

	if len(store.snapshot()) != 0 {
		t.Fatal("rows were written before a flush; the hot path must not block on I/O")
	}
	if err := a.Flush(context.Background()); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	rows := store.snapshot()
	if len(rows) != 1 {
		t.Fatalf("wrote %d rows, want 1 per feed per minute", len(rows))
	}

	row := rows[0]
	if row.EventsReceived != 500 {
		t.Errorf("EventsReceived = %d, want 500", row.EventsReceived)
	}
	if row.EventsRejected != 10 {
		t.Errorf("EventsRejected = %d, want 10", row.EventsRejected)
	}
	if row.DuplicatesSuppressed != 15 {
		t.Errorf("DuplicatesSuppressed = %d, want 15", row.DuplicatesSuppressed)
	}
	if row.BytesReceived != 5120 {
		t.Errorf("BytesReceived = %d, want 5120", row.BytesReceived)
	}
	if !row.Minute.Equal(minute) {
		t.Errorf("Minute = %v, want it truncated to %v", row.Minute, minute)
	}
}

func TestSamplesSplitAcrossMinutes(t *testing.T) {
	store := &fakeHealthStore{}
	now := time.Date(2026, 8, 6, 12, 30, 0, 0, time.UTC)
	a := newTestAggregator(store, func() time.Time { return now })

	tenant, feed := uuid.New(), uuid.New()
	a.Record(context.Background(), HealthSample{TenantID: tenant, FeedID: feed, EventsReceived: 10})
	now = now.Add(time.Minute)
	a.Record(context.Background(), HealthSample{TenantID: tenant, FeedID: feed, EventsReceived: 20})

	if err := a.Flush(context.Background()); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	if got := len(store.snapshot()); got != 2 {
		t.Errorf("wrote %d rows, want one per minute", got)
	}
}

func TestFeedsAreAccumulatedSeparately(t *testing.T) {
	store := &fakeHealthStore{}
	a := newTestAggregator(store, nil)
	tenant := uuid.New()
	feedA, feedB := uuid.New(), uuid.New()

	a.Record(context.Background(), HealthSample{TenantID: tenant, FeedID: feedA, EventsReceived: 10})
	a.Record(context.Background(), HealthSample{TenantID: tenant, FeedID: feedB, EventsReceived: 20})

	if err := a.Flush(context.Background()); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	rows := store.snapshot()
	if len(rows) != 2 {
		t.Fatalf("wrote %d rows, want one per feed", len(rows))
	}
	for _, row := range rows {
		switch row.FeedID {
		case feedA:
			if row.EventsReceived != 10 {
				t.Errorf("feed A EventsReceived = %d, want 10", row.EventsReceived)
			}
		case feedB:
			if row.EventsReceived != 20 {
				t.Errorf("feed B EventsReceived = %d, want 20", row.EventsReceived)
			}
		default:
			t.Errorf("unexpected feed %v in the output", row.FeedID)
		}
	}
}

// One bad credential must be visible even among successful deliveries in the same
// minute — otherwise an expired token hides behind the traffic that still works.
func TestOneInvalidCredentialMarksTheWholeMinute(t *testing.T) {
	store := &fakeHealthStore{}
	a := newTestAggregator(store, nil)
	tenant, feed := uuid.New(), uuid.New()
	ctx := context.Background()

	ok := HealthSample{TenantID: tenant, FeedID: feed, EventsReceived: 100, CredentialValid: true}
	bad := HealthSample{TenantID: tenant, FeedID: feed, CredentialValid: false}

	a.Record(ctx, ok)
	a.Record(ctx, bad)
	a.Record(ctx, ok)

	if err := a.Flush(ctx); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	rows := store.snapshot()
	if len(rows) != 1 {
		t.Fatalf("wrote %d rows, want 1", len(rows))
	}
	if rows[0].CredentialValid {
		t.Error("CredentialValid = true despite a failed authentication in the minute")
	}
}

func TestMaxLagIsRetained(t *testing.T) {
	store := &fakeHealthStore{}
	a := newTestAggregator(store, nil)
	tenant, feed := uuid.New(), uuid.New()
	ctx := context.Background()

	for _, lag := range []uint32{100, 5000, 250} {
		a.Record(ctx, HealthSample{TenantID: tenant, FeedID: feed, IngestLagMS: lag})
	}
	if err := a.Flush(ctx); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	if got := store.snapshot()[0].MaxIngestLagMS; got != 5000 {
		t.Errorf("MaxIngestLagMS = %d, want the peak of 5000", got)
	}
}

func TestFlushClearsAccumulatedState(t *testing.T) {
	store := &fakeHealthStore{}
	a := newTestAggregator(store, nil)
	tenant, feed := uuid.New(), uuid.New()
	ctx := context.Background()

	a.Record(ctx, HealthSample{TenantID: tenant, FeedID: feed, EventsReceived: 10})
	if err := a.Flush(ctx); err != nil {
		t.Fatalf("first Flush() error = %v", err)
	}
	if err := a.Flush(ctx); err != nil {
		t.Fatalf("second Flush() error = %v", err)
	}

	if got := len(store.snapshot()); got != 1 {
		t.Errorf("wrote %d rows across two flushes, want 1 — counters were not cleared", got)
	}
}

func TestFlushWithNothingBufferedIsANoOp(t *testing.T) {
	store := &fakeHealthStore{err: errors.New("should not be called")}

	if err := newTestAggregator(store, nil).Flush(context.Background()); err != nil {
		t.Errorf("Flush() with nothing buffered = %v, want nil", err)
	}
}

// Record is called from every ingest request, so concurrent use must be safe.
func TestConcurrentRecordIsSafe(t *testing.T) {
	store := &fakeHealthStore{}
	a := newTestAggregator(store, nil)
	tenant, feed := uuid.New(), uuid.New()
	ctx := context.Background()

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				a.Record(ctx, HealthSample{TenantID: tenant, FeedID: feed, EventsReceived: 1})
			}
		}()
	}
	wg.Wait()

	if err := a.Flush(ctx); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	if got := store.snapshot()[0].EventsReceived; got != 1000 {
		t.Errorf("EventsReceived = %d, want 1000 — counts were lost to a race", got)
	}
}

// The last minute of health must survive shutdown.
func TestRunFlushesOnShutdown(t *testing.T) {
	store := &fakeHealthStore{}
	a := newTestAggregator(store, nil)
	tenant, feed := uuid.New(), uuid.New()

	ctx, cancel := context.WithCancel(context.Background())
	a.Record(ctx, HealthSample{TenantID: tenant, FeedID: feed, EventsReceived: 42})

	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not return after cancellation")
	}

	rows := store.snapshot()
	if len(rows) != 1 || rows[0].EventsReceived != 42 {
		t.Error("the buffered minute was lost on shutdown")
	}
}

// A dead feed looks identical to clean traffic on a dashboard, so silence has to be
// asserted rather than inferred from an empty chart.
func TestIsSilent(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		lastEventAt time.Time
		want        bool
	}{
		{"just received", now.Add(-time.Second), false},
		{"a few minutes ago", now.Add(-5 * time.Minute), false},
		{"just inside the threshold", now.Add(-14 * time.Minute), false},
		{"past the threshold", now.Add(-16 * time.Minute), true},
		{"hours ago", now.Add(-6 * time.Hour), true},
		// A feed that has never delivered is new, not silent. Warning on creation
		// would train operators to ignore the signal.
		{"never delivered", time.Time{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSilent(tt.lastEventAt, now); got != tt.want {
				t.Errorf("IsSilent(%v) = %v, want %v", tt.lastEventAt, got, tt.want)
			}
		})
	}
}

func TestAggregatorName(t *testing.T) {
	if got := NewHealthAggregator(&fakeHealthStore{}).Name(); got != "feed-health" {
		t.Errorf("Name() = %q, want %q", got, "feed-health")
	}
}

// THE PRODUCTION FAILURE THIS GUARDS. Counters accumulate IN MEMORY and reach ClickHouse
// only when this loop writes them, so an aggregator that is constructed but never run
// discards everything it is given — silently, because recording a sample cannot fail.
// siem-ingest did exactly that, and feed_health held no rows at all: the filtered counter,
// the credential status and the received volume for every push feed were all missing while
// ingestion itself looked perfectly healthy.
//
// Asserted through shutdown rather than the tick, because the interval is a minute and a
// test that waits for it would be a minute of nothing.
func TestRunPersistsWhatWasRecorded(t *testing.T) {
	store := &fakeHealthStore{}
	aggregator := newTestAggregator(store, nil)

	aggregator.Record(context.Background(), HealthSample{
		TenantID: uuid.New(), FeedID: uuid.New(),
		EventsReceived: 7, EventsFiltered: 3, CredentialValid: true,
	})

	if len(store.snapshot()) != 0 {
		t.Fatal("a sample reached storage before any flush, so this test proves nothing")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- aggregator.Run(ctx) }()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}

	rows := store.snapshot()
	if len(rows) != 1 {
		t.Fatalf("%d rows persisted, want 1 — a running aggregator must not lose "+
			"what it accumulated", len(rows))
	}
	if rows[0].EventsReceived != 7 || rows[0].EventsFiltered != 3 {
		t.Errorf("persisted received=%d filtered=%d, want 7 and 3",
			rows[0].EventsReceived, rows[0].EventsFiltered)
	}
}
