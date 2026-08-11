package dedup

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// memStore is an in-memory Store with SetNX semantics.
type memStore struct {
	seen map[string]bool
	err  error
	// failAfter makes the store fail partway through a batch, so the fail-open path
	// can be exercised mid-stream rather than only on the first call.
	failAfter int
	calls     int
	// setCalls counts marking round trips, separately from lookups.
	setCalls int
}

func newMemStore() *memStore {
	return &memStore{seen: map[string]bool{}, failAfter: -1}
}

func (m *memStore) Exists(_ context.Context, keys ...string) (int64, error) {
	m.calls++
	if m.err != nil {
		return 0, m.err
	}
	if m.failAfter >= 0 && m.calls > m.failAfter {
		return 0, errors.New("redis unavailable")
	}
	var count int64
	for _, key := range keys {
		if m.seen[key] {
			count++
		}
	}
	return count, nil
}

// ExistsMany answers from the same map the singular form uses, so a batched caller sees
// exactly what an unbatched one would. It counts as ONE call, which is what lets a test
// assert that a batch costs one round trip rather than one per event.
func (m *memStore) ExistsMany(
	_ context.Context, keys []string,
) (map[string]bool, error) {
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	if m.failAfter >= 0 && m.calls > m.failAfter {
		return nil, errors.New("redis unavailable")
	}
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
	m.setCalls++
	if m.err != nil {
		return m.err
	}
	for _, key := range keys {
		m.seen[key] = true
	}
	return nil
}

func (m *memStore) Set(_ context.Context, key, _ string, _ time.Duration) error {
	if m.err != nil {
		return m.err
	}
	m.seen[key] = true
	return nil
}

// filterAndMark is the normal caller sequence: filter, commit, then mark.
func filterAndMark(t *testing.T, d *Deduper, tenant string, ids []string) Result {
	t.Helper()

	result, err := d.Filter(context.Background(), tenant, ids)
	if err != nil {
		t.Fatalf("Filter() error = %v", err)
	}

	fresh := make([]string, 0, len(result.Fresh))
	for _, idx := range result.Fresh {
		fresh = append(fresh, ids[idx])
	}
	if err := d.Mark(context.Background(), tenant, fresh); err != nil {
		t.Fatalf("Mark() error = %v", err)
	}
	return result
}

func TestFirstDeliveryIsFresh(t *testing.T) {
	d := New(newMemStore(), time.Minute)

	result := filterAndMark(t, d, "tenant-a", []string{"e1", "e2", "e3"})

	if len(result.Fresh) != 3 {
		t.Errorf("Fresh = %v, want all 3 events", result.Fresh)
	}
	if result.Duplicates != 0 {
		t.Errorf("Duplicates = %d, want 0 on first delivery", result.Duplicates)
	}
}

// The behaviour FR-004 promises: a replayed batch is fully suppressed and counted.
func TestReplayedBatchIsFullySuppressed(t *testing.T) {
	d := New(newMemStore(), time.Minute)
	ctx := context.Background()
	batch := []string{"e1", "e2", "e3"}

	filterAndMark(t, d, "tenant-a", batch)
	result := filterAndMark(t, d, "tenant-a", batch)
	_ = ctx

	if len(result.Fresh) != 0 {
		t.Errorf("Fresh = %v, want none on a full replay", result.Fresh)
	}
	if result.Duplicates != 3 {
		t.Errorf("Duplicates = %d, want 3", result.Duplicates)
	}
}

// A vendor retry commonly overlaps rather than repeating exactly: the new events must
// still get through.
func TestPartiallyOverlappingBatch(t *testing.T) {
	d := New(newMemStore(), time.Minute)
	ctx := context.Background()

	filterAndMark(t, d, "tenant-a", []string{"e1", "e2"})
	result := filterAndMark(t, d, "tenant-a", []string{"e1", "e2", "e3", "e4"})
	_ = ctx

	if result.Duplicates != 2 {
		t.Errorf("Duplicates = %d, want 2", result.Duplicates)
	}
	if len(result.Fresh) != 2 {
		t.Fatalf("Fresh = %v, want the 2 new events", result.Fresh)
	}
	// Indices must refer back to the caller's input positions.
	if result.Fresh[0] != 2 || result.Fresh[1] != 3 {
		t.Errorf("Fresh = %v, want indices [2 3] into the input batch", result.Fresh)
	}
}

// One tenant's traffic must never suppress another's, even for an identical event id.
func TestDedupIsScopedPerTenant(t *testing.T) {
	d := New(newMemStore(), time.Minute)
	ctx := context.Background()

	filterAndMark(t, d, "tenant-a", []string{"shared-id"})
	result := filterAndMark(t, d, "tenant-b", []string{"shared-id"})
	_ = ctx
	if result.Duplicates != 0 {
		t.Error("tenant B's event was suppressed by tenant A's identical event id")
	}
}

// Losing a customer's logs because Redis is down would be far worse than briefly
// over-counting, and ClickHouse still deduplicates at the storage layer.
func TestFailsOpenWhenStoreIsUnavailable(t *testing.T) {
	store := newMemStore()
	store.err = errors.New("redis unavailable")
	d := New(store, time.Minute)

	result, err := d.Filter(context.Background(), "tenant-a", []string{"e1", "e2", "e3"})

	if err == nil {
		t.Error("Filter() hid a store failure; the caller must be able to log the degradation")
	}
	if len(result.Fresh) != 3 {
		t.Errorf("Fresh = %v, want all events accepted when the store is unavailable", result.Fresh)
	}
	if result.Duplicates != 0 {
		t.Errorf("Duplicates = %d, want 0 when nothing could be checked", result.Duplicates)
	}
}

// A STORE FAILURE ACCEPTS THE WHOLE BATCH, with every index still aligned to the input.
//
// This used to be phrased as "a failure PARTWAY THROUGH must not drop the events after
// it", because the lookup ran one Redis call per event and could fail on any of them.
// The lookup is now a single batched call, so there is no partway: it either answers for
// the batch or fails for the batch. The property that survives is the one that always
// mattered — a store that cannot answer must never cost a customer their logs, and the
// indices handed back must still point at the right parsed records.
func TestAStoreFailureAcceptsTheWholeBatch(t *testing.T) {
	store := newMemStore()
	store.failAfter = 0 // the very first lookup fails
	d := New(store, time.Minute)

	result, err := d.Filter(context.Background(), "tenant-a", []string{"e1", "e2", "e3", "e4", "e5"})

	if err == nil {
		t.Error("Filter() hid a store failure")
	}
	if len(result.Fresh) != 5 {
		t.Errorf("Fresh = %v, want all 5 events accepted after the failure", result.Fresh)
	}
	for i, idx := range result.Fresh {
		if idx != i {
			t.Errorf("Fresh[%d] = %d, want %d — indices must stay aligned to the input", i, idx, i)
		}
	}
}

// The batched lookup must cost ONE round trip regardless of batch size. A Cloudflare
// delivery carries 7,605 events on average, and asking per event put 17.5% of the ingest
// service's CPU into blocking Redis calls.
func TestFilteringABatchCostsOneRoundTrip(t *testing.T) {
	store := newMemStore()
	d := New(store, time.Minute)

	eventIDs := make([]string, 0, 500)
	for i := range 500 {
		eventIDs = append(eventIDs, fmt.Sprintf("e%d", i))
	}

	if _, err := d.Filter(context.Background(), "tenant-a", eventIDs); err != nil {
		t.Fatalf("Filter() error = %v", err)
	}
	if store.calls != 1 {
		t.Errorf("Filter() over %d events made %d lookup round trips, want 1",
			len(eventIDs), store.calls)
	}

	if err := d.Mark(context.Background(), "tenant-a", eventIDs); err != nil {
		t.Fatalf("Mark() error = %v", err)
	}
	if store.setCalls != 1 {
		t.Errorf("Mark() over %d events made %d write round trips, want 1",
			len(eventIDs), store.setCalls)
	}
}

// An event with no derivable identity cannot be recognized as a redelivery, so it is
// accepted rather than silently dropped.
func TestEmptyEventIDIsTreatedAsFresh(t *testing.T) {
	d := New(newMemStore(), time.Minute)

	result, err := d.Filter(context.Background(), "tenant-a", []string{"", "", ""})
	if err != nil {
		t.Fatalf("Filter() error = %v", err)
	}
	if len(result.Fresh) != 3 {
		t.Errorf("Fresh = %v, want events with no identity accepted", result.Fresh)
	}
	if result.Duplicates != 0 {
		t.Errorf("Duplicates = %d, want 0", result.Duplicates)
	}
}

// A zero window would silently turn every retry into a double-count, so it falls back
// to the default rather than disabling deduplication.
func TestNonPositiveWindowFallsBackToDefault(t *testing.T) {
	for _, window := range []time.Duration{0, -time.Minute} {
		if got := New(newMemStore(), window).Window(); got != DefaultWindow {
			t.Errorf("New(window=%v).Window() = %v, want %v", window, got, DefaultWindow)
		}
	}
}

func TestSeen(t *testing.T) {
	d := New(newMemStore(), time.Minute)
	ctx := context.Background()

	seen, err := d.Seen(ctx, "tenant-a", "e1")
	if err != nil {
		t.Fatalf("Seen() error = %v", err)
	}
	if seen {
		t.Error("Seen() = true for an event never marked")
	}

	// Seen is read-only: only Mark records.
	if err := d.Mark(ctx, "tenant-a", []string{"e1"}); err != nil {
		t.Fatalf("Mark() error = %v", err)
	}
	seen, err = d.Seen(ctx, "tenant-a", "e1")
	if err != nil {
		t.Fatalf("Seen() error = %v", err)
	}
	if !seen {
		t.Error("Seen() = false after the event was marked")
	}
}

func TestSeenPropagatesStoreErrors(t *testing.T) {
	store := newMemStore()
	store.err = errors.New("redis unavailable")

	if _, err := New(store, time.Minute).Seen(context.Background(), "t", "e1"); err == nil {
		t.Error("Seen() hid a store failure")
	}
}

func TestCheckHandlesEmptyBatch(t *testing.T) {
	result, err := New(newMemStore(), time.Minute).Filter(context.Background(), "t", nil)
	if err != nil {
		t.Fatalf("Filter() error = %v", err)
	}
	if len(result.Fresh) != 0 || result.Duplicates != 0 {
		t.Errorf("Filter(nil) = %+v, want an empty result", result)
	}
}

// THE regression test for the data-loss bug this design exists to prevent.
//
// Marking an event as seen at filter time meant that when the publish then failed and
// the vendor retried after the 503, the retry was suppressed as a duplicate — so the
// event was never committed at all. Filter must record nothing.
func TestFilterRecordsNothingSoAFailedPublishCanBeRetried(t *testing.T) {
	d := New(newMemStore(), time.Minute)
	ctx := context.Background()
	batch := []string{"e1", "e2", "e3"}

	// First attempt: filtered as fresh, then the publish fails — Mark is never called.
	first, err := d.Filter(ctx, "tenant-a", batch)
	if err != nil {
		t.Fatalf("Filter() error = %v", err)
	}
	if len(first.Fresh) != 3 {
		t.Fatalf("Fresh = %v, want all 3 events", first.Fresh)
	}

	// The vendor retries after the 503. Every event MUST still be deliverable.
	retry, err := d.Filter(ctx, "tenant-a", batch)
	if err != nil {
		t.Fatalf("Filter() on retry error = %v", err)
	}
	if len(retry.Fresh) != 3 {
		t.Errorf("Fresh = %v on retry, want all 3 — a failed publish must not "+
			"suppress the vendor's retry, or the events are lost permanently", retry.Fresh)
	}
	if retry.Duplicates != 0 {
		t.Errorf("Duplicates = %d on retry, want 0", retry.Duplicates)
	}
}

// Duplicates inside a single batch are caught before anything is recorded.
func TestFilterCatchesDuplicatesWithinOneBatch(t *testing.T) {
	d := New(newMemStore(), time.Minute)

	result, err := d.Filter(context.Background(), "tenant-a",
		[]string{"e1", "e2", "e1", "e3", "e2"})
	if err != nil {
		t.Fatalf("Filter() error = %v", err)
	}

	if len(result.Fresh) != 3 {
		t.Errorf("Fresh = %v, want the 3 distinct events", result.Fresh)
	}
	if result.Duplicates != 2 {
		t.Errorf("Duplicates = %d, want 2", result.Duplicates)
	}
}

// A Mark failure must not be fatal: the events are already durable, and a lost marker
// only means a later redelivery is re-published and collapsed by storage.
func TestMarkFailureIsReportedNotSilent(t *testing.T) {
	store := newMemStore()
	store.err = errors.New("redis unavailable")

	if err := New(store, time.Minute).Mark(context.Background(), "t", []string{"e1"}); err == nil {
		t.Error("Mark() hid a store failure")
	}
}
