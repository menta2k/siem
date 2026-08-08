package correlate_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/correlate"
	"github.com/menta2k/siem/internal/correlate/keys"
	"github.com/menta2k/siem/internal/correlate/window"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/data/stream"
	mw "github.com/menta2k/siem/internal/middleware"
)

var batchTenant = uuid.MustParse("00000000-0000-4000-8000-00000000ba01")

// countingWindowStore records every write and how many ROUND TRIPS it took. The
// round-trip count is the entire point of the batch path.
type countingWindowStore struct {
	lists map[string][]string
	zset  map[string]map[string]float64

	pushCalls int
	zaddCalls int

	fail error
}

func newCountingWindowStore() *countingWindowStore {
	return &countingWindowStore{
		lists: map[string][]string{},
		zset:  map[string]map[string]float64{},
	}
}

func (s *countingWindowStore) RPush(
	_ context.Context, key, value string, _ time.Duration,
) (int64, error) {
	s.pushCalls++
	if s.fail != nil {
		return 0, s.fail
	}
	s.lists[key] = append(s.lists[key], value)
	return int64(len(s.lists[key])), nil
}

func (s *countingWindowStore) RPushMany(
	_ context.Context, entries []window.ListEntry,
) error {
	s.pushCalls++
	if s.fail != nil {
		return s.fail
	}
	for _, entry := range entries {
		s.lists[entry.Key] = append(s.lists[entry.Key], entry.Value)
	}
	return nil
}

func (s *countingWindowStore) ZAdd(
	_ context.Context, key, member string, score float64, _ time.Duration,
) error {
	s.zaddCalls++
	if s.fail != nil {
		return s.fail
	}
	if s.zset[key] == nil {
		s.zset[key] = map[string]float64{}
	}
	s.zset[key][member] = score
	return nil
}

func (s *countingWindowStore) ZAddMany(
	_ context.Context, entries []window.ScoreEntry,
) error {
	s.zaddCalls++
	if s.fail != nil {
		return s.fail
	}
	for _, entry := range entries {
		if s.zset[entry.Key] == nil {
			s.zset[entry.Key] = map[string]float64{}
		}
		s.zset[entry.Key][entry.Member] = entry.Score
	}
	return nil
}

func (s *countingWindowStore) LRange(_ context.Context, key string) ([]string, error) {
	return s.lists[key], nil
}

func (s *countingWindowStore) SetNX(
	context.Context, string, string, time.Duration,
) (bool, error) {
	return true, nil
}

func (s *countingWindowStore) Get(context.Context, string) (string, error) {
	return "", nil
}

func (s *countingWindowStore) Lookup(context.Context, string) (string, bool, error) {
	return "", false, nil
}

// ZPopDue pops due members for real, so the closer tests exercise the same claim
// loop the running closer does rather than a stub that always looks drained.
func (s *countingWindowStore) ZPopDue(
	_ context.Context, key string, max float64, limit int64,
) ([]string, error) {
	popped := make([]string, 0, limit)
	for member, score := range s.zset[key] {
		if int64(len(popped)) >= limit {
			break
		}
		if score <= max {
			popped = append(popped, member)
		}
	}
	for _, member := range popped {
		delete(s.zset[key], member)
	}
	return popped, nil
}

func newBatchWorker(store *countingWindowStore) *correlate.Worker {
	return correlate.NewWorker(
		window.New(store),
		correlate.FixedSettings{Value: correlate.Resolved{Keys: keys.DefaultSettings()}},
		mw.NewLogger("error", "json"))
}

// eventRecord builds a normalized event carrying both a request id and a full request
// shape, so it files under BOTH its exact and its heuristic key.
func eventRecord(t *testing.T, requestID, path string, at time.Time) stream.Record {
	t.Helper()

	event := chdata.NormalizedEvent{
		TenantID: batchTenant, EventID: uuid.NewString(), Vendor: "cloudflare",
		EventTime: at, VendorRequestID: requestID,
		ClientIP: net.ParseIP("203.0.113.10"), RequestHost: "shop.example.com",
		RequestPath: path, RequestMethod: "GET",
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("encode event: %v", err)
	}
	return stream.Record{Key: []byte(event.EventID), Value: encoded}
}

func recordBatch(t *testing.T, n int) []stream.Record {
	t.Helper()

	// Each event describes a DIFFERENT request, so it forms its own heuristic window.
	// Events sharing a request shape correctly collapse into one window, which would
	// hide a batch that filed too few keys.
	at := time.Now().UTC().Add(-time.Minute)
	records := make([]stream.Record, 0, n)
	for i := range n {
		path := fmt.Sprintf("/checkout/%d", i)
		records = append(records, eventRecord(t, uuid.NewString(), path, at))
	}
	return records
}

// The whole point: a fetch costs a fixed number of round trips, not three per event.
func TestABatchFilesInAFixedNumberOfRoundTrips(t *testing.T) {
	store := newCountingWindowStore()

	failures, err := newBatchWorker(store).HandleBatch(context.Background(), recordBatch(t, 400))
	if err != nil {
		t.Fatalf("HandleBatch: %v", err)
	}
	if len(failures) != 0 {
		t.Fatalf("%d failures on a clean batch", len(failures))
	}

	if store.pushCalls != 1 || store.zaddCalls != 1 {
		t.Errorf("%d push and %d zadd round trips for 400 events, want 1 each",
			store.pushCalls, store.zaddCalls)
	}
}

// The batch path must file EXACTLY what the single-record path files. If it drifts,
// the join silently changes shape — which is the failure this whole feature exists to
// avoid.
func TestTheBatchPathFilesTheSameStateAsTheSinglePath(t *testing.T) {
	records := recordBatch(t, 25)

	single := newCountingWindowStore()
	worker := newBatchWorker(single)
	for _, record := range records {
		if err := worker.Handle(context.Background(), record); err != nil {
			t.Fatalf("Handle: %v", err)
		}
	}

	batched := newCountingWindowStore()
	if _, err := newBatchWorker(batched).HandleBatch(context.Background(), records); err != nil {
		t.Fatalf("HandleBatch: %v", err)
	}

	if len(batched.lists) != len(single.lists) {
		t.Fatalf("batch filed %d window keys, single-record filed %d",
			len(batched.lists), len(single.lists))
	}
	for key, values := range single.lists {
		if len(batched.lists[key]) != len(values) {
			t.Errorf("window %s holds %d members after batching, %d after single-record",
				key, len(batched.lists[key]), len(values))
		}
	}
	if len(batched.zset) != len(single.zset) {
		t.Errorf("batch scheduled %d schedule keys, single-record scheduled %d",
			len(batched.zset), len(single.zset))
	}
	for key, members := range single.zset {
		if len(batched.zset[key]) != len(members) {
			t.Errorf("schedule %s holds %d windows after batching, %d after single-record",
				key, len(batched.zset[key]), len(members))
		}
	}
}

// An event with both keys is filed under two windows, but only ONE is scheduled.
// Scheduling the exact-key lookup bucket too would emit every request twice, with the
// first record arriving already marked as an amendment of itself.
func TestOnlyTheClosingWindowIsScheduled(t *testing.T) {
	store := newCountingWindowStore()

	records := recordBatch(t, 10)
	if _, err := newBatchWorker(store).HandleBatch(context.Background(), records); err != nil {
		t.Fatalf("HandleBatch: %v", err)
	}

	if len(store.lists) != 20 {
		t.Errorf("%d window keys for 10 two-key events, want 20", len(store.lists))
	}

	scheduled := 0
	for _, members := range store.zset {
		scheduled += len(members)
	}
	if scheduled != 10 {
		t.Errorf("%d scheduled windows for 10 events, want 10 — one per closing key",
			scheduled)
	}
}

// A store failure must fail the WHOLE batch so no offset commits and every event is
// refiled on redelivery.
func TestAStoreFailureFailsTheWholeBatch(t *testing.T) {
	store := newCountingWindowStore()
	store.fail = errors.New("redis unavailable")

	failures, err := newBatchWorker(store).HandleBatch(context.Background(), recordBatch(t, 10))
	if err == nil {
		t.Fatal("a store failure was reported as success; the offsets would commit and " +
			"the events would never be correlated")
	}
	if len(failures) != 0 {
		t.Error("a store failure dead-lettered records that are not at fault")
	}
}

// An undecodable record is skipped, not retried and not fatal: it will never parse,
// retrying stalls the partition behind it, and the event is already durably stored.
func TestAnUndecodableRecordIsSkippedWithoutSinkingTheBatch(t *testing.T) {
	store := newCountingWindowStore()

	records := append(recordBatch(t, 3),
		stream.Record{Key: []byte("junk"), Value: []byte("{not json")})

	failures, err := newBatchWorker(store).HandleBatch(context.Background(), records)
	if err != nil {
		t.Fatalf("HandleBatch: %v", err)
	}
	if len(failures) != 0 {
		t.Errorf("%d failures; an unparseable record is skipped, not dead-lettered",
			len(failures))
	}
	if len(store.lists) != 6 {
		t.Errorf("%d window keys, want the 6 belonging to the 3 good events",
			len(store.lists))
	}
}

// An empty fetch must not issue writes.
func TestAnEmptyBatchDoesNothing(t *testing.T) {
	store := newCountingWindowStore()

	if _, err := newBatchWorker(store).HandleBatch(context.Background(), nil); err != nil {
		t.Fatalf("HandleBatch: %v", err)
	}
	if store.pushCalls != 0 || store.zaddCalls != 0 {
		t.Error("an empty batch issued writes")
	}
}
