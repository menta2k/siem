package correlate_test

import (
	"context"
	"errors"
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

// countingCorrelatedStore records how many inserts the closer issued and how many
// records each one carried.
type countingCorrelatedStore struct {
	calls        int
	records      int
	versionCalls int

	// existing seeds records that are already stored, so the amendment path can be
	// exercised without a second close pass.
	existing map[uuid.UUID]uint64

	// written keeps the rows themselves, so the version contract can be asserted on
	// what was actually stored rather than on a count.
	written []chdata.CorrelatedRequest

	// bounds keeps the partition range each lookup was given, so a test can assert
	// that the reads are pruned rather than trusting that they are.
	bounds []chdata.PartitionBound
}

func (s *countingCorrelatedStore) Insert(
	_ context.Context, records []chdata.CorrelatedRequest,
) error {
	s.calls++
	s.records += len(records)
	s.written = append(s.written, records...)
	return nil
}

// ByIDs returns the records this store has already been given, so an amendment can be
// merged into them exactly as it is against real storage.
func (s *countingCorrelatedStore) ByIDs(
	_ context.Context, correlationIDs []uuid.UUID, bound chdata.PartitionBound,
) (map[uuid.UUID]chdata.CorrelatedRequest, error) {
	s.bounds = append(s.bounds, bound)
	wanted := make(map[uuid.UUID]struct{}, len(correlationIDs))
	for _, id := range correlationIDs {
		wanted[id] = struct{}{}
	}

	out := map[uuid.UUID]chdata.CorrelatedRequest{}
	for _, record := range s.written {
		if _, ok := wanted[record.CorrelationID]; ok {
			// The newest write wins, as FINAL would return.
			out[record.CorrelationID] = record
		}
	}
	return out, nil
}

func (s *countingCorrelatedStore) Versions(
	_ context.Context, correlationIDs []uuid.UUID, bound chdata.PartitionBound,
) (map[uuid.UUID]uint64, error) {
	s.versionCalls++
	s.bounds = append(s.bounds, bound)

	found := map[uuid.UUID]uint64{}
	for _, id := range correlationIDs {
		if version, ok := s.existing[id]; ok {
			found[id] = version
		}
	}
	return found, nil
}

func newCloser(
	windowStore *countingWindowStore, records correlate.CorrelatedStore,
) *correlate.Closer {
	return correlate.NewCloser(
		window.New(windowStore), records,
		correlate.FixedSettings{Value: correlate.Resolved{Keys: keys.DefaultSettings()}},
		mw.NewLogger("error", "json"))
}

// fileAndClose files n events, then closes every window they opened.
func fileAndClose(
	t *testing.T, n int, windowStore *countingWindowStore, records correlate.CorrelatedStore,
) {
	t.Helper()
	fileAndCloseBatch(t, recordBatch(t, n), windowStore, records)
}

// fileAndCloseBatch runs one PARTICULAR batch through the pipeline.
//
// Exists so a test can put the SAME events through twice. recordBatch stamps its events
// at call time and a correlation id is derived from the event's window start, so two
// calls either side of a five-second boundary describe different requests entirely — and
// a test that redelivers a batch by rebuilding it silently stops testing redelivery
// whenever the clock crosses that line mid-run.
func fileAndCloseBatch(
	t *testing.T, batch []stream.Record, windowStore *countingWindowStore,
	records correlate.CorrelatedStore,
) {
	t.Helper()

	if _, err := newBatchWorker(windowStore).
		HandleBatch(context.Background(), batch); err != nil {
		t.Fatalf("HandleBatch: %v", err)
	}

	// Far enough ahead that every window's deadline has passed.
	future := time.Now().UTC().Add(time.Hour)
	if err := newCloser(windowStore, records).Tick(context.Background(), future); err != nil {
		t.Fatalf("Tick: %v", err)
	}
}

// Closing a window used to cost a full ClickHouse round trip EACH, which under the
// ingest profile's wait_for_async_insert is the entire cost of closing. A tick now
// writes its whole claim in one insert per tenant.
func TestATickWritesOneInsertPerTenant(t *testing.T) {
	windowStore := newCountingWindowStore()
	records := &countingCorrelatedStore{}

	fileAndClose(t, 100, windowStore, records)

	if records.calls != 1 {
		t.Errorf("%d inserts for 100 single-tenant windows, want 1", records.calls)
	}
	if records.records != 100 {
		t.Errorf("wrote %d correlated records, want 100", records.records)
	}
}

// A tick keeps claiming while the schedule hands back full batches. Without that, a
// backlog drains at one batch per second no matter how cheap each window became.
func TestATickDrainsMoreThanOneBatch(t *testing.T) {
	windowStore := newCountingWindowStore()
	records := &countingCorrelatedStore{}

	// Comfortably more than window.DefaultBatch, so a single-claim tick would leave
	// most of it behind.
	const windows = 900
	fileAndClose(t, windows, windowStore, records)

	if records.records != windows {
		t.Errorf("one tick emitted %d of %d closed windows; a backlog would drain at "+
			"one batch per tick", records.records, windows)
	}
}

// The pass bound has to hold, or one tenant's continuously rescheduled windows would
// hold the close loop forever and starve every other tenant.
func TestATickStopsAtThePassBound(t *testing.T) {
	windowStore := newCountingWindowStore()
	records := &countingCorrelatedStore{}

	// More windows than the bound can claim in one tick.
	total := correlate.MaxPassesPerTick*window.DefaultBatch + 500
	fileAndClose(t, total, windowStore, records)

	if records.records >= total {
		t.Errorf("one tick emitted %d of %d windows; the pass bound did not hold",
			records.records, total)
	}
	if records.records == 0 {
		t.Error("the bounded tick emitted nothing at all")
	}
}

// The version lookup is one query per close pass, not one per record. It used to be a
// ClickHouse point query on every correlated record, which is what made closing a
// window cost a round trip.
func TestVersionsIsAskedOncePerPass(t *testing.T) {
	windowStore := newCountingWindowStore()
	records := &countingCorrelatedStore{}

	fileAndClose(t, 100, windowStore, records)

	if records.versionCalls != 1 {
		t.Errorf("%d version lookups for 100 windows, want 1", records.versionCalls)
	}
}

// A record with no existing row is version 1 and not an amendment.
func TestANewRecordIsVersionOne(t *testing.T) {
	windowStore := newCountingWindowStore()
	records := &countingCorrelatedStore{}

	fileAndClose(t, 5, windowStore, records)

	if len(records.written) == 0 {
		t.Fatal("nothing was written")
	}
	for _, record := range records.written {
		if record.Version != 1 {
			t.Errorf("new record written at version %d, want 1", record.Version)
		}
		if record.Amended {
			t.Error("a first emission was marked as an amendment")
		}
	}
}

// A record that already exists is an amendment at the next version — the late-arrival
// contract (FR-018). Losing this would strand the analyst who bookmarked the id, and
// the batched version lookup is where that decision now happens.
func TestAnExistingRecordIsAmendedAtTheNextVersion(t *testing.T) {
	windowStore := newCountingWindowStore()

	// Close once to learn the ids the closer assigns. The batch is kept so the second
	// pass replays the SAME events — rebuilding it would re-stamp them at the current
	// instant, and a correlation id derives from the window that instant falls in.
	batch := recordBatch(t, 5)
	first := &countingCorrelatedStore{}
	fileAndCloseBatch(t, batch, windowStore, first)

	stored := map[uuid.UUID]uint64{}
	for _, record := range first.written {
		stored[record.CorrelationID] = 3
	}

	// Re-file the SAME events, so the same windows close again under the same ids,
	// this time against a store that already holds them at version 3.
	second := &countingCorrelatedStore{existing: stored}
	if _, err := newBatchWorker(windowStore).
		HandleBatch(context.Background(), batch); err != nil {
		t.Fatalf("HandleBatch: %v", err)
	}
	future := time.Now().UTC().Add(2 * time.Hour)
	if err := newCloser(windowStore, second).Tick(context.Background(), future); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	amended := 0
	for _, record := range second.written {
		if _, seeded := stored[record.CorrelationID]; !seeded {
			continue
		}
		amended++
		if record.Version != 4 {
			t.Errorf("amendment written at version %d, want 4", record.Version)
		}
		if !record.Amended {
			t.Error("an amendment was written without its amended flag")
		}
	}
	if amended == 0 {
		t.Fatal("no window closed under a previously seen correlation id, so the " +
			"amendment path was never exercised")
	}
}

// failingCorrelatedStore rejects every insert, so the closer's error reporting can be
// asserted rather than assumed.
type failingCorrelatedStore struct{}

func (s *failingCorrelatedStore) Insert(
	_ context.Context, _ []chdata.CorrelatedRequest,
) error {
	return errors.New("clickhouse unavailable")
}

func (s *failingCorrelatedStore) Versions(
	_ context.Context, _ []uuid.UUID, _ chdata.PartitionBound,
) (map[uuid.UUID]uint64, error) {
	return map[uuid.UUID]uint64{}, nil
}

func (s *failingCorrelatedStore) ByIDs(
	_ context.Context, _ []uuid.UUID, _ chdata.PartitionBound,
) (map[uuid.UUID]chdata.CorrelatedRequest, error) {
	return map[uuid.UUID]chdata.CorrelatedRequest{}, nil
}
