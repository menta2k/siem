package correlate_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/correlate"
)

// chunkRecordingStore records the size of each version lookup so the query bound can be
// asserted rather than assumed.
type chunkRecordingStore struct {
	countingCorrelatedStore
	lookupSizes []int
}

func (s *chunkRecordingStore) Versions(
	ctx context.Context, correlationIDs []uuid.UUID,
) (map[uuid.UUID]uint64, error) {
	s.lookupSizes = append(s.lookupSizes, len(correlationIDs))
	return s.countingCorrelatedStore.Versions(ctx, correlationIDs)
}

// THE PRODUCTION FAILURE THIS FIXES. Batching the closer's writes was right — it took the
// part rate from 1/s to 0.1/s — but it also made one tick gather up to
// MaxPassesPerTick*DefaultBatch records, and the version lookup turned all of them into a
// single IN list. Past roughly 7,000 ids that exceeds ClickHouse's 256 KB max_query_size,
// the whole close pass fails, and correlated output collapses: measured on production at
// 5,218 records/minute falling to 137 before this was chunked.
//
// The insert stays whole — one part is the entire point of batching. Only the READ is
// split, because that is the side with a query-size limit.
func TestTheVersionLookupIsChunked(t *testing.T) {
	windowStore := newCountingWindowStore()
	records := &chunkRecordingStore{}

	// Comfortably more than one chunk, so the split is exercised.
	const windows = correlate.VersionLookupChunk * 3
	fileAndClose(t, windows, windowStore, records)

	if len(records.lookupSizes) < 3 {
		t.Errorf("%d version lookups for %d records, want at least 3 — an unbounded IN "+
			"list is what exceeded max_query_size in production",
			len(records.lookupSizes), windows)
	}
	for i, size := range records.lookupSizes {
		if size > correlate.VersionLookupChunk {
			t.Errorf("lookup %d asked for %d ids, over the %d bound",
				i, size, correlate.VersionLookupChunk)
		}
	}
}

// Chunking must not lose an amendment. A record whose id lands in the second chunk still
// has to be recognised as existing, or the late-arrival contract breaks for most of a
// batch and every amendment is rewritten as a brand new version 1.
func TestAmendmentsSurviveChunking(t *testing.T) {
	windowStore := newCountingWindowStore()

	first := &countingCorrelatedStore{}
	// More than one chunk, so an amendment necessarily lands in a later batch.
	const windows = correlate.VersionLookupChunk*2 + 500
	fileAndClose(t, windows, windowStore, first)

	stored := map[uuid.UUID]uint64{}
	for _, record := range first.written {
		stored[record.CorrelationID] = 5
	}
	if len(stored) < correlate.VersionLookupChunk {
		t.Skipf("only %d distinct records, too few to span a chunk", len(stored))
	}

	second := &countingCorrelatedStore{existing: stored}
	if _, err := newBatchWorker(windowStore).
		HandleBatch(context.Background(), recordBatch(t, windows)); err != nil {
		t.Fatalf("HandleBatch: %v", err)
	}
	if err := newCloser(windowStore, second).
		Tick(context.Background(), time.Now().UTC().Add(2*time.Hour)); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	amended := 0
	for _, record := range second.written {
		if _, seeded := stored[record.CorrelationID]; !seeded {
			continue
		}
		if record.Version != 6 || !record.Amended {
			t.Errorf("record %s written at version %d amended=%v, want 6 and true — "+
				"a chunked lookup lost an existing record",
				record.CorrelationID, record.Version, record.Amended)
		}
		amended++
	}
	if amended == 0 {
		t.Fatal("no seeded record closed again, so chunking was never exercised")
	}
}

// The write stays a single insert regardless of how many chunks the read took. Splitting
// it too would undo the part-rate fix that motivated the batching in the first place.
func TestTheInsertIsNotChunkedWithTheLookup(t *testing.T) {
	windowStore := newCountingWindowStore()
	records := &chunkRecordingStore{}

	fileAndClose(t, correlate.VersionLookupChunk*3, windowStore, records)

	if records.calls != 1 {
		t.Errorf("%d inserts, want 1 — chunking the read must not chunk the write",
			records.calls)
	}
}
