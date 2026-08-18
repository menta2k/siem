package correlate_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/correlate"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
)

// chunkRecordingStore records the size of each version lookup so the query bound can be
// asserted rather than assumed.
type chunkRecordingStore struct {
	countingCorrelatedStore
	lookupSizes []int
}

func (s *chunkRecordingStore) Versions(
	ctx context.Context, correlationIDs []uuid.UUID, bound chdata.PartitionBound,
) (map[uuid.UUID]uint64, error) {
	s.lookupSizes = append(s.lookupSizes, len(correlationIDs))
	return s.countingCorrelatedStore.Versions(ctx, correlationIDs, bound)
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

	// Built ONCE and replayed below. A correlation id is derived from the event's window
	// start, and recordBatch stamps its events at call time, so rebuilding the batch for
	// the second pass produces different ids whenever the two calls fall either side of
	// a five-second window boundary. This test files 2,500 windows and closes them
	// first, which takes long enough that crossing one is a coin flip: on CI it failed
	// with "no seeded record closed again" roughly half the time, reporting a broken
	// amendment path when nothing was broken but the clock.
	batch := recordBatch(t, windows)
	fileAndCloseBatch(t, batch, windowStore, first)

	stored := map[uuid.UUID]uint64{}
	for _, record := range first.written {
		stored[record.CorrelationID] = 5
	}
	if len(stored) < correlate.VersionLookupChunk {
		t.Skipf("only %d distinct records, too few to span a chunk", len(stored))
	}

	second := &countingCorrelatedStore{existing: stored}
	// The SAME events again, as a redelivery would present them.
	if _, err := newBatchWorker(windowStore).
		HandleBatch(context.Background(), batch); err != nil {
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

// The version lookup must name the partitions it is looking in.
//
// THE PRODUCTION FAILURE THIS FIXES. correlated_requests is partitioned by
// toDate(window_start) and ordered by (tenant_id, toDate(window_start), correlation_id),
// so a lookup that names no date prunes nothing: correlation_id is the third key column
// and the second is missing. Measured on production, the closer's version lookup
// averaged 964ms across 68 million rows and spent 246 seconds of every 600 there — more
// than the inserts, the record loads and everything else in a close pass combined. The
// closer could not keep up with the rate windows were being filed, and a closer that
// cannot keep up eventually falls past the window TTL, where every window it closes is
// empty and correlation stops entirely.
//
// The range has to COVER the records being written, though, or an amendment silently
// becomes a second first-emission. It is derived from their own window starts, widened
// by the lateness bound — how far a record's window start can move between emissions —
// and a day of slack for feeds that deliver events hours late.
func TestTheLookupsAreBoundedToTheRecordsOwnPartitions(t *testing.T) {
	windowStore := newCountingWindowStore()
	records := &countingCorrelatedStore{}

	fileAndClose(t, 10, windowStore, records)

	if len(records.bounds) == 0 {
		t.Fatal("no lookup was made, so nothing was asserted")
	}

	written := records.written[0].WindowStart
	for _, bound := range records.bounds {
		if !bound.From.Before(written) || !bound.To.After(written) {
			t.Errorf("bound [%s, %s] does not cover a record written at %s — an "+
				"amendment inside it would be read as a record that does not exist",
				bound.From, bound.To, written)
		}
		// Wide enough to cover, narrow enough to prune: anything approaching the
		// ninety-day retention would leave the scan exactly where it was.
		if span := bound.To.Sub(bound.From); span > 7*24*time.Hour {
			t.Errorf("bound spans %s, which prunes almost nothing off a 90-day table",
				span)
		}
	}
}
