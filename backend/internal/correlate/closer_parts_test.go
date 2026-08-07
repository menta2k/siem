package correlate_test

import (
	"context"
	"testing"
	"time"

	"github.com/menta2k/siem/internal/correlate"
	"github.com/menta2k/siem/internal/correlate/window"
)

// THE BUG THIS FIXES. Every insert into correlated_requests becomes a ClickHouse PART,
// and every part is then merged — repeatedly, because AggregatingMergeTree and
// ReplacingMergeTree rewrite parts until they are large. Measured on production, the
// closer produced 3,859 parts per hour at 58 rows each, and the disagreement rollup's
// materialized view turned every one of those into a part holding a SINGLE row.
//
// ClickHouse wants inserts in the thousands of rows. Insert size is therefore not a
// tuning detail here — it sets the merge load for two tables, and merge load was the
// single largest CPU consumer in the database.
//
// A tick already claimed many passes worth of windows, but inserted once PER PASS, so
// raising the poll interval alone would only have produced more passes of the same small
// size. The write has to happen once per tick.
func TestATickWritesOnceEvenAcrossManyPasses(t *testing.T) {
	windowStore := newCountingWindowStore()
	records := &countingCorrelatedStore{}

	// Several times the per-pass claim, so the tick is forced through multiple passes.
	const windows = window.DefaultBatch * 4
	fileAndClose(t, windows, windowStore, records)

	if records.records != windows {
		t.Fatalf("emitted %d of %d windows", records.records, windows)
	}
	if records.calls != 1 {
		t.Errorf("%d inserts for %d windows across %d passes, want 1 — each insert is a "+
			"ClickHouse part, and a part is merged repeatedly",
			records.calls, windows, windows/window.DefaultBatch)
	}
}

// The whole point is the SIZE of the resulting insert. A tick that writes once but is
// woken so often that it finds only a handful of closed windows produces the same tiny
// parts by a different route.
func TestTheInsertCarriesEnoughRowsToBeWorthAPart(t *testing.T) {
	windowStore := newCountingWindowStore()
	records := &countingCorrelatedStore{}

	const windows = 2000
	fileAndClose(t, windows, windowStore, records)

	if records.calls == 0 {
		t.Fatal("nothing was written")
	}
	// ClickHouse's own guidance is at least ~1,000 rows per insert. Below that the part
	// costs more to merge than it carries.
	if rows := records.records / records.calls; rows < 1000 {
		t.Errorf("averaged %d rows per insert, want >= 1000", rows)
	}
}

// The poll interval decides how many closed windows a tick finds. At one second the
// closer inserted roughly once a second whatever the volume, which is what produced
// 58-row parts. It must be long enough to accumulate a worthwhile batch.
//
// This is a latency trade and a cheap one: a window is emitted only after its deadline
// has already passed, so this delay is added to a wait already measured in minutes.
func TestThePollIntervalBatchesRatherThanPollingEverySecond(t *testing.T) {
	if correlate.DefaultPollInterval < 5*time.Second {
		t.Errorf("poll interval is %s, too short to accumulate a batch worth a part",
			correlate.DefaultPollInterval)
	}
	// An upper bound too: the interval is also the worst-case delay before a closed
	// window becomes visible, and an analyst watching live traffic notices minutes.
	if correlate.DefaultPollInterval > 30*time.Second {
		t.Errorf("poll interval is %s, long enough to be visible as staleness",
			correlate.DefaultPollInterval)
	}
}

// Failure isolation must survive the batching change. Windows are claimed off the
// schedule before the insert, so a failed write is reported and the tick moves on —
// batching more per write widens what one failure drops, and that must stay visible
// rather than silent.
func TestAFailedInsertIsReported(t *testing.T) {
	windowStore := newCountingWindowStore()
	records := &failingCorrelatedStore{}

	if _, err := newBatchWorker(windowStore).
		HandleBatch(context.Background(), recordBatch(t, 10)); err != nil {
		t.Fatalf("HandleBatch: %v", err)
	}

	future := time.Now().UTC().Add(time.Hour)
	err := newCloser(windowStore, records).Tick(context.Background(), future)
	if err == nil {
		t.Error("a failed insert was not reported, so the loss would be silent")
	}
}
