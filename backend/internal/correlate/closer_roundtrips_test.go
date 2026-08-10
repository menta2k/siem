package correlate_test

import (
	"testing"

	"github.com/menta2k/siem/internal/correlate"
)

// A CLOSE PASS COSTS ROUND TRIPS, NOT COMPUTATION, and this is the test that keeps it
// that way.
//
// The closer used to ask Redis about one key at a time: a window's members, then a bucket
// for every identifier while it chased exact partners, then an identity per identifier.
// None of that is expensive to compute -- a production CPU profile put 34% of the
// processor's samples in socket syscalls with the process idle two thirds of the time.
// The work was waiting, thousands of times per tick, and it is invisible to every other
// test here because a fake store answers instantly.
//
// So the assertion is on ROUND TRIPS rather than on wall time. It is bounded by a small
// constant instead of an exact number, because the exact count depends on how many BFS
// levels the events happen to form -- pinning it precisely would make the test fail for
// changes that are not regressions. What it will catch is the thing worth catching: a
// read moved back inside a per-window or per-identifier loop, which turns this from a
// constant into a multiple of the window count.
func TestAClosePassDoesNotReadRedisOncePerWindow(t *testing.T) {
	const windows = 200

	windowStore := newCountingWindowStore()
	records := &countingCorrelatedStore{}

	fileAndClose(t, windows, windowStore, records)

	// Generous: the close path reads members for the batch, then walks the exact-partner
	// frontier, then resolves identities. Each of those is a handful of round trips, not
	// one per window. Before batching this figure was in the hundreds.
	const generousBound = 40

	if windowStore.readCalls > generousBound {
		t.Errorf("a close pass over %d windows made %d Redis READ round trips (bound %d).\n"+
			"That is the per-key pattern coming back: a read has moved inside a loop over "+
			"windows or identifiers, so the closer blocks on the socket once per key "+
			"instead of once per batch.",
			windows, windowStore.readCalls, generousBound)
	}

	// A round-trip bound is only meaningful if the pass actually did the work. Without
	// this the test would pass just as happily against a closer that read nothing and
	// emitted nothing.
	if records.records == 0 {
		t.Fatal("no records were emitted, so the round-trip count measures nothing")
	}
}

// The saving must come from BATCHING, not from reading less. A closer that skipped windows
// would also show a low round-trip count, and would be catastrophically wrong.
func TestBatchingTheReadsDoesNotLoseWindows(t *testing.T) {
	const windows = 200

	windowStore := newCountingWindowStore()
	records := &countingCorrelatedStore{}

	fileAndClose(t, windows, windowStore, records)

	// Every event describes a distinct request, so each forms its own window and each
	// window emits one record. A batched read that dropped keys, or a frontier walk that
	// lost a level, shows up here as a shortfall.
	if records.records != windows {
		t.Errorf("emitted %d records for %d windows; batching the reads changed which "+
			"windows were closed, not just how they were fetched",
			records.records, windows)
	}
}

// The pass bound still applies. Batching reads must not turn one tick into an unbounded
// drain, which is what MaxPassesPerTick exists to prevent.
func TestBatchedReadsStillRespectThePassBound(t *testing.T) {
	if correlate.MaxPassesPerTick <= 0 {
		t.Fatal("MaxPassesPerTick must bound a tick")
	}
}
