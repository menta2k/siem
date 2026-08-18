package clickhouse_test

import (
	"testing"
	"time"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
)

// The status rules are the whole watchdog. They decide, from counters alone, whether
// somebody has to be told — so they are asserted against the shapes the two production
// incidents actually had, not against invented ones.
func TestCorrelationStatus(t *testing.T) {
	const ttl = 19 * time.Minute

	tests := []struct {
		name   string
		health chdata.CorrelationHealth
		want   chdata.CorrelationStatus
	}{{
		// 2026-08-18. The closer had fallen an hour behind, so the windows it claimed
		// had outlived their member state: 1.7 million dropped against 70 records a
		// minute. The console showed the records from before the fall and looked fine.
		name: "every window closing empty is data loss in progress",
		health: chdata.CorrelationHealth{
			EventsFiled: 172_000, WindowsClosed: 900, WindowsDroppedEmpty: 1_701_942,
			RecordsEmitted: 900, ClaimLag: 90 * time.Minute, WindowTTL: ttl,
		},
		want: chdata.CorrelationLosing,
	}, {
		// 8c32245. correlatedColumns gained a column the scan did not, so every close
		// pass returned an error and nothing was written at all.
		name: "close passes erroring with no output is a failing closer",
		health: chdata.CorrelationHealth{
			EventsFiled: 50_000, CloseFailures: 6, RecordsEmitted: 0, WindowTTL: ttl,
		},
		want: chdata.CorrelationFailing,
	}, {
		name: "events in and nothing out is a stall, whatever the cause",
		health: chdata.CorrelationHealth{
			EventsFiled: 50_000, WindowsClosed: 1_000, RecordsEmitted: 0, WindowTTL: ttl,
		},
		want: chdata.CorrelationStalled,
	}, {
		// The warning the second incident never got to give: still emitting, but the
		// claim lag has eaten half the margin before windows start expiring.
		name: "lag past half the TTL with a real backlog is the warning before the loss",
		health: chdata.CorrelationHealth{
			EventsFiled: 172_000, WindowsClosed: 40_000, RecordsEmitted: 40_000,
			WindowsDue: 315_000, ClaimLag: 12 * time.Minute, WindowTTL: ttl,
		},
		want: chdata.CorrelationBehind,
	}, {
		// MEASURED ON PRODUCTION, from the first health rows this table ever held: a
		// claim lag of 4.2 hours with 23 windows waiting and nothing dropped. The
		// closer was entirely caught up — a feed delivering hours-late events had put
		// an entry at the head of the schedule that was overdue the moment it was
		// written. Reported as behind, this would have been on every screen forever,
		// and a warning that is always on is one nobody reads.
		name: "a stale schedule head with nothing behind it is not a slow closer",
		health: chdata.CorrelationHealth{
			EventsFiled: 41_886, WindowsClosed: 18_579, RecordsEmitted: 21_908,
			WindowsDue: 23, ClaimLag: 4*time.Hour + 9*time.Minute, WindowTTL: ttl,
		},
		want: chdata.CorrelationHealthy,
	}, {
		// A tenant that filed nothing has a pipeline that did nothing wrong. Calling
		// that healthy would be a claim the data does not support; calling it stalled
		// would train an operator to ignore the word.
		name:   "nothing filed is idle, not healthy and not broken",
		health: chdata.CorrelationHealth{WindowTTL: ttl},
		want:   chdata.CorrelationIdle,
	}, {
		// Late arrivals happen continuously at a low rate on a busy tenant and are not
		// a fault: the events arrived past the lateness bound the tenant configured.
		name: "a trickle of expired windows is normal, not lossy",
		health: chdata.CorrelationHealth{
			EventsFiled: 172_000, WindowsClosed: 40_000, WindowsDroppedEmpty: 300,
			RecordsEmitted: 40_000, ClaimLag: time.Minute, WindowTTL: ttl,
		},
		want: chdata.CorrelationHealthy,
	}, {
		// A close pass can fail and be retried on the next one. What makes failures an
		// emergency is output having stopped with them.
		name: "a failure that did not stop the output is not a failing closer",
		health: chdata.CorrelationHealth{
			EventsFiled: 172_000, WindowsClosed: 40_000, RecordsEmitted: 40_000,
			CloseFailures: 1, ClaimLag: time.Minute, WindowTTL: ttl,
		},
		want: chdata.CorrelationHealthy,
	}, {
		// Before the closer has reported a TTL there is nothing to compare a lag
		// against, and guessing one would report a healthy pipeline as behind on every
		// deployment whose settings differ from the guess.
		name: "an unknown TTL is not judged behind",
		health: chdata.CorrelationHealth{
			EventsFiled: 100, WindowsClosed: 10, RecordsEmitted: 10,
			ClaimLag: 9 * time.Hour,
		},
		want: chdata.CorrelationHealthy,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.health.Status(); got != tc.want {
				t.Errorf("Status() = %q, want %q", got, tc.want)
			}
		})
	}
}
