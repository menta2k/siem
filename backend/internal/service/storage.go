package service

import (
	"time"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
)

// Projection is the disk-headroom answer: how fast the platform is growing and how long
// the remaining space lasts at that rate.
type Projection struct {
	BytesPerDay   uint64
	MeasuredDays  int
	DaysRemaining float64
	// Steady is true when no growth could be measured, so there is no date at which the
	// disk fills. Reported as its own flag rather than as "0 days remaining", which
	// would read as the opposite of what it means.
	Steady bool
}

// project computes the headroom from what is on disk.
//
// TODAY IS EXCLUDED. Its partition is still being written, so counting it averages a
// part-day against whole ones and understates the rate — on a panel whose entire purpose
// is warning early, an estimate that is optimistic by construction is worse than none.
//
// Growth is the MEAN of the whole days present, not the difference between the first and
// last. Differencing would read a retention expiry as a fall in traffic and project that
// the disk is emptying.
//
// The number this produces is deliberately a SIMPLE extrapolation: bytes per day against
// bytes free. It does not model retention, and it cannot — TTLs are per tenant and expiry
// runs on ClickHouse's own merge schedule, so any attempt would be a guess dressed as
// arithmetic. Once the oldest data reaches its TTL, expiry starts offsetting ingestion
// and the real figure becomes larger than this one. The panel says so in as many words:
// an operator who knows the estimate is conservative can act on it, while one who is
// told a modelled number they cannot verify cannot.
func project(storage chdata.Storage, now time.Time) Projection {
	whole := wholeDays(storage.Daily, now)
	if len(whole) == 0 {
		return Projection{Steady: true}
	}

	var total uint64
	for _, day := range whole {
		total += day.Bytes
	}
	perDay := total / uint64(len(whole))

	projection := Projection{BytesPerDay: perDay, MeasuredDays: len(whole)}
	if perDay == 0 {
		projection.Steady = true
		return projection
	}

	projection.DaysRemaining = float64(storage.DiskFreeBytes) / float64(perDay)
	return projection
}

// wholeDays returns the days whose partitions are no longer being written to.
func wholeDays(daily []chdata.DayBytes, now time.Time) []chdata.DayBytes {
	today := now.UTC().Truncate(24 * time.Hour)

	whole := make([]chdata.DayBytes, 0, len(daily))
	for _, day := range daily {
		// Today is still open. A partition dated ahead of the clock is skipped by the
		// same test: it is not a whole day either, and it happens when a vendor's
		// timestamps run fast.
		if day.Day.UTC().Before(today) {
			whole = append(whole, day)
		}
	}
	return whole
}
