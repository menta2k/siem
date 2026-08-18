package correlate

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
)

// HealthFlushInterval is how often accumulated correlation counters are written.
//
// One row per tenant per minute, matching feed_health. The closer ticks continuously
// while it is behind, so writing per tick would put a ClickHouse insert on the path of
// the very loop whose slowness is being measured.
const HealthFlushInterval = time.Minute

// HealthSample is one close pass's contribution to the pipeline's health.
//
// Counts, not rates: the reader divides by the minute. Lag and backlog are the
// exception — they are levels rather than totals, so the highest reading in the minute
// is what is kept.
type HealthSample struct {
	TenantID uuid.UUID
	// EventsFiled is the denominator that makes the rest mean anything: no records
	// emitted is healthy when nothing was filed and an outage when thousands were.
	EventsFiled    int
	WindowsClosed  int
	RecordsEmitted int
	WindowsDropped int
	CloseFailures  int
	WindowsDue     uint64
	ClaimLag       time.Duration
	WindowTTL      time.Duration
}

// HealthStore persists accumulated correlation counters.
type HealthStore interface {
	InsertCorrelationHealth(ctx context.Context, rows []chdata.CorrelationHealthRow) error
}

// HealthAggregator batches per-pass samples into per-minute rows.
//
// WHY THIS EXISTS. Correlation has stopped on production twice without anything saying
// so — once because every close pass was failing, once because the closer had fallen
// past the window TTL and was closing empty windows. Both times the console kept
// serving the records written before the fall, because the API reads stored records and
// a stored record cannot know that no new ones are arriving. This is the row that knows.
type HealthAggregator struct {
	mu      sync.Mutex
	buckets map[bucketKey]*chdata.CorrelationHealthRow
	store   HealthStore
	now     func() time.Time
}

type bucketKey struct {
	tenantID uuid.UUID
	minute   int64
}

// NewHealthAggregator constructs an aggregator.
func NewHealthAggregator(store HealthStore) *HealthAggregator {
	return &HealthAggregator{
		buckets: map[bucketKey]*chdata.CorrelationHealthRow{},
		store:   store,
		now:     time.Now,
	}
}

// Record accumulates one sample. It never blocks on I/O: the closer must not wait on a
// health write to close the next window.
func (a *HealthAggregator) Record(sample HealthSample) {
	minute := a.now().UTC().Truncate(time.Minute)
	key := bucketKey{sample.TenantID, minute.Unix()}

	a.mu.Lock()
	defer a.mu.Unlock()

	row, ok := a.buckets[key]
	if !ok {
		row = &chdata.CorrelationHealthRow{TenantID: sample.TenantID, Minute: minute}
		a.buckets[key] = row
	}

	row.EventsFiled += uint64(max(sample.EventsFiled, 0))            //nolint:gosec // clamped
	row.WindowsClosed += uint64(max(sample.WindowsClosed, 0))        //nolint:gosec // clamped
	row.RecordsEmitted += uint64(max(sample.RecordsEmitted, 0))      //nolint:gosec // clamped
	row.WindowsDroppedEmpty += uint64(max(sample.WindowsDropped, 0)) //nolint:gosec // clamped
	row.CloseFailures += uint64(max(sample.CloseFailures, 0))        //nolint:gosec // clamped

	row.WindowsDue = max(row.WindowsDue, sample.WindowsDue)
	row.MaxClaimLagMS = max(row.MaxClaimLagMS, millis(sample.ClaimLag))
	row.WindowTTLMS = max(row.WindowTTLMS, millis(sample.WindowTTL))
}

// millis clamps a duration to whole non-negative milliseconds.
func millis(d time.Duration) uint64 {
	if d <= 0 {
		return 0
	}
	return uint64(d.Milliseconds()) //nolint:gosec // non-negative by the guard above
}

// Flush writes and clears the accumulated buckets.
func (a *HealthAggregator) Flush(ctx context.Context) error {
	a.mu.Lock()
	if len(a.buckets) == 0 {
		a.mu.Unlock()
		return nil
	}
	rows := make([]chdata.CorrelationHealthRow, 0, len(a.buckets))
	for _, row := range a.buckets {
		rows = append(rows, *row)
	}
	a.buckets = map[bucketKey]*chdata.CorrelationHealthRow{}
	a.mu.Unlock()

	return a.store.InsertCorrelationHealth(ctx, rows)
}

// Run flushes on an interval until ctx is cancelled, then flushes once more.
func (a *HealthAggregator) Run(ctx context.Context) error {
	ticker := time.NewTicker(HealthFlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// A final flush on shutdown, so the minute in which a processor was
			// restarted — often the most interesting one — is not the missing one.
			flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return a.Flush(flushCtx)
		case <-ticker.C:
			if err := a.Flush(ctx); err != nil {
				return err
			}
		}
	}
}

// Name identifies the worker.
func (a *HealthAggregator) Name() string { return "correlation-health" }
