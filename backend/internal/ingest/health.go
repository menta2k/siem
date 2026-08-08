package ingest

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Feed-health thresholds.
const (
	// flushInterval is how often accumulated counters are written.
	//
	// Per-delivery writes would put one ClickHouse insert on the hot path of every
	// vendor request, which at 15k events/sec is exactly the merge-storm pattern the
	// schema is designed to avoid. One write per feed per minute is enough for the
	// resolution a health view needs.
	flushInterval = time.Minute

	// silenceThreshold is how long a feed may report nothing before it is called
	// silent. Detecting this matters because a dead feed looks identical to clean
	// traffic on a dashboard — the absence of events is not visible on its own.
	silenceThreshold = 15 * time.Minute
)

// HealthSample is one delivery's contribution to a feed's health.
type HealthSample struct {
	TenantID       uuid.UUID
	FeedID         uuid.UUID
	EventsReceived int
	EventsRejected int
	// EventsFiltered counts events excluded by the tenant's ingest filters. A filtered
	// event leaves no other trace anywhere, so this counter is the only evidence that a
	// rule is doing something — and the only warning when it is doing too much.
	EventsFiltered       int
	DuplicatesSuppressed int
	BytesReceived        int64
	UnknownFieldEvents   int
	IngestLagMS          uint32
	CredentialValid      bool
}

// HealthStore persists accumulated health counters.
type HealthStore interface {
	InsertFeedHealth(ctx context.Context, rows []FeedHealthRow) error
}

// FeedHealthRow is one minute of a feed's activity.
type FeedHealthRow struct {
	TenantID             uuid.UUID
	FeedID               uuid.UUID
	Minute               time.Time
	EventsReceived       uint64
	EventsRejected       uint64
	EventsFiltered       uint64
	DuplicatesSuppressed uint64
	BytesReceived        uint64
	MaxIngestLagMS       uint32
	UnknownFieldEvents   uint64
	CredentialValid      bool
}

// HealthAggregator batches per-delivery samples into per-minute rows.
type HealthAggregator struct {
	mu      sync.Mutex
	buckets map[bucketKey]*FeedHealthRow
	store   HealthStore
	now     func() time.Time
}

type bucketKey struct {
	tenantID uuid.UUID
	feedID   uuid.UUID
	minute   int64
}

// NewHealthAggregator constructs an aggregator.
func NewHealthAggregator(store HealthStore) *HealthAggregator {
	return &HealthAggregator{
		buckets: map[bucketKey]*FeedHealthRow{},
		store:   store,
		now:     time.Now,
	}
}

// Record accumulates one sample. It never blocks on I/O: the ingest hot path must not
// wait on a health write.
func (a *HealthAggregator) Record(_ context.Context, sample HealthSample) {
	minute := a.now().UTC().Truncate(time.Minute)
	key := bucketKey{sample.TenantID, sample.FeedID, minute.Unix()}

	a.mu.Lock()
	defer a.mu.Unlock()

	row, ok := a.buckets[key]
	if !ok {
		row = &FeedHealthRow{
			TenantID: sample.TenantID, FeedID: sample.FeedID, Minute: minute,
			// Starts valid and is cleared by any failure in the minute, so one bad
			// credential is visible even among successful deliveries.
			CredentialValid: true,
		}
		a.buckets[key] = row
	}

	row.EventsReceived += uint64(max(sample.EventsReceived, 0))             //nolint:gosec // clamped
	row.EventsRejected += uint64(max(sample.EventsRejected, 0))             //nolint:gosec // clamped
	row.EventsFiltered += uint64(max(sample.EventsFiltered, 0))             //nolint:gosec // clamped
	row.DuplicatesSuppressed += uint64(max(sample.DuplicatesSuppressed, 0)) //nolint:gosec // clamped
	row.UnknownFieldEvents += uint64(max(sample.UnknownFieldEvents, 0))     //nolint:gosec // clamped
	if sample.BytesReceived > 0 {
		row.BytesReceived += uint64(sample.BytesReceived)
	}
	if sample.IngestLagMS > row.MaxIngestLagMS {
		row.MaxIngestLagMS = sample.IngestLagMS
	}
	if !sample.CredentialValid {
		row.CredentialValid = false
	}
}

// Flush writes and clears the accumulated buckets.
func (a *HealthAggregator) Flush(ctx context.Context) error {
	a.mu.Lock()
	if len(a.buckets) == 0 {
		a.mu.Unlock()
		return nil
	}
	rows := make([]FeedHealthRow, 0, len(a.buckets))
	for _, row := range a.buckets {
		rows = append(rows, *row)
	}
	a.buckets = map[bucketKey]*FeedHealthRow{}
	a.mu.Unlock()

	return a.store.InsertFeedHealth(ctx, rows)
}

// Run flushes on an interval until ctx is cancelled, then flushes once more.
func (a *HealthAggregator) Run(ctx context.Context) error {
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// A final flush on shutdown, so the last minute of health is not lost.
			// A fresh context is used because the caller's is already cancelled.
			flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return a.Flush(flushCtx)
		case <-ticker.C:
			if err := a.Flush(ctx); err != nil {
				// Health is observability, not customer data. A failed write is
				// reported but must not stop ingestion.
				return err
			}
		}
	}
}

// Name identifies the worker.
func (a *HealthAggregator) Name() string { return "feed-health" }

// IsSilent reports whether a feed has gone quiet.
//
// This is the check that distinguishes a dead feed from genuinely clean traffic. A
// dashboard showing zero blocked requests looks the same either way, so silence has
// to be asserted rather than inferred from an empty chart.
func IsSilent(lastEventAt time.Time, now time.Time) bool {
	if lastEventAt.IsZero() {
		// A feed that has never delivered is not "silent" — it is simply new, and
		// calling it silent on creation would train operators to ignore the warning.
		return false
	}
	return now.Sub(lastEventAt) > silenceThreshold
}

// SilenceThreshold exposes the threshold for the API and the console.
func SilenceThreshold() time.Duration { return silenceThreshold }
