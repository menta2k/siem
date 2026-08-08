package puller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/ingest"
	"github.com/menta2k/siem/internal/ingest/dedup"
	"github.com/menta2k/siem/internal/ingest/filter"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/normalize"
	"github.com/menta2k/siem/internal/tenancy"
	"github.com/menta2k/siem/internal/vendors"
)

// FeedStore lists and updates pull feeds.
type FeedStore interface {
	ListPullFeeds(ctx context.Context) ([]chdata.Feed, error)
	SetWatermark(ctx context.Context, feedID uuid.UUID, watermark string) error
}

// Publisher durably commits fetched events.
type Publisher interface {
	PublishBatch(ctx context.Context, envelopes []ingest.Envelope) error
}

// HealthRecorder receives per-poll health.
type HealthRecorder interface {
	Record(ctx context.Context, sample ingest.HealthSample)
}

// Worker polls every enabled pull feed on its own interval.
type Worker struct {
	feeds     FeedStore
	sources   *Registry
	adapters  *vendors.Registry
	publisher Publisher
	deduper   *dedup.Deduper
	secrets   SecretResolver
	filters   *filter.Cache
	health    HealthRecorder
	log       mw.Logger

	// lastPolled tracks per-feed timing so feeds with different intervals are not
	// forced onto a common schedule.
	lastPolled map[uuid.UUID]time.Time
	now        func() time.Time
}

// NewWorker constructs the pull worker.
func NewWorker(
	feeds FeedStore, sources *Registry, adapters *vendors.Registry,
	publisher Publisher, deduper *dedup.Deduper, secretStore SecretResolver,
	filters *filter.Cache, health HealthRecorder, log mw.Logger,
) *Worker {
	return &Worker{
		feeds: feeds, sources: sources, adapters: adapters,
		publisher: publisher, deduper: deduper, secrets: secretStore,
		filters: filters, health: health, log: log,
		lastPolled: map[uuid.UUID]time.Time{},
		now:        time.Now,
	}
}

// Name identifies the worker in logs and metrics.
func (w *Worker) Name() string { return "puller" }

// tickInterval is how often the worker re-examines which feeds are due. It is finer
// than any feed's poll interval so a 30-second feed is not delayed by the loop itself.
const tickInterval = 10 * time.Second

// Run polls due feeds until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) error {
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := w.PollDue(ctx); err != nil {
				// One feed's failure must not stop the loop: the others are still
				// delivering, and a vendor outage is not a reason to stop polling
				// everyone else.
				w.log.Error(ctx, "pull cycle failed", "cause", err.Error())
			}
		}
	}
}

// PollDue polls every feed whose interval has elapsed.
func (w *Worker) PollDue(ctx context.Context) error {
	feeds, err := w.feeds.ListPullFeeds(ctx)
	if err != nil {
		return fmt.Errorf("list pull feeds: %w", err)
	}

	var errs []error
	for _, feed := range feeds {
		if !w.due(feed) {
			continue
		}
		w.lastPolled[feed.ID] = w.now()

		if err := w.pollFeed(ctx, feed); err != nil {
			errs = append(errs, fmt.Errorf("feed %s: %w", feed.ID, err))
		}
	}
	return errors.Join(errs...)
}

func (w *Worker) due(feed chdata.Feed) bool {
	cfg, err := ParseConfig(feed.PullConfig)
	if err != nil {
		// A feed with unusable configuration is polled on the default interval so its
		// failure keeps surfacing in health rather than going quiet after one attempt.
		return w.now().Sub(w.lastPolled[feed.ID]) >= DefaultInterval
	}
	return w.now().Sub(w.lastPolled[feed.ID]) >= cfg.Interval()
}

// pollFeed fetches and commits one feed's outstanding batches.
//
// THE ordering rule: each batch is durably committed BEFORE its watermark is
// persisted. A crash in between replays the batch, which deduplication absorbs.
// The reverse order would lose it.
func (w *Worker) pollFeed(ctx context.Context, feed chdata.Feed) error {
	ctx = tenancy.WithTenant(ctx, tenancy.Tenant{ID: feed.TenantID})

	cfg, err := ParseConfig(feed.PullConfig)
	if err != nil {
		w.recordFailure(ctx, feed)
		return err
	}

	source, ok := w.sources.Get(feed.Vendor)
	if !ok {
		w.recordFailure(ctx, feed)
		return fmt.Errorf("no pull source for vendor %q", feed.Vendor)
	}

	adapter, err := w.adapters.Get(feed.Vendor)
	if err != nil {
		w.recordFailure(ctx, feed)
		return err
	}

	// The credential is resolved per poll and travels in the fetch context, never in
	// the stored configuration — so it cannot be accidentally serialized into a feed
	// row or echoed by the API.
	if w.secrets != nil {
		credential, err := w.secrets.Resolve(ctx, feed.CredentialRef)
		if err != nil {
			w.recordFailure(ctx, feed)
			return fmt.Errorf("resolve credential for feed %s: %w", feed.ID, err)
		}
		ctx = WithCredential(ctx, credential)
	}

	// Fetch may return BOTH batches and an error when paging fails part-way. Whatever
	// arrived is committed first — discarding it would re-fetch the same data on every
	// poll while the vendor stays unhealthy — and the error is reported afterwards.
	batches, fetchErr := source.Fetch(ctx, cfg, feed.PullWatermark)
	if fetchErr != nil {
		// Usually an expired credential or a vendor outage; both need to reach feed
		// health rather than only a log.
		w.recordFailure(ctx, feed)
	}

	if len(batches) > cfg.MaxBatches() {
		// A large backlog is drained across several polls rather than in one
		// unbounded fetch. The remainder is picked up next cycle from the watermark.
		w.log.Info(ctx, "pull backlog exceeds the per-poll cap, draining gradually",
			"feed_id", feed.ID.String(), "available", len(batches), "cap", cfg.MaxBatches())
		batches = batches[:cfg.MaxBatches()]
	}

	for _, batch := range batches {
		if err := w.commitBatch(ctx, feed, adapter, batch); err != nil {
			// Stop at the first failure: continuing would commit a later batch while
			// the watermark still points before this one, and the next poll would
			// then re-fetch and re-commit everything in between.
			return errors.Join(fetchErr, err)
		}
	}

	if fetchErr != nil {
		return fmt.Errorf("fetch from %s: %w", feed.Vendor, fetchErr)
	}
	return nil
}

// commitBatch publishes one batch and only then advances the watermark.
func (w *Worker) commitBatch(
	ctx context.Context, feed chdata.Feed, adapter vendors.Adapter, batch Batch,
) error {
	format, recognized := adapter.Detect(batch.Payload)
	if !recognized {
		// An unreadable object must not stall the feed forever. The watermark advances
		// past it and the failure is counted, so the backlog keeps draining.
		w.log.Warn(ctx, "unrecognized pull payload, skipping",
			"feed_id", feed.ID.String(), "batch", batch.Label)
		return w.advance(ctx, feed, batch)
	}

	records, err := adapter.Parse(batch.Payload, format)
	if err != nil {
		w.log.Warn(ctx, "unparseable pull payload, skipping",
			"feed_id", feed.ID.String(), "batch", batch.Label, "cause", err.Error())
		return w.advance(ctx, feed, batch)
	}

	receivedAt := w.now().UTC()
	envelopes, rejections, filtered := ingest.BuildEnvelopes(adapter, records, ingest.EnvelopeMeta{
		TenantID: feed.TenantID, FeedID: feed.ID,
		BatchID: normalize.BatchID(), ReceivedAt: receivedAt,
		IdentityFor: func(vendor, vendorRequestID string, raw []byte) string {
			return normalize.EventIDFor(feed.ID, vendor, vendorRequestID, raw)
		},
		Filters: w.filters.For(ctx, feed.TenantID),
	})

	accepted, duplicates := w.filter(ctx, feed, envelopes, rejections)

	if err := w.publisher.PublishBatch(ctx, accepted); err != nil {
		// The watermark is NOT advanced: the next poll re-fetches this batch.
		return fmt.Errorf("durable commit of batch %s: %w", batch.Label, err)
	}

	// Marking follows the commit, exactly as it does on the push path — marking first
	// would suppress the replay after a failure and lose the batch.
	if err := w.deduper.Mark(ctx, feed.TenantID.String(), eventIDsOf(accepted)); err != nil {
		w.log.Warn(ctx, "could not record dedup markers", "cause", err.Error())
	}

	w.health.Record(ctx, ingest.HealthSample{
		TenantID: feed.TenantID, FeedID: feed.ID,
		EventsReceived: len(accepted), EventsRejected: len(rejections),
		EventsFiltered:       filtered,
		DuplicatesSuppressed: duplicates, BytesReceived: int64(len(batch.Payload)),
		CredentialValid: true,
	})
	ingest.ObserveDelivery(feed.Vendor, feed.ID.String(), ingest.Outcome{
		Accepted: len(accepted), DuplicatesSuppressed: duplicates, Rejected: rejections,
	}, int64(len(batch.Payload)), 0)

	return w.advance(ctx, feed, batch)
}

// filter removes rejected and already-seen events. Read-only: nothing is recorded
// until the commit succeeds.
func (w *Worker) filter(
	ctx context.Context, feed chdata.Feed,
	envelopes []ingest.Envelope, rejections []ingest.Rejection,
) (accepted []ingest.Envelope, duplicates int) {
	rejected := make(map[int]bool, len(rejections))
	for _, rejection := range rejections {
		rejected[rejection.Index] = true
	}

	candidates := make([]ingest.Envelope, 0, len(envelopes))
	eventIDs := make([]string, 0, len(envelopes))
	for i, envelope := range envelopes {
		if rejected[i] {
			continue
		}
		candidates = append(candidates, envelope)
		eventIDs = append(eventIDs, envelope.EventID)
	}

	result, err := w.deduper.Filter(ctx, feed.TenantID.String(), eventIDs)
	if err != nil {
		w.log.Warn(ctx, "dedup unavailable, accepting all events", "cause", err.Error())
	}

	accepted = make([]ingest.Envelope, 0, len(result.Fresh))
	for _, idx := range result.Fresh {
		if idx >= 0 && idx < len(candidates) {
			accepted = append(accepted, candidates[idx])
		}
	}
	return accepted, result.Duplicates
}

// advance persists the watermark. A failure here is safe in the recoverable
// direction: the batch is re-fetched next poll and deduplication absorbs it.
func (w *Worker) advance(ctx context.Context, feed chdata.Feed, batch Batch) error {
	if batch.Watermark == "" {
		return nil
	}
	if err := w.feeds.SetWatermark(ctx, feed.ID, batch.Watermark); err != nil {
		return fmt.Errorf("advance watermark to %s: %w", batch.Watermark, err)
	}
	return nil
}

// recordFailure marks the feed's credential as suspect so the operator sees it.
func (w *Worker) recordFailure(ctx context.Context, feed chdata.Feed) {
	w.health.Record(ctx, ingest.HealthSample{
		TenantID: feed.TenantID, FeedID: feed.ID, CredentialValid: false,
	})
}

func eventIDsOf(envelopes []ingest.Envelope) []string {
	ids := make([]string, 0, len(envelopes))
	for _, envelope := range envelopes {
		ids = append(ids, envelope.EventID)
	}
	return ids
}
