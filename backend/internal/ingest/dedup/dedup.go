// Package dedup suppresses redelivered events at the ingest boundary.
//
// There are two layers of deduplication in this system and they do different jobs:
//
//   - ClickHouse's ReplacingMergeTree deduplicates by event id, but only EVENTUALLY,
//     during background merges. It guarantees storage correctness.
//   - This package deduplicates immediately, over a short window, and is what
//     produces the duplicates_suppressed count a vendor sees in its 202 response
//     (FR-004). ClickHouse cannot answer that question at request time.
//
// The window is intentionally short. Holding every event id for the full lateness
// bound at 15k events/sec would need tens of millions of Redis keys; the storage
// layer already catches anything that escapes this window.
//
// # Why marking is separate from filtering
//
// Filter is READ-ONLY and Mark is called only AFTER a durable commit succeeds.
// Combining them — marking an event seen at the moment it is checked — loses data:
// if the publish then fails and the vendor retries, the retry is suppressed as a
// duplicate and the event is never committed at all. That is the exact failure the
// 503-and-retry contract exists to prevent, so the two steps stay apart.
package dedup

import (
	"context"
	"fmt"
	"time"
)

// Store is the subset of Redis this package needs.
type Store interface {
	// Exists reports how many of the given keys are present.
	Exists(ctx context.Context, keys ...string) (int64, error)
	// Set records a key with a TTL.
	Set(ctx context.Context, key, value string, ttl time.Duration) error
}

// DefaultWindow is how long an event id is remembered at the ingest boundary.
const DefaultWindow = 10 * time.Minute

// Deduper reports whether an event has been seen recently.
type Deduper struct {
	store  Store
	window time.Duration
}

// New builds a deduper. A non-positive window falls back to DefaultWindow rather than
// disabling deduplication, because a zero window would silently turn every retry into
// a double-count.
func New(store Store, window time.Duration) *Deduper {
	if window <= 0 {
		window = DefaultWindow
	}
	return &Deduper{store: store, window: window}
}

// Result reports the outcome of filtering one batch.
type Result struct {
	// Fresh holds the indices of events not seen before, in input order.
	Fresh []int
	// Duplicates counts events suppressed as already seen.
	Duplicates int
}

// Filter partitions a batch into fresh and already-seen events WITHOUT recording
// anything. Call Mark once the batch has been durably committed.
//
// Two concurrent deliveries of the same event can both pass this check and both be
// published. That is deliberate: the storage layer deduplicates by event id, so an
// occasional double-publish is absorbed, whereas suppressing an event that was never
// committed loses it for good.
//
// On a store failure it fails OPEN — every event is treated as fresh. Losing a
// customer's logs because Redis is unavailable would be far worse than briefly
// over-counting. The error is returned alongside the result so the caller can log the
// degradation rather than have it pass silently.
func (d *Deduper) Filter(ctx context.Context, tenantID string, eventIDs []string) (Result, error) {
	result := Result{Fresh: make([]int, 0, len(eventIDs))}

	// Duplicates within a single batch are caught here rather than in Redis, since
	// nothing has been recorded yet for this batch.
	seenInBatch := make(map[string]bool, len(eventIDs))

	for i, eventID := range eventIDs {
		if eventID == "" {
			// No identity means no way to recognize a redelivery. Treat it as fresh
			// and let the storage layer sort it out.
			result.Fresh = append(result.Fresh, i)
			continue
		}
		if seenInBatch[eventID] {
			result.Duplicates++
			continue
		}
		seenInBatch[eventID] = true

		count, err := d.store.Exists(ctx, key(tenantID, eventID))
		if err != nil {
			// Fail open: everything from here on is accepted, and the caller is told.
			for j := i; j < len(eventIDs); j++ {
				result.Fresh = append(result.Fresh, j)
			}
			return result, fmt.Errorf("dedup check for tenant %s: %w", tenantID, err)
		}

		if count == 0 {
			result.Fresh = append(result.Fresh, i)
			continue
		}
		result.Duplicates++
	}

	return result, nil
}

// Mark records event ids as seen. It must be called ONLY after the events have been
// durably committed.
//
// A failure here is not fatal: the worst outcome is that a later redelivery is
// re-published and deduplicated by the storage layer, which is the safe direction.
func (d *Deduper) Mark(ctx context.Context, tenantID string, eventIDs []string) error {
	for _, eventID := range eventIDs {
		if eventID == "" {
			continue
		}
		if err := d.store.Set(ctx, key(tenantID, eventID), "1", d.window); err != nil {
			return fmt.Errorf("record dedup marker for tenant %s: %w", tenantID, err)
		}
	}
	return nil
}

// Seen reports whether an event id was already recorded, without recording it.
func (d *Deduper) Seen(ctx context.Context, tenantID, eventID string) (bool, error) {
	if eventID == "" {
		return false, nil
	}

	count, err := d.store.Exists(ctx, key(tenantID, eventID))
	if err != nil {
		return false, fmt.Errorf("dedup check for tenant %s: %w", tenantID, err)
	}
	return count > 0, nil
}

// key namespaces the dedup set per tenant, so one tenant's volume cannot evict
// another's entries.
func key(tenantID, eventID string) string {
	return "dedup:" + tenantID + ":" + eventID
}

// Window returns the configured window, for reporting in feed health.
func (d *Deduper) Window() time.Duration { return d.window }
