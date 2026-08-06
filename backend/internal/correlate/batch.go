package correlate

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/correlate/keys"
	"github.com/menta2k/siem/internal/correlate/window"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/data/stream"
)

// HandleBatch files a whole fetch of normalized events into their windows at once.
//
// Filing one event costs up to three Redis round trips, and at correlation volumes it
// is the round trips — not Redis, not the CPU — that set the ceiling. Describing the
// batch as a list of writes and sending it in two pipelined calls removes that ceiling.
//
// The filing rules are exactly Handle's, because they are what the join depends on:
// an event goes into BOTH its keys when it has both, and only the closing key is ever
// scheduled. Filing only under the exact key would leave events with unmatched ids
// uncorrelated; scheduling the lookup bucket too would emit every request twice.
//
// A Redis failure fails the whole batch: nothing is committed, everything is
// redelivered, and window membership collapses duplicates by event id, so a retry
// after a partial write costs nothing.
func (w *Worker) HandleBatch(
	ctx context.Context, records []stream.Record,
) ([]stream.RecordFailure, error) {
	writes := make([]window.Write, 0, 2*len(records))
	filed := make([]string, 0, len(records))

	for _, record := range records {
		event, ok := w.decodeEvent(ctx, record)
		if !ok {
			continue
		}
		writes = append(writes, w.writesFor(ctx, event)...)
		filed = append(filed, event.Vendor)
	}

	if err := w.windows.AddBatch(ctx, writes); err != nil {
		return nil, err
	}

	// Counted only after the write succeeded, so the metric never claims events that
	// a failed batch will file again on redelivery.
	for _, vendor := range filed {
		EventsFiled.WithLabelValues(vendor).Inc()
	}
	return nil, nil
}

// decodeEvent parses a record, reporting whether it is usable.
//
// An unusable record is logged and skipped rather than dead-lettered or retried: it
// will never parse, retrying would stall the partition behind it, and the event itself
// is already durably in ClickHouse — written before this publish ever happened.
func (w *Worker) decodeEvent(
	ctx context.Context, record stream.Record,
) (chdata.NormalizedEvent, bool) {
	var event chdata.NormalizedEvent
	if err := json.Unmarshal(record.Value, &event); err != nil {
		w.log.Error(ctx, "correlate: undecodable normalized event, skipping",
			"error", err, "record_key", string(record.Key))
		return chdata.NormalizedEvent{}, false
	}
	if event.EventID == "" || event.TenantID == uuid.Nil {
		w.log.Error(ctx, "correlate: normalized event missing identity, skipping",
			"event_id", event.EventID)
		return chdata.NormalizedEvent{}, false
	}
	return event, true
}

// writesFor turns one event into the window writes that file it.
func (w *Worker) writesFor(ctx context.Context, event chdata.NormalizedEvent) []window.Write {
	member := toMember(event)
	settings := w.settings.For(ctx, event.TenantID).Keys
	candidates := keys.Derive(event, settings)

	writes := make([]window.Write, 0, 2)

	// The exact bucket is a LOOKUP, not a window: the closer consults it to find a
	// partner that landed elsewhere. It carries no ScheduleAt, so it never emits.
	if candidates.HasExact() {
		writes = append(writes, window.Write{
			TenantID: event.TenantID, Key: candidates.Exact.Value,
			Member: member, Settings: settings,
		})
	}

	// The window that actually closes. An event with no client address or host cannot
	// attract a partner, so it gets a bucket of its own keyed by its event id — it
	// still becomes a single-vendor record rather than being dropped.
	closingKey := candidates.Heuristic.Value
	if candidates.Heuristic.Tier == keys.TierNone {
		closingKey = "solo|" + event.EventID
	}
	return append(writes, window.Write{
		TenantID: event.TenantID, Key: closingKey, Member: member,
		Settings: settings, ScheduleAt: event.EventTime,
	})
}
