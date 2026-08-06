package window

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/correlate/keys"
)

// Write places one event into one window, optionally scheduling that window to close.
//
// Filing an event costs up to three Redis round trips when done one call at a time —
// the exact bucket, the closing bucket, and the schedule — and at correlation volumes
// that round-trip latency, not Redis itself, is the ceiling. Describing the writes as
// data lets a whole fetch go out in two pipelined calls instead of three per event.
type Write struct {
	TenantID uuid.UUID
	Key      string
	Member   Member
	Settings keys.Settings

	// ScheduleAt, when non-zero, also schedules Key to close for an event at this
	// time. Only the window that actually emits a record carries it; the exact-key
	// lookup bucket is filed but never scheduled, which is what stops one request
	// being emitted twice.
	ScheduleAt time.Time
}

// AddBatch applies many window writes in as few round trips as possible.
//
// The semantics are identical to calling Add and Schedule for each write in order:
// members are appended, TTLs are refreshed from the latest write, and scheduling a key
// again moves its deadline out. Only the number of round trips changes.
//
// A failure returns an error for the whole batch. The caller has not committed any
// offset yet, so the events are redelivered and refiled; window membership collapses
// duplicates by event id, so a partially applied batch costs nothing on retry.
func (w *Windows) AddBatch(ctx context.Context, writes []Write) error {
	if len(writes) == 0 {
		return nil
	}

	members := make([]ListEntry, 0, len(writes))
	scheduled := make([]ScoreEntry, 0, len(writes))

	for _, write := range writes {
		encoded, err := json.Marshal(write.Member)
		if err != nil {
			return fmt.Errorf("encode window member %s: %w", write.Member.EventID, err)
		}

		ttl := w.TTL(write.Settings)
		members = append(members, ListEntry{
			Key:   membersKey(write.TenantID, write.Key),
			Value: string(encoded),
			TTL:   ttl,
		})

		if write.ScheduleAt.IsZero() {
			continue
		}
		// Deadlines are measured from the EVENT time for the same reason Schedule
		// does it: a backlogged feed must not push its own windows into the future.
		closesAt := write.ScheduleAt.UTC().
			Add(normalizeSettings(write.Settings).Window).Add(w.grace)
		scheduled = append(scheduled, ScoreEntry{
			Key:    scheduleKey(),
			Member: encodeScheduled(write.TenantID, write.Key),
			Score:  float64(closesAt.UnixMilli()),
			TTL:    ttl,
		})
	}

	if err := w.store.RPushMany(ctx, members); err != nil {
		return fmt.Errorf("file %d window members: %w", len(members), err)
	}
	if err := w.store.ZAddMany(ctx, scheduled); err != nil {
		return fmt.Errorf("schedule %d windows: %w", len(scheduled), err)
	}
	return nil
}
