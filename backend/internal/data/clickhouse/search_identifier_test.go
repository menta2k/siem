package clickhouse

import (
	"errors"
	"testing"
	"time"
)

// fakeRows replays a fixed result set.
type fakeRows struct {
	ids    []string
	times  []time.Time
	cursor int
	err    error
}

func (f *fakeRows) Next() bool {
	if f.cursor >= len(f.ids) {
		return false
	}
	f.cursor++
	return true
}

func (f *fakeRows) Scan(dest ...any) error {
	if len(dest) != 2 {
		return errors.New("unexpected destination count")
	}
	id, ok := dest[0].(*string)
	if !ok {
		return errors.New("first destination is not a string")
	}
	at, ok := dest[1].(*time.Time)
	if !ok {
		return errors.New("second destination is not a time")
	}
	*id, *at = f.ids[f.cursor-1], f.times[f.cursor-1]
	return nil
}

func (f *fakeRows) Err() error { return f.err }

var moment = time.Date(2026, 8, 17, 13, 35, 12, 0, time.UTC)

// THE HALF THAT MAKES THE LOOKUP AFFORDABLE. Correlated records are searched with
// hasAny(event_ids, ...), which no index answers, so the range decides the cost — a week
// reads 69 million rows on production. The events carry the only honest answer to "when
// should we look", so the span comes back with them.
func TestTheResolvedEventsReportTheSpanTheyCover(t *testing.T) {
	rows := &fakeRows{
		ids: []string{"early", "late", "middle"},
		times: []time.Time{
			moment, moment.Add(4 * time.Second), moment.Add(2 * time.Second),
		},
	}

	got, err := scanIdentifiedEvents(rows)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if !got.First.Equal(moment) {
		t.Errorf("first = %s, want the earliest event %s", got.First, moment)
	}
	if want := moment.Add(4 * time.Second); !got.Last.Equal(want) {
		t.Errorf("last = %s, want the latest event %s", got.Last, want)
	}
	if len(got.IDs) != 3 {
		t.Errorf("resolved %d events, want 3", len(got.IDs))
	}
}

// A ray reaches one row per vendor per hop, and the same event id can arrive twice from a
// re-delivery. Deduplication moved into Go when the timestamps had to be read, and the
// duplicate would otherwise be sent to the correlated query as a repeated id.
func TestARepeatedEventIsResolvedOnce(t *testing.T) {
	rows := &fakeRows{
		ids:   []string{"event-1", "event-1"},
		times: []time.Time{moment, moment},
	}

	got, err := scanIdentifiedEvents(rows)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(got.IDs) != 1 {
		t.Errorf("resolved %v, want the id once", got.IDs)
	}
}

// Resolving to nothing is a real answer — "no such request" — and it must leave the span
// unset rather than at the zero time, which as a range would mean the year 1.
func TestNothingResolvedLeavesTheSpanUnset(t *testing.T) {
	got, err := scanIdentifiedEvents(&fakeRows{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(got.IDs) != 0 || !got.First.IsZero() || !got.Last.IsZero() {
		t.Errorf("got %+v, want an empty resolution", got)
	}
}

// An error mid-stream must not be reported as a complete, shorter answer: the caller would
// narrow to a span that never held all the events.
func TestAFailedIterationIsReported(t *testing.T) {
	rows := &fakeRows{
		ids: []string{"event-1"}, times: []time.Time{moment}, err: errors.New("connection lost"),
	}

	if _, err := scanIdentifiedEvents(rows); err == nil {
		t.Error("a failed iteration was reported as a complete resolution")
	}
}
