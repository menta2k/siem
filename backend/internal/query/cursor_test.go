package query_test

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/query"
)

func TestCursorRoundTrips(t *testing.T) {
	want := query.Cursor{
		EventTime: time.Date(2026, 8, 6, 12, 0, 0, 123_000_000, time.UTC),
		ID:        "cf-ray-0001",
	}

	got, err := query.DecodeCursor(query.EncodeCursor(want))
	if err != nil {
		t.Fatalf("DecodeCursor: %v", err)
	}
	if !got.EventTime.Equal(want.EventTime) {
		t.Errorf("EventTime = %v, want %v", got.EventTime, want.EventTime)
	}
	if got.ID != want.ID {
		t.Errorf("ID = %q, want %q", got.ID, want.ID)
	}
}

// Millisecond precision must survive the round trip. The column is DateTime64(3), so
// a cursor rounded to the second would re-read up to a second of rows on every page —
// duplicates, at exactly the boundary an analyst is most likely to be reading.
func TestCursorPreservesMillisecondPrecision(t *testing.T) {
	for _, ms := range []int{1, 37, 500, 999} {
		at := time.Date(2026, 8, 6, 12, 0, 0, ms*1_000_000, time.UTC)
		got, err := query.DecodeCursor(query.EncodeCursor(query.Cursor{EventTime: at, ID: "e"}))
		if err != nil {
			t.Fatalf("DecodeCursor: %v", err)
		}
		if !got.EventTime.Equal(at) {
			t.Errorf("%d ms lost in the round trip: got %v", ms, got.EventTime)
		}
	}
}

// The cursor is opaque on purpose. A client that parses it starts depending on the
// sort key, and the sort key then cannot change without breaking every saved link.
func TestCursorIsOpaque(t *testing.T) {
	encoded := query.EncodeCursor(query.Cursor{
		EventTime: time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC),
		ID:        "cf-ray-0001",
	})

	if encoded == "" {
		t.Fatal("empty cursor")
	}
	for _, leak := range []string{"cf-ray-0001", "2026-08-06", "event_time"} {
		if strings.Contains(encoded, leak) {
			t.Errorf("cursor leaks %q in plain text: %s", leak, encoded)
		}
	}
}

func TestMalformedCursorIsRejected(t *testing.T) {
	cases := map[string]string{
		"not base64":     "!!!!not-base64!!!!",
		"base64 of junk": "aGVsbG8gd29ybGQ",
		"truncated":      query.EncodeCursor(query.Cursor{EventTime: queryNow, ID: "x"})[:4],
		"no tiebreaker":  base64.RawURLEncoding.EncodeToString(make([]byte, 9)),
		// An unbounded timestamp wraps to a negative int64 and pages through nothing.
		"timestamp overflow": base64.RawURLEncoding.EncodeToString(
			append([]byte{1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, "e1"...)),
	}

	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := query.DecodeCursor(encoded)
			if err == nil {
				t.Fatal("a malformed cursor was accepted")
			}
			if got := mw.AsError(err).Code; got != mw.CodeCursorInvalid {
				t.Errorf("code = %q, want %q", got, mw.CodeCursorInvalid)
			}
		})
	}
}

// An empty cursor means "first page", which is not an error. Whitespace counts as
// empty: a client sending a blank cursor means "no cursor", and answering with page
// one is both what they meant and incapable of skipping or repeating a row.
func TestEmptyCursorMeansFirstPage(t *testing.T) {
	for _, token := range []string{"", "   ", "\t"} {
		got, err := query.DecodeCursor(token)
		if err != nil {
			t.Fatalf("cursor %q was rejected: %v", token, err)
		}
		if !got.IsZero() {
			t.Errorf("cursor %q gave %+v, want the zero cursor", token, got)
		}
	}
}

// ---------------------------------------------------------------- paging behaviour

// row models a stored event for the paging simulation below.
type row struct {
	at time.Time
	id string
}

// page applies the cursor predicate the query builder emits, so this exercises the
// real ordering rule rather than a restatement of it.
func page(rows []row, after query.Cursor, size int) []row {
	var out []row
	for _, r := range rows {
		if !after.IsZero() && !query.After(after, r.at, r.id) {
			continue
		}
		out = append(out, r)
		if len(out) == size {
			break
		}
	}
	return out
}

// sorted returns rows in the order the query returns them: newest first, with the id
// breaking ties so the order is total rather than merely mostly-defined.
func sorted(rows []row) []row {
	out := make([]row, len(rows))
	copy(out, rows)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			swap := out[j].at.After(out[i].at) ||
				(out[j].at.Equal(out[i].at) && out[j].id > out[i].id)
			if swap {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func TestPagingNeverSkipsOrRepeats(t *testing.T) {
	var rows []row
	for i := range 25 {
		rows = append(rows, row{at: queryNow.Add(-time.Duration(i) * time.Second),
			id: "e" + string(rune('a'+i%26))})
	}
	rows = sorted(rows)

	seen := map[string]int{}
	cursor := query.Cursor{}
	for range 10 {
		got := page(rows, cursor, 7)
		if len(got) == 0 {
			break
		}
		for _, r := range got {
			seen[r.id]++
		}
		last := got[len(got)-1]
		cursor = query.Cursor{EventTime: last.at, ID: last.id}
	}

	if len(seen) != len(rows) {
		t.Errorf("saw %d distinct rows, want %d — paging skipped some", len(seen), len(rows))
	}
	for id, count := range seen {
		if count != 1 {
			t.Errorf("row %s returned %d times, want once", id, count)
		}
	}
}

// Rows sharing a timestamp to the millisecond are common — one vendor delivers a batch
// and every event lands in the same instant. Without the id in the cursor the page
// boundary inside that group is undefined and rows are lost.
func TestPagingIsStableAcrossIdenticalTimestamps(t *testing.T) {
	var rows []row
	for i := range 12 {
		rows = append(rows, row{at: queryNow, id: "batch-" + string(rune('a'+i))})
	}
	rows = sorted(rows)

	seen := map[string]int{}
	cursor := query.Cursor{}
	for range 8 {
		got := page(rows, cursor, 5)
		if len(got) == 0 {
			break
		}
		for _, r := range got {
			seen[r.id]++
		}
		last := got[len(got)-1]
		cursor = query.Cursor{EventTime: last.at, ID: last.id}
	}

	if len(seen) != len(rows) {
		t.Errorf("saw %d of %d rows sharing one timestamp", len(seen), len(rows))
	}
	for id, count := range seen {
		if count != 1 {
			t.Errorf("row %s returned %d times, want once", id, count)
		}
	}
}

// New events arriving mid-pagination must not shift the pages already served. Because
// the cursor descends from a fixed point, later events sort ABOVE it and are simply not
// visible to this walk — which is the correct answer for a point-in-time investigation.
func TestNewEventsDoNotDisturbAnInFlightWalk(t *testing.T) {
	var rows []row
	for i := range 20 {
		rows = append(rows, row{at: queryNow.Add(-time.Duration(i) * time.Second),
			id: "old-" + string(rune('a'+i))})
	}
	rows = sorted(rows)

	seen := map[string]int{}
	cursor := query.Cursor{}

	first := page(rows, cursor, 6)
	for _, r := range first {
		seen[r.id]++
	}
	last := first[len(first)-1]
	cursor = query.Cursor{EventTime: last.at, ID: last.id}

	// A live feed lands five newer events between page one and page two.
	for i := range 5 {
		rows = append(rows, row{at: queryNow.Add(time.Duration(i+1) * time.Second),
			id: "new-" + string(rune('a'+i))})
	}
	rows = sorted(rows)

	for range 10 {
		got := page(rows, cursor, 6)
		if len(got) == 0 {
			break
		}
		for _, r := range got {
			seen[r.id]++
		}
		tail := got[len(got)-1]
		cursor = query.Cursor{EventTime: tail.at, ID: tail.id}
	}

	for id, count := range seen {
		if count != 1 {
			t.Errorf("row %s returned %d times, want once", id, count)
		}
	}
	for i := range 20 {
		id := "old-" + string(rune('a'+i))
		if seen[id] != 1 {
			t.Errorf("pre-existing row %s was skipped after new events arrived", id)
		}
	}
	for i := range 5 {
		if id := "new-" + string(rune('a'+i)); seen[id] != 0 {
			t.Errorf("row %s arrived after the walk began but appeared in it", id)
		}
	}
}
