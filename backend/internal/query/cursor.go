package query

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"time"

	mw "github.com/menta2k/siem/internal/middleware"
)

// Cursor marks the last row a page returned.
//
// Keyset pagination, not OFFSET. OFFSET re-reads and discards every preceding row, so
// page 500 costs 500 pages of work — and worse, if rows arrive or merge between
// requests the offset shifts underneath the reader and rows are skipped or repeated.
// A cursor anchored to a row cannot drift, because it names a position rather than
// counting to one.
//
// The ID is not decoration. Events sharing a timestamp to the millisecond are routine
// — one vendor delivers a batch and every event lands in the same instant — and
// without a tiebreaker the page boundary inside that group is undefined. That is a
// silent loss exactly where the reader is looking hardest.
type Cursor struct {
	EventTime time.Time
	ID        string
}

// IsZero reports whether this is the first page.
func (c Cursor) IsZero() bool { return c.EventTime.IsZero() && c.ID == "" }

// After reports whether a row sorts strictly after the cursor in the query's order.
//
// The order is (event_time DESC, id DESC), so "after" means older, or the same instant
// with a lower id. Exported because the paging tests exercise the real predicate rather
// than a restatement of it — a second copy of this rule is a second chance to get it
// subtly wrong.
func After(cursor Cursor, at time.Time, id string) bool {
	if at.Before(cursor.EventTime) {
		return true
	}
	if at.Equal(cursor.EventTime) {
		return id < cursor.ID
	}
	return false
}

// maxCursorMillis is the year 2100, matching the plausibility bound the vendor
// timestamp parsers apply. Anything past it did not come from a real event.
const maxCursorMillis int64 = 4102444800000

// cursorVersion prefixes the payload so the encoding can change without a cursor from
// an older build being silently misread as a valid position.
const cursorVersion byte = 1

// EncodeCursor renders a cursor as an opaque token.
//
// Opaque on purpose. A readable cursor invites clients to construct their own, and
// they then depend on the sort key — after which the sort key cannot change without
// breaking every saved link and bookmarked investigation.
func EncodeCursor(c Cursor) string {
	if c.IsZero() {
		return ""
	}

	payload := make([]byte, 0, 9+len(c.ID))
	payload = append(payload, cursorVersion)
	payload = binary.BigEndian.AppendUint64(payload, uint64(c.EventTime.UTC().UnixMilli()))
	payload = append(payload, c.ID...)

	return base64.RawURLEncoding.EncodeToString(payload)
}

// DecodeCursor parses a cursor token. An empty token means the first page, which is an
// ordinary request rather than an error.
func DecodeCursor(token string) (Cursor, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return Cursor{}, nil
	}

	payload, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return Cursor{}, mw.CursorInvalid()
	}
	// Version byte plus a millisecond timestamp; anything shorter cannot be a cursor.
	if len(payload) < 9 || payload[0] != cursorVersion {
		return Cursor{}, mw.CursorInvalid()
	}

	id := string(payload[9:])
	if id == "" {
		// A cursor without its tiebreaker would make the boundary between rows sharing
		// a timestamp undefined, which is the exact failure the ID exists to prevent.
		return Cursor{}, mw.CursorInvalid()
	}

	// Bounded before conversion. An unchecked uint64 wraps to a negative int64 and
	// yields a timestamp in the far past, which is not a crash but a cursor that
	// silently pages through nothing — a blank result an analyst reads as "no data".
	raw := binary.BigEndian.Uint64(payload[1:9])
	if raw > uint64(maxCursorMillis) {
		return Cursor{}, mw.CursorInvalid()
	}

	return Cursor{
		EventTime: time.UnixMilli(int64(raw)).UTC(),
		ID:        id,
	}, nil
}
