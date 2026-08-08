// Package normalize turns raw vendor deliveries into common-model events and writes
// them to storage.
//
// This package owns the two guarantees that make retries safe: a stable event
// identity, so a redelivered event is recognizable, and a deterministic correlation
// id, so a late-arriving event amends the record it belongs to rather than creating a
// second one.
package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/vendors"
)

// EventID derives a stable identity for one event.
//
// The identity must be byte-identical across redeliveries, because that is what makes
// a vendor retry safe: ReplacingMergeTree deduplicates on it, and the ingest dedup
// window reports it as a suppressed duplicate rather than double-counting.
//
// The feed id is part of the hash so two tenants receiving the same vendor request id
// — which happens when they share a Cloudflare zone — cannot collide into one event.
//
// When a vendor supplies a request identifier it is used directly. Otherwise the raw
// bytes are hashed, which is still stable for an identical redelivery but will treat
// a semantically identical event with different whitespace as new. That is the
// correct trade: over-counting a duplicate is recoverable, silently merging two
// distinct events is not.
func EventID(feedID uuid.UUID, vendorRequestID string, rawBytes []byte) string {
	h := sha256.New()

	// Length-prefixed so a feed id ending in digits cannot run into a request id
	// beginning with them and produce the same digest for different inputs.
	writeField(h, feedID.String())

	if trimmed := strings.TrimSpace(vendorRequestID); trimmed != "" {
		writeField(h, "rid")
		writeField(h, trimmed)
	} else {
		writeField(h, "raw")
		writeField(h, string(rawBytes))
	}

	return hex.EncodeToString(h.Sum(nil))
}

// CorrelationID derives a deterministic id for a correlation window.
//
// Determinism is the whole point: when a late event arrives for a window that has
// already been emitted, recomputing this id targets the SAME row, so the amendment
// updates the existing correlated request instead of creating a duplicate (FR-018).
func CorrelationID(tenantID uuid.UUID, joinKey string, windowStart time.Time) uuid.UUID {
	h := sha256.New()
	writeField(h, tenantID.String())
	writeField(h, joinKey)
	writeField(h, windowStart.UTC().Format(time.RFC3339Nano))

	sum := h.Sum(nil)

	// Build a v4-shaped UUID from the digest so the value is a valid UUID while
	// remaining a pure function of its inputs.
	var id uuid.UUID
	copy(id[:], sum[:16])
	id[6] = (id[6] & 0x0f) | 0x40 // version 4
	id[8] = (id[8] & 0x3f) | 0x80 // RFC4122 variant
	return id
}

// writeField appends a length-prefixed field to a hash.
func writeField(h interface{ Write([]byte) (int, error) }, value string) {
	// hash.Hash.Write never returns an error.
	_, _ = fmt.Fprintf(h, "%d:%s|", len(value), value)
}

// BatchID generates an identifier for one delivery, used to group events for replay
// and troubleshooting.
func BatchID() uuid.UUID { return uuid.New() }

// EventIDFor is a convenience wrapper deriving the identity from a normalized event.
//
// The VENDOR is part of the identity, and leaving it out caused real data loss in
// production. A vendor request id identifies a REQUEST, not a record of one, so the
// moment a single feed can produce events for more than one vendor — which the
// DataDome-from-Cloudflare derivation introduced — two genuinely different records
// legitimately share it. Their ids then collided, the ingest deduper read the second
// as a redelivery, and roughly a quarter of all received events were silently
// discarded: 0 suppressed duplicates per minute before the change, 2,300-4,900 after.
//
// Identity therefore has to be per (feed, vendor, request id). It reads as belt and
// braces only while one feed means one vendor, and that is exactly the assumption that
// stopped being true.
func EventIDFor(feedID uuid.UUID, event vendors.Event, rawBytes []byte) string {
	requestID := strings.TrimSpace(event.VendorRequestID)
	if requestID == "" {
		// Left empty so EventID still falls through to hashing the raw bytes. Passing
		// the vendor alone here would make every id-less event of one vendor share a
		// single identity — a far worse version of the bug being fixed.
		return EventID(feedID, "", rawBytes)
	}
	return EventID(feedID, event.Vendor+"|"+requestID, rawBytes)
}
