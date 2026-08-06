package keys

import (
	"crypto/sha256"
	"fmt"

	"github.com/google/uuid"
)

// deterministicUUID derives a stable v4-shaped UUID from a string.
//
// It must be a pure function: a late-arriving event recomputes this id to find the
// record it belongs to, so any dependence on the clock or on randomness would create
// a second record instead of amending the first (FR-018).
func deterministicUUID(value string) uuid.UUID {
	h := sha256.New()
	// Length-prefixed so two different keys cannot collide by concatenation.
	fmt.Fprintf(h, "%d:%s", len(value), value) //nolint:errcheck // hash.Hash.Write never errors
	sum := h.Sum(nil)

	var id uuid.UUID
	copy(id[:], sum[:16])
	id[6] = (id[6] & 0x0f) | 0x40 // version 4
	id[8] = (id[8] & 0x3f) | 0x80 // RFC4122 variant
	return id
}
