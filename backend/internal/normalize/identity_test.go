package normalize

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// The central property: a redelivered event must produce the same id, or dedup cannot
// work and a vendor retry silently double-counts.
func TestEventIDIsStableAcrossRedelivery(t *testing.T) {
	feed := uuid.New()
	raw := []byte(`{"RayID":"abc","EdgeStartTimestamp":"2026-08-06T12:00:00Z"}`)

	first := EventID(feed, "abc", raw)
	second := EventID(feed, "abc", raw)

	if first != second {
		t.Errorf("EventID() is not stable: %q != %q", first, second)
	}
	if len(first) != 64 {
		t.Errorf("EventID() = %q, want a 64-character sha256 hex digest", first)
	}
}

// Two tenants can legitimately share a Cloudflare zone and therefore see the same
// RayID. Their events must not collide into one.
func TestEventIDIsScopedToFeed(t *testing.T) {
	raw := []byte(`{"RayID":"abc"}`)

	first := EventID(uuid.New(), "abc", raw)
	second := EventID(uuid.New(), "abc", raw)

	if first == second {
		t.Error("the same vendor request id on two different feeds produced one identity")
	}
}

func TestEventIDDistinguishesDifferentRequests(t *testing.T) {
	feed := uuid.New()

	first := EventID(feed, "request-a", []byte(`{}`))
	second := EventID(feed, "request-b", []byte(`{}`))

	if first == second {
		t.Error("two different vendor request ids produced the same identity")
	}
}

// A vendor request id takes precedence over the raw bytes, so a redelivery that
// differs only in whitespace or field order is still recognized as the same event.
func TestEventIDPrefersVendorRequestIDOverBytes(t *testing.T) {
	feed := uuid.New()

	compact := EventID(feed, "abc", []byte(`{"RayID":"abc","x":1}`))
	spaced := EventID(feed, "abc", []byte(`{ "RayID": "abc", "x": 1 }`))

	if compact != spaced {
		t.Error("the same event delivered with different formatting produced two identities")
	}
}

// Without a vendor request id the raw bytes are the only stable signal available.
func TestEventIDFallsBackToRawBytes(t *testing.T) {
	feed := uuid.New()

	first := EventID(feed, "", []byte(`{"a":1}`))
	same := EventID(feed, "", []byte(`{"a":1}`))
	different := EventID(feed, "", []byte(`{"a":2}`))

	if first != same {
		t.Error("identical raw bytes produced different identities")
	}
	if first == different {
		t.Error("different raw bytes produced the same identity")
	}
}

// Length-prefixed hashing: a feed id running into a request id must not produce the
// same digest as a different split of the same characters.
func TestEventIDIsUnambiguousAcrossFieldBoundaries(t *testing.T) {
	feed := uuid.MustParse("00000000-0000-0000-0000-0000000000ab")

	first := EventID(feed, "cd", nil)
	second := EventID(feed, "c", []byte("d"))

	if first == second {
		t.Error("two different inputs produced the same identity; fields must be length-prefixed")
	}
}

func TestEventIDIgnoresSurroundingWhitespaceInRequestID(t *testing.T) {
	feed := uuid.New()

	if EventID(feed, "abc", nil) != EventID(feed, "  abc  ", nil) {
		t.Error("a request id differing only in whitespace produced a different identity")
	}
}

// A late event must target the SAME correlated record, or the amendment creates a
// duplicate instead of updating the original (FR-018).
func TestCorrelationIDIsDeterministic(t *testing.T) {
	tenant := uuid.New()
	window := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	key := "203.0.113.1|shop.example.com|/api/checkout|POST"

	first := CorrelationID(tenant, key, window)
	second := CorrelationID(tenant, key, window)

	if first != second {
		t.Errorf("CorrelationID() is not deterministic: %v != %v", first, second)
	}
	if first == uuid.Nil {
		t.Error("CorrelationID() returned the nil UUID")
	}
}

func TestCorrelationIDIsAValidV4UUID(t *testing.T) {
	id := CorrelationID(uuid.New(), "key", time.Now())

	if got := id.Version(); got != 4 {
		t.Errorf("Version() = %d, want 4", got)
	}
	if got := id.Variant(); got != uuid.RFC4122 {
		t.Errorf("Variant() = %v, want RFC4122", got)
	}
	// It must survive a text round trip, since it is stored and returned over the API.
	parsed, err := uuid.Parse(id.String())
	if err != nil || parsed != id {
		t.Errorf("the correlation id did not round-trip through its string form: %v", err)
	}
}

func TestCorrelationIDSeparatesTenantsKeysAndWindows(t *testing.T) {
	tenantA, tenantB := uuid.New(), uuid.New()
	window := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	const key = "k"

	base := CorrelationID(tenantA, key, window)

	tests := []struct {
		name string
		id   uuid.UUID
	}{
		{"different tenant", CorrelationID(tenantB, key, window)},
		{"different key", CorrelationID(tenantA, "other", window)},
		{"different window", CorrelationID(tenantA, key, window.Add(5*time.Second))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.id == base {
				t.Errorf("%s produced the same correlation id", tt.name)
			}
		})
	}
}

// The window is normalized to UTC, so a caller passing a zoned time cannot split one
// window into two.
func TestCorrelationIDNormalizesTimezone(t *testing.T) {
	tenant := uuid.New()
	utc := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	zoned := utc.In(time.FixedZone("CEST", 2*60*60))

	if CorrelationID(tenant, "k", utc) != CorrelationID(tenant, "k", zoned) {
		t.Error("the same instant in two timezones produced different correlation ids")
	}
}

func TestBatchIDIsUnique(t *testing.T) {
	seen := map[uuid.UUID]bool{}
	for range 100 {
		id := BatchID()
		if seen[id] {
			t.Fatal("BatchID() produced a duplicate")
		}
		seen[id] = true
	}
}
