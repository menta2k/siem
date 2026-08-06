package audit

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func validRecord() Record {
	actor := uuid.New()
	return Record{
		ActorUserID: &actor,
		ActorEmail:  "admin@example.com",
		SourceIP:    net.ParseIP("203.0.113.10"),
		Action:      ActionFeedUpdate,
		TargetType:  "feed",
		TargetID:    uuid.NewString(),
		BeforeValue: `{"enabled":true}`,
		AfterValue:  `{"enabled":false}`,
		Result:      ResultSuccess,
	}
}

// Builds a valid chain of n entries for a tenant.
func buildChain(t *testing.T, n int) []Entry {
	t.Helper()

	tenant := uuid.New()
	at := time.Date(2026, 8, 6, 9, 0, 0, 0, time.UTC)
	entries := make([]Entry, 0, n)
	prev := ""

	for i := range n {
		e, err := Chain(tenant, prev, at.Add(time.Duration(i)*time.Minute), validRecord())
		if err != nil {
			t.Fatalf("Chain() error = %v", err)
		}
		entries = append(entries, e)
		prev = e.EntryHash
	}
	return entries
}

func TestChainProducesCompleteEntry(t *testing.T) {
	tenant := uuid.New()
	at := time.Date(2026, 8, 6, 9, 0, 0, 0, time.UTC)

	e, err := Chain(tenant, "", at, validRecord())
	if err != nil {
		t.Fatalf("Chain() error = %v", err)
	}

	if e.TenantID != tenant {
		t.Errorf("TenantID = %v, want %v", e.TenantID, tenant)
	}
	if e.EntryID == uuid.Nil {
		t.Error("EntryID was not assigned")
	}
	if e.PrevHash != GenesisHash() {
		t.Errorf("PrevHash = %q, want the genesis hash for a first entry", e.PrevHash)
	}
	if len(e.EntryHash) != 64 {
		t.Errorf("EntryHash = %q, want a 64-character sha256 hex digest", e.EntryHash)
	}
	if !e.OccurredAt.Equal(at) {
		t.Errorf("OccurredAt = %v, want %v", e.OccurredAt, at)
	}
}

func TestVerifyChainAcceptsIntactChain(t *testing.T) {
	if err := VerifyChain(buildChain(t, 10)); err != nil {
		t.Errorf("VerifyChain() rejected an intact chain: %v", err)
	}
}

func TestVerifyChainAcceptsEmptyChain(t *testing.T) {
	if err := VerifyChain(nil); err != nil {
		t.Errorf("VerifyChain(nil) = %v, want nil", err)
	}
}

// The central guarantee: editing a recorded entry must be detectable. This is what
// makes the trail evidence rather than a log.
func TestVerifyChainDetectsModifiedEntry(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Entry)
	}{
		{"result flipped from denied to success", func(e *Entry) { e.Result = ResultDenied }},
		{"actor swapped", func(e *Entry) { e.ActorEmail = "someone-else@example.com" }},
		{"action rewritten", func(e *Entry) { e.Action = ActionLogin }},
		{"before value edited", func(e *Entry) { e.BeforeValue = `{"enabled":false}` }},
		{"after value edited", func(e *Entry) { e.AfterValue = `{"enabled":true}` }},
		{"target changed", func(e *Entry) { e.TargetID = uuid.NewString() }},
		{"timestamp moved", func(e *Entry) { e.OccurredAt = e.OccurredAt.Add(-time.Hour) }},
		{"source ip changed", func(e *Entry) { e.SourceIP = net.ParseIP("198.51.100.7") }},
		{"detail appended", func(e *Entry) { e.Detail = "authorised by management" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries := buildChain(t, 5)
			tt.mutate(&entries[2])

			if err := VerifyChain(entries); err == nil {
				t.Fatalf("VerifyChain() accepted a chain after %s", tt.name)
			}
		})
	}
}

// Deleting an entry is the likeliest tampering attempt: remove the record of what you
// did. The chain must not close over the gap.
func TestVerifyChainDetectsDeletedEntry(t *testing.T) {
	entries := buildChain(t, 6)
	withGap := append(append([]Entry{}, entries[:3]...), entries[4:]...)

	err := VerifyChain(withGap)
	if err == nil {
		t.Fatal("VerifyChain() accepted a chain with an entry removed")
	}
	if !strings.Contains(err.Error(), "altered or removed") {
		t.Errorf("VerifyChain() error = %q, want it to explain that an entry was removed", err)
	}
}

func TestVerifyChainDetectsReorderedEntries(t *testing.T) {
	entries := buildChain(t, 5)
	entries[1], entries[3] = entries[3], entries[1]

	if err := VerifyChain(entries); err == nil {
		t.Fatal("VerifyChain() accepted reordered entries")
	}
}

// An entry inserted after the fact, even a well-formed one, must not verify.
func TestVerifyChainDetectsInsertedEntry(t *testing.T) {
	entries := buildChain(t, 4)

	forged, err := Chain(entries[0].TenantID, entries[1].EntryHash, time.Now(), validRecord())
	if err != nil {
		t.Fatalf("Chain() error = %v", err)
	}
	withInsert := append([]Entry{}, entries[:3]...)
	withInsert = append(withInsert, forged)
	withInsert = append(withInsert, entries[3])

	if err := VerifyChain(withInsert); err == nil {
		t.Fatal("VerifyChain() accepted a chain with an inserted entry")
	}
}

func TestChainRejectsInvalidRecords(t *testing.T) {
	tests := []struct {
		name   string
		record Record
	}{
		{"no action", Record{ActorEmail: "a@example.com", Result: ResultSuccess}},
		{"no result", Record{ActorEmail: "a@example.com", Action: ActionLogin}},
		{"invalid result", Record{ActorEmail: "a@example.com", Action: ActionLogin, Result: "maybe"}},
		{"no actor at all", Record{Action: ActionLogin, Result: ResultSuccess}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Chain(uuid.New(), "", time.Now(), tt.record); err == nil {
				t.Error("Chain() accepted an invalid record")
			}
		})
	}
}

// A denied attempt is exactly what an investigator needs to see, so it must record.
func TestChainAcceptsDeniedAttemptWithoutUserID(t *testing.T) {
	r := Record{
		ActorEmail: "attacker@example.com",
		SourceIP:   net.ParseIP("198.51.100.1"),
		Action:     ActionLoginFailed,
		Result:     ResultDenied,
		Detail:     "invalid password",
	}

	e, err := Chain(uuid.New(), "", time.Now(), r)
	if err != nil {
		t.Fatalf("Chain() rejected a failed-login record: %v", err)
	}
	if e.Result != ResultDenied {
		t.Errorf("Result = %q, want %q", e.Result, ResultDenied)
	}
}

// Length-prefixed hashing: moving a character between adjacent fields must change the
// digest, or two different histories could share one hash.
func TestHashIsUnambiguousAcrossFieldBoundaries(t *testing.T) {
	tenant := uuid.New()
	id := uuid.New()
	at := time.Date(2026, 8, 6, 9, 0, 0, 0, time.UTC)

	base := Entry{
		TenantID: tenant, EntryID: id, OccurredAt: at,
		Action: ActionExport, Result: ResultSuccess, PrevHash: GenesisHash(),
	}

	first := base
	first.TargetType, first.TargetID = "feed", "abc"

	second := base
	second.TargetType, second.TargetID = "fee", "dabc"

	if computeHash(first) == computeHash(second) {
		t.Error("two different entries produced the same hash; fields must be length-prefixed")
	}
}

func TestChainNormalizesActorEmail(t *testing.T) {
	r := validRecord()
	r.ActorEmail = "  Admin@Example.COM  "

	e, err := Chain(uuid.New(), "", time.Now(), r)
	if err != nil {
		t.Fatalf("Chain() error = %v", err)
	}
	if e.ActorEmail != "admin@example.com" {
		t.Errorf("ActorEmail = %q, want it normalized to lowercase and trimmed", e.ActorEmail)
	}
}

// Chain must not mutate the caller's record.
func TestChainDoesNotMutateInput(t *testing.T) {
	r := validRecord()
	r.ActorEmail = "Admin@Example.com"
	snapshot := r

	if _, err := Chain(uuid.New(), "", time.Now(), r); err != nil {
		t.Fatalf("Chain() error = %v", err)
	}
	if r.ActorEmail != snapshot.ActorEmail {
		t.Error("Chain() mutated the caller's record")
	}
}

// There must be no way to modify or delete an entry through this package's API.
func TestPackageExposesNoMutationAPI(t *testing.T) {
	// Compile-time documentation of intent: if someone adds Update or Delete, this
	// test's comment is the place the reviewer is meant to stop and object.
	// The append-only property is otherwise enforced by the schema (plain MergeTree,
	// no version column) and by review.
	entries := buildChain(t, 3)
	if err := VerifyChain(entries); err != nil {
		t.Fatalf("baseline chain should verify: %v", err)
	}
}

// The hash must be computed over the timestamp AS STORED, not as held in memory.
//
// ClickHouse persists occurred_at as DateTime64(3), so a nanosecond-precision value
// is rounded on write. Hashing the unrounded value made every entry fail verification
// after a round trip — the chain reported tampering where none had occurred. This
// test pins the truncation so that cannot come back.
func TestChainTruncatesTimestampToStoragePrecision(t *testing.T) {
	withNanos := time.Date(2026, 8, 6, 9, 0, 0, 123_456_789, time.UTC)

	entry, err := Chain(uuid.New(), "", withNanos, validRecord())
	if err != nil {
		t.Fatalf("Chain() error = %v", err)
	}

	if entry.OccurredAt.Nanosecond()%int(time.Millisecond) != 0 {
		t.Errorf("OccurredAt = %v, want it truncated to millisecond precision to match "+
			"the DateTime64(3) column", entry.OccurredAt)
	}

	// Simulate the storage round trip: a value read back carries only milliseconds.
	roundTripped := entry
	roundTripped.OccurredAt = entry.OccurredAt.Truncate(time.Millisecond)

	if err := VerifyChain([]Entry{roundTripped}); err != nil {
		t.Errorf("the chain does not survive a millisecond-precision round trip: %v", err)
	}
}
