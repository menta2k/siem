package window_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/correlate/window"
)

// The decode cache serves ONE parsed member to every bucket that stored the same bytes,
// which is where its speed comes from and also its only hazard: the returned members share
// a RuleIDs slice and a Score pointer. That is safe precisely because a decoded member is
// read-only in this codebase — nothing between MembersMany and the emitted record writes to
// one. These tests pin the behaviour that safety rests on.

func cachedTestStore(tb testing.TB, byKey map[string][]window.Member) *fixedStore {
	tb.Helper()
	encoded := make(map[string][]string, len(byKey))
	for key, members := range byKey {
		for _, member := range members {
			raw, err := json.Marshal(member)
			if err != nil {
				tb.Fatalf("encode member: %v", err)
			}
			encoded[key] = append(encoded[key], string(raw))
		}
	}
	return &fixedStore{byKey: encoded}
}

// Two buckets holding the SAME event must both receive it, fully populated. A cache that
// served the first caller and starved the second would lose a vendor from a correlated
// record, which is indistinguishable from the request never having been seen.
func TestOverlappingBucketsEachReceiveTheSharedMember(t *testing.T) {
	tenantID := uuid.New()
	score := float32(0.91)
	shared := window.Member{
		EventID: "cf-1", Vendor: "cloudflare",
		EventTime:       time.Unix(1770000000, 0).UTC(),
		VendorRequestID: "ray-a", LinkedRequestID: "ray-b",
		RuleIDs: []string{"waf-1", "bot-3"}, Score: &score,
		RequestHost: "shop.example.com",
	}

	store := cachedTestStore(t, map[string][]window.Member{
		membersKeyFor(tenantID, "ray-a"): {shared},
		membersKeyFor(tenantID, "ray-b"): {shared},
	})

	got, err := window.New(store).MembersMany(t.Context(), tenantID, []string{"ray-a", "ray-b"})
	if err != nil {
		t.Fatalf("MembersMany: %v", err)
	}

	for _, key := range []string{"ray-a", "ray-b"} {
		members := got[key]
		if len(members) != 1 {
			t.Fatalf("%s returned %d members, want 1", key, len(members))
		}
		m := members[0]
		if m.EventID != "cf-1" || m.RequestHost != "shop.example.com" {
			t.Errorf("%s got a hollow member: %+v", key, m)
		}
		if len(m.RuleIDs) != 2 || m.Score == nil || *m.Score != score {
			t.Errorf("%s lost the nested fields: rules=%v score=%v", key, m.RuleIDs, m.Score)
		}
	}
}

// Entries that differ must decode separately. Keying the cache on the stored BYTES is what
// guarantees it: two members can never be conflated unless they are byte-identical, in
// which case they are the same member.
func TestDistinctEntriesDoNotShareADecode(t *testing.T) {
	tenantID := uuid.New()
	first := window.Member{EventID: "cf-1", Vendor: "cloudflare", RequestHost: "a.example"}
	second := window.Member{EventID: "f5-1", Vendor: "f5", RequestHost: "b.example"}

	store := cachedTestStore(t, map[string][]window.Member{
		membersKeyFor(tenantID, "w1"): {first, second},
	})

	got, err := window.New(store).MembersMany(t.Context(), tenantID, []string{"w1"})
	if err != nil {
		t.Fatalf("MembersMany: %v", err)
	}

	members := got["w1"]
	if len(members) != 2 {
		t.Fatalf("got %d members, want 2: %+v", len(members), members)
	}
	if members[0].EventID != "cf-1" || members[1].EventID != "f5-1" {
		t.Errorf("members were conflated: %+v", members)
	}
	if members[0].RequestHost == members[1].RequestHost {
		t.Errorf("both members carry %q; one decode was served for two entries",
			members[0].RequestHost)
	}
}

// A corrupt entry is skipped, and skipping it must not cost the valid ones. The cache
// remembers which bytes failed so a bad value is parsed once for the whole read rather
// than once per bucket it appears in — but it must never turn one bad entry into a lost
// window.
func TestACorruptEntryIsSkippedWithoutLosingTheRest(t *testing.T) {
	tenantID := uuid.New()
	good := window.Member{EventID: "cf-1", Vendor: "cloudflare"}
	raw, err := json.Marshal(good)
	if err != nil {
		t.Fatalf("encode member: %v", err)
	}

	store := &fixedStore{byKey: map[string][]string{
		membersKeyFor(tenantID, "w1"): {"{not json", string(raw)},
		membersKeyFor(tenantID, "w2"): {string(raw), "{not json"},
	}}

	got, err := window.New(store).MembersMany(t.Context(), tenantID, []string{"w1", "w2"})
	if err != nil {
		t.Fatalf("MembersMany: %v", err)
	}

	for _, key := range []string{"w1", "w2"} {
		if len(got[key]) != 1 || got[key][0].EventID != "cf-1" {
			t.Errorf("%s = %+v, want just the valid member; a corrupt neighbour must not "+
				"sink the window", key, got[key])
		}
	}
}

// Batched and unbatched reads must agree. MembersMany is the only path the closer uses, so
// a divergence here would be invisible until a correlated record came out wrong.
func TestBatchedAndSingleReadsAgree(t *testing.T) {
	tenantID := uuid.New()
	score := float32(0.5)
	members := []window.Member{
		{EventID: "cf-1", Vendor: "cloudflare", RuleIDs: []string{"waf-1"}, Score: &score},
		{EventID: "f5-1", Vendor: "f5"},
	}
	store := cachedTestStore(t, map[string][]window.Member{
		membersKeyFor(tenantID, "w1"): members,
	})
	windows := window.New(store)

	single, err := windows.Members(t.Context(), tenantID, "w1")
	if err != nil {
		t.Fatalf("Members: %v", err)
	}
	batched, err := windows.MembersMany(t.Context(), tenantID, []string{"w1"})
	if err != nil {
		t.Fatalf("MembersMany: %v", err)
	}

	if len(single) != len(batched["w1"]) {
		t.Fatalf("single read gave %d members, batched gave %d",
			len(single), len(batched["w1"]))
	}
	for i := range single {
		if single[i].EventID != batched["w1"][i].EventID {
			t.Errorf("member %d differs: single=%s batched=%s",
				i, single[i].EventID, batched["w1"][i].EventID)
		}
	}
}

// membersKeyFor mirrors the package's own member-key layout, so a test can seed the store
// with the exact keys MembersMany will ask for.
func membersKeyFor(tenantID uuid.UUID, key string) string {
	return fmt.Sprintf("correlate:members:%s:%s", tenantID, key)
}

// fixedStore serves canned lists. It implements only what MembersMany touches; the rest of
// the Store surface is present to satisfy the interface and is never called here.
type fixedStore struct {
	byKey map[string][]string
}

func (s *fixedStore) LRange(_ context.Context, key string) ([]string, error) {
	return s.byKey[key], nil
}

func (s *fixedStore) LRangeMany(
	_ context.Context, keyNames []string,
) (map[string][]string, error) {
	out := make(map[string][]string, len(keyNames))
	for _, key := range keyNames {
		out[key] = s.byKey[key]
	}
	return out, nil
}

func (s *fixedStore) LookupMany(context.Context, []string) (map[string]string, error) {
	return map[string]string{}, nil
}
func (s *fixedStore) RPush(context.Context, string, string, time.Duration) (int64, error) {
	return 0, nil
}
func (s *fixedStore) RPushMany(context.Context, []window.ListEntry) error { return nil }
func (s *fixedStore) ZAddMany(context.Context, []window.ScoreEntry) error { return nil }
func (s *fixedStore) SetNX(context.Context, string, string, time.Duration) (bool, error) {
	return true, nil
}
func (s *fixedStore) Get(context.Context, string) (string, error) { return "", nil }
func (s *fixedStore) Lookup(context.Context, string) (string, bool, error) {
	return "", false, nil
}
func (s *fixedStore) ZAdd(context.Context, string, string, float64, time.Duration) error {
	return nil
}
func (s *fixedStore) ZPopDue(context.Context, string, float64, int64) ([]string, error) {
	return nil, nil
}

func (s *fixedStore) ZBacklog(context.Context, string, float64) (int64, float64, error) {
	return 0, 0, nil
}
