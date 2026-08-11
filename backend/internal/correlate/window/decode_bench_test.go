package window_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/correlate/keys"
	"github.com/menta2k/siem/internal/correlate/window"
)

// benchMembers builds one window's worth of stored members, shaped like production: a
// Cloudflare row carrying a ray and a full request shape, an F5 row carrying a rule, and
// a DataDome row carrying only a verdict and a score.
func benchMembers(n int) []window.Member {
	score := float32(0.82)
	out := make([]window.Member, 0, n)
	for i := range n {
		out = append(out, window.Member{
			EventID:         fmt.Sprintf("cf-%d", i),
			Vendor:          "cloudflare",
			EventTime:       time.Unix(1770000000, 0).UTC(),
			VendorRequestID: fmt.Sprintf("a28b5c488d9151%02x", i),
			LinkedRequestID: fmt.Sprintf("b39c6d599e0262%02x", i),
			ClientIP:        "203.0.113.10",
			ClientASN:       13335,
			ClientCountry:   "BG",
			RequestHost:     "shop.example.com",
			RequestPath:     "/checkout/confirm",
			RequestMethod:   "POST",
			Verdict:         "allowed",
			RuleID:          "waf-1",
			RuleIDs:         []string{"waf-1", "bot-3"},
			Score:           &score,
			ScoreKind:       "bot",
		})
	}
	return out
}

// benchStore serves pre-encoded members without touching a network, so the benchmark
// measures DECODING and nothing else.
type benchStore struct {
	encoded []string
}

func newBenchStore(tb testing.TB, n int) *benchStore {
	tb.Helper()
	encoded := make([]string, 0, n)
	for _, member := range benchMembers(n) {
		raw, err := json.Marshal(member)
		if err != nil {
			tb.Fatalf("encode member: %v", err)
		}
		encoded = append(encoded, string(raw))
	}
	return &benchStore{encoded: encoded}
}

func (s *benchStore) LRange(context.Context, string) ([]string, error) {
	return s.encoded, nil
}

func (s *benchStore) LRangeMany(
	_ context.Context, keyNames []string,
) (map[string][]string, error) {
	out := make(map[string][]string, len(keyNames))
	for _, key := range keyNames {
		out[key] = s.encoded
	}
	return out, nil
}

// overlapStore reproduces what the partner walk actually reads: buckets holding
// OVERLAPPING subsets of one request's members. A store whose every key returns the same
// slice would flatter a decode cache; one whose keys share nothing would hide it. In
// production a tier-1 record spans 4.75 events, each filed under up to two identifiers.
type overlapStore struct {
	entries []string
	perKey  int
}

func newOverlapStore(tb testing.TB, distinct, perKey int) *overlapStore {
	tb.Helper()
	store := newBenchStore(tb, distinct)
	return &overlapStore{entries: store.encoded, perKey: perKey}
}

func (s *overlapStore) bucket(i int) []string {
	out := make([]string, 0, s.perKey)
	for j := range s.perKey {
		out = append(out, s.entries[(i+j)%len(s.entries)])
	}
	return out
}

func (s *overlapStore) LRange(_ context.Context, key string) ([]string, error) {
	return s.bucket(len(key)), nil
}

func (s *overlapStore) LRangeMany(
	_ context.Context, keyNames []string,
) (map[string][]string, error) {
	out := make(map[string][]string, len(keyNames))
	for i, key := range keyNames {
		out[key] = s.bucket(i)
	}
	return out, nil
}

func (s *overlapStore) LookupMany(context.Context, []string) (map[string]string, error) {
	return map[string]string{}, nil
}
func (s *overlapStore) RPush(context.Context, string, string, time.Duration) (int64, error) {
	return 0, nil
}
func (s *overlapStore) RPushMany(context.Context, []window.ListEntry) error { return nil }
func (s *overlapStore) ZAddMany(context.Context, []window.ScoreEntry) error { return nil }
func (s *overlapStore) SetNX(context.Context, string, string, time.Duration) (bool, error) {
	return true, nil
}
func (s *overlapStore) Get(context.Context, string) (string, error) { return "", nil }
func (s *overlapStore) Lookup(context.Context, string) (string, bool, error) {
	return "", false, nil
}
func (s *overlapStore) ZAdd(context.Context, string, string, float64, time.Duration) error {
	return nil
}
func (s *overlapStore) ZPopDue(context.Context, string, float64, int64) ([]string, error) {
	return nil, nil
}

// BenchmarkPartnerWalkLevel is the read the decode cache exists for: one level of the
// exact-partner walk, where nine buckets hold overlapping subsets of one request's five
// members.
func BenchmarkPartnerWalkLevel(b *testing.B) {
	const (
		distinctMembers  = 5
		bucketsPerLevel  = 9
		membersPerBucket = 3
	)

	store := newOverlapStore(b, distinctMembers, membersPerBucket)
	windows := window.New(store)
	tenantID := uuid.New()
	ctx := b.Context()

	keyNames := make([]string, 0, bucketsPerLevel)
	for i := range bucketsPerLevel {
		keyNames = append(keyNames, keys.ExactKeyValue(tenantID, fmt.Sprintf("ray-%d", i)))
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, err := windows.MembersMany(ctx, tenantID, keyNames); err != nil {
			b.Fatal(err)
		}
	}
}

func (s *benchStore) LookupMany(context.Context, []string) (map[string]string, error) {
	return map[string]string{}, nil
}
func (s *benchStore) RPush(context.Context, string, string, time.Duration) (int64, error) {
	return 0, nil
}
func (s *benchStore) RPushMany(context.Context, []window.ListEntry) error { return nil }
func (s *benchStore) ZAddMany(context.Context, []window.ScoreEntry) error { return nil }
func (s *benchStore) SetNX(context.Context, string, string, time.Duration) (bool, error) {
	return true, nil
}
func (s *benchStore) Get(context.Context, string) (string, error) { return "", nil }
func (s *benchStore) Lookup(context.Context, string) (string, bool, error) {
	return "", false, nil
}
func (s *benchStore) ZAdd(context.Context, string, string, float64, time.Duration) error {
	return nil
}
func (s *benchStore) ZPopDue(context.Context, string, float64, int64) ([]string, error) {
	return nil, nil
}

// BenchmarkMembers measures one window's decode. A production CPU profile put 13.2% of the
// processor's samples in encoding/json, essentially all of it here, which makes this the
// second-largest cost in the closer after the Redis round trips.
func BenchmarkMembers(b *testing.B) {
	for _, size := range []int{3, 32} {
		b.Run(fmt.Sprintf("members=%d", size), func(b *testing.B) {
			store := newBenchStore(b, size)
			windows := window.New(store)
			tenantID := uuid.New()
			ctx := b.Context()

			b.ReportAllocs()
			for b.Loop() {
				if _, err := windows.Members(ctx, tenantID, "k"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkMembersMany measures a whole close pass's worth of decoding, which is the shape
// that actually runs: one batched read covering every due window.
func BenchmarkMembersMany(b *testing.B) {
	const windowsInBatch = 256

	store := newBenchStore(b, 3)
	windows := window.New(store)
	tenantID := uuid.New()
	ctx := b.Context()

	keyNames := make([]string, 0, windowsInBatch)
	for i := range windowsInBatch {
		keyNames = append(keyNames, keys.ExactKeyValue(tenantID, fmt.Sprintf("ray-%d", i)))
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, err := windows.MembersMany(ctx, tenantID, keyNames); err != nil {
			b.Fatal(err)
		}
	}
}
