package window_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/correlate/keys"
	"github.com/menta2k/siem/internal/correlate/window"
)

var (
	winTenant = uuid.MustParse("00000000-0000-4000-8000-0000000000d1")
	winBase   = time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
)

// fakeStore models the Redis operations the window tracker uses, including expiry, so
// the tests exercise the real semantics rather than a stub that always succeeds.
type fakeStore struct {
	mu sync.Mutex

	lists   map[string][]string
	values  map[string]string
	expiry  map[string]time.Time
	zset    map[string]map[string]float64
	now     time.Time
	failAll error
}

func newFakeStore(now time.Time) *fakeStore {
	return &fakeStore{
		lists: map[string][]string{}, values: map[string]string{},
		expiry: map[string]time.Time{},
		zset:   map[string]map[string]float64{},
		now:    now,
	}
}

func (f *fakeStore) alive(key string) bool {
	expiry, ok := f.expiry[key]
	return !ok || expiry.After(f.now)
}

func (f *fakeStore) RPush(_ context.Context, key, value string, ttl time.Duration) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAll != nil {
		return 0, f.failAll
	}
	if !f.alive(key) {
		delete(f.lists, key)
	}
	f.lists[key] = append(f.lists[key], value)
	f.expiry[key] = f.now.Add(ttl)
	return int64(len(f.lists[key])), nil
}

func (f *fakeStore) LRange(_ context.Context, key string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAll != nil {
		return nil, f.failAll
	}
	if !f.alive(key) {
		return nil, nil
	}
	return append([]string(nil), f.lists[key]...), nil
}

func (f *fakeStore) SetNX(_ context.Context, key, value string, ttl time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAll != nil {
		return false, f.failAll
	}
	if existing, ok := f.values[key]; ok && f.alive(key) {
		_ = existing
		return false, nil
	}
	f.values[key] = value
	f.expiry[key] = f.now.Add(ttl)
	return true, nil
}

// Lookup mirrors the real client: an ABSENT key is reported as not-found rather than
// raised. A stub that gets this wrong is exactly how the identity fix reached
// production and failed every close pass.
func (f *fakeStore) Lookup(ctx context.Context, key string) (string, bool, error) {
	value, err := f.Get(ctx, key)
	if err != nil {
		return "", false, err
	}
	if value == "" {
		return "", false, nil
	}
	return value, true, nil
}

func (f *fakeStore) Get(_ context.Context, key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAll != nil {
		return "", f.failAll
	}
	if !f.alive(key) {
		return "", nil
	}
	return f.values[key], nil
}

func (f *fakeStore) ZAdd(
	_ context.Context, key, member string, score float64, ttl time.Duration,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAll != nil {
		return f.failAll
	}
	if f.zset[key] == nil {
		f.zset[key] = map[string]float64{}
	}
	f.zset[key][member] = score
	f.expiry[key] = f.now.Add(ttl)
	return nil
}

func (f *fakeStore) ZPopDue(
	_ context.Context, key string, max float64, limit int64,
) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAll != nil {
		return nil, f.failAll
	}

	var due []string
	for member, score := range f.zset[key] {
		if score <= max && int64(len(due)) < limit {
			due = append(due, member)
		}
	}
	for _, member := range due {
		delete(f.zset[key], member)
	}
	return due, nil
}

func member(id string, at time.Time) window.Member {
	return window.Member{
		EventID: id, Vendor: "cloudflare", EventTime: at,
		ClientIP: "203.0.113.10", RequestHost: "shop.example.com",
	}
}

func TestMembersAccumulate(t *testing.T) {
	store := newFakeStore(winBase)
	windows := window.New(store)
	settings := keys.DefaultSettings()
	ctx := context.Background()

	for _, id := range []string{"a", "b", "c"} {
		if err := windows.Add(ctx, winTenant, "k1", member(id, winBase), settings); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}

	members, err := windows.Members(ctx, winTenant, "k1")
	if err != nil {
		t.Fatalf("Members: %v", err)
	}
	if len(members) != 3 {
		t.Errorf("got %d members, want 3", len(members))
	}
}

// A redelivered event must not appear twice in a record, and must not inflate the
// candidate count into reporting a false ambiguity.
func TestRedeliveredMembersAreCollapsed(t *testing.T) {
	store := newFakeStore(winBase)
	windows := window.New(store)
	settings := keys.DefaultSettings()
	ctx := context.Background()

	for range 4 {
		if err := windows.Add(ctx, winTenant, "k1", member("dup", winBase), settings); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}

	members, err := windows.Members(ctx, winTenant, "k1")
	if err != nil {
		t.Fatalf("Members: %v", err)
	}
	if len(members) != 1 {
		t.Errorf("got %d members for one redelivered event, want 1", len(members))
	}
}

// A single corrupt entry must not sink the whole window: the rest of the evidence is
// still valid and a partial record beats no record.
func TestACorruptMemberDoesNotDiscardTheWindow(t *testing.T) {
	store := newFakeStore(winBase)
	windows := window.New(store)
	settings := keys.DefaultSettings()
	ctx := context.Background()

	if err := windows.Add(ctx, winTenant, "k1", member("good", winBase), settings); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Corrupt entry injected directly, as a bad write or a partial flush would leave it.
	store.mu.Lock()
	for key := range store.lists {
		if strings.Contains(key, "members") {
			store.lists[key] = append(store.lists[key], "{not json")
		}
	}
	store.mu.Unlock()

	members, err := windows.Members(ctx, winTenant, "k1")
	if err != nil {
		t.Fatalf("Members: %v", err)
	}
	if len(members) != 1 {
		t.Errorf("got %d members, want the one readable entry", len(members))
	}
}

// Identity is assigned once and reused. Recomputing it after a tier change would
// produce a SECOND row rather than amending the first, and the schema has no way to
// supersede a row — the orphan would be permanent.
func TestIdentityIsStableOnceClaimed(t *testing.T) {
	store := newFakeStore(winBase)
	windows := window.New(store)
	settings := keys.DefaultSettings()
	ctx := context.Background()

	first := uuid.New()
	claimed, err := windows.Identity(ctx, winTenant, "k1", first, settings)
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if claimed != first {
		t.Errorf("first claim returned %s, want %s", claimed, first)
	}

	// A later caller proposing a DIFFERENT id must get the original back.
	again, err := windows.Identity(ctx, winTenant, "k1", uuid.New(), settings)
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if again != first {
		t.Errorf("identity changed to %s; the amendment would write a second row", again)
	}
}

// Two workers can close the same window concurrently; exactly one identity must win.
func TestConcurrentIdentityClaimsAgree(t *testing.T) {
	store := newFakeStore(winBase)
	windows := window.New(store)
	settings := keys.DefaultSettings()

	const workers = 20
	results := make([]uuid.UUID, workers)

	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id, err := windows.Identity(
				context.Background(), winTenant, "k1", uuid.New(), settings)
			if err == nil {
				results[i] = id
			}
		}(i)
	}
	wg.Wait()

	for i, id := range results {
		if id != results[0] {
			t.Fatalf("worker %d got identity %s, worker 0 got %s", i, id, results[0])
		}
	}
}

// Windows are scheduled from the EVENT time, not from arrival: measuring from arrival
// would let a backlogged feed keep pushing its windows into the future, so a replay of
// yesterday's logs would never close anything.
func TestDueClaimsWindowsPastTheirDeadline(t *testing.T) {
	store := newFakeStore(winBase)
	windows := window.New(store)
	settings := keys.DefaultSettings()
	ctx := context.Background()

	if err := windows.Schedule(ctx, winTenant, "k1", winBase, settings); err != nil {
		t.Fatalf("Schedule: %v", err)
	}

	// Before the deadline: nothing is due.
	early, err := windows.Due(ctx, winBase, 10)
	if err != nil {
		t.Fatalf("Due: %v", err)
	}
	if len(early) != 0 {
		t.Errorf("%d windows claimed before their deadline", len(early))
	}

	// After the window plus its grace period.
	late, err := windows.Due(ctx, winBase.Add(2*time.Minute), 10)
	if err != nil {
		t.Fatalf("Due: %v", err)
	}
	if len(late) != 1 {
		t.Fatalf("%d windows claimed after the deadline, want 1", len(late))
	}
	if late[0].TenantID != winTenant || late[0].Key != "k1" {
		t.Errorf("claimed %+v, want tenant %s key k1", late[0], winTenant)
	}
}

// Claiming removes the window from the schedule, so each closed window is handed to
// exactly one worker. Two workers emitting the same window is a duplicate record.
func TestDueClaimsEachWindowOnce(t *testing.T) {
	store := newFakeStore(winBase)
	windows := window.New(store)
	settings := keys.DefaultSettings()
	ctx := context.Background()

	if err := windows.Schedule(ctx, winTenant, "k1", winBase, settings); err != nil {
		t.Fatalf("Schedule: %v", err)
	}

	first, err := windows.Due(ctx, winBase.Add(2*time.Minute), 10)
	if err != nil {
		t.Fatalf("Due: %v", err)
	}
	second, err := windows.Due(ctx, winBase.Add(2*time.Minute), 10)
	if err != nil {
		t.Fatalf("Due: %v", err)
	}

	if len(first) != 1 || len(second) != 0 {
		t.Errorf("claimed %d then %d, want the window handed out exactly once",
			len(first), len(second))
	}
}

// The TTL must cover the lateness bound, or a record cannot be amended right up to
// the deadline the platform advertises.
func TestTTLCoversTheLatenessBound(t *testing.T) {
	windows := window.New(newFakeStore(winBase))

	settings := keys.Settings{Window: 5 * time.Second, LatenessBound: time.Hour}
	if got := windows.TTL(settings); got < settings.LatenessBound {
		t.Errorf("TTL %s is shorter than the lateness bound %s", got, settings.LatenessBound)
	}
}

// Unset settings must fall back to platform defaults rather than producing a zero TTL,
// which Redis rejects and which would discard window state immediately.
func TestZeroSettingsFallBackToDefaults(t *testing.T) {
	windows := window.New(newFakeStore(winBase))

	if got := windows.TTL(keys.Settings{}); got <= 0 {
		t.Errorf("TTL for unset settings = %s, want a positive default", got)
	}
}

func TestStoreFailuresSurface(t *testing.T) {
	store := newFakeStore(winBase)
	store.failAll = errors.New("redis unavailable")
	windows := window.New(store)
	settings := keys.DefaultSettings()
	ctx := context.Background()

	if err := windows.Add(ctx, winTenant, "k1", member("a", winBase), settings); err == nil {
		t.Error("a failed write was reported as success")
	}
	if _, err := windows.Members(ctx, winTenant, "k1"); err == nil {
		t.Error("a failed read was reported as success")
	}
	if _, err := windows.Due(ctx, winBase, 10); err == nil {
		t.Error("a failed claim was reported as success")
	}
}

// RPushMany and ZAddMany delegate to the single-key methods, so the fake proves the
// batch path produces the SAME state as the one-at-a-time path rather than a
// separately-modelled one that could drift from it.
func (f *fakeStore) RPushMany(ctx context.Context, entries []window.ListEntry) error {
	for _, entry := range entries {
		if _, err := f.RPush(ctx, entry.Key, entry.Value, entry.TTL); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeStore) ZAddMany(ctx context.Context, entries []window.ScoreEntry) error {
	for _, entry := range entries {
		if err := f.ZAdd(ctx, entry.Key, entry.Member, entry.Score, entry.TTL); err != nil {
			return err
		}
	}
	return nil
}
