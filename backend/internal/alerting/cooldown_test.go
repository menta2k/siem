package alerting_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/alerting"
)

// fakeCooldownStore models Redis SETNX with expiry, so the tests exercise the real
// claim semantics rather than a boolean the test controls directly.
type fakeCooldownStore struct {
	mu      sync.Mutex
	keys    map[string]time.Time
	now     time.Time
	err     error
	setCall int
}

func newFakeStore(now time.Time) *fakeCooldownStore {
	return &fakeCooldownStore{keys: map[string]time.Time{}, now: now}
}

func (f *fakeCooldownStore) SetNX(
	_ context.Context, key, _ string, ttl time.Duration,
) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.setCall++
	if f.err != nil {
		return false, f.err
	}
	if expiry, exists := f.keys[key]; exists && expiry.After(f.now) {
		return false, nil
	}
	f.keys[key] = f.now.Add(ttl)
	return true, nil
}

func (f *fakeCooldownStore) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

var (
	cdTenant = uuid.MustParse("00000000-0000-4000-8000-0000000000b1")
	cdRule   = uuid.MustParse("00000000-0000-4000-8000-0000000000b2")
	cdNow    = time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
)

func TestSecondWindowInsideTheCooldownIsSuppressed(t *testing.T) {
	store := newFakeStore(cdNow)
	cooldown := alerting.NewCooldown(store)
	ctx := context.Background()

	first, err := cooldown.Allow(ctx, cdTenant, cdRule, nil, 15*time.Minute)
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if !first {
		t.Fatal("the first qualifying window did not fire")
	}

	store.advance(5 * time.Minute)

	second, err := cooldown.Allow(ctx, cdTenant, cdRule, nil, 15*time.Minute)
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if second {
		t.Error("a second window inside the cooldown fired")
	}
}

func TestTheFirstWindowAfterTheCooldownFires(t *testing.T) {
	store := newFakeStore(cdNow)
	cooldown := alerting.NewCooldown(store)
	ctx := context.Background()

	if _, err := cooldown.Allow(ctx, cdTenant, cdRule, nil, 15*time.Minute); err != nil {
		t.Fatalf("Allow: %v", err)
	}

	store.advance(16 * time.Minute)

	again, err := cooldown.Allow(ctx, cdTenant, cdRule, nil, 15*time.Minute)
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if !again {
		t.Error("the first window after the cooldown did not fire")
	}
}

// A rule firing for one host must not silence the same rule for a different host —
// that hides the second incident behind the first, which nobody would think to check.
func TestCooldownIsPerGroup(t *testing.T) {
	store := newFakeStore(cdNow)
	cooldown := alerting.NewCooldown(store)
	ctx := context.Background()

	hostA := map[string]string{"request_host": "a.example.com"}
	hostB := map[string]string{"request_host": "b.example.com"}

	firstA, err := cooldown.Allow(ctx, cdTenant, cdRule, hostA, 15*time.Minute)
	if err != nil || !firstA {
		t.Fatalf("host A did not fire: %v", err)
	}

	firstB, err := cooldown.Allow(ctx, cdTenant, cdRule, hostB, 15*time.Minute)
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if !firstB {
		t.Error("host B was suppressed by host A's cooldown")
	}

	repeatA, err := cooldown.Allow(ctx, cdTenant, cdRule, hostA, 15*time.Minute)
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if repeatA {
		t.Error("host A fired twice inside its cooldown")
	}
}

// Two tenants running identical rules must not suppress each other.
func TestCooldownIsPerTenant(t *testing.T) {
	store := newFakeStore(cdNow)
	cooldown := alerting.NewCooldown(store)
	ctx := context.Background()
	other := uuid.MustParse("00000000-0000-4000-8000-0000000000b9")

	if _, err := cooldown.Allow(ctx, cdTenant, cdRule, nil, 15*time.Minute); err != nil {
		t.Fatalf("Allow: %v", err)
	}

	fired, err := cooldown.Allow(ctx, other, cdRule, nil, 15*time.Minute)
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if !fired {
		t.Error("one tenant's cooldown suppressed another tenant's alert")
	}
}

// Go map iteration is randomised. An unsorted key would differ between two evaluations
// of the same group, so the cooldown would never match itself and every window fires.
func TestTheKeyIsStableAcrossMapOrdering(t *testing.T) {
	group := map[string]string{
		"request_host": "shop.example.com",
		"country":      "DE",
		"client_ip":    "203.0.113.10",
	}

	first := alerting.CooldownKey(cdTenant, cdRule, group)
	for range 50 {
		if got := alerting.CooldownKey(cdTenant, cdRule, group); got != first {
			t.Fatalf("key changed between calls: %q vs %q", got, first)
		}
	}
}

// Group values are attacker-influenced — a hostname, a client address — so two
// distinct groups must not be able to collide onto one cooldown and silence each other.
func TestDistinctGroupsProduceDistinctKeys(t *testing.T) {
	groups := []map[string]string{
		{"a": "b", "c": "d"},
		{"a": "b:c", "c": "d"},
		{"a": "b", "c": "d:e"},
		{"ac": "bd"},
		{"a": "bcd"},
	}

	seen := map[string]int{}
	for i, group := range groups {
		key := alerting.CooldownKey(cdTenant, cdRule, group)
		if previous, clash := seen[key]; clash {
			t.Errorf("groups %d and %d collided onto one cooldown key", previous, i)
		}
		seen[key] = i
	}
}

// Failing open would turn a Redis outage into an alert storm, at exactly the moment
// operators are least able to absorb one.
func TestAStoreFailureSuppressesRatherThanFloods(t *testing.T) {
	store := newFakeStore(cdNow)
	store.err = errors.New("redis unavailable")

	fired, err := alerting.NewCooldown(store).
		Allow(context.Background(), cdTenant, cdRule, nil, 15*time.Minute)

	if err == nil {
		t.Error("a store failure was reported as success")
	}
	if fired {
		t.Error("an alert fired despite the cooldown being unreadable")
	}
}

// Claim and check are one atomic operation. Two processors evaluating the same rule
// concurrently must produce exactly one alert.
func TestConcurrentEvaluationsFireOnce(t *testing.T) {
	store := newFakeStore(cdNow)
	cooldown := alerting.NewCooldown(store)

	const workers = 20
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		fires int
	)

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			allowed, err := cooldown.Allow(
				context.Background(), cdTenant, cdRule, nil, 15*time.Minute)
			if err == nil && allowed {
				mu.Lock()
				fires++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if fires != 1 {
		t.Errorf("%d of %d concurrent evaluations fired, want exactly 1", fires, workers)
	}
}

// A rule with no cooldown fires every window. That is a valid choice for a
// low-frequency rule, so it is honoured rather than silently overridden.
func TestZeroCooldownAlwaysFires(t *testing.T) {
	store := newFakeStore(cdNow)
	cooldown := alerting.NewCooldown(store)
	ctx := context.Background()

	for i := range 3 {
		allowed, err := cooldown.Allow(ctx, cdTenant, cdRule, nil, 0)
		if err != nil {
			t.Fatalf("Allow: %v", err)
		}
		if !allowed {
			t.Errorf("evaluation %d was suppressed by a zero cooldown", i)
		}
	}
	if store.setCall != 0 {
		t.Error("a zero cooldown still wrote to the store")
	}
}

func TestDescribeGroupIsStableAndReadable(t *testing.T) {
	group := map[string]string{"request_host": "shop.example.com", "country": "DE"}

	first := alerting.DescribeGroup(group)
	for range 20 {
		if got := alerting.DescribeGroup(group); got != first {
			t.Fatalf("description changed between calls: %q vs %q", got, first)
		}
	}
	if first != "country=DE request_host=shop.example.com" {
		t.Errorf("description = %q, want the fields sorted by name", first)
	}
	if alerting.DescribeGroup(nil) != "" {
		t.Error("an ungrouped alert produced a group description")
	}
}
