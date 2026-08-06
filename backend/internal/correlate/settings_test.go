package correlate_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/correlate"
	"github.com/menta2k/siem/internal/correlate/keys"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
)

var settingsTenant = uuid.MustParse("00000000-0000-4000-8000-0000000000ff")

// stubTenants records how often it was read, so caching can be asserted rather than
// assumed.
type stubTenants struct {
	mu     sync.Mutex
	tenant chdata.Tenant
	err    error
	calls  int
}

func (s *stubTenants) GetByID(context.Context, uuid.UUID) (chdata.Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return s.tenant, s.err
}

func (s *stubTenants) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *stubTenants) set(tenant chdata.Tenant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tenant = tenant
}

func TestTenantSettingsAreApplied(t *testing.T) {
	tenants := &stubTenants{tenant: chdata.Tenant{
		ID: settingsTenant, CorrelationWindowMS: 2000,
		LatenessBoundMS: 60_000, ScoreConflictThreshold: 0.6,
	}}
	cache := correlate.NewSettingsCache(tenants, time.Minute)

	got := cache.For(context.Background(), settingsTenant)
	if got.Keys.Window != 2*time.Second {
		t.Errorf("window = %v, want 2s", got.Keys.Window)
	}
	if got.Keys.LatenessBound != time.Minute {
		t.Errorf("lateness bound = %v, want 1m", got.Keys.LatenessBound)
	}
	if got.ScoreConflictThreshold != 0.6 {
		t.Errorf("score threshold = %v, want 0.6", got.ScoreConflictThreshold)
	}
}

// Correlation must not stop because the tenant table is briefly unreadable. Dropping
// events would be the alternative, and correlating on defaults beats not correlating.
func TestUnreadableTenantFallsBackToDefaults(t *testing.T) {
	tenants := &stubTenants{err: errors.New("clickhouse unavailable")}
	cache := correlate.NewSettingsCache(tenants, time.Minute)

	got := cache.For(context.Background(), settingsTenant)
	if got.Keys.Window != keys.DefaultSettings().Window {
		t.Errorf("window = %v, want the platform default", got.Keys.Window)
	}
	if got.ScoreConflictThreshold <= 0 {
		t.Error("score threshold fell back to zero, which would report every allowed " +
			"request as a score conflict")
	}
}

// A window of hours would join every request a client made in that time into one
// record — not a slow correlation but a wrong one, and silently so.
func TestOutOfRangeSettingsAreClamped(t *testing.T) {
	cases := map[string]struct {
		tenant chdata.Tenant
		check  func(*testing.T, correlate.Resolved)
	}{
		"window far too large": {
			tenant: chdata.Tenant{CorrelationWindowMS: 86_400_000},
			check: func(t *testing.T, r correlate.Resolved) {
				if r.Keys.Window != correlate.MaxWindow {
					t.Errorf("window = %v, want it clamped to %v", r.Keys.Window, correlate.MaxWindow)
				}
			},
		},
		"window far too small": {
			tenant: chdata.Tenant{CorrelationWindowMS: 1},
			check: func(t *testing.T, r correlate.Resolved) {
				if r.Keys.Window != correlate.MinWindow {
					t.Errorf("window = %v, want it clamped to %v", r.Keys.Window, correlate.MinWindow)
				}
			},
		},
		"lateness bound too large": {
			tenant: chdata.Tenant{LatenessBoundMS: 7 * 24 * 3600 * 1000},
			check: func(t *testing.T, r correlate.Resolved) {
				if r.Keys.LatenessBound != correlate.MaxLatenessBound {
					t.Errorf("lateness bound = %v, want it clamped", r.Keys.LatenessBound)
				}
			},
		},
		"threshold of zero": {
			tenant: chdata.Tenant{ScoreConflictThreshold: 0},
			check: func(t *testing.T, r correlate.Resolved) {
				if r.ScoreConflictThreshold != correlate.DefaultResolved().ScoreConflictThreshold {
					t.Errorf("threshold = %v, want the default; zero would flag everything",
						r.ScoreConflictThreshold)
				}
			},
		},
		"threshold above one": {
			tenant: chdata.Tenant{ScoreConflictThreshold: 4.2},
			check: func(t *testing.T, r correlate.Resolved) {
				if r.ScoreConflictThreshold > 1 {
					t.Errorf("threshold = %v, want the default; nothing could ever reach 4.2",
						r.ScoreConflictThreshold)
				}
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cache := correlate.NewSettingsCache(&stubTenants{tenant: tc.tenant}, time.Minute)
			tc.check(t, cache.For(context.Background(), settingsTenant))
		})
	}
}

func TestSettingsAreCached(t *testing.T) {
	tenants := &stubTenants{tenant: chdata.Tenant{CorrelationWindowMS: 2000}}
	cache := correlate.NewSettingsCache(tenants, time.Minute)

	for range 10 {
		cache.For(context.Background(), settingsTenant)
	}
	if got := tenants.callCount(); got != 1 {
		t.Errorf("tenant read %d times, want 1; a lookup per event would put a "+
			"ClickHouse query on a 15k/sec path", got)
	}
}

// The point of the cache is hot reload: an operator changing the window must not have
// to wait for a deploy, and after an explicit invalidation must not wait at all.
func TestInvalidateForcesAReload(t *testing.T) {
	tenants := &stubTenants{tenant: chdata.Tenant{CorrelationWindowMS: 2000}}
	cache := correlate.NewSettingsCache(tenants, time.Minute)

	if got := cache.For(context.Background(), settingsTenant).Keys.Window; got != 2*time.Second {
		t.Fatalf("window = %v, want 2s", got)
	}

	tenants.set(chdata.Tenant{CorrelationWindowMS: 8000})
	cache.Invalidate(settingsTenant)

	if got := cache.For(context.Background(), settingsTenant).Keys.Window; got != 8*time.Second {
		t.Errorf("window = %v, want 8s after invalidation", got)
	}
}

func TestConcurrentReadsAreSafe(t *testing.T) {
	tenants := &stubTenants{tenant: chdata.Tenant{CorrelationWindowMS: 2000}}
	cache := correlate.NewSettingsCache(tenants, time.Minute)

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%10 == 0 {
				cache.Invalidate(settingsTenant)
			}
			cache.For(context.Background(), settingsTenant)
		}(i)
	}
	wg.Wait()
}
