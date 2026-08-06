package correlate

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/correlate/keys"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/normalize"
)

// Bounds on tenant-supplied correlation settings.
//
// These are clamps, not validation errors, because they are applied on the hot path
// where there is nobody to report an error to. The API validates on write; this is the
// backstop that keeps a bad row — from a migration, a seed script, or a direct
// ClickHouse edit — from taking correlation down for that tenant.
//
// The upper window bound matters most. A window of hours would join every request a
// client made in that time into one record, which is not a slow correlation but a
// wrong one, and it would do so silently.
const (
	MinWindow        = 100 * time.Millisecond
	MaxWindow        = 5 * time.Minute
	MinLatenessBound = time.Second
	MaxLatenessBound = 24 * time.Hour
)

// SettingsSource supplies a tenant's correlation settings.
//
// An interface so the workers do not have to reach a tenant repository — and so a test
// can pin the settings without standing up ClickHouse.
type SettingsSource interface {
	For(ctx context.Context, tenantID uuid.UUID) Resolved
}

// FixedSettings is a SettingsSource that returns the same values for every tenant.
type FixedSettings struct{ Value Resolved }

// For returns the fixed settings.
func (f FixedSettings) For(context.Context, uuid.UUID) Resolved { return f.Value }

// TenantLookup reads tenant configuration.
type TenantLookup interface {
	GetByID(ctx context.Context, tenantID uuid.UUID) (chdata.Tenant, error)
}

// DefaultSettingsTTL is how long a tenant's settings are cached.
//
// Hot reload without a restart, at the cost of a bounded staleness window. A change
// takes effect within this interval; the alternative — reading the tenant row for
// every event — puts a ClickHouse query on a 15k/sec path.
const DefaultSettingsTTL = 30 * time.Second

// SettingsCache resolves per-tenant correlation parameters.
//
// Values are cached per tenant and refreshed on expiry, so an operator's change to the
// correlation window applies to the running workers without a deploy (FR-020).
type SettingsCache struct {
	tenants TenantLookup
	ttl     time.Duration
	now     func() time.Time

	mu     sync.RWMutex
	cached map[uuid.UUID]cachedSettings
}

// Resolved is one tenant's correlation configuration.
type Resolved struct {
	Keys keys.Settings
	// ScoreConflictThreshold is the normalized bot score at or above which an allowed
	// request is reported as a conflict.
	ScoreConflictThreshold float32
}

type cachedSettings struct {
	value     Resolved
	expiresAt time.Time
}

// NewSettingsCache builds a settings resolver.
func NewSettingsCache(tenants TenantLookup, ttl time.Duration) *SettingsCache {
	if ttl <= 0 {
		ttl = DefaultSettingsTTL
	}
	return &SettingsCache{
		tenants: tenants,
		ttl:     ttl,
		now:     time.Now,
		cached:  map[uuid.UUID]cachedSettings{},
	}
}

// DefaultResolved is the platform default, used when a tenant cannot be read.
func DefaultResolved() Resolved {
	return Resolved{
		Keys:                   keys.DefaultSettings(),
		ScoreConflictThreshold: normalize.DefaultScoreConflictThreshold,
	}
}

// For returns a tenant's correlation settings.
//
// A lookup failure yields the platform defaults rather than an error. Correlation must
// not stop because the tenant table is briefly unreadable: the alternative is dropping
// events on the floor, and correlating them with default parameters is strictly better
// than not correlating them at all.
func (s *SettingsCache) For(ctx context.Context, tenantID uuid.UUID) Resolved {
	if cached, ok := s.lookup(tenantID); ok {
		return cached
	}

	resolved := DefaultResolved()
	if tenant, err := s.tenants.GetByID(ctx, tenantID); err == nil {
		resolved = fromTenant(tenant)
	}

	s.mu.Lock()
	s.cached[tenantID] = cachedSettings{value: resolved, expiresAt: s.now().Add(s.ttl)}
	s.mu.Unlock()

	return resolved
}

// Invalidate drops a tenant's cached settings so the next read reloads them.
//
// Called when the settings are updated through the API, which turns the TTL into a
// staleness ceiling rather than the normal path: an operator who changes the window
// sees it applied immediately instead of wondering whether it took.
func (s *SettingsCache) Invalidate(tenantID uuid.UUID) {
	s.mu.Lock()
	delete(s.cached, tenantID)
	s.mu.Unlock()
}

func (s *SettingsCache) lookup(tenantID uuid.UUID) (Resolved, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cached, ok := s.cached[tenantID]
	if !ok || s.now().After(cached.expiresAt) {
		return Resolved{}, false
	}
	return cached.value, true
}

// fromTenant converts stored tenant configuration into correlation settings.
func fromTenant(t chdata.Tenant) Resolved {
	defaults := DefaultResolved()

	resolved := Resolved{
		Keys: keys.Settings{
			Window: clampDuration(
				time.Duration(t.CorrelationWindowMS)*time.Millisecond,
				MinWindow, MaxWindow, defaults.Keys.Window),
			LatenessBound: clampDuration(
				time.Duration(t.LatenessBoundMS)*time.Millisecond,
				MinLatenessBound, MaxLatenessBound, defaults.Keys.LatenessBound),
		},
		ScoreConflictThreshold: defaults.ScoreConflictThreshold,
	}

	// A threshold outside (0, 1] is not a tuning choice, it is a broken row: 0 would
	// report every allowed request as a score conflict, and above 1 nothing could ever
	// reach it. Either way the setting is ignored in favour of the default.
	if t.ScoreConflictThreshold > 0 && t.ScoreConflictThreshold <= 1 {
		resolved.ScoreConflictThreshold = t.ScoreConflictThreshold
	}
	return resolved
}

// clampDuration bounds a configured duration, falling back when it is unset.
func clampDuration(value, minimum, maximum, fallback time.Duration) time.Duration {
	switch {
	case value <= 0:
		return fallback
	case value < minimum:
		return minimum
	case value > maximum:
		return maximum
	default:
		return value
	}
}
