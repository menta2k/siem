package filter

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

// DefaultCacheTTL bounds how stale a tenant's filters may be.
//
// Short enough that a rule change takes effect while the operator is still watching, long
// enough that a tenant reading per delivery does not become a database query per thousand
// events.
const DefaultCacheTTL = 30 * time.Second

// TenantLookup reads the stored rules for a tenant. Narrow on purpose: this package must
// not depend on the tenant row's shape.
type TenantLookup interface {
	IngestFilters(ctx context.Context, tenantID uuid.UUID) (string, error)
}

type cached struct {
	set     Set
	expires time.Time
}

// Cache resolves a tenant's compiled filter set, memoised for a short interval.
type Cache struct {
	tenants TenantLookup
	ttl     time.Duration
	now     func() time.Time

	mu     sync.Mutex
	byWhom map[uuid.UUID]cached
}

// NewCache constructs the cache.
func NewCache(tenants TenantLookup, ttl time.Duration) *Cache {
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	return &Cache{
		tenants: tenants, ttl: ttl, now: time.Now,
		byWhom: map[uuid.UUID]cached{},
	}
}

// For returns a tenant's filters.
//
// A LOOKUP FAILURE YIELDS NO FILTERS, so a briefly unreadable tenant table ingests
// everything rather than dropping it. That direction is not arbitrary: ingesting an event
// that should have been filtered wastes storage and can be corrected later, while dropping
// one that should have been kept destroys it permanently. Failure must fall towards the
// recoverable mistake.
func (c *Cache) For(ctx context.Context, tenantID uuid.UUID) Set {
	// A nil cache filters nothing. Same reasoning as every other failure path here: a
	// caller that was never given one must ingest everything rather than drop everything.
	if c == nil {
		return Set{}
	}
	if set, ok := c.lookup(tenantID); ok {
		return set
	}

	encoded, err := c.tenants.IngestFilters(ctx, tenantID)
	if err != nil {
		return Set{}
	}

	rules, err := Decode(encoded)
	if err != nil {
		return Set{}
	}
	set, err := Compile(rules)
	if err != nil {
		// Stored rules that no longer compile — written before a validation rule, or by
		// hand. Filtering on a set we cannot fully understand risks dropping the wrong
		// traffic, so nothing is filtered until it is fixed.
		return Set{}
	}

	c.store(tenantID, set)
	return set
}

func (c *Cache) lookup(tenantID uuid.UUID) (Set, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.byWhom[tenantID]
	if !ok || c.now().After(entry.expires) {
		return Set{}, false
	}
	return entry.set, true
}

func (c *Cache) store(tenantID uuid.UUID, set Set) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byWhom[tenantID] = cached{set: set, expires: c.now().Add(c.ttl)}
}
