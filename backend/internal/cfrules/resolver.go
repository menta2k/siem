package cfrules

import (
	"context"
	"sync"
	"time"

	"github.com/menta2k/siem/internal/tenancy"
)

// DescriptionReader resolves rule ids to descriptions within the caller's tenant.
type DescriptionReader interface {
	DescriptionsFor(ctx context.Context, ruleIDs []string) (map[string]string, error)
}

// DefaultCacheTTL is how long a resolved name is reused.
//
// Five minutes, against a table refreshed hourly. Short because a rule RENAME should
// reach the console promptly — an analyst searching for a name they were just told about
// should not be reading an hour-old label — and the lookup is cheap enough that a longer
// window buys little.
const DefaultCacheTTL = 5 * time.Minute

// cacheKey scopes an entry to a tenant.
//
// The tenant is part of the KEY, not a filter applied afterwards. These are one
// customer's rule names held in a process shared by all of them, and a cache keyed on the
// rule id alone would serve tenant A's description to tenant B for any id they had in
// common — which the Cloudflare-managed rulesets guarantee, since every customer is
// deployed the same managed rule ids.
type cacheKey struct {
	tenant string
	ruleID string
}

// Resolver names rules for the read paths, caching what it has looked up.
//
// Names are DECORATION. Every method degrades to "no name" rather than to an error: a
// search that failed because a label was unavailable would be a strictly worse product
// than one showing the bare rule id, which is what it showed before this existed.
type Resolver struct {
	reader DescriptionReader
	ttl    time.Duration
	now    func() time.Time

	mu     sync.RWMutex
	names  map[cacheKey]string
	loaded map[cacheKey]time.Time
}

// NewResolver constructs a resolver over the rule table.
func NewResolver(reader DescriptionReader, ttl time.Duration) *Resolver {
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	return &Resolver{
		reader: reader,
		ttl:    ttl,
		now:    time.Now,
		names:  map[cacheKey]string{},
		loaded: map[cacheKey]time.Time{},
	}
}

// Describe resolves rule ids, returning only those it could name.
func (r *Resolver) Describe(ctx context.Context, ruleIDs []string) map[string]string {
	resolved := map[string]string{}
	if r == nil || len(ruleIDs) == 0 {
		return resolved
	}

	// Without a tenant there is nothing safe to answer: an unscoped lookup is exactly
	// the cross-tenant leak this type is careful about elsewhere.
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return resolved
	}
	tenant := tenantID.String()

	missing := r.cached(tenant, ruleIDs, resolved)
	if len(missing) == 0 {
		return resolved
	}

	found, err := r.reader.DescriptionsFor(ctx, missing)
	if err != nil {
		return resolved
	}

	// A MISS IS CACHED TOO, as an empty name: a rule deleted from Cloudflare since the
	// event was logged will never resolve, and without this every page view would ask
	// again for exactly the ids that cannot be answered.
	at := r.now()
	r.mu.Lock()
	for _, ruleID := range missing {
		entry := cacheKey{tenant: tenant, ruleID: ruleID}
		r.names[entry] = found[ruleID]
		r.loaded[entry] = at
	}
	r.mu.Unlock()

	for ruleID, name := range found {
		if name != "" {
			resolved[ruleID] = name
		}
	}
	return resolved
}

// cached fills in what is already known and returns what must be fetched.
func (r *Resolver) cached(
	tenant string, ruleIDs []string, resolved map[string]string,
) []string {
	cutoff := r.now().Add(-r.ttl)

	r.mu.RLock()
	defer r.mu.RUnlock()

	var missing []string
	seen := make(map[cacheKey]struct{}, len(ruleIDs))

	for _, ruleID := range ruleIDs {
		if ruleID == "" {
			continue
		}
		entry := cacheKey{tenant: tenant, ruleID: ruleID}
		// One page repeats the same rule across many rows; asking once is the point of
		// collecting the ids before resolving them.
		if _, duplicate := seen[entry]; duplicate {
			continue
		}
		seen[entry] = struct{}{}

		at, known := r.loaded[entry]
		if !known || at.Before(cutoff) {
			missing = append(missing, ruleID)
			continue
		}
		if name := r.names[entry]; name != "" {
			resolved[ruleID] = name
		}
	}
	return missing
}
