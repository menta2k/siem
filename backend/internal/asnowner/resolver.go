package asnowner

import (
	"context"
	"sync"
	"time"
)

// NameReader resolves AS numbers to owner names.
type NameReader interface {
	NamesFor(ctx context.Context, asns []uint32) (map[uint32]string, error)
}

// DefaultCacheTTL is how long a resolved name is reused.
//
// An hour, against a table refreshed daily. The value is not the freshness of the data —
// that is a day at best — it is how long a name survives without a query. AS ownership
// does not change while an analyst is reading a page, and a dashboard load asking
// ClickHouse to re-resolve the same ten networks every few seconds is pure overhead on
// the hot path.
const DefaultCacheTTL = time.Hour

// Resolver names networks for the read paths, caching what it has already looked up.
//
// Names are DECORATION. Every method here degrades to "no name" rather than to an error:
// a panel that fails to render because a label was unavailable would be a strictly worse
// product than one showing a bare AS number, which is what it showed before this existed.
type Resolver struct {
	reader NameReader
	ttl    time.Duration
	now    func() time.Time

	mu     sync.RWMutex
	names  map[uint32]string
	loaded map[uint32]time.Time
}

// NewResolver constructs a resolver over the owner table.
func NewResolver(reader NameReader, ttl time.Duration) *Resolver {
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	return &Resolver{
		reader: reader,
		ttl:    ttl,
		now:    time.Now,
		names:  map[uint32]string{},
		loaded: map[uint32]time.Time{},
	}
}

// Names resolves a set of AS numbers, returning only those it could name.
//
// A lookup failure yields what is already cached rather than an error, for the reason
// in the type comment. The caller renders whatever comes back.
func (r *Resolver) Names(ctx context.Context, asns []uint32) map[uint32]string {
	if r == nil || len(asns) == 0 {
		return map[uint32]string{}
	}

	resolved, missing := r.cached(asns)
	if len(missing) == 0 {
		return resolved
	}

	fetched, err := r.reader.NamesFor(ctx, missing)
	if err != nil {
		return resolved
	}

	// A MISS IS CACHED TOO, as an empty name. Most unnamed ASNs are unnamed because the
	// published table does not list them, so without this every page view re-queries
	// for the same networks that will never resolve.
	at := r.now()
	r.mu.Lock()
	for _, asn := range missing {
		r.names[asn] = fetched[asn]
		r.loaded[asn] = at
	}
	r.mu.Unlock()

	for asn, name := range fetched {
		if name != "" {
			resolved[asn] = name
		}
	}
	return resolved
}

// Name resolves a single AS number, returning "" when it is unknown.
func (r *Resolver) Name(ctx context.Context, asn uint32) string {
	if asn == 0 {
		return ""
	}
	return r.Names(ctx, []uint32{asn})[asn]
}

// cached splits the request into what is already known and what must be fetched.
func (r *Resolver) cached(asns []uint32) (resolved map[uint32]string, missing []uint32) {
	resolved = make(map[uint32]string, len(asns))
	cutoff := r.now().Add(-r.ttl)

	r.mu.RLock()
	defer r.mu.RUnlock()

	seen := make(map[uint32]struct{}, len(asns))
	for _, asn := range asns {
		if asn == 0 {
			continue
		}
		// The same network appears on many rows of a panel; asking for it once is the
		// point of collecting the ids before resolving them.
		if _, duplicate := seen[asn]; duplicate {
			continue
		}
		seen[asn] = struct{}{}

		at, known := r.loaded[asn]
		if !known || at.Before(cutoff) {
			missing = append(missing, asn)
			continue
		}
		if name := r.names[asn]; name != "" {
			resolved[asn] = name
		}
	}
	return resolved, missing
}
