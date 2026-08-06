// Package puller fetches logs from vendors that cannot push to us.
//
// The ordering rule this package exists to enforce: a watermark advances ONLY after
// the fetched events are durably committed. A crash between fetch and commit replays
// the object or page rather than skipping it, which is at-least-once — and the
// deduplication layer absorbs the repeat. Advancing the watermark first would be
// at-most-once, and would lose the batch on any crash.
package puller

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Batch is one unit of fetched data: an object, an API page, or a time slice.
type Batch struct {
	// Payload is the vendor's bytes, verbatim, exactly as a push delivery would carry.
	Payload []byte
	// Watermark identifies this batch's position. It is persisted only after the
	// payload is durably committed, so it must be stable and monotonic for a source.
	Watermark string
	// Label describes the batch for logs — an object key, a cursor, a time range.
	Label string
}

// Source fetches batches from one vendor.
//
// Implementations must be resumable from a watermark and must return batches in a
// stable order, because a crash resumes from the last committed watermark and any
// reordering would silently skip whatever sorted before it.
type Source interface {
	// Vendor names the vendor this source serves.
	Vendor() string
	// Fetch returns batches newer than the watermark, oldest first. An empty result
	// means "nothing new", not an error.
	//
	// It may return BOTH batches and an error: a paging failure part-way through
	// leaves earlier pages perfectly committable, and discarding them would mean
	// re-fetching the same data on every poll while the vendor stays unhealthy. The
	// caller commits what it got and then reports the error, so a vendor outage is
	// still visible rather than silently absorbed.
	Fetch(ctx context.Context, cfg Config, watermark string) ([]Batch, error)
}

// Config is a feed's pull configuration, decoded from its stored JSON.
type Config struct {
	// Endpoint is the object-store or API base URL.
	Endpoint string `json:"endpoint"`
	// Bucket and Prefix locate objects in an object store (Cloudflare Logpush).
	Bucket string `json:"bucket"`
	Prefix string `json:"prefix"`
	// Namespace scopes an API query (F5 Distributed Cloud).
	Namespace string `json:"namespace"`
	// IntervalSeconds is how often to poll. Clamped to a sane floor below.
	IntervalSeconds int `json:"interval_seconds"`
	// MaxBatchesPerPoll bounds one poll's work so a large backlog is drained
	// gradually rather than in one unbounded fetch that could exhaust memory.
	MaxBatchesPerPoll int `json:"max_batches_per_poll"`
}

// Polling bounds.
//
// The floor exists because a misconfigured one-second interval against a vendor's API
// is indistinguishable from an attack and will get the customer rate-limited or
// blocked. The ceiling keeps a typo from silently disabling a feed for a day.
const (
	MinInterval     = 30 * time.Second
	MaxInterval     = 1 * time.Hour
	DefaultInterval = 5 * time.Minute

	defaultMaxBatches = 100
)

// Interval returns the effective poll interval, clamped.
func (c Config) Interval() time.Duration {
	if c.IntervalSeconds <= 0 {
		return DefaultInterval
	}

	interval := time.Duration(c.IntervalSeconds) * time.Second
	if interval < MinInterval {
		return MinInterval
	}
	if interval > MaxInterval {
		return MaxInterval
	}
	return interval
}

// MaxBatches returns the effective per-poll batch cap.
func (c Config) MaxBatches() int {
	if c.MaxBatchesPerPoll <= 0 {
		return defaultMaxBatches
	}
	return c.MaxBatchesPerPoll
}

// ParseConfig decodes a feed's stored pull configuration.
func ParseConfig(raw string) (Config, error) {
	if raw == "" || raw == "{}" {
		return Config{}, fmt.Errorf("puller: the feed has no pull configuration")
	}

	var cfg Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return Config{}, fmt.Errorf("puller: pull configuration is not valid JSON: %w", err)
	}
	if cfg.Endpoint == "" {
		return Config{}, fmt.Errorf("puller: pull configuration needs an endpoint")
	}
	return cfg, nil
}

// Registry resolves sources by vendor name.
type Registry struct {
	sources map[string]Source
}

// NewRegistry builds a registry from the given sources.
func NewRegistry(sources ...Source) *Registry {
	registry := &Registry{sources: make(map[string]Source, len(sources))}
	for _, s := range sources {
		registry.sources[s.Vendor()] = s
	}
	return registry
}

// Get returns the source for a vendor.
func (r *Registry) Get(vendorName string) (Source, bool) {
	source, ok := r.sources[vendorName]
	return source, ok
}
