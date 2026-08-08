package correlate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/correlate/group"
	"github.com/menta2k/siem/internal/correlate/keys"
	"github.com/menta2k/siem/internal/correlate/window"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/tenancy"
)

// CorrelatedStore is the storage surface the closer writes through.
type CorrelatedStore interface {
	Insert(ctx context.Context, records []chdata.CorrelatedRequest) error
	// Versions reports the current version of each id that already exists. Ids with
	// no record are absent, which is how "this is a new record" is expressed.
	Versions(ctx context.Context, correlationIDs []uuid.UUID) (map[uuid.UUID]uint64, error)
}

// DefaultPollInterval is how often the closer looks for windows that have closed.
//
// It is really the batch-size control. Each tick writes one insert per tenant and each
// insert becomes a ClickHouse part that is then merged repeatedly, so polling decides how
// many rows a part carries. At one second the closer wrote whatever had closed in the last
// second — 58 rows in production — and ClickHouse's own guidance is at least ~1,000.
//
// The cost is latency, and it is cheap: a window is emitted only once its deadline has
// already passed, so this is added to a wait already measured in minutes. It stays well
// under a minute because it is also the worst case before a closed window becomes visible,
// and an analyst watching live traffic notices staleness on that scale.
const DefaultPollInterval = 10 * time.Second

// Closer emits correlated records for windows whose deadline has passed.
//
// It runs on a timer rather than reacting to events, because "no further event will
// arrive for this request" is a statement about time. An event-driven closer cannot
// make it: the very case that needs closing is the one where nothing else arrives.
type Closer struct {
	windows  *window.Windows
	store    CorrelatedStore
	settings SettingsSource
	interval time.Duration
	batch    int
	log      mw.Logger
}

// NewCloser constructs the closer.
func NewCloser(
	windows *window.Windows, store CorrelatedStore, settings SettingsSource, log mw.Logger,
) *Closer {
	return &Closer{
		windows: windows, store: store, settings: settings,
		interval: DefaultPollInterval, batch: window.DefaultBatch, log: log,
	}
}

// Name identifies the closer in logs and metrics.
func (c *Closer) Name() string { return "correlation-closer" }

// Run polls for closed windows until the context is cancelled.
func (c *Closer) Run(ctx context.Context) error {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := c.Tick(ctx, time.Now()); err != nil {
				// A failed tick is retried on the next one. The windows it could not
				// process were already claimed off the schedule, but their state is
				// still in Redis under the lateness bound, so a later arrival — or an
				// operator's replay — can still close them. Stopping the loop here
				// would halt correlation for every tenant over one bad batch.
				c.log.Error(ctx, "correlate: close pass failed", "error", err)
			}
		}
	}
}

// MaxPassesPerTick bounds how many claims one tick makes.
//
// A tick keeps claiming while the schedule hands back full batches, so a backlog
// drains at the speed of the work rather than at one batch per second. The bound stops
// a tenant whose windows are being rescheduled as fast as they close from holding the
// loop forever — the next tick picks up where this one stopped.
const MaxPassesPerTick = 32

// Tick processes closed windows until the schedule is drained or the pass bound is hit,
// then writes everything it gathered in ONE insert per tenant.
//
// The insert is here rather than in pass() because every insert becomes a ClickHouse
// PART, and a part is merged repeatedly until it is large enough to stop being merged.
// Inserting per pass produced a part per 256 windows — measured in production as 3,859
// parts an hour at 58 rows each, with the disagreement rollup's materialized view turning
// every one of them into a part holding a single row. Merge load was the largest CPU
// consumer in the database, and this is what set it.
//
// Accumulating first bounds memory at MaxPassesPerTick * batch records, which is small:
// a correlated record is a handful of fields, and the bound already exists to stop a tick
// running forever.
func (c *Closer) Tick(ctx context.Context, now time.Time) error {
	var failed error
	byTenant := map[uuid.UUID][]emission{}

	for range MaxPassesPerTick {
		drained, err := c.pass(ctx, now, byTenant)
		failed = errors.Join(failed, err)
		if drained {
			break
		}
	}

	// Windows are claimed off the schedule before this point, so a failed insert is
	// reported and the tick moves on. Batching widens what one failure drops, which is
	// why it is reported rather than swallowed: the window state survives in Redis under
	// the lateness bound, and a late arrival still reopens it.
	for tenantID, emitted := range byTenant {
		if err := c.insert(ctx, tenantID, emitted); err != nil {
			failed = errors.Join(failed, err)
		}
	}
	return failed
}

// pass claims one batch of closed windows and accumulates their records into byTenant,
// reporting whether the schedule had fewer than a full batch left — which is what
// "drained" means here.
func (c *Closer) pass(
	ctx context.Context, now time.Time, byTenant map[uuid.UUID][]emission,
) (bool, error) {
	due, err := c.windows.Due(ctx, now, c.batch)
	if err != nil {
		CloseFailures.WithLabelValues("claim").Inc()
		return true, fmt.Errorf("claim closed windows: %w", err)
	}
	if len(due) == 0 {
		return true, nil
	}

	var failed error
	for _, scheduled := range due {
		emitted, err := c.build(ctx, scheduled)
		if err != nil {
			// One window's failure must not abandon the rest of the batch.
			failed = errors.Join(failed, err)
			continue
		}
		byTenant[scheduled.TenantID] = append(byTenant[scheduled.TenantID], emitted...)
	}
	return len(due) < c.batch, failed
}

// VersionLookupChunk bounds how many ids one version query asks about.
//
// The lookup becomes an IN list, and ClickHouse caps a query at 256 KB. A tick gathers up
// to MaxPassesPerTick*window.DefaultBatch records — over 8,000 — and at ~38 bytes per
// rendered uuid the whole set overruns that limit, failing the ENTIRE close pass. It did:
// correlated output on production fell from 5,218 records a minute to 137 before this was
// bounded. This size leaves an order of magnitude of headroom.
const VersionLookupChunk = 1000

// versionsOf reads existing versions in bounded batches.
//
// Only the READ is split. The insert stays whole because one part per tick is the entire
// point of batching — it is the read that has a query-size limit, not the write.
func (c *Closer) versionsOf(
	ctx context.Context, ids []uuid.UUID,
) (map[uuid.UUID]uint64, error) {
	existing := make(map[uuid.UUID]uint64, len(ids))

	for start := 0; start < len(ids); start += VersionLookupChunk {
		end := min(start+VersionLookupChunk, len(ids))

		found, err := c.store.Versions(ctx, ids[start:end])
		if err != nil {
			return nil, err
		}
		for id, version := range found {
			existing[id] = version
		}
	}
	return existing, nil
}

// emission is one correlated record together with the evidence it was built from,
// which the metrics need after the write succeeds.
type emission struct {
	record  chdata.CorrelatedRequest
	members int
}

// insert versions and writes one tenant's closed windows.
//
// Versioning happens here, not per record, because it is a storage read: asking
// whether each record already exists one id at a time puts a ClickHouse round trip on
// every correlated record.
func (c *Closer) insert(ctx context.Context, tenantID uuid.UUID, emitted []emission) error {
	if len(emitted) == 0 {
		return nil
	}

	scoped := tenancy.WithTenant(ctx, tenancy.Tenant{ID: tenantID})

	ids := make([]uuid.UUID, 0, len(emitted))
	for _, e := range emitted {
		ids = append(ids, e.record.CorrelationID)
	}

	existing, err := c.versionsOf(scoped, ids)
	if err != nil {
		CloseFailures.WithLabelValues("read").Inc()
		return fmt.Errorf("look up %d existing records: %w", len(ids), err)
	}

	records := make([]chdata.CorrelatedRequest, 0, len(emitted))
	for i, e := range emitted {
		record := e.record
		// A record that already exists is an AMENDMENT: same correlation id, higher
		// version, amended set. That is the late-arrival contract (FR-018) — the
		// analyst who bookmarked a correlation id still finds it, now with the extra
		// vendor attached.
		if version, ok := existing[record.CorrelationID]; ok {
			record.Version = version + 1
			record.Amended = true
		} else {
			record.Version = 1
		}
		emitted[i].record = record
		records = append(records, record)
	}

	if err := c.store.Insert(scoped, records); err != nil {
		CloseFailures.WithLabelValues("insert").Inc()
		return fmt.Errorf("write %d correlated records: %w", len(records), err)
	}

	for _, e := range emitted {
		observeRecord(e.record.JoinTier, e.record.Confidence, e.record.VendorCount,
			e.members, e.record.Amended)
	}
	return nil
}

// build assembles the records for one closed window without writing them.
//
// Writing is left to the caller so a whole tick's records go out in one insert.
func (c *Closer) build(
	ctx context.Context, scheduled window.Scheduled,
) ([]emission, error) {
	members, err := c.windows.Members(ctx, scheduled.TenantID, scheduled.Key)
	if err != nil {
		CloseFailures.WithLabelValues("read").Inc()
		return nil, fmt.Errorf("read window %s: %w", scheduled.Key, err)
	}
	if len(members) == 0 {
		// The window expired before it was closed, which means it is older than the
		// lateness bound. There is nothing left to emit and nothing to repair.
		LateArrivalsDropped.Inc()
		return nil, nil
	}

	members, err = c.withExactPartners(ctx, scheduled.TenantID, members)
	if err != nil {
		return nil, err
	}

	settings := c.settings.For(ctx, scheduled.TenantID)

	events := make([]group.Event, 0, len(members))
	for _, m := range members {
		events = append(events, group.Event{Ref: m.EventID, Row: toRow(scheduled.TenantID, m)})
	}

	groups := group.Batch(events, settings.Keys)
	emitted := make([]emission, 0, len(groups))
	for _, g := range groups {
		record, err := c.materialize(ctx, scheduled.TenantID, g, settings)
		if err != nil {
			return nil, err
		}
		emitted = append(emitted, emission{record: record, members: len(members)})
	}

	// Membership is deliberately NOT released here. It has to outlive the emission,
	// because an amendment rebuilds the record from the WHOLE window, not just the
	// event that triggered it. Clearing it on close would leave a late arrival with
	// only itself to work from, and the amendment would overwrite a two-vendor record
	// with a one-vendor one — silently deleting the correlation it was meant to add.
	// The TTL reclaims it once the lateness bound has passed and amendment is over.
	return emitted, nil
}

// withExactPartners pulls in events that share a vendor request id with a member but
// landed in a different window.
//
// This is the case tier 1 exists for. Two vendors report the same request with clocks
// far enough apart that they fall into different time windows; only the shared
// identifier can reunite them, and it can only do so by looking outside this window.
func (c *Closer) withExactPartners(
	ctx context.Context, tenantID uuid.UUID, members []window.Member,
) ([]window.Member, error) {
	seen := make(map[string]bool, len(members))
	for _, m := range members {
		seen[m.EventID] = true
	}

	out := members
	for _, m := range members {
		if m.VendorRequestID == "" {
			continue
		}
		key := keys.ExactKeyValue(tenantID, m.VendorRequestID)
		partners, err := c.windows.Members(ctx, tenantID, key)
		if err != nil {
			return nil, fmt.Errorf("read exact bucket for %s: %w", m.EventID, err)
		}
		for _, partner := range partners {
			if seen[partner.EventID] {
				continue
			}
			seen[partner.EventID] = true
			out = append(out, partner)
		}
	}
	return out, nil
}

// materialize assigns a record its stable identity and its version.
//
// The version is NOT assigned here. Whether a record is new or an amendment is a
// storage read, and insert answers it for a whole close pass in one query.
func (c *Closer) materialize(
	ctx context.Context, tenantID uuid.UUID, g group.Group, settings Resolved,
) (chdata.CorrelatedRequest, error) {
	record := buildRecord(tenantID, g, settings.ScoreConflictThreshold)

	correlationID, err := c.windows.Identity(
		ctx, tenantID, g.Key.Value, keys.CorrelationID(g.Key), settings.Keys)
	if err != nil {
		return chdata.CorrelatedRequest{}, fmt.Errorf("resolve correlation id: %w", err)
	}
	record.CorrelationID = correlationID
	return record, nil
}
