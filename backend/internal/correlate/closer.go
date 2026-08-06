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
const DefaultPollInterval = time.Second

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

// Tick processes closed windows until the schedule is drained or the pass bound is hit.
func (c *Closer) Tick(ctx context.Context, now time.Time) error {
	var failed error

	for pass := 0; pass < MaxPassesPerTick; pass++ {
		drained, err := c.pass(ctx, now)
		failed = errors.Join(failed, err)
		if drained {
			break
		}
	}
	return failed
}

// pass claims one batch of closed windows and emits them, reporting whether the
// schedule had fewer than a full batch left — which is what "drained" means here.
func (c *Closer) pass(ctx context.Context, now time.Time) (bool, error) {
	due, err := c.windows.Due(ctx, now, c.batch)
	if err != nil {
		CloseFailures.WithLabelValues("claim").Inc()
		return true, fmt.Errorf("claim closed windows: %w", err)
	}
	if len(due) == 0 {
		return true, nil
	}

	var failed error
	byTenant := map[uuid.UUID][]emission{}

	for _, scheduled := range due {
		emitted, err := c.build(ctx, scheduled)
		if err != nil {
			// One window's failure must not abandon the rest of the batch.
			failed = errors.Join(failed, err)
			continue
		}
		byTenant[scheduled.TenantID] = append(byTenant[scheduled.TenantID], emitted...)
	}

	// One insert per tenant per tick, not one per window. A correlated record is a
	// handful of rows, so a per-window insert pays a full ClickHouse round trip —
	// which, under the ingest profile's wait_for_async_insert, is the entire cost of
	// closing a window. Windows are claimed off the schedule before this point, so a
	// failed insert is reported and the tick moves on; the window state survives in
	// Redis under the lateness bound, and a late arrival still reopens it.
	for tenantID, emitted := range byTenant {
		if err := c.insert(ctx, tenantID, emitted); err != nil {
			failed = errors.Join(failed, err)
		}
	}
	return len(due) < c.batch, failed
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

	existing, err := c.store.Versions(scoped, ids)
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
