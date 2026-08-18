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
	// ByIDs loads the stored records so an amendment can be MERGED into what is there
	// rather than replacing it. See mergeRecords.
	ByIDs(
		ctx context.Context, correlationIDs []uuid.UUID,
	) (map[uuid.UUID]chdata.CorrelatedRequest, error)
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
//
// The ticker paces the IDLE loop, not the working one. A tick that hits its pass bound
// with the schedule still full means the closer is behind, and sleeping for the interval
// there caps it at MaxPassesPerTick*batch per interval — 8,192 windows every ten seconds,
// under a thousand a second. Production files windows faster than that, so once the
// closer fell behind it could never catch up: it kept claiming windows whose member
// state had already passed its TTL, closed them empty, and wrote nothing. 1.7 million
// windows were dropped that way against 70 records a minute emitted, while the console
// showed the records from before the fall and looked healthy.
//
// So a tick that did not drain the schedule is followed immediately by another. The
// interval only applies once there is nothing left due, which is the state the constant
// was written for.
func (c *Closer) Run(ctx context.Context) error {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		for {
			drained, err := c.tick(ctx, time.Now())
			if err != nil {
				// A failed tick is retried on the next one. The windows it could not
				// process were already claimed off the schedule, but their state is
				// still in Redis under the lateness bound, so a later arrival — or an
				// operator's replay — can still close them. Stopping the loop here
				// would halt correlation for every tenant over one bad batch.
				c.log.Error(ctx, "correlate: close pass failed", "error", err)
			}
			// A failed tick stops the catch-up loop as well as reporting: whatever is
			// wrong is more likely to still be wrong a microsecond later than a second
			// later, and spinning on it would bury the log in repeats of one fault.
			if drained || err != nil || ctx.Err() != nil {
				break
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
	_, err := c.tick(ctx, now)
	return err
}

// tick is Tick, also reporting whether the schedule was drained — which is what tells
// Run whether to sleep or to keep working. Tick keeps the plain signature because that
// is what the tests and any future caller want.
func (c *Closer) tick(ctx context.Context, now time.Time) (bool, error) {
	var failed error
	drainedAll := true
	byTenant := map[uuid.UUID][]emission{}

	for range MaxPassesPerTick {
		drained, err := c.pass(ctx, now, byTenant)
		failed = errors.Join(failed, err)
		if drained {
			break
		}
		// Every pass took a full batch, so the pass bound is what ended the tick, not
		// the schedule running out: there is more due right now.
		drainedAll = false
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
	return drainedAll, failed
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

	// EVERY WINDOW'S MEMBERS IN ONE ROUND TRIP, before any of them is built. Reading them
	// inside the loop cost a blocking round trip per window, and a batch is up to
	// DefaultBatch of them.
	members, err := c.membersForBatch(ctx, due)
	if err != nil {
		CloseFailures.WithLabelValues("read").Inc()
		return true, err
	}

	// Exact partners for the WHOLE batch, walked level by level across every window at
	// once rather than window by window. Same closure, same members, a round trip per
	// level instead of one per window.
	members, err = c.expandExactPartners(ctx, due, members)
	if err != nil {
		CloseFailures.WithLabelValues("read").Inc()
		return true, err
	}

	var failed error
	for _, scheduled := range due {
		emitted, err := c.build(ctx, scheduled, members[scheduled])
		if err != nil {
			// One window's failure must not abandon the rest of the batch.
			failed = errors.Join(failed, err)
			continue
		}
		byTenant[scheduled.TenantID] = append(byTenant[scheduled.TenantID], emitted...)
	}
	return len(due) < c.batch, failed
}

// membersForBatch reads the members of every due window, one round trip per tenant.
//
// Grouped by tenant because the storage key is tenant-scoped, so a single read cannot span
// them. A batch is normally one tenant's windows, which makes this one round trip in
// practice and never more than one per tenant present.
func (c *Closer) membersForBatch(
	ctx context.Context, due []window.Scheduled,
) (map[window.Scheduled][]window.Member, error) {
	keysByTenant := make(map[uuid.UUID][]string, 1)
	for _, scheduled := range due {
		keysByTenant[scheduled.TenantID] = append(keysByTenant[scheduled.TenantID], scheduled.Key)
	}

	out := make(map[window.Scheduled][]window.Member, len(due))
	for tenantID, keys := range keysByTenant {
		found, err := c.windows.MembersMany(ctx, tenantID, keys)
		if err != nil {
			return nil, fmt.Errorf("read %d windows: %w", len(keys), err)
		}
		for key, members := range found {
			out[window.Scheduled{TenantID: tenantID, Key: key}] = members
		}
	}
	return out, nil
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

	// The stored records are read only for ids that already exist, so a tick of first
	// emissions — the ordinary case — costs nothing extra.
	stored, err := c.storedFor(scoped, existing)
	if err != nil {
		CloseFailures.WithLabelValues("read").Inc()
		return fmt.Errorf("load %d existing records: %w", len(existing), err)
	}

	records := make([]chdata.CorrelatedRequest, 0, len(emitted))
	for i, e := range emitted {
		record := e.record
		// A record that already exists is an AMENDMENT: same correlation id, higher
		// version, amended set. That is the late-arrival contract (FR-018) — the
		// analyst who bookmarked a correlation id still finds it, now with the extra
		// vendor attached.
		if version, ok := existing[record.CorrelationID]; ok {
			// MERGED, not replaced. The window behind this closing may hold only the
			// late event: its member state expires with the lateness bound while the
			// correlation id does not, so an amendment built from the window alone
			// would overwrite the other vendors with nothing.
			if previous, ok := stored[record.CorrelationID]; ok {
				record = mergeRecords(previous, record,
					c.settings.For(ctx, tenantID).ScoreConflictThreshold)
			}
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

// storedFor loads the records behind the ids that already exist.
func (c *Closer) storedFor(
	ctx context.Context, existing map[uuid.UUID]uint64,
) (map[uuid.UUID]chdata.CorrelatedRequest, error) {
	if len(existing) == 0 {
		return nil, nil
	}

	ids := make([]uuid.UUID, 0, len(existing))
	for id := range existing {
		ids = append(ids, id)
	}
	return c.store.ByIDs(ctx, ids)
}

// build assembles the records for one closed window without writing them.
//
// Writing is left to the caller so a whole tick's records go out in one insert.
func (c *Closer) build(
	ctx context.Context, scheduled window.Scheduled, members []window.Member,
) ([]emission, error) {
	if len(members) == 0 {
		// The window expired before it was closed, which means it is older than the
		// lateness bound. There is nothing left to emit and nothing to repair.
		LateArrivalsDropped.Inc()
		return nil, nil
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

// expandExactPartners pulls in events that share a vendor request id with a member but
// landed in a different window, for every window in the batch at once.
//
// This is the case tier 1 exists for. Two vendors report the same request with clocks
// far enough apart that they fall into different time windows; only the shared
// identifier can reunite them, and it can only do so by looking outside this window.
// The traversal is TRANSITIVE, and it has to be. A Worker-protected request produces
// three Cloudflare rows with three different rays: the client-facing one, the call to
// DataDome, and the fetch to the origin. F5 sees only the origin fetch's ray, and the
// DataDome verdict is reachable only through the client-facing one, so the origin
// fetch — which carries both — is the sole bridge between them. Following one level
// from the starting members finds that bridge from one side but not the other, and
// which side a request landed on would decide whether it got two verdicts or three.
//
// IT WALKS EVERY WINDOW IN LOCKSTEP, one level at a time, so a level costs ONE round trip
// for the whole batch instead of one per window. Done window by window this was the
// closer's dominant cost: a production profile put 34% of the processor's CPU samples in
// socket syscalls while the process sat idle two thirds of the time.
//
// Each window keeps its OWN seen and visited sets. Sharing them across windows would be
// faster still and completely wrong: two windows reaching the same bucket must each
// receive its members, and a shared seen set would silently give them to whichever window
// happened to be visited first.
func (c *Closer) expandExactPartners(
	ctx context.Context, due []window.Scheduled,
	byWindow map[window.Scheduled][]window.Member,
) (map[window.Scheduled][]window.Member, error) {
	walks := newPartnerWalks(due, byWindow)

	// Bounded by the longest chain any window forms, not by the number of windows. The
	// closure is self-limiting: each member contributes at most two identifiers and each
	// window visits a bucket once, so a window runs out of new identifiers quickly.
	for {
		wanted, byTenant := nextIdentifiers(due, walks)
		if len(byTenant) == 0 {
			break
		}

		buckets, err := c.readBuckets(ctx, byTenant)
		if err != nil {
			return nil, err
		}
		advanceWalks(due, walks, wanted, buckets)
	}

	out := make(map[window.Scheduled][]window.Member, len(due))
	for scheduled, w := range walks {
		out[scheduled] = w.out
	}
	return out, nil
}

// partnerWalk is one window's position in the traversal.
//
// Each window keeps its OWN seen and visited sets. Sharing them across windows would be
// faster still and completely wrong: two windows reaching the same bucket must each
// receive its members, and a shared seen set would silently give them to whichever window
// happened to be visited first.
type partnerWalk struct {
	seen     map[string]bool
	visited  map[string]bool
	out      []window.Member
	frontier []window.Member
}

func newPartnerWalks(
	due []window.Scheduled, byWindow map[window.Scheduled][]window.Member,
) map[window.Scheduled]*partnerWalk {
	walks := make(map[window.Scheduled]*partnerWalk, len(due))
	for _, scheduled := range due {
		members := byWindow[scheduled]
		w := &partnerWalk{
			seen:    make(map[string]bool, len(members)),
			visited: map[string]bool{},
			out:     make([]window.Member, 0, len(members)),
		}
		for _, m := range members {
			if w.seen[m.EventID] {
				continue
			}
			w.seen[m.EventID] = true
			w.out = append(w.out, m)
			w.frontier = append(w.frontier, m)
		}
		walks[scheduled] = w
	}
	return walks
}

// nextIdentifiers reports which buckets each window still wants, and the deduplicated set
// to ask for per tenant.
//
// Several members of one request carry the same ray, and several windows in a batch often
// want the same bucket. Both are worth reading once, which is why the per-window list and
// the per-tenant set are built together rather than derived from each other.
func nextIdentifiers(
	due []window.Scheduled, walks map[window.Scheduled]*partnerWalk,
) (map[window.Scheduled][]string, map[uuid.UUID]map[string]struct{}) {
	wanted := make(map[window.Scheduled][]string, len(due))
	byTenant := make(map[uuid.UUID]map[string]struct{}, 1)

	for _, scheduled := range due {
		w := walks[scheduled]
		for _, member := range w.frontier {
			for _, identifier := range identifiersOf(scheduled.TenantID, member) {
				if w.visited[identifier] {
					continue
				}
				w.visited[identifier] = true
				wanted[scheduled] = append(wanted[scheduled], identifier)

				if byTenant[scheduled.TenantID] == nil {
					byTenant[scheduled.TenantID] = map[string]struct{}{}
				}
				byTenant[scheduled.TenantID][identifier] = struct{}{}
			}
		}
	}
	return wanted, byTenant
}

// readBuckets fetches one level's buckets, one round trip per tenant.
func (c *Closer) readBuckets(
	ctx context.Context, byTenant map[uuid.UUID]map[string]struct{},
) (map[uuid.UUID]map[string][]window.Member, error) {
	buckets := make(map[uuid.UUID]map[string][]window.Member, len(byTenant))
	for tenantID, set := range byTenant {
		identifiers := make([]string, 0, len(set))
		for identifier := range set {
			identifiers = append(identifiers, identifier)
		}
		found, err := c.windows.MembersMany(ctx, tenantID, identifiers)
		if err != nil {
			return nil, fmt.Errorf("read %d exact buckets: %w", len(identifiers), err)
		}
		buckets[tenantID] = found
	}
	return buckets, nil
}

// advanceWalks hands each window the partners its own identifiers reached.
func advanceWalks(
	due []window.Scheduled, walks map[window.Scheduled]*partnerWalk,
	wanted map[window.Scheduled][]string,
	buckets map[uuid.UUID]map[string][]window.Member,
) {
	for _, scheduled := range due {
		w := walks[scheduled]
		// Iterate the identifier SLICE this window asked for, not a map: map order is
		// random, and it decides the order partners enter the record's event list.
		next := make([]window.Member, 0, len(wanted[scheduled]))
		for _, identifier := range wanted[scheduled] {
			for _, partner := range buckets[scheduled.TenantID][identifier] {
				if w.seen[partner.EventID] {
					continue
				}
				w.seen[partner.EventID] = true
				w.out = append(w.out, partner)
				next = append(next, partner)
			}
		}
		w.frontier = next
	}
}

// identifiersOf returns the exact bucket keys a member is reachable through.
func identifiersOf(tenantID uuid.UUID, m window.Member) []string {
	out := make([]string, 0, 2)
	for _, id := range []string{m.VendorRequestID, m.LinkedRequestID} {
		if id == "" {
			continue
		}
		out = append(out, keys.ExactKeyValue(tenantID, id))
	}
	return out
}

// materialize assigns a record its stable identity and its version.
//
// The version is NOT assigned here. Whether a record is new or an amendment is a
// storage read, and insert answers it for a whole close pass in one query.
func (c *Closer) materialize(
	ctx context.Context, tenantID uuid.UUID, g group.Group, settings Resolved,
) (chdata.CorrelatedRequest, error) {
	record := buildRecord(tenantID, g, settings.ScoreConflictThreshold)

	// Claimed under every identifier the group carries, not just its key. The key is the
	// smallest identifier in the component and therefore CHANGES as late events widen
	// it, which split 92.7% of f5+nginx records off into orphans: the amendment computed
	// a different id and wrote a second record instead of updating the first.
	//
	// A heuristic group returns none of these and falls back to its key, since those
	// members share no identifier and aliasing on their rays would merge unrelated
	// requests.
	identifiers := g.Identifiers()
	proposed := keys.CorrelationID(g.Key)

	resolve := func() (uuid.UUID, error) {
		if len(identifiers) == 0 {
			return c.windows.Identity(ctx, tenantID, g.Key.Value, proposed, settings.Keys)
		}
		return c.windows.IdentityForAny(ctx, tenantID, identifiers, proposed, settings.Keys)
	}

	correlationID, err := resolve()
	if err != nil {
		return chdata.CorrelatedRequest{}, fmt.Errorf("resolve correlation id: %w", err)
	}
	record.CorrelationID = correlationID
	return record, nil
}
