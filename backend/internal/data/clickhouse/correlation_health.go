package clickhouse

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/tenancy"
)

// CorrelationHealthRow is one minute of the correlation pipeline's activity for one
// tenant, as written by the closer's health aggregator.
type CorrelationHealthRow struct {
	TenantID            uuid.UUID
	Minute              time.Time
	EventsFiled         uint64
	WindowsClosed       uint64
	RecordsEmitted      uint64
	WindowsDroppedEmpty uint64
	CloseFailures       uint64
	WindowsDue          uint64
	MaxClaimLagMS       uint64
	WindowTTLMS         uint64
}

// CorrelationHealthRepo reads and writes the correlation pipeline's health.
type CorrelationHealthRepo struct {
	client *Client
}

// NewCorrelationHealthRepo constructs the repo.
func NewCorrelationHealthRepo(client *Client) *CorrelationHealthRepo {
	return &CorrelationHealthRepo{client: client}
}

// InsertCorrelationHealth writes accumulated per-minute rows.
func (r *CorrelationHealthRepo) InsertCorrelationHealth(
	ctx context.Context, rows []CorrelationHealthRow,
) error {
	if len(rows) == 0 {
		return nil
	}

	batch, err := r.client.PrepareBatch(ctx, `INSERT INTO correlation_health (
		tenant_id, minute, events_filed, windows_closed, records_emitted,
		windows_dropped_empty, close_failures, windows_due, max_claim_lag_ms,
		window_ttl_ms)`)
	if err != nil {
		return fmt.Errorf("prepare correlation health batch: %w", err)
	}

	for _, row := range rows {
		err := batch.Append(
			row.TenantID, row.Minute, row.EventsFiled, row.WindowsClosed,
			row.RecordsEmitted, row.WindowsDroppedEmpty, row.CloseFailures,
			row.WindowsDue, row.MaxClaimLagMS, row.WindowTTLMS)
		if err != nil {
			return fmt.Errorf("append correlation health row: %w", err)
		}
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("send correlation health batch: %w", err)
	}
	return nil
}

// CorrelationAssessmentWindow is how much recent history a verdict is drawn from.
//
// Long enough that one slow minute — a merge, a restart, a feed arriving in a burst —
// does not read as an outage, short enough that a real stall is reported while it is
// still happening rather than after it has been averaged away. The two production
// incidents lasted hours; this reports them in minutes.
const CorrelationAssessmentWindow = 15 * time.Minute

// CorrelationHealth is the recent state of the correlation pipeline for one tenant.
type CorrelationHealth struct {
	Since               time.Time
	EventsFiled         uint64
	WindowsClosed       uint64
	RecordsEmitted      uint64
	WindowsDroppedEmpty uint64
	CloseFailures       uint64
	WindowsDue          uint64
	ClaimLag            time.Duration
	WindowTTL           time.Duration
	LastRecordAt        time.Time
}

// CorrelationStatus is the single word the console shows.
type CorrelationStatus string

// The states, worst first. Ordering is the whole design: a pipeline can be several of
// these at once, and the one an operator must act on is the one that gets reported.
const (
	// CorrelationFailing means close passes are erroring. Nothing is being written and
	// the cause is in the closer itself — the 8c32245 shape, where a column was added
	// to the insert and not to the scan.
	CorrelationFailing CorrelationStatus = "failing"
	// CorrelationStalled means events are being filed and no records are coming out.
	// The cause is unknown, which is exactly why it is worth reporting: it is the
	// shape both known incidents shared.
	CorrelationStalled CorrelationStatus = "stalled"
	// CorrelationLosing means windows are being closed after their state expired, so
	// the events in them will never be correlated. This is data loss in progress, not
	// a slowdown, and it is what the second incident did for hours.
	CorrelationLosing CorrelationStatus = "losing"
	// CorrelationBehind means the closer is falling back through its own budget but is
	// still emitting. The warning before the loss.
	CorrelationBehind CorrelationStatus = "behind"
	// CorrelationIdle means nothing was filed. Not healthy and not broken — there is
	// simply nothing to judge, and saying "healthy" would be a claim the data does not
	// support.
	CorrelationIdle CorrelationStatus = "idle"
	// CorrelationHealthy means events went in and records came out.
	CorrelationHealthy CorrelationStatus = "healthy"
)

// DroppedShareThreshold is the share of closed windows that may expire before the
// pipeline is called lossy.
//
// Not zero. A window whose events genuinely arrived past the lateness bound closes
// empty through no fault of the closer, and on a busy tenant that happens continuously
// at a low rate. It was 100% during the incident and a fraction of a percent either
// side of it, so the line does not need to be finely drawn — only drawn.
const DroppedShareThreshold = 0.05

// BehindShareOfTTL is how much of the window TTL the claim lag may consume before the
// closer is called behind.
//
// Half. Past the TTL, window state has expired and every window closed is empty, so
// half is the point at which the remaining margin is smaller than the ground already
// lost — and the pipeline has minutes, not hours, before it starts losing data.
const BehindShareOfTTL = 0.5

// BehindWindowsFloor is how many windows must be waiting before a lag means anything.
//
// One tick's claim: the closer takes up to 32 batches of 256 in a pass, so a backlog
// smaller than that is one it will clear on its next tick whatever the clock says.
//
// The floor is not a tolerance, it is a CORRECTION. The lag is the age of the oldest
// entry in the schedule, and a window's deadline is derived from its events' time, so a
// feed delivering hours-late events puts an entry at the head that was born overdue.
// Production does this during a backfill: the first health rows written showed a claim
// lag of 4.2 hours against 23 windows waiting and nothing dropped — a closer that was
// entirely caught up, which the lag alone would have reported as behind on every
// screen, forever. A warning that is always on is one nobody reads, which would leave
// the pipeline exactly as unwatched as it was before this table existed.
const BehindWindowsFloor = 32 * 256

// Status reports the state an operator should act on.
func (h CorrelationHealth) Status() CorrelationStatus {
	switch {
	case h.CloseFailures > 0 && h.RecordsEmitted == 0:
		return CorrelationFailing
	case h.EventsFiled == 0:
		return CorrelationIdle
	case h.RecordsEmitted == 0:
		return CorrelationStalled
	case h.losing():
		return CorrelationLosing
	case h.behind():
		return CorrelationBehind
	default:
		return CorrelationHealthy
	}
}

// losing reports whether closed windows are expiring faster than the ordinary trickle.
func (h CorrelationHealth) losing() bool {
	attempted := h.WindowsClosed + h.WindowsDroppedEmpty
	if attempted == 0 {
		return false
	}
	return float64(h.WindowsDroppedEmpty)/float64(attempted) > DroppedShareThreshold
}

// behind reports whether a real backlog has been waiting past half the window TTL.
//
// BOTH readings, for the reason BehindWindowsFloor gives: a lag with nothing behind it
// is a stale entry, not a slow closer. Silent when the TTL is unknown — a row written
// before the closer reported one — rather than comparing against a default the
// deployment may not use.
func (h CorrelationHealth) behind() bool {
	if h.WindowTTL <= 0 || h.WindowsDue < BehindWindowsFloor {
		return false
	}
	return h.ClaimLag > time.Duration(float64(h.WindowTTL)*BehindShareOfTTL)
}

// GetCorrelationHealth reads the recent state of the tenant's correlation pipeline.
//
// Counters are SUMMED over the assessment window and the levels are taken at their
// highest, matching how the columns are aggregated in the table itself.
func (r *CorrelationHealthRepo) GetCorrelationHealth(
	ctx context.Context,
) (CorrelationHealth, error) {
	tenantID, err := tenancy.MustID(ctx)
	if err != nil {
		return CorrelationHealth{}, err
	}

	since := time.Now().UTC().Add(-CorrelationAssessmentWindow)

	row := r.client.QueryRow(ctx,
		"SELECT sum(events_filed), sum(windows_closed), sum(records_emitted), "+
			"sum(windows_dropped_empty), sum(close_failures), max(windows_due), "+
			"max(max_claim_lag_ms), max(window_ttl_ms), "+
			// The last minute that produced anything, which is what an operator reads
			// first: "records stopped 53 minutes ago" is the whole story of both
			// incidents, and a rate alone never says it.
			"maxIf(minute, records_emitted > 0) "+
			"FROM correlation_health WHERE tenant_id = ? AND minute >= ?",
		tenantID, since)

	var (
		health = CorrelationHealth{Since: since}
		lagMS  uint64
		ttlMS  uint64
	)
	err = row.Scan(
		&health.EventsFiled, &health.WindowsClosed, &health.RecordsEmitted,
		&health.WindowsDroppedEmpty, &health.CloseFailures, &health.WindowsDue,
		&lagMS, &ttlMS)
	if err != nil {
		return CorrelationHealth{}, fmt.Errorf("query correlation health: %w", err)
	}

	health.ClaimLag = time.Duration(lagMS) * time.Millisecond
	health.WindowTTL = time.Duration(ttlMS) * time.Millisecond
	return health, nil
}
