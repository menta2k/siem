//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/menta2k/siem/internal/correlate"
	"github.com/menta2k/siem/internal/correlate/keys"
	"github.com/menta2k/siem/internal/correlate/window"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/data/stream"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/normalize"
	"github.com/menta2k/siem/internal/vendors"
	"github.com/menta2k/siem/test/support"
)

// correlateRig is the correlation pipeline wired to real Redis and ClickHouse.
type correlateRig struct {
	fixture  *support.Fixture
	worker   *correlate.Worker
	closer   *correlate.Closer
	store    *chdata.CorrelatedRepo
	settings keys.Settings
	ctx      context.Context
	tenant   chdata.Tenant
}

func newCorrelateRig(t *testing.T, name string) *correlateRig {
	t.Helper()

	fixture := support.Shared(t)
	ctx, tenant := fixture.NewTenant(t, name)

	settings := keys.DefaultSettings()
	windows := window.New(fixture.Redis)
	store := chdata.NewCorrelatedRepo(fixture.ClickHouse)
	log := mw.NewLogger("error", "json")
	source := correlate.FixedSettings{Value: correlate.DefaultResolved()}

	return &correlateRig{
		fixture:  fixture,
		worker:   correlate.NewWorker(windows, source, log),
		closer:   correlate.NewCloser(windows, store, source, log),
		store:    store,
		settings: settings,
		ctx:      ctx,
		tenant:   tenant,
	}
}

// feed pushes one normalized event through the worker exactly as the topic would.
func (r *correlateRig) feed(t *testing.T, event chdata.NormalizedEvent) {
	t.Helper()

	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("encode event: %v", err)
	}
	if err := r.worker.Handle(r.ctx, stream.Record{
		Key: []byte(event.EventID), Value: encoded,
	}); err != nil {
		t.Fatalf("handle event %s: %v", event.EventID, err)
	}
}

// afterDeadline is a time by which a window holding an event at `at` is genuinely due.
//
// DERIVED, never a hand-written offset. A window closes at eventTime + Window + grace,
// and the grace has been raised twice — 30s, then 90s, then 210s — as the measured
// delivery tail grew. Each raise left these tests closing at a hardcoded "+2 minutes",
// which is BEFORE the deadline, so the closer correctly emitted nothing and every
// assertion downstream read that empty result as a correlation bug. The failure looked
// like "0 correlated records, want 1" and pointed at the pipeline rather than at the
// clock the test had chosen.
//
// Deriving it from the same constants the closer uses means the next change to either
// bound moves these tests with it instead of silently breaking them.
func afterDeadline(at time.Time) time.Time {
	settings := correlate.DefaultResolved().Keys
	return at.Add(settings.Window).Add(window.DefaultGrace).Add(time.Second)
}

// closeWindows runs a close pass far enough in the future that everything is due.
func (r *correlateRig) closeWindows(t *testing.T, at time.Time) {
	t.Helper()

	if err := r.closer.Tick(r.ctx, at); err != nil {
		t.Fatalf("close pass: %v", err)
	}
	r.fixture.Sync(t, "correlated_requests")
}

// only returns the single correlated record, failing if there is not exactly one.
func (r *correlateRig) only(t *testing.T) chdata.CorrelatedRequest {
	t.Helper()

	records := r.list(t)
	if len(records) != 1 {
		t.Fatalf("got %d correlated records, want exactly 1: %+v", len(records), records)
	}
	return records[0]
}

func (r *correlateRig) list(t *testing.T) []chdata.CorrelatedRequest {
	t.Helper()

	records, err := r.store.List(r.ctx, chdata.CorrelatedFilter{
		From: corrBase.Add(-time.Hour), To: corrBase.Add(time.Hour), Limit: 100,
	})
	if err != nil {
		t.Fatalf("list correlated records: %v", err)
	}
	return records
}

var corrBase = time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)

func normalizedEvent(
	tenant chdata.Tenant, id, vendor, requestID string, at time.Time,
	mutate ...func(*chdata.NormalizedEvent),
) chdata.NormalizedEvent {
	event := chdata.NormalizedEvent{
		TenantID:        tenant.ID,
		EventID:         id,
		EventTime:       at.UTC(),
		ReceivedAt:      at.UTC(),
		Vendor:          vendor,
		VendorRequestID: requestID,
		ClientIP:        net.ParseIP("203.0.113.10"),
		RequestHost:     "shop.example.com",
		RequestPath:     "/checkout",
		RequestMethod:   "GET",
		Verdict:         vendors.VerdictAllowed,
	}
	for _, m := range mutate {
		m(&event)
	}
	return event
}

// An in-bound late arrival must AMEND the record an analyst may already have opened:
// same correlation id, higher version, amended set (FR-018).
func TestLateArrivalAmendsTheExistingRecord(t *testing.T) {
	rig := newCorrelateRig(t, "correlate-late-amend")

	rig.feed(t, normalizedEvent(rig.tenant, "cf-1", vendors.Cloudflare, "ray-1", corrBase))
	rig.closeWindows(t, afterDeadline(corrBase))

	first := rig.only(t)
	if first.Version != 1 || first.Amended {
		t.Fatalf("first emission: version=%d amended=%v, want version=1 amended=false",
			first.Version, first.Amended)
	}
	if first.VendorCount != 1 {
		t.Fatalf("vendor_count = %d, want 1 — a single-vendor record is a valid answer",
			first.VendorCount)
	}

	// The F5 report of the same request arrives late, but inside the lateness bound.
	rig.feed(t, normalizedEvent(rig.tenant, "f5-1", vendors.F5, "support-9",
		corrBase.Add(time.Second)))
	rig.closeWindows(t, afterDeadline(corrBase.Add(time.Second)))

	amended := rig.only(t)
	if amended.CorrelationID != first.CorrelationID {
		t.Errorf("correlation id changed on amendment: %s -> %s; a bookmarked record "+
			"must stay findable", first.CorrelationID, amended.CorrelationID)
	}
	if amended.Version <= first.Version {
		t.Errorf("version = %d, want greater than %d", amended.Version, first.Version)
	}
	if !amended.Amended {
		t.Error("amended flag not set on a re-emitted record")
	}
	if amended.VendorCount != 2 {
		t.Errorf("vendor_count = %d, want 2 after the late vendor joined", amended.VendorCount)
	}
	if len(amended.EventIDs) != 2 {
		t.Errorf("event_ids = %v, want both events", amended.EventIDs)
	}
}

// An arrival beyond the lateness bound must NOT silently rewrite history. Its window
// state has expired, so it becomes its own record rather than amending a closed one.
func TestOutOfBoundArrivalDoesNotAmend(t *testing.T) {
	rig := newCorrelateRig(t, "correlate-out-of-bound")

	rig.feed(t, normalizedEvent(rig.tenant, "cf-2", vendors.Cloudflare, "ray-2", corrBase))
	rig.closeWindows(t, afterDeadline(corrBase))
	first := rig.only(t)

	// Far outside the correlation window: a different request entirely.
	late := corrBase.Add(2 * time.Hour)
	rig.feed(t, normalizedEvent(rig.tenant, "f5-2", vendors.F5, "support-8", late))
	if err := rig.closer.Tick(rig.ctx, afterDeadline(late)); err != nil {
		t.Fatalf("close pass: %v", err)
	}
	rig.fixture.Sync(t, "correlated_requests")

	records, err := rig.store.List(rig.ctx, chdata.CorrelatedFilter{
		From: corrBase.Add(-time.Hour), To: late.Add(time.Hour), Limit: 100,
	})
	if err != nil {
		t.Fatalf("list correlated records: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2 — an out-of-bound event is a separate request", len(records))
	}
	for _, record := range records {
		if record.CorrelationID == first.CorrelationID && record.Amended {
			t.Error("an out-of-bound arrival amended a record it does not belong to")
		}
	}
}

// Two vendors reporting the same request id must join at tier 1 even when their clocks
// put them in different windows — that is the entire reason tier 1 exists.
func TestSharedRequestIDJoinsAcrossWindows(t *testing.T) {
	rig := newCorrelateRig(t, "correlate-tier-one")

	// Deliberately far enough apart that the heuristic key cannot match.
	rig.feed(t, normalizedEvent(rig.tenant, "cf-3", vendors.Cloudflare, "ray-shared", corrBase))
	rig.feed(t, normalizedEvent(rig.tenant, "f5-3", vendors.F5, "ray-shared",
		corrBase.Add(45*time.Second)))
	rig.closeWindows(t, afterDeadline(corrBase.Add(45*time.Second)))

	var joined *chdata.CorrelatedRequest
	for _, record := range rig.list(t) {
		if record.VendorCount == 2 {
			r := record
			joined = &r
		}
	}
	if joined == nil {
		t.Fatal("no two-vendor record; a shared request id must join across windows")
	}
	if joined.JoinTier != uint8(keys.TierExact) {
		t.Errorf("join_tier = %d, want %d (exact)", joined.JoinTier, keys.TierExact)
	}
	if joined.Confidence != "high" {
		t.Errorf("confidence = %q, want high for an exact identifier match", joined.Confidence)
	}
}

// The record's headline output: two vendors, opposite verdicts.
func TestDisagreementIsRecorded(t *testing.T) {
	rig := newCorrelateRig(t, "correlate-disagreement")

	rig.feed(t, normalizedEvent(rig.tenant, "cf-4", vendors.Cloudflare, "ray-4", corrBase))
	rig.feed(t, normalizedEvent(rig.tenant, "f5-4", vendors.F5, "support-4",
		corrBase.Add(time.Second), func(e *chdata.NormalizedEvent) {
			e.Verdict = vendors.VerdictBlocked
		}))
	rig.closeWindows(t, afterDeadline(corrBase.Add(time.Second)))

	record := rig.only(t)
	if !record.HasDisagreement {
		t.Fatalf("allow vs block was not flagged as a disagreement: %+v", record.Verdicts)
	}
	if record.DisagreementKind != string(normalize.DisagreementAllowVsBlock) {
		t.Errorf("disagreement_kind = %q, want allow_vs_block", record.DisagreementKind)
	}
	if record.CombinedOutcome != vendors.VerdictBlocked {
		t.Errorf("combined_outcome = %q, want the most restrictive verdict",
			record.CombinedOutcome)
	}
	if record.Verdicts[vendors.Cloudflare] != vendors.VerdictAllowed ||
		record.Verdicts[vendors.F5] != vendors.VerdictBlocked {
		t.Errorf("per-vendor verdicts lost: %+v", record.Verdicts)
	}
}

// A redelivered event must not appear twice, and must not inflate the candidate count
// into reporting a false ambiguity.
func TestRedeliveredEventDoesNotDuplicateInTheRecord(t *testing.T) {
	rig := newCorrelateRig(t, "correlate-redelivery")

	event := normalizedEvent(rig.tenant, "cf-5", vendors.Cloudflare, "ray-5", corrBase)
	rig.feed(t, event)
	rig.feed(t, event)
	rig.closeWindows(t, afterDeadline(corrBase))

	record := rig.only(t)
	if len(record.EventIDs) != 1 {
		t.Errorf("event_ids = %v, want one entry", record.EventIDs)
	}
	if record.CandidateCount != 1 {
		t.Errorf("candidate_count = %d, want 1; a redelivery is not a second candidate",
			record.CandidateCount)
	}
}
