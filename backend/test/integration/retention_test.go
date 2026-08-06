//go:build integration

package integration

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/retention"
	"github.com/menta2k/siem/internal/vendors"
	"github.com/menta2k/siem/test/support"
)

// retentionRig is the retention worker wired to real ClickHouse.
type retentionRig struct {
	fixture *support.Fixture
	worker  *retention.Worker
	events  *chdata.EventRepo
	tenants *chdata.TenantRepo
	ctx     context.Context
	tenant  chdata.Tenant
}

func newRetentionRig(t *testing.T, name string, rawDays uint16) *retentionRig {
	t.Helper()

	f := support.Shared(t)
	ctx, _ := f.NewTenant(t, name)

	locker := chdata.NewLocker(f.Redis)
	tenants := chdata.NewTenantRepo(f.ClickHouse, locker)
	events := chdata.NewEventRepo(f.ClickHouse)

	// The tenant's configured window is what the worker reconciles against.
	updated, err := tenants.Update(ctx, func(current chdata.Tenant) chdata.Tenant {
		current.RawRetentionDays = rawDays
		current.CorrelatedRetentionDays = rawDays
		return current
	})
	if err != nil {
		t.Fatalf("set retention: %v", err)
	}
	f.Sync(t, "tenants")

	worker := retention.NewWorker(tenants,
		retention.Repos{Events: events, Correlated: chdata.NewCorrelatedRepo(f.ClickHouse)},
		chdata.NewAuditRepo(f.ClickHouse, locker), mw.NewLogger("error", "json"))

	return &retentionRig{
		fixture: f, worker: worker, events: events, tenants: tenants,
		ctx: ctx, tenant: updated,
	}
}

// seedAt writes one event at a given age.
func (r *retentionRig) seedAt(t *testing.T, id string, age time.Duration) {
	t.Helper()

	at := time.Now().UTC().Add(-age)
	err := r.events.InsertNormalized(r.ctx, []chdata.NormalizedEvent{{
		TenantID: r.tenant.ID, EventID: id, EventTime: at, ReceivedAt: at,
		Vendor: vendors.Cloudflare, ClientIP: net.ParseIP("203.0.113.10"),
		RequestHost: "shop.example.com", RequestPath: "/checkout",
		RequestMethod: "GET", Verdict: vendors.VerdictAllowed, IngestVersion: 1,
	}})
	if err != nil {
		t.Fatalf("seed %s: %v", id, err)
	}
	r.fixture.Sync(t, "normalized_events")
}

// remaining returns the event ids still stored.
func (r *retentionRig) remaining(t *testing.T) map[string]bool {
	t.Helper()

	// A lightweight DELETE is applied asynchronously, so the test waits for it rather
	// than sleeping a fixed interval and hoping.
	r.fixture.Sync(t, "normalized_events")

	rows, err := r.fixture.ClickHouse.Query(r.ctx,
		"SELECT event_id FROM normalized_events FINAL WHERE tenant_id = ?", r.tenant.ID)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	defer func() { _ = rows.Close() }()

	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[id] = true
	}
	return out
}

// waitFor polls until the condition holds or the deadline passes.
//
// SC-010 allows expiry within a window rather than instantly, and ClickHouse applies
// lightweight deletes asynchronously. Polling asserts the outcome that matters without
// pinning the test to an implementation detail of when the mutation lands.
func waitFor(t *testing.T, timeout time.Duration, condition func() bool) bool {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(250 * time.Millisecond)
	}
	return condition()
}

// Expired data must actually be gone, and in-window data must be untouched. Getting
// either half wrong is a compliance failure in opposite directions.
func TestRetentionRemovesExpiredAndKeepsCurrent(t *testing.T) {
	rig := newRetentionRig(t, "retention-window", 7)

	rig.seedAt(t, "fresh", 1*time.Hour)
	rig.seedAt(t, "recent", 6*24*time.Hour)
	// 20 days: past the tenant's 7-day window but inside the table's own 30-day
	// TTL, so what is asserted is the WORKER removing it rather than ClickHouse.
	rig.seedAt(t, "expired", 20*24*time.Hour)

	before := rig.remaining(t)
	for _, id := range []string{"fresh", "recent", "expired"} {
		if !before[id] {
			t.Fatalf("%s was not seeded", id)
		}
	}

	if err := rig.worker.Reconcile(rig.ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	ok := waitFor(t, 30*time.Second, func() bool {
		return !rig.remaining(t)["expired"]
	})
	if !ok {
		t.Error("data past the retention window was not removed")
	}

	after := rig.remaining(t)
	if !after["fresh"] {
		t.Error("an event one hour old was deleted by a seven-day retention window")
	}
	if !after["recent"] {
		t.Error("an event inside the retention window was deleted")
	}
}

// Retention is per tenant. One tenant's short window must not touch another's data.
func TestRetentionIsPerTenant(t *testing.T) {
	shortRig := newRetentionRig(t, "retention-short", 1)
	longRig := newRetentionRig(t, "retention-long", 365)

	shortRig.seedAt(t, "short-old", 10*24*time.Hour)
	longRig.seedAt(t, "long-old", 10*24*time.Hour)

	if err := shortRig.worker.Reconcile(shortRig.ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if !waitFor(t, 30*time.Second, func() bool { return !shortRig.remaining(t)["short-old"] }) {
		t.Error("the short-retention tenant's expired data was not removed")
	}
	if !longRig.remaining(t)["long-old"] {
		t.Error("one tenant's retention pass deleted another tenant's data")
	}
}

// An unset window means "use the platform default", not "keep nothing". Reading zero
// as immediate expiry would delete a tenant's data the moment it landed.
func TestUnsetRetentionDoesNotDeleteEverything(t *testing.T) {
	rig := newRetentionRig(t, "retention-unset", 0)

	rig.seedAt(t, "today", time.Hour)

	if err := rig.worker.Reconcile(rig.ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	time.Sleep(2 * time.Second)
	if !rig.remaining(t)["today"] {
		t.Error("an unset retention window deleted data written an hour ago")
	}
}

// A purge is destructive and outside the normal path, so it must be audited whether or
// not it succeeds — a destructive operation that leaves no trace when it fails is
// exactly what an investigator needs and cannot get.
func TestPurgeIsAuditedAndBounded(t *testing.T) {
	rig := newRetentionRig(t, "retention-purge", 365)

	rig.seedAt(t, "inside", 5*24*time.Hour)
	// Inside the table TTL, outside the purge range: this proves the purge is
	// bounded rather than that the TTL happened to catch it.
	rig.seedAt(t, "outside", 20*24*time.Hour)

	actor := uuid.New()
	from := time.Now().UTC().Add(-7 * 24 * time.Hour)
	to := time.Now().UTC().Add(-2 * 24 * time.Hour)

	err := rig.worker.Purge(rig.ctx, retention.PurgeRequest{
		TenantID: rig.tenant.ID, From: from, To: to,
		Reason: "customer data deletion request", Actor: &actor,
		ActorEmail: "admin@example.com",
	})
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}

	if !waitFor(t, 30*time.Second, func() bool { return !rig.remaining(t)["inside"] }) {
		t.Error("the purged range was not removed")
	}
	if !rig.remaining(t)["outside"] {
		t.Error("the purge removed data outside its range")
	}

	// The audit listing requires an explicit range; an unset one reads as year zero.
	entries, err := chdata.NewAuditRepo(rig.fixture.ClickHouse,
		chdata.NewLocker(rig.fixture.Redis)).List(rig.ctx, chdata.ListFilter{
		From: time.Now().UTC().Add(-time.Hour), To: time.Now().UTC().Add(time.Hour),
		Limit: 50,
	})
	if err != nil {
		t.Fatalf("list audit entries: %v", err)
	}

	var purges int
	for _, entry := range entries {
		if entry.Action == "purge" {
			purges++
			if entry.ActorEmail != "admin@example.com" {
				t.Errorf("purge recorded actor %q, want the requesting admin", entry.ActorEmail)
			}
			if entry.Detail == "" {
				t.Error("the purge was recorded without its stated reason")
			}
		}
	}
	// Started and completed: an interrupted purge still leaves the first entry.
	if purges < 2 {
		t.Errorf("%d purge audit entries, want a start and a completion", purges)
	}
}

// A purge with no stated reason is indistinguishable from an attack afterwards.
func TestPurgeRequiresAReasonAndABoundedRange(t *testing.T) {
	rig := newRetentionRig(t, "retention-purge-invalid", 365)
	now := time.Now().UTC()

	cases := map[string]retention.PurgeRequest{
		"no reason": {
			TenantID: rig.tenant.ID, From: now.Add(-time.Hour), To: now,
		},
		"inverted range": {
			TenantID: rig.tenant.ID, From: now, To: now.Add(-time.Hour),
			Reason: "oops",
		},
	}

	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			if err := rig.worker.Purge(rig.ctx, req); err == nil {
				t.Error("an invalid purge was accepted")
			}
		})
	}
}
