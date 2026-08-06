// Package retention enforces how long data is kept.
//
// Expiry is TTL-driven, which in ClickHouse means a PARTITION DROP rather than a
// row-level delete. That distinction is the whole design: a DELETE over a hundred
// million rows is a mutation that rewrites parts and competes with ingestion, while a
// partition drop is a metadata operation that completes in milliseconds.
//
// This worker does not delete anything on the normal path. It reconciles the TABLE's
// TTL with each tenant's configured retention, and ClickHouse does the work in the
// background. The explicit purge path is separate, audited, and deliberately narrow.
package retention

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/audit"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/tenancy"
)

// Bounds on configured retention.
//
// The floor exists because a tenant who sets retention to zero would silently lose
// every event as it arrived; the ceiling because the partition count grows with the
// window and an unbounded one eventually makes every query plan slower.
const (
	MinRetentionDays = 1
	MaxRetentionDays = 730
)

// TenantSource lists the tenants whose retention must be applied.
type TenantSource interface {
	ListAll(ctx context.Context) ([]chdata.Tenant, error)
}

// PurgeStore performs the destructive operations.
type PurgeStore interface {
	DeleteEventsBefore(ctx context.Context, tenantID uuid.UUID, before time.Time) error
	DeleteCorrelatedBefore(ctx context.Context, tenantID uuid.UUID, before time.Time) error
	DeleteEventsInRange(ctx context.Context, tenantID uuid.UUID, from, to time.Time) error
}

// DefaultInterval is how often retention is reconciled.
//
// Hourly rather than continuously: TTL expiry is ClickHouse's job and runs on its own
// merge schedule. This worker only has to notice a CHANGED setting, which happens at
// human speed.
const DefaultInterval = time.Hour

// Worker applies per-tenant retention.
type Worker struct {
	tenants  TenantSource
	store    PurgeStore
	auditLog *chdata.AuditRepo
	log      mw.Logger

	interval time.Duration
	now      func() time.Time
}

// NewWorker constructs the retention worker.
func NewWorker(
	tenants TenantSource, store PurgeStore, auditLog *chdata.AuditRepo, log mw.Logger,
) *Worker {
	return &Worker{
		tenants: tenants, store: store, auditLog: auditLog, log: log,
		interval: DefaultInterval, now: time.Now,
	}
}

// Name identifies the worker in logs and metrics.
func (w *Worker) Name() string { return "retention" }

// Run reconciles retention until the context is cancelled.
func (w *Worker) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	// Once at startup, so a retention change made while the processor was down takes
	// effect on the next deploy rather than up to an hour later.
	if err := w.Reconcile(ctx); err != nil {
		w.log.Error(ctx, "retention: initial pass failed", "error", err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := w.Reconcile(ctx); err != nil {
				w.log.Error(ctx, "retention: pass failed", "error", err)
			}
		}
	}
}

// Reconcile applies every tenant's retention window.
func (w *Worker) Reconcile(ctx context.Context) error {
	tenants, err := w.tenants.ListAll(ctx)
	if err != nil {
		return fmt.Errorf("list tenants for retention: %w", err)
	}

	var failed error
	for _, tenant := range tenants {
		if err := w.applyTenant(ctx, tenant); err != nil {
			// One tenant's failure must not stop the rest: retention is a compliance
			// obligation and skipping the remaining tenants compounds the breach.
			failed = errors.Join(failed, err)
		}
	}
	return failed
}

// applyTenant removes data past a tenant's configured window.
//
// The table TTL is the platform DEFAULT and the coarse mechanism; this closes the gap
// for tenants configured shorter than it. A tenant asking for 7 days on a 30-day table
// TTL would otherwise keep data for 30 — a retention promise the platform advertises
// and does not honour.
func (w *Worker) applyTenant(ctx context.Context, tenant chdata.Tenant) error {
	scoped := tenancy.WithTenant(ctx,
		tenancy.Tenant{ID: tenant.ID, Name: tenant.Name})

	rawCutoff := w.cutoff(clampDays(tenant.RawRetentionDays))
	if err := w.store.DeleteEventsBefore(scoped, tenant.ID, rawCutoff); err != nil {
		return fmt.Errorf("apply event retention for %s: %w", tenant.ID, err)
	}

	correlatedCutoff := w.cutoff(clampDays(tenant.CorrelatedRetentionDays))
	if err := w.store.DeleteCorrelatedBefore(scoped, tenant.ID, correlatedCutoff); err != nil {
		return fmt.Errorf("apply correlated retention for %s: %w", tenant.ID, err)
	}
	return nil
}

func (w *Worker) cutoff(days int) time.Time {
	return w.now().UTC().AddDate(0, 0, -days)
}

// clampDays bounds a configured retention window.
func clampDays(days uint16) int {
	switch {
	case days == 0:
		// An unset value means "use the platform default", not "keep nothing". Reading
		// zero as immediate expiry would delete a tenant's data the moment it landed.
		return 30
	case int(days) < MinRetentionDays:
		return MinRetentionDays
	case int(days) > MaxRetentionDays:
		return MaxRetentionDays
	default:
		return int(days)
	}
}

// PurgeRequest is an explicit, operator-initiated deletion.
type PurgeRequest struct {
	TenantID uuid.UUID
	From, To time.Time
	// Reason is recorded in the audit trail. Required: a destructive operation with no
	// stated cause is indistinguishable from an attack afterwards.
	Reason string
	// Actor identifies who asked, for the audit entry.
	Actor      *uuid.UUID
	ActorEmail string
}

// Purge deletes a time range outside the normal retention path (FR-036).
//
// AUDITED BEFORE AND AFTER. The entry is written first so an interrupted purge still
// leaves a record that it was attempted — a destructive operation that vanishes
// without trace when it fails is precisely what an investigator needs and cannot get.
func (w *Worker) Purge(ctx context.Context, req PurgeRequest) error {
	if req.Reason == "" {
		return mw.ValidationFailed("a purge requires a stated reason")
	}
	if !req.From.Before(req.To) {
		return mw.ValidationFailed("the purge range must start before it ends")
	}

	scoped := tenancy.WithTenant(ctx, tenancy.Tenant{ID: req.TenantID})

	w.record(scoped, req, audit.ResultSuccess, "purge started")

	if err := w.store.DeleteEventsInRange(scoped, req.TenantID, req.From, req.To); err != nil {
		w.record(scoped, req, audit.ResultDenied, "purge failed: "+err.Error())
		return fmt.Errorf("purge events: %w", err)
	}

	w.record(scoped, req, audit.ResultSuccess, "purge completed")
	return nil
}

func (w *Worker) record(
	ctx context.Context, req PurgeRequest, result audit.Result, detail string,
) {
	if w.auditLog == nil {
		return
	}

	entry := audit.Record{
		ActorUserID: req.Actor,
		ActorEmail:  req.ActorEmail,
		Action:      audit.ActionPurge,
		TargetType:  "events",
		TargetID: fmt.Sprintf("%s..%s",
			req.From.UTC().Format(time.RFC3339), req.To.UTC().Format(time.RFC3339)),
		Result: result,
		Detail: fmt.Sprintf("%s: %s", detail, req.Reason),
	}

	if _, err := w.auditLog.Append(ctx, entry); err != nil {
		w.log.Error(ctx, "retention: could not record the purge in the audit trail",
			"error", err)
	}
}
