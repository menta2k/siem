package alerting

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/alerting/rule"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/tenancy"
)

// RuleStore is the rule and alert surface the worker writes through.
type RuleStore interface {
	ListEnabledRules(ctx context.Context) ([]chdata.AlertRule, error)
	GetRule(ctx context.Context, ruleID uuid.UUID) (chdata.AlertRule, error)
	InsertAlert(ctx context.Context, alert chdata.Alert) (chdata.Alert, error)
	UpdateAlert(ctx context.Context, alertID uuid.UUID,
		mutate func(chdata.Alert) chdata.Alert) (chdata.Alert, error)
	PendingDeliveries(ctx context.Context, limit int) ([]chdata.Alert, error)
}

// Deliverer posts an alert to its webhook.
type Deliverer interface {
	Deliver(ctx context.Context, rule chdata.AlertRule, alert chdata.Alert) (
		status string, attempts uint8, lastErr string)
}

// Default worker cadences.
const (
	DefaultEvaluateInterval = 30 * time.Second
	DefaultDeliverInterval  = 10 * time.Second
	DefaultDeliverBatch     = 50
)

// Worker evaluates rules and delivers the alerts they produce.
//
// Evaluation and delivery run on SEPARATE tickers. A webhook receiver that has become
// slow must not delay rule evaluation: the alert's existence is the guarantee, and the
// notification is best-effort on top of it.
type Worker struct {
	rules     RuleStore
	evaluator *Evaluator
	cooldown  *Cooldown
	deliverer Deliverer
	log       mw.Logger

	evaluateInterval time.Duration
	deliverInterval  time.Duration
	now              func() time.Time
}

// NewWorker constructs the alerting worker.
func NewWorker(
	rules RuleStore, evaluator *Evaluator, cooldown *Cooldown,
	deliverer Deliverer, log mw.Logger,
) *Worker {
	return &Worker{
		rules: rules, evaluator: evaluator, cooldown: cooldown,
		deliverer: deliverer, log: log,
		evaluateInterval: DefaultEvaluateInterval,
		deliverInterval:  DefaultDeliverInterval,
		now:              time.Now,
	}
}

// Name identifies the worker in logs and metrics.
func (w *Worker) Name() string { return "alerting" }

// Run evaluates and delivers until the context is cancelled.
func (w *Worker) Run(ctx context.Context) error {
	evaluate := time.NewTicker(w.evaluateInterval)
	defer evaluate.Stop()
	deliver := time.NewTicker(w.deliverInterval)
	defer deliver.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-evaluate.C:
			if err := w.EvaluateAll(ctx, w.now()); err != nil {
				// Logged, not returned. One tenant's broken rule must not stop
				// evaluation for everyone else.
				w.log.Error(ctx, "alerting: evaluation pass failed", "error", err)
			}
		case <-deliver.C:
			if err := w.DeliverPending(ctx); err != nil {
				w.log.Error(ctx, "alerting: delivery pass failed", "error", err)
			}
		}
	}
}

// EvaluateAll runs every enabled rule once.
func (w *Worker) EvaluateAll(ctx context.Context, now time.Time) error {
	rules, err := w.rules.ListEnabledRules(ctx)
	if err != nil {
		return fmt.Errorf("list enabled rules: %w", err)
	}

	var failed error
	for _, r := range rules {
		if err := w.evaluateRule(ctx, r, now); err != nil {
			failed = errors.Join(failed, err)
		}
	}
	return failed
}

// evaluateRule measures one rule and fires the groups that qualify.
func (w *Worker) evaluateRule(ctx context.Context, r chdata.AlertRule, now time.Time) error {
	RulesEvaluated.Inc()

	condition, err := rule.Parse(r.Condition)
	if err != nil {
		EvaluationFailures.WithLabelValues("invalid_condition").Inc()
		return fmt.Errorf("rule %s has an invalid condition: %w", r.ID, err)
	}

	results, err := w.evaluator.Evaluate(ctx, r, WindowFor(r, now))
	if err != nil {
		EvaluationFailures.WithLabelValues("measure").Inc()
		return err
	}

	scoped := tenancy.WithTenant(ctx, tenancy.Tenant{ID: r.TenantID})

	var failed error
	for _, result := range results {
		if !result.Fired {
			continue
		}
		if err := w.fire(scoped, r, condition, result, now); err != nil {
			failed = errors.Join(failed, err)
		}
	}
	return failed
}

// fire claims the cooldown and persists an alert.
//
// The cooldown is claimed BEFORE the alert is written. The other order would persist
// an alert and then discover it should have been suppressed, leaving a row that the
// operator sees and the webhook never mentions — a discrepancy with no explanation.
func (w *Worker) fire(
	ctx context.Context, r chdata.AlertRule, condition rule.Condition,
	result Result, now time.Time,
) error {
	allowed, err := w.cooldown.Allow(
		ctx, r.TenantID, r.ID, result.GroupValues, condition.Cooldown())
	if err != nil {
		return err
	}
	if !allowed {
		Suppressed.Inc()
		return nil
	}

	alert := chdata.Alert{
		TenantID:               r.TenantID,
		RuleID:                 r.ID,
		FiredAt:                now.UTC(),
		Severity:               r.Severity,
		State:                  chdata.AlertStateNew,
		GroupValues:            result.GroupValues,
		ObservedValue:          result.Observed,
		Threshold:              condition.Threshold,
		EvidenceCorrelationIDs: result.EvidenceCorrelationIDs,
		NotifyStatus:           chdata.NotifyPending,
	}

	if _, err := w.rules.InsertAlert(ctx, alert); err != nil {
		return fmt.Errorf("persist alert for rule %s: %w", r.ID, err)
	}

	Fired.WithLabelValues(r.Severity).Inc()
	return nil
}

// DeliverPending attempts delivery for alerts whose webhook has not yet succeeded.
func (w *Worker) DeliverPending(ctx context.Context) error {
	pending, err := w.rules.PendingDeliveries(ctx, DefaultDeliverBatch)
	if err != nil {
		return fmt.Errorf("list pending deliveries: %w", err)
	}
	PendingDeliveries.Set(float64(len(pending)))

	var failed error
	for _, alert := range pending {
		if err := w.deliverOne(ctx, alert); err != nil {
			failed = errors.Join(failed, err)
		}
	}
	return failed
}

func (w *Worker) deliverOne(ctx context.Context, alert chdata.Alert) error {
	scoped := tenancy.WithTenant(ctx, tenancy.Tenant{ID: alert.TenantID})

	r, err := w.rules.GetRule(scoped, alert.RuleID)
	if err != nil {
		// A rule is disabled rather than deleted, so this means the row is genuinely
		// gone. The alert cannot be delivered and must not be retried forever.
		if _, updateErr := w.markDelivery(scoped, alert.ID,
			chdata.NotifyFailed, alert.NotifyAttempts+1,
			"the rule behind this alert no longer exists"); updateErr != nil {
			return updateErr
		}
		DeliveryFailures.Inc()
		return nil
	}

	// Respects the backoff without a scheduler: an alert that has already failed N
	// times is skipped until enough time has passed since it fired.
	if !w.dueForRetry(alert) {
		return nil
	}

	started := w.now()
	status, attempts, lastErr := w.deliverer.Deliver(scoped, r, alert)
	DeliveryDuration.Observe(w.now().Sub(started).Seconds())

	switch status {
	case chdata.NotifyDelivered:
		DeliveryAttempts.WithLabelValues("delivered").Inc()
	case chdata.NotifyFailed:
		DeliveryAttempts.WithLabelValues("failed").Inc()
		DeliveryFailures.Inc()
	default:
		DeliveryAttempts.WithLabelValues("retrying").Inc()
	}

	if _, err := w.markDelivery(scoped, alert.ID, status, attempts, lastErr); err != nil {
		return err
	}
	return nil
}

// dueForRetry reports whether enough time has passed since the alert fired for the
// next attempt, using the same exponential schedule the backoff describes.
func (w *Worker) dueForRetry(alert chdata.Alert) bool {
	if alert.NotifyAttempts == 0 {
		return true
	}
	wait := Backoff(int(alert.NotifyAttempts))
	return !w.now().UTC().Before(alert.FiredAt.UTC().Add(wait))
}

func (w *Worker) markDelivery(
	ctx context.Context, alertID uuid.UUID, status string, attempts uint8, lastErr string,
) (chdata.Alert, error) {
	return w.rules.UpdateAlert(ctx, alertID, func(current chdata.Alert) chdata.Alert {
		current.NotifyStatus = status
		current.NotifyAttempts = attempts
		current.NotifyLastError = lastErr
		return current
	})
}
