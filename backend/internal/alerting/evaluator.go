// Package alerting evaluates rules over correlated data and delivers the results.
//
// The pipeline is evaluate → suppress → persist → deliver, and the order is the
// contract. Persisting BEFORE delivering is what makes FR-032 hold: an alert that
// exists but was not delivered is a visible failure an operator can act on, while an
// alert that was delivered but never stored is a notification with nothing behind it.
package alerting

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/alerting/rule"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/query"
	"github.com/menta2k/siem/internal/tenancy"
)

// MaxEvidence caps how many correlated records an alert links.
//
// The evidence is a starting point for an investigation, not the result set. A rule
// that matched fifty thousand records would otherwise write fifty thousand ids into a
// row that gets read on every triage page load.
const MaxEvidence = 20

// Window is the slice of time a rule is evaluated over.
type Window struct {
	From time.Time
	To   time.Time
}

// Result is one group's measurement within a window.
type Result struct {
	// GroupValues are the group-by values this measurement is for. Empty for an
	// ungrouped rule.
	GroupValues map[string]string
	// Observed is the aggregate's value.
	Observed float64
	// Total is the denominator a rate was computed against, carried so the alert can
	// say "12 of 400" rather than "3%", which is what an operator needs to judge it.
	Total float64
	// EvidenceCorrelationIDs are the records behind the measurement.
	EvidenceCorrelationIDs []uuid.UUID
	// Fired reports whether the condition was satisfied.
	Fired bool
}

// Store is the read surface the evaluator needs.
type Store interface {
	Measure(ctx context.Context, q MeasureQuery) ([]Measurement, error)
}

// MeasureQuery is a validated request for one rule's window.
type MeasureQuery struct {
	Window     Window
	Aggregate  rule.Aggregate
	Conditions string
	Args       []any
	GroupBy    []query.Column
	// EvidenceLimit caps the ids collected per group.
	EvidenceLimit int
}

// Measurement is one group's raw figures from storage.
type Measurement struct {
	GroupValues            map[string]string
	Value                  float64
	Total                  float64
	EvidenceCorrelationIDs []uuid.UUID
}

// Evaluator measures rules against correlated requests.
type Evaluator struct {
	store Store
}

// NewEvaluator constructs the evaluator.
func NewEvaluator(store Store) *Evaluator {
	return &Evaluator{store: store}
}

// Evaluate measures one rule over one window and reports which groups fired.
//
// Groups that did NOT fire are returned too. The caller needs them for a dry run — a
// rule author previewing a rule has to see the values it did not trip on, or they are
// tuning a threshold blind.
func (e *Evaluator) Evaluate(
	ctx context.Context, r chdata.AlertRule, window Window,
) ([]Result, error) {
	condition, err := rule.Parse(r.Condition)
	if err != nil {
		return nil, err
	}

	conditions, args, err := buildConditions(condition)
	if err != nil {
		return nil, err
	}

	groupBy, err := condition.GroupColumns()
	if err != nil {
		return nil, err
	}

	// The evaluator runs without a request, so it scopes each rule to the tenant
	// recorded on the rule row itself.
	scoped := tenancy.WithTenant(ctx, tenancy.Tenant{ID: r.TenantID})

	measurements, err := e.store.Measure(scoped, MeasureQuery{
		Window:        window,
		Aggregate:     condition.Aggregate,
		Conditions:    conditions,
		Args:          args,
		GroupBy:       groupBy,
		EvidenceLimit: MaxEvidence,
	})
	if err != nil {
		return nil, fmt.Errorf("measure rule %s: %w", r.ID, err)
	}

	results := make([]Result, 0, len(measurements))
	for _, m := range measurements {
		results = append(results, Result{
			GroupValues:            m.GroupValues,
			Observed:               m.Value,
			Total:                  m.Total,
			EvidenceCorrelationIDs: m.EvidenceCorrelationIDs,
			Fired:                  condition.Satisfied(m.Value),
		})
	}
	return results, nil
}

// WindowFor returns the window a rule should be evaluated over at `now`.
//
// The window ENDS at now and extends backwards. Aligning it to a clock boundary would
// be tidier to read but would make every rule with the same window fire in the same
// second, which turns a cluster-wide traffic change into a synchronised alert storm.
func WindowFor(r chdata.AlertRule, now time.Time) Window {
	seconds := r.WindowSeconds
	if seconds == 0 {
		seconds = uint32(rule.MinWindow.Seconds())
	}
	to := now.UTC()
	return Window{From: to.Add(-time.Duration(seconds) * time.Second), To: to}
}

// clampVendorCount saturates a configured minimum into the column's range.
func clampVendorCount(n uint32) uint8 {
	if n > 255 {
		return 255
	}
	return uint8(n)
}

// buildConditions renders a rule's filters through the allowlisting query builder.
//
// The same builder a search uses. A rule cannot express a filter an analyst could not
// also run, which matters because the first thing anyone does with an alert is try to
// reproduce it.
func buildConditions(condition rule.Condition) (string, []any, error) {
	b := query.NewBuilder(query.CorrelatedTable)

	for field, value := range condition.Filters {
		b.WhereIfSet(field, query.OpEqual, value)
	}
	if condition.OnlyDisagreements {
		b.Where("has_disagreement", query.OpEqual, true)
	}
	if condition.MinVendorCount > 0 {
		// Saturated rather than wrapped: the column is a UInt8, and a nonsensical
		// filter should narrow to nothing rather than silently become zero and match
		// every record.
		b.Where("vendor_count", query.OpGreaterEqual, clampVendorCount(condition.MinVendorCount))
	}

	return b.Conditions()
}
