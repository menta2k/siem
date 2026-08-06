package alerting_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/alerting"
	"github.com/menta2k/siem/internal/alerting/rule"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/tenancy"
)

var (
	evalTenant = uuid.MustParse("00000000-0000-4000-8000-0000000000a1")
	evalNow    = time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
)

// stubStore records the query it was asked for, so the tests can assert on what the
// evaluator ACTUALLY requested rather than only on what it returned.
type stubStore struct {
	measurements []alerting.Measurement
	err          error

	lastQuery  alerting.MeasureQuery
	lastTenant uuid.UUID
	calls      int
}

func (s *stubStore) Measure(
	ctx context.Context, q alerting.MeasureQuery,
) ([]alerting.Measurement, error) {
	s.calls++
	s.lastQuery = q
	if tenant, err := tenancy.FromContext(ctx); err == nil {
		s.lastTenant = tenant.ID
	}
	return s.measurements, s.err
}

func ruleWith(t *testing.T, condition rule.Condition) chdata.AlertRule {
	t.Helper()

	encoded, err := condition.Encode()
	if err != nil {
		t.Fatalf("encode condition: %v", err)
	}
	return chdata.AlertRule{
		TenantID: evalTenant, ID: uuid.New(), Name: "test rule",
		Enabled: true, Severity: chdata.SeverityHigh,
		Condition:       encoded,
		WindowSeconds:   condition.WindowSeconds,
		GroupBy:         condition.GroupBy,
		CooldownSeconds: condition.CooldownSeconds,
	}
}

func countRule(t *testing.T, threshold float64) chdata.AlertRule {
	t.Helper()
	return ruleWith(t, rule.Condition{
		Aggregate: rule.AggregateCount, Comparator: rule.ComparatorGreaterThan,
		Threshold: threshold, WindowSeconds: 300, CooldownSeconds: 900,
	})
}

func TestFiresWhenTheThresholdIsExceeded(t *testing.T) {
	store := &stubStore{measurements: []alerting.Measurement{{Value: 25, Total: 100}}}
	evaluator := alerting.NewEvaluator(store)

	results, err := evaluator.Evaluate(context.Background(), countRule(t, 10),
		alerting.Window{From: evalNow.Add(-5 * time.Minute), To: evalNow})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if !results[0].Fired {
		t.Error("25 did not fire against a threshold of 10")
	}
}

func TestDoesNotFireBelowTheThreshold(t *testing.T) {
	store := &stubStore{measurements: []alerting.Measurement{{Value: 3, Total: 100}}}
	evaluator := alerting.NewEvaluator(store)

	results, err := evaluator.Evaluate(context.Background(), countRule(t, 10),
		alerting.Window{From: evalNow.Add(-5 * time.Minute), To: evalNow})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if results[0].Fired {
		t.Error("3 fired against a threshold of 10")
	}
}

// A rule author previewing a rule has to see the values it did NOT trip on, or they
// are tuning a threshold blind.
func TestNonFiringGroupsAreStillReturned(t *testing.T) {
	store := &stubStore{measurements: []alerting.Measurement{
		{GroupValues: map[string]string{"request_host": "a.example.com"}, Value: 50},
		{GroupValues: map[string]string{"request_host": "b.example.com"}, Value: 2},
	}}
	evaluator := alerting.NewEvaluator(store)

	r := ruleWith(t, rule.Condition{
		Aggregate: rule.AggregateCount, Comparator: rule.ComparatorGreaterThan,
		Threshold: 10, WindowSeconds: 300, CooldownSeconds: 900,
		GroupBy: []string{"request_host"},
	})

	results, err := evaluator.Evaluate(context.Background(), r,
		alerting.Window{From: evalNow.Add(-5 * time.Minute), To: evalNow})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want both groups", len(results))
	}

	fired := map[string]bool{}
	for _, result := range results {
		fired[result.GroupValues["request_host"]] = result.Fired
	}
	if !fired["a.example.com"] {
		t.Error("the group above the threshold did not fire")
	}
	if fired["b.example.com"] {
		t.Error("the group below the threshold fired")
	}
}

// Group-by fields must reach storage as resolved COLUMNS, never as the caller's
// strings: the value lands in a GROUP BY clause that no placeholder protects.
func TestGroupByReachesStorageAsResolvedColumns(t *testing.T) {
	store := &stubStore{}
	evaluator := alerting.NewEvaluator(store)

	r := ruleWith(t, rule.Condition{
		Aggregate: rule.AggregateCount, Comparator: rule.ComparatorGreaterThan,
		Threshold: 1, WindowSeconds: 300, CooldownSeconds: 900,
		GroupBy: []string{"country"},
	})

	if _, err := evaluator.Evaluate(context.Background(), r,
		alerting.Window{From: evalNow.Add(-5 * time.Minute), To: evalNow}); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if len(store.lastQuery.GroupBy) != 1 {
		t.Fatalf("got %d group columns, want 1", len(store.lastQuery.GroupBy))
	}
	if got := string(store.lastQuery.GroupBy[0]); got != "client_country" {
		t.Errorf("group column = %q, want client_country", got)
	}
}

// The evaluator runs as a background worker with no request to inherit a tenant from,
// so it must scope each rule to the tenant on the rule row. Without this a rule would
// measure every tenant's data and alert one customer about another's traffic.
func TestEvaluationIsScopedToTheRuleTenant(t *testing.T) {
	store := &stubStore{}
	evaluator := alerting.NewEvaluator(store)

	if _, err := evaluator.Evaluate(context.Background(), countRule(t, 1),
		alerting.Window{From: evalNow.Add(-5 * time.Minute), To: evalNow}); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if store.lastTenant != evalTenant {
		t.Errorf("measured as tenant %s, want %s", store.lastTenant, evalTenant)
	}
}

// Filters reach storage as bound parameters, exactly as a search does.
func TestFiltersAreBoundNotInterpolated(t *testing.T) {
	store := &stubStore{}
	evaluator := alerting.NewEvaluator(store)

	r := ruleWith(t, rule.Condition{
		Aggregate: rule.AggregateCount, Comparator: rule.ComparatorGreaterThan,
		Threshold: 1, WindowSeconds: 300, CooldownSeconds: 900,
		Filters:           map[string]string{"request_host": "shop.example.com"},
		OnlyDisagreements: true,
	})

	if _, err := evaluator.Evaluate(context.Background(), r,
		alerting.Window{From: evalNow.Add(-5 * time.Minute), To: evalNow}); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	conditions := store.lastQuery.Conditions
	if strings.Contains(conditions, "shop.example.com") {
		t.Fatalf("a filter value was interpolated into the query: %s", conditions)
	}
	if strings.Count(conditions, "?") != len(store.lastQuery.Args) {
		t.Errorf("%d placeholders but %d args", strings.Count(conditions, "?"),
			len(store.lastQuery.Args))
	}
}

// A rule whose stored condition is corrupt must fail loudly rather than measure
// something arbitrary — a rule that quietly evaluates the wrong thing is worse than
// one that reports itself broken.
func TestACorruptConditionFailsEvaluation(t *testing.T) {
	store := &stubStore{}
	evaluator := alerting.NewEvaluator(store)

	broken := countRule(t, 10)
	broken.Condition = `{"aggregate":"median","comparator":"gt","threshold":1}`

	if _, err := evaluator.Evaluate(context.Background(), broken,
		alerting.Window{From: evalNow.Add(-5 * time.Minute), To: evalNow}); err == nil {
		t.Fatal("a rule with an invalid condition was evaluated")
	}
	if store.calls != 0 {
		t.Error("a query was issued for a rule that could not be parsed")
	}
}

// The window ends at now and extends backwards, rather than snapping to a clock
// boundary — otherwise every rule with the same window fires in the same second and a
// cluster-wide traffic change becomes a synchronised alert storm.
func TestWindowEndsAtNow(t *testing.T) {
	r := countRule(t, 10)
	r.WindowSeconds = 300

	window := alerting.WindowFor(r, evalNow)

	if !window.To.Equal(evalNow) {
		t.Errorf("window ends at %v, want %v", window.To, evalNow)
	}
	if got := window.To.Sub(window.From); got != 5*time.Minute {
		t.Errorf("window width = %v, want 5m", got)
	}
}

func TestEvidenceIsBounded(t *testing.T) {
	store := &stubStore{}
	evaluator := alerting.NewEvaluator(store)

	if _, err := evaluator.Evaluate(context.Background(), countRule(t, 1),
		alerting.Window{From: evalNow.Add(-5 * time.Minute), To: evalNow}); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if store.lastQuery.EvidenceLimit <= 0 ||
		store.lastQuery.EvidenceLimit > alerting.MaxEvidence {
		t.Errorf("evidence limit = %d, want a positive value up to %d",
			store.lastQuery.EvidenceLimit, alerting.MaxEvidence)
	}
}
