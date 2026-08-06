// Package rule models the conditions an alert fires on.
//
// A condition is stored as JSON and evaluated against correlated_requests. It is
// deliberately NOT an expression language: an operator writing a rule should not be
// able to author something that scans without bounds, references a column that does
// not exist, or reaches SQL. Every field, aggregate, and comparator below is a closed
// set, validated on write and again before evaluation.
package rule

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/query"
)

// Aggregate is what a rule measures over its window.
type Aggregate string

// The supported aggregates.
const (
	// AggregateCount counts matching correlated requests.
	AggregateCount Aggregate = "count"
	// AggregateRate is matching requests as a fraction of all requests in the window.
	// Distinct from count because a spike in blocks during a traffic surge is normal,
	// while the same count during quiet hours is not.
	AggregateRate Aggregate = "rate"
	// AggregateDistinctIPs counts unique client addresses, which is what separates one
	// noisy client from a distributed attack.
	AggregateDistinctIPs Aggregate = "distinct_ips"
)

// Comparator is how the observed value is tested against the threshold.
type Comparator string

// The supported comparators.
const (
	ComparatorGreaterThan  Comparator = "gt"
	ComparatorGreaterEqual Comparator = "gte"
	ComparatorLessThan     Comparator = "lt"
	ComparatorLessEqual    Comparator = "lte"
)

// Bounds on rule parameters.
//
// The window bounds matter most. A window of days would make every evaluation a scan
// of days of data on every pass, and a window of a second would fire on ordinary
// jitter — both produce an alerting system nobody trusts, by different routes.
const (
	MinWindow   = 30 * time.Second
	MaxWindow   = 24 * time.Hour
	MinCooldown = time.Minute
	MaxCooldown = 7 * 24 * time.Hour
	// MaxGroupBy caps the group-by cardinality. Each group is a separate alert and a
	// separate cooldown key; three is already enough to produce thousands of alerts
	// from one rule.
	MaxGroupBy = 3
)

// groupableFields are the columns a rule may group by.
//
// A closed set because the value reaches a GROUP BY clause. Grouping by a
// high-cardinality column such as correlation_id would produce one alert per request,
// which is not an alert but a copy of the data.
var groupableFields = map[string]query.Column{
	"request_host":      "request_host",
	"client_ip":         "client_ip",
	"country":           "client_country",
	"disagreement_kind": "disagreement_kind",
	"combined_outcome":  "combined_outcome",
	"confidence":        "confidence",
}

// Condition is the stored, validated shape of a rule.
type Condition struct {
	// Filters narrow which correlated requests the rule considers. Field names are
	// validated against the correlated-request allowlist, exactly as a search is.
	Filters map[string]string `json:"filters,omitempty"`
	// OnlyDisagreements restricts the rule to records where vendors conflicted.
	OnlyDisagreements bool `json:"only_disagreements,omitempty"`
	// MinVendorCount restricts the rule to genuine cross-vendor joins.
	MinVendorCount uint32 `json:"min_vendor_count,omitempty"`

	Aggregate  Aggregate  `json:"aggregate"`
	Comparator Comparator `json:"comparator"`
	Threshold  float64    `json:"threshold"`

	WindowSeconds   uint32   `json:"window_seconds"`
	GroupBy         []string `json:"group_by,omitempty"`
	CooldownSeconds uint32   `json:"cooldown_seconds"`
}

// Window is the evaluation window as a duration.
func (c Condition) Window() time.Duration {
	return time.Duration(c.WindowSeconds) * time.Second
}

// Cooldown is the suppression period as a duration.
func (c Condition) Cooldown() time.Duration {
	return time.Duration(c.CooldownSeconds) * time.Second
}

// Satisfied reports whether an observed value trips the condition.
func (c Condition) Satisfied(observed float64) bool {
	switch c.Comparator {
	case ComparatorGreaterThan:
		return observed > c.Threshold
	case ComparatorGreaterEqual:
		return observed >= c.Threshold
	case ComparatorLessThan:
		return observed < c.Threshold
	case ComparatorLessEqual:
		return observed <= c.Threshold
	default:
		// An unknown comparator never fires. A rule that cannot be evaluated must stay
		// silent rather than alert on everything — a storm of meaningless alerts is how
		// a team learns to ignore the channel.
		return false
	}
}

// GroupColumns resolves the group-by fields to physical columns.
func (c Condition) GroupColumns() ([]query.Column, error) {
	columns := make([]query.Column, 0, len(c.GroupBy))
	for _, field := range c.GroupBy {
		column, ok := groupableFields[strings.ToLower(strings.TrimSpace(field))]
		if !ok {
			return nil, mw.RuleConditionInvalid(
				fmt.Sprintf("cannot group by %q", field))
		}
		columns = append(columns, column)
	}
	return columns, nil
}

// Parse decodes and validates a stored condition.
//
// Validation happens on read as well as on write. A row can reach the database through
// a migration, a seed script, or a direct edit, and an evaluator that trusts its input
// turns any of those into a malformed query at runtime.
func Parse(encoded string) (Condition, error) {
	var condition Condition

	decoder := json.NewDecoder(strings.NewReader(encoded))
	// Unknown fields are rejected rather than ignored: a typo in a field name would
	// otherwise silently produce a rule that does not filter what its author believes
	// it filters, and it would fire for months before anyone noticed.
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&condition); err != nil {
		return Condition{}, mw.RuleConditionInvalid(
			fmt.Sprintf("the condition is not valid JSON: %v", err))
	}

	if err := condition.Validate(); err != nil {
		return Condition{}, err
	}
	return condition, nil
}

// Encode renders a condition for storage.
func (c Condition) Encode() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		return "", mw.RuleConditionInvalid("the condition could not be encoded")
	}
	return string(encoded), nil
}

// Validate checks every field of a condition.
func (c Condition) Validate() error {
	if err := c.validateAggregate(); err != nil {
		return err
	}
	if err := c.validateThreshold(); err != nil {
		return err
	}
	if err := c.validateWindow(); err != nil {
		return err
	}
	if err := c.validateGroupBy(); err != nil {
		return err
	}
	return c.validateFilters()
}

func (c Condition) validateAggregate() error {
	switch c.Aggregate {
	case AggregateCount, AggregateRate, AggregateDistinctIPs:
		return nil
	case "":
		return mw.RuleConditionInvalid("an aggregate is required")
	default:
		return mw.RuleConditionInvalid(
			fmt.Sprintf("unsupported aggregate %q", c.Aggregate))
	}
}

func (c Condition) validateThreshold() error {
	switch c.Comparator {
	case ComparatorGreaterThan, ComparatorGreaterEqual,
		ComparatorLessThan, ComparatorLessEqual:
	case "":
		return mw.RuleConditionInvalid("a comparator is required")
	default:
		return mw.RuleConditionInvalid(
			fmt.Sprintf("unsupported comparator %q", c.Comparator))
	}

	if c.Threshold < 0 {
		return mw.RuleConditionInvalid("the threshold cannot be negative")
	}
	// A rate is a fraction. A threshold above 1 can never be reached, so the rule would
	// sit enabled and silent — the worst state for an alert, because it looks healthy.
	if c.Aggregate == AggregateRate && c.Threshold > 1 {
		return mw.RuleConditionInvalid(
			"a rate threshold is a fraction between 0 and 1")
	}
	return nil
}

func (c Condition) validateWindow() error {
	window := c.Window()
	if window < MinWindow || window > MaxWindow {
		return mw.RuleConditionInvalid(fmt.Sprintf(
			"the window must be between %s and %s", MinWindow, MaxWindow))
	}

	cooldown := c.Cooldown()
	if cooldown < MinCooldown || cooldown > MaxCooldown {
		return mw.RuleConditionInvalid(fmt.Sprintf(
			"the cooldown must be between %s and %s", MinCooldown, MaxCooldown))
	}

	// A cooldown shorter than the window re-fires on data the previous alert already
	// covered, so one sustained condition produces a stream of duplicate alerts.
	if cooldown < window {
		return mw.RuleConditionInvalid(
			"the cooldown must be at least as long as the window")
	}
	return nil
}

func (c Condition) validateGroupBy() error {
	if len(c.GroupBy) > MaxGroupBy {
		return mw.RuleConditionInvalid(fmt.Sprintf(
			"a rule may group by at most %d fields", MaxGroupBy))
	}

	seen := map[string]bool{}
	for _, field := range c.GroupBy {
		normalized := strings.ToLower(strings.TrimSpace(field))
		if _, ok := groupableFields[normalized]; !ok {
			return mw.RuleConditionInvalid(fmt.Sprintf("cannot group by %q", field))
		}
		if seen[normalized] {
			return mw.RuleConditionInvalid(
				fmt.Sprintf("duplicate group-by field %q", field))
		}
		seen[normalized] = true
	}
	return nil
}

// validateFilters checks filter names against the same allowlist a search uses.
//
// Reusing the search allowlist is deliberate: a rule that could filter on a field a
// search cannot would fire on something an analyst is unable to investigate.
func (c Condition) validateFilters() error {
	for field := range c.Filters {
		if _, err := query.CorrelatedTable.Resolve(field); err != nil {
			return mw.RuleConditionInvalid(
				fmt.Sprintf("unknown filter field %q", field))
		}
	}
	if c.MinVendorCount > 255 {
		return mw.RuleConditionInvalid("min_vendor_count is out of range")
	}
	return nil
}
