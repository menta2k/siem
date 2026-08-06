package rule_test

import (
	"strings"
	"testing"
	"time"

	"github.com/menta2k/siem/internal/alerting/rule"
	mw "github.com/menta2k/siem/internal/middleware"
)

func validCondition() rule.Condition {
	return rule.Condition{
		Aggregate:       rule.AggregateCount,
		Comparator:      rule.ComparatorGreaterThan,
		Threshold:       10,
		WindowSeconds:   300,
		CooldownSeconds: 900,
	}
}

func TestValidConditionRoundTrips(t *testing.T) {
	want := validCondition()
	want.GroupBy = []string{"request_host"}
	want.Filters = map[string]string{"confidence": "high"}

	encoded, err := want.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	got, err := rule.Parse(encoded)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Aggregate != want.Aggregate || got.Threshold != want.Threshold {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if len(got.GroupBy) != 1 || got.GroupBy[0] != "request_host" {
		t.Errorf("group by = %v, want [request_host]", got.GroupBy)
	}
}

// A malformed condition must be rejected with the stable code, so the console can tell
// the author their rule is wrong rather than showing them a generic failure.
func TestMalformedConditionsAreRejected(t *testing.T) {
	const base = `"window_seconds":300,"cooldown_seconds":900`

	cases := map[string]string{
		"not json":           `{`,
		"empty":              ``,
		"no aggregate":       `{"comparator":"gt","threshold":1,` + base + `}`,
		"no comparator":      `{"aggregate":"count","threshold":1,` + base + `}`,
		"unknown aggregate":  `{"aggregate":"median","comparator":"gt","threshold":1,` + base + `}`,
		"unknown comparator": `{"aggregate":"count","comparator":"x","threshold":1,` + base + `}`,
		"negative threshold": `{"aggregate":"count","comparator":"gt","threshold":-1,` + base + `}`,
		"unknown filter": `{"aggregate":"count","comparator":"gt","threshold":1,` +
			base + `,"filters":{"password":"x"}}`,
		"unknown group field": `{"aggregate":"count","comparator":"gt","threshold":1,` +
			base + `,"group_by":["correlation_id"]}`,
	}

	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := rule.Parse(encoded)
			if err == nil {
				t.Fatalf("condition %q was accepted", encoded)
			}
			if got := mw.AsError(err).Code; got != mw.CodeRuleConditionInvalid {
				t.Errorf("code = %q, want %q", got, mw.CodeRuleConditionInvalid)
			}
		})
	}
}

// A typo in a field name would otherwise produce a rule that does not filter what its
// author believes it filters, and it would fire for months before anyone noticed.
func TestUnknownJSONFieldsAreRejected(t *testing.T) {
	encoded := `{"aggregate":"count","comparator":"gt","threshold":1,
	             "window_seconds":300,"cooldown_seconds":900,"treshold":99}`

	if _, err := rule.Parse(encoded); err == nil {
		t.Error("a misspelled field was silently ignored")
	}
}

// A window of days scans days of data on every pass; a window of a second fires on
// ordinary jitter. Both produce an alerting system nobody trusts.
func TestWindowBoundsAreEnforced(t *testing.T) {
	cases := map[string]struct {
		window, cooldown uint32
		wantErr          bool
	}{
		"too short":       {5, 900, true},
		"too long":        {uint32((48 * time.Hour).Seconds()), 900, true},
		"at the minimum":  {uint32(rule.MinWindow.Seconds()), 900, false},
		"at the maximum":  {uint32(rule.MaxWindow.Seconds()), uint32(rule.MaxCooldown.Seconds()), false},
		"cooldown short":  {300, 30, true},
		"cooldown normal": {300, 900, false},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := validCondition()
			c.WindowSeconds, c.CooldownSeconds = tc.window, tc.cooldown

			err := c.Validate()
			if tc.wantErr && err == nil {
				t.Errorf("window=%d cooldown=%d was accepted", tc.window, tc.cooldown)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("window=%d cooldown=%d was rejected: %v", tc.window, tc.cooldown, err)
			}
		})
	}
}

// A cooldown shorter than the window re-fires on data the previous alert already
// covered, so one sustained condition becomes a stream of duplicates.
func TestCooldownMustCoverTheWindow(t *testing.T) {
	c := validCondition()
	c.WindowSeconds, c.CooldownSeconds = 600, 300

	if err := c.Validate(); err == nil {
		t.Error("a cooldown shorter than the window was accepted")
	}
}

// A rate threshold above 1 can never be reached, so the rule sits enabled and silent —
// the worst state for an alert, because it looks healthy.
func TestRateThresholdMustBeAFraction(t *testing.T) {
	c := validCondition()
	c.Aggregate = rule.AggregateRate
	c.Threshold = 5

	if err := c.Validate(); err == nil {
		t.Error("a rate threshold of 5 was accepted")
	}

	c.Threshold = 0.05
	if err := c.Validate(); err != nil {
		t.Errorf("a valid rate threshold was rejected: %v", err)
	}
}

// Each group is a separate alert and a separate cooldown key.
func TestGroupByIsBounded(t *testing.T) {
	c := validCondition()
	c.GroupBy = []string{"request_host", "client_ip", "country", "confidence"}

	if err := c.Validate(); err == nil {
		t.Error("a rule grouping by four fields was accepted")
	}
}

func TestDuplicateGroupByIsRejected(t *testing.T) {
	c := validCondition()
	c.GroupBy = []string{"request_host", "request_host"}

	if err := c.Validate(); err == nil {
		t.Error("a duplicated group-by field was accepted")
	}
}

// The group-by value reaches a GROUP BY clause, which no placeholder can protect.
func TestGroupByResolvesThroughTheAllowlist(t *testing.T) {
	c := validCondition()
	c.GroupBy = []string{"request_host", "country"}

	columns, err := c.GroupColumns()
	if err != nil {
		t.Fatalf("GroupColumns: %v", err)
	}
	if len(columns) != 2 {
		t.Fatalf("got %d columns, want 2", len(columns))
	}
	if string(columns[1]) != "client_country" {
		t.Errorf("country resolved to %q, want client_country", columns[1])
	}

	c.GroupBy = []string{"request_host); DROP TABLE alerts --"}
	if _, err := c.GroupColumns(); err == nil {
		t.Error("an injection attempt was accepted as a group-by field")
	}
}

func TestComparators(t *testing.T) {
	cases := []struct {
		comparator rule.Comparator
		threshold  float64
		observed   float64
		want       bool
	}{
		{rule.ComparatorGreaterThan, 10, 11, true},
		{rule.ComparatorGreaterThan, 10, 10, false},
		{rule.ComparatorGreaterEqual, 10, 10, true},
		{rule.ComparatorLessThan, 10, 9, true},
		{rule.ComparatorLessThan, 10, 10, false},
		{rule.ComparatorLessEqual, 10, 10, true},
	}

	for _, tc := range cases {
		c := validCondition()
		c.Comparator, c.Threshold = tc.comparator, tc.threshold

		if got := c.Satisfied(tc.observed); got != tc.want {
			t.Errorf("%s %v against %v = %v, want %v",
				tc.comparator, tc.observed, tc.threshold, got, tc.want)
		}
	}
}

// A rule that cannot be evaluated must stay SILENT. Firing on an unknown comparator
// would turn a corrupt row into a storm of meaningless alerts, which is how a team
// learns to ignore the channel.
func TestAnUnknownComparatorNeverFires(t *testing.T) {
	c := validCondition()
	c.Comparator = rule.Comparator("whenever")

	for _, observed := range []float64{0, 1, 1e9} {
		if c.Satisfied(observed) {
			t.Errorf("an unevaluable rule fired on %v", observed)
		}
	}
}

func TestErrorsAreUserFacing(t *testing.T) {
	_, err := rule.Parse(`{"aggregate":"median","comparator":"gt","threshold":1,
	                       "window_seconds":300,"cooldown_seconds":900}`)
	if err == nil {
		t.Fatal("expected an error")
	}

	message := mw.AsError(err).Message
	if !strings.Contains(message, "median") {
		t.Errorf("message %q does not name the offending value; a rule author "+
			"cannot fix what the error will not identify", message)
	}
}
