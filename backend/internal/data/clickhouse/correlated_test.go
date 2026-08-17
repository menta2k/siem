package clickhouse

import (
	"strings"
	"testing"
)

// countingScanner records how many destinations a scan function asks for.
type countingScanner struct{ destinations int }

func (c *countingScanner) Scan(dest ...any) error {
	c.destinations = len(dest)
	return nil
}

// THE BUG THIS PINS. correlatedColumns is used by the INSERT and by every SELECT that
// scans a whole record. Adding a column to it without adding a destination to
// scanCorrelated compiles, passes every unit test, and then breaks the correlate closer in
// production with "expected 28 destination arguments in Scan, not 27" — which stops
// correlated records being written at all while the API keeps serving the last ones.
//
// So the two are compared here, where a mismatch is a failing test rather than an incident.
func TestCorrelatedColumnsMatchTheScanDestinations(t *testing.T) {
	var scanner countingScanner
	if _, err := scanCorrelated(&scanner); err != nil {
		t.Fatalf("scanCorrelated(): %v", err)
	}

	columns := strings.Split(correlatedColumns, ",")
	if len(columns) != scanner.destinations {
		t.Errorf("the column list has %d columns and scanCorrelated takes %d destinations; "+
			"a SELECT built from that list will fail at runtime",
			len(columns), scanner.destinations)
	}

	// Named explicitly as well, because a column list that drifts in BOTH places by the
	// same amount would satisfy the count while reading the wrong values into each field.
	for _, name := range []string{"matched_rule_ids", "rule_ids", "verdicts", "scores"} {
		if !strings.Contains(correlatedColumns, name) {
			t.Errorf("column %q is missing from the list", name)
		}
	}
}
