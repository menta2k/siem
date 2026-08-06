package query_test

import (
	"strings"
	"testing"

	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/query"
)

// The guarantee this package exists to provide: no caller-supplied string reaches SQL.
// Every one of these is a real injection attempt through a FIELD NAME, which is the
// one position a placeholder cannot protect.
func TestUnknownFieldsAreRejected(t *testing.T) {
	attempts := []string{
		"password",
		"event_id; DROP TABLE normalized_events",
		"event_id) OR 1=1 --",
		"*",
		"1=1",
		"event_id UNION SELECT * FROM users",
		"",
		"   ",
	}

	for _, field := range attempts {
		t.Run(field, func(t *testing.T) {
			_, _, err := query.NewBuilder(query.EventsTable).
				Where(field, query.OpEqual, "x").
				Conditions()
			if err == nil {
				t.Fatalf("field %q was accepted into a query", field)
			}
			if got := mw.AsError(err).HTTPStatus(); got != 400 {
				t.Errorf("status = %d, want 400", got)
			}
		})
	}
}

// A rejected filter must fail the query, never be silently dropped: skipping it returns
// a WIDER result set than was asked for, with nothing to signal that it happened.
func TestARejectedFilterFailsTheWholeQuery(t *testing.T) {
	_, _, err := query.NewBuilder(query.EventsTable).
		Where("request_host", query.OpEqual, "shop.example.com").
		Where("no_such_field", query.OpEqual, "x").
		Where("verdict", query.OpEqual, "blocked").
		Conditions()

	if err == nil {
		t.Fatal("a query with one bad filter was built anyway, silently widening the result")
	}
}

func TestValuesAreAlwaysBound(t *testing.T) {
	sql, args, err := query.NewBuilder(query.EventsTable).
		Where("request_host", query.OpEqual, "shop.example.com").
		Where("verdict", query.OpEqual, "blocked'; DROP TABLE users; --").
		Conditions()
	if err != nil {
		t.Fatalf("Conditions: %v", err)
	}

	if strings.Contains(sql, "shop.example.com") || strings.Contains(sql, "DROP TABLE") {
		t.Fatalf("a value was interpolated into the SQL: %s", sql)
	}
	if got := strings.Count(sql, "?"); got != 2 {
		t.Errorf("%d placeholders in %q, want 2", got, sql)
	}
	if len(args) != 2 {
		t.Errorf("%d args, want 2", len(args))
	}
}

func TestUnsupportedComparisonsAreRejected(t *testing.T) {
	_, _, err := query.NewBuilder(query.EventsTable).
		Where("verdict", query.Op("; DROP TABLE users --"), "x").
		Conditions()
	if err == nil {
		t.Fatal("an arbitrary comparison operator was accepted")
	}
}

// A user searching for a literal `%` must not accidentally request a full scan.
func TestLikeWildcardsInUserTextAreEscaped(t *testing.T) {
	_, args, err := query.NewBuilder(query.EventsTable).
		Where("request_path", query.OpContains, "100%_off").
		Conditions()
	if err != nil {
		t.Fatalf("Conditions: %v", err)
	}

	arg, ok := args[0].(string)
	if !ok {
		t.Fatalf("arg is %T, want string", args[0])
	}
	if !strings.Contains(arg, `\%`) || !strings.Contains(arg, `\_`) {
		t.Errorf("wildcards not escaped in %q — this filter would stop filtering", arg)
	}
	if !strings.HasPrefix(arg, "%") || !strings.HasSuffix(arg, "%") {
		t.Errorf("arg %q is missing the surrounding wildcards the builder should add", arg)
	}
}

// An empty IN list matches nothing in SQL. Accepting it would return zero rows for a
// filter the analyst believed was inclusive — a wrong answer that looks like a fact.
func TestEmptyInListIsRejected(t *testing.T) {
	for name, value := range map[string]any{
		"empty slice": []string{},
		"nil slice":   []string(nil),
		"wrong type":  "cloudflare",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := query.NewBuilder(query.EventsTable).
				Where("vendor", query.OpIn, value).Conditions(); err == nil {
				t.Error("an unusable IN list was accepted")
			}
		})
	}
}

func TestInListBindsEveryValue(t *testing.T) {
	sql, args, err := query.NewBuilder(query.EventsTable).
		Where("vendor", query.OpIn, []string{"cloudflare", "f5", "datadome"}).
		Conditions()
	if err != nil {
		t.Fatalf("Conditions: %v", err)
	}

	if got := strings.Count(sql, "?"); got != 3 {
		t.Errorf("%d placeholders in %q, want 3", got, sql)
	}
	if len(args) != 3 {
		t.Errorf("%d args, want 3", len(args))
	}
}

func TestFieldNamesAreCaseAndSpaceInsensitive(t *testing.T) {
	for _, field := range []string{"request_host", "Request_Host", "  request_host  "} {
		if _, _, err := query.NewBuilder(query.EventsTable).
			Where(field, query.OpEqual, "x").Conditions(); err != nil {
			t.Errorf("field %q was rejected: %v", field, err)
		}
	}
}

// The API's field names are decoupled from the physical columns so that renaming a
// column does not break every saved search.
func TestApiFieldsMapToPhysicalColumns(t *testing.T) {
	sql, _, err := query.NewBuilder(query.EventsTable).
		Where("country", query.OpEqual, "DE").
		Conditions()
	if err != nil {
		t.Fatalf("Conditions: %v", err)
	}
	if !strings.Contains(sql, "client_country") {
		t.Errorf("field `country` did not resolve to client_country: %s", sql)
	}
}

func TestNoFiltersProducesNoClause(t *testing.T) {
	sql, args, err := query.NewBuilder(query.EventsTable).Conditions()
	if err != nil {
		t.Fatalf("Conditions: %v", err)
	}
	if sql != "" || len(args) != 0 {
		t.Errorf("got %q with %d args, want an empty clause", sql, len(args))
	}
}

func TestBlankOptionalFiltersAreSkipped(t *testing.T) {
	sql, _, err := query.NewBuilder(query.EventsTable).
		WhereIfSet("request_host", query.OpEqual, "").
		WhereIfSet("verdict", query.OpEqual, "  ").
		WhereIfSet("rule_id", query.OpEqual, "waf-1").
		Conditions()
	if err != nil {
		t.Fatalf("Conditions: %v", err)
	}
	if got := strings.Count(sql, "?"); got != 1 {
		t.Errorf("%d placeholders in %q, want only the set filter", got, sql)
	}
}

// ---------------------------------------------------------------- ordering

func TestCursorConditionIsATupleComparison(t *testing.T) {
	sql, args := query.EventsTable.CursorCondition(
		query.Cursor{EventTime: queryNow, ID: "e1"})

	if !strings.Contains(sql, "(event_time, event_id) < (?, ?)") {
		t.Errorf("cursor predicate = %q, want a tuple comparison", sql)
	}
	if len(args) != 2 {
		t.Errorf("%d args, want 2", len(args))
	}
}

func TestFirstPageHasNoCursorCondition(t *testing.T) {
	sql, args := query.EventsTable.CursorCondition(query.Cursor{})
	if sql != "" || args != nil {
		t.Errorf("got %q with %v, want nothing for the first page", sql, args)
	}
}

// The ORDER BY must match the cursor's columns exactly, or paging skips rows.
func TestOrderByMatchesTheCursorColumns(t *testing.T) {
	for _, table := range []query.Table{query.EventsTable, query.CorrelatedTable} {
		order := table.OrderBy()
		cursorSQL, _ := table.CursorCondition(query.Cursor{EventTime: queryNow, ID: "x"})

		for _, column := range []string{string(table.Sort), string(table.Tiebreak)} {
			if !strings.Contains(order, column) {
				t.Errorf("%s: ORDER BY %q omits %q", table.Name, order, column)
			}
			if !strings.Contains(cursorSQL, column) {
				t.Errorf("%s: cursor predicate %q omits %q", table.Name, cursorSQL, column)
			}
		}
		if !strings.Contains(order, "DESC") {
			t.Errorf("%s: ORDER BY %q is not descending", table.Name, order)
		}
	}
}

// A table whose tiebreaker is not unique cannot produce a total order, and paging
// across rows sharing a sort value would then skip or repeat.
func TestEveryTableHasAUniqueTiebreak(t *testing.T) {
	cases := []struct {
		table query.Table
		want  query.Column
	}{
		{query.EventsTable, "event_id"},
		{query.CorrelatedTable, "correlation_id"},
	}
	for _, tc := range cases {
		if tc.table.Tiebreak != tc.want {
			t.Errorf("%s tiebreak = %q, want %q", tc.table.Name, tc.table.Tiebreak, tc.want)
		}
	}
}
