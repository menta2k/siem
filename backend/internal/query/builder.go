package query

import (
	"fmt"
	"strings"

	mw "github.com/menta2k/siem/internal/middleware"
)

// Column is a field an analyst may filter on.
//
// A named type over a plain string so a raw, caller-supplied string cannot reach the
// builder by accident. Conversion has to be deliberate, and the only place that
// converts is Resolve, which checks the allowlist first.
type Column string

// Op is a comparison a filter may use.
type Op string

// The supported comparisons. This set is closed: an operator that is not here cannot
// be expressed, so no caller can smuggle one in through a filter name.
const (
	OpEqual        Op = "="
	OpNotEqual     Op = "!="
	OpGreaterEqual Op = ">="
	OpLessEqual    Op = "<="
	OpIn           Op = "IN"
	OpContains     Op = "LIKE"
	OpHasToken     Op = "hasToken"
)

// Table names a searchable table and the columns it exposes.
type Table struct {
	Name string
	// Columns is the ALLOWLIST. Nothing outside it can be referenced, which is what
	// makes injection through a field name impossible rather than merely unlikely:
	// the untrusted string is compared against this map and then discarded — the SQL
	// is built from the map's own value, never from the input.
	Columns map[string]Column
	// Sort is the column the cursor walks. It must be part of a total order together
	// with Tiebreak, or paging can skip rows.
	Sort Column
	// Tiebreak makes the sort total when two rows share a Sort value.
	Tiebreak Column
}

// EventsTable is the searchable surface of normalized_events.
//
// The map keys are the API's field names and the values are the physical columns. The
// indirection is deliberate: renaming a column must not break saved searches, and an
// API field must never be assumed to equal a column name.
var EventsTable = Table{
	Name: "normalized_events",
	Columns: map[string]Column{
		"event_id":          "event_id",
		"event_time":        "event_time",
		"vendor":            "vendor",
		"feed_id":           "feed_id",
		"client_ip":         "client_ip",
		"client_asn":        "client_asn",
		"country":           "client_country",
		"request_host":      "request_host",
		"request_path":      "request_path",
		"request_method":    "request_method",
		"user_agent":        "user_agent",
		"http_status":       "http_status",
		"verdict":           "verdict",
		"rule_id":           "rule_id",
		"score":             "score",
		"score_kind":        "score_kind",
		"vendor_request_id": "vendor_request_id",
	},
	Sort:     "event_time",
	Tiebreak: "event_id",
}

// CorrelatedTable is the searchable surface of correlated_requests.
var CorrelatedTable = Table{
	Name: "correlated_requests",
	Columns: map[string]Column{
		"correlation_id":    "correlation_id",
		"window_start":      "window_start",
		"last_event_time":   "last_event_time",
		"client_ip":         "client_ip",
		"client_asn":        "client_asn",
		"country":           "client_country",
		"request_host":      "request_host",
		"request_path":      "request_path",
		"request_method":    "request_method",
		"vendor_count":      "vendor_count",
		"has_disagreement":  "has_disagreement",
		"disagreement_kind": "disagreement_kind",
		"confidence":        "confidence",
		"combined_outcome":  "combined_outcome",
		"join_tier":         "join_tier",
	},
	Sort:     "last_event_time",
	Tiebreak: "correlation_id",
}

// Resolve maps an API field name to a physical column.
//
// The ONLY way a column name enters a query. An unknown field is rejected by name in
// the error, which is safe — the name came from the caller and is echoed back to
// them, never interpolated into SQL.
func (t Table) Resolve(field string) (Column, error) {
	column, ok := t.Columns[strings.ToLower(strings.TrimSpace(field))]
	if !ok {
		return "", mw.ValidationFailed(fmt.Sprintf("unknown filter field %q", field))
	}
	return column, nil
}

// Filter is one validated predicate.
type Filter struct {
	Column Column
	Op     Op
	Value  any
}

// Builder assembles a parameterized SELECT.
//
// Every value becomes a `?` placeholder and travels in the args slice. No branch of
// this type formats a caller value into the SQL string — the only strings that reach
// the statement are the table name, allowlisted columns, and the fixed operators
// above, all of which originate in this file.
type Builder struct {
	table   Table
	filters []Filter
	err     error
}

// NewBuilder starts a query against a table.
func NewBuilder(table Table) *Builder { return &Builder{table: table} }

// Where adds a predicate on an allowlisted field.
//
// Errors are accumulated rather than returned per call so filters can be chained; the
// first failure surfaces from Build. Silently skipping a rejected filter would be far
// worse than failing: the analyst would receive a WIDER result set than they asked
// for and no indication that their filter was dropped.
func (b *Builder) Where(field string, op Op, value any) *Builder {
	if b.err != nil {
		return b
	}

	column, err := b.table.Resolve(field)
	if err != nil {
		b.err = err
		return b
	}
	if !validOp(op) {
		b.err = mw.ValidationFailed(fmt.Sprintf("unsupported comparison %q", op))
		return b
	}

	b.filters = append(b.filters, Filter{Column: column, Op: op, Value: value})
	return b
}

// WhereIfSet adds a predicate only when the value is non-empty, which keeps the many
// optional filters of a search request from each needing a conditional at the call site.
func (b *Builder) WhereIfSet(field string, op Op, value string) *Builder {
	if strings.TrimSpace(value) == "" {
		return b
	}
	return b.Where(field, op, value)
}

func validOp(op Op) bool {
	switch op {
	case OpEqual, OpNotEqual, OpGreaterEqual, OpLessEqual, OpIn, OpContains, OpHasToken:
		return true
	default:
		return false
	}
}

// Conditions renders the accumulated filters.
//
// Returns the SQL fragment and its arguments in matching order. The tenant predicate
// is NOT added here: it is applied by the repository from the request context, so a
// caller cannot omit it by forgetting to call a method.
func (b *Builder) Conditions() (string, []any, error) {
	if b.err != nil {
		return "", nil, b.err
	}

	var (
		clauses []string
		args    []any
	)
	for _, f := range b.filters {
		switch f.Op {
		case OpIn:
			values, ok := f.Value.([]string)
			if !ok || len(values) == 0 {
				// An empty IN list matches nothing in SQL, which would silently return
				// zero rows for a filter the analyst thought was inclusive.
				return "", nil, mw.ValidationFailed(
					fmt.Sprintf("filter on %s needs at least one value", f.Column))
			}
			placeholders := strings.TrimSuffix(strings.Repeat("?,", len(values)), ",")
			clauses = append(clauses, fmt.Sprintf("%s IN (%s)", f.Column, placeholders))
			for _, v := range values {
				args = append(args, v)
			}

		case OpContains:
			// The wildcards are added HERE, around a bound parameter, rather than being
			// accepted from the caller. A caller-supplied `%` would otherwise turn a
			// specific filter into a full scan without anyone noticing.
			clauses = append(clauses, fmt.Sprintf("%s LIKE ?", f.Column))
			args = append(args, "%"+escapeLike(fmt.Sprint(f.Value))+"%")

		case OpHasToken:
			// Uses the token bloom index on user_agent and request_path, which LIKE
			// cannot: a leading-wildcard LIKE reads every granule.
			clauses = append(clauses, fmt.Sprintf("hasToken(%s, ?)", f.Column))
			args = append(args, f.Value)

		case OpEqual, OpNotEqual, OpGreaterEqual, OpLessEqual:
			clauses = append(clauses, fmt.Sprintf("%s %s ?", f.Column, f.Op))
			args = append(args, f.Value)

		default:
			return "", nil, mw.ValidationFailed(
				fmt.Sprintf("unsupported comparison %q", f.Op))
		}
	}

	if len(clauses) == 0 {
		return "", nil, nil
	}
	return " AND " + strings.Join(clauses, " AND "), args, nil
}

// escapeLike neutralizes the wildcards inside a user's literal search text.
//
// Without this, searching for a path containing `%` matches everything from that point
// on — a filter that quietly stops filtering, which is the failure mode an analyst is
// least likely to notice.
func escapeLike(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return replacer.Replace(value)
}

// CursorCondition renders the keyset predicate for a page after the given cursor.
//
// A tuple comparison rather than two ORed clauses: `(a, b) < (?, ?)` is one expression
// ClickHouse can evaluate against the sort order directly, and it cannot be written
// with the boundary subtly wrong the way the expanded form can.
func (t Table) CursorCondition(cursor Cursor) (string, []any) {
	if cursor.IsZero() {
		return "", nil
	}
	return fmt.Sprintf(" AND (%s, %s) < (?, ?)", t.Sort, t.Tiebreak),
		[]any{cursor.EventTime.UTC(), cursor.ID}
}

// OrderBy renders the descending total order the cursor walks.
func (t Table) OrderBy() string {
	return fmt.Sprintf(" ORDER BY %s DESC, %s DESC", t.Sort, t.Tiebreak)
}
