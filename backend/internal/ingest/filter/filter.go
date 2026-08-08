// Package filter decides which events are never ingested at all.
//
// A filtered event is not stored anywhere — not as a raw payload, not as a normalized
// row, not as a rejection. That is the point: static assets and health checks can be a
// large share of a WAF's log volume while carrying no security signal, and the cheapest
// event is the one that is never written.
//
// It is also why this package is deliberately unambitious. Dropping is IRREVERSIBLE and
// silent by nature, so the matching vocabulary is closed and literal: no regular
// expressions, no negation, no arbitrary field paths. A rule an operator can misread is a
// rule that quietly deletes the traffic they needed, and unlike every other data loss in
// this system there is no raw copy to fall back on.
package filter

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/menta2k/siem/internal/vendors"
)

// The fields a rule may test. A closed set, not a lookup into the event: an operator
// cannot filter on something the platform does not model, and a typo is rejected rather
// than silently matching nothing.
const (
	FieldRequestHost = "request_host"
	FieldRequestPath = "request_path"
)

// The comparisons a rule may use. Literal string operations only — see the package note
// on why there is no regular expression here.
const (
	OpEquals   = "equals"
	OpSuffix   = "suffix"
	OpPrefix   = "prefix"
	OpContains = "contains"
)

// MaxRules bounds a tenant's rule set.
//
// Every rule is evaluated against every event of every delivery, so an unbounded list is
// a way to make ingestion arbitrarily slow through configuration alone.
const MaxRules = 64

// Rule is one condition. An event is dropped when ANY value of ANY rule matches.
type Rule struct {
	Field  string   `json:"field"`
	Op     string   `json:"op"`
	Values []string `json:"values"`
}

// Set is a compiled, ready-to-evaluate rule set.
//
// Compiled once per delivery rather than per event: the lowercasing below is the whole
// of the preparation, and doing it per event would repeat it a thousand times a second
// for no benefit.
type Set struct {
	rules []Rule
}

// Empty reports whether the set can drop anything at all, so callers can skip the work
// entirely for the overwhelmingly common case of a tenant with no filters.
func (s Set) Empty() bool { return len(s.rules) == 0 }

// Compile validates rules and prepares them for matching.
//
// Validation happens HERE rather than at match time so a bad rule is refused when it is
// saved. A rule that silently matches nothing is indistinguishable from one that works
// until someone compares the volume, by which point the events it should have dropped are
// already stored — or the ones it wrongly dropped are already gone.
func Compile(rules []Rule) (Set, error) {
	if len(rules) > MaxRules {
		return Set{}, fmt.Errorf("%d filter rules exceeds the maximum of %d", len(rules), MaxRules)
	}

	compiled := make([]Rule, 0, len(rules))
	for i, rule := range rules {
		switch rule.Field {
		case FieldRequestHost, FieldRequestPath:
		default:
			return Set{}, fmt.Errorf("rule %d: unknown field %q", i, rule.Field)
		}

		switch rule.Op {
		case OpEquals, OpSuffix, OpPrefix, OpContains:
		default:
			return Set{}, fmt.Errorf("rule %d: unknown operator %q", i, rule.Op)
		}

		values := make([]string, 0, len(rule.Values))
		for _, value := range rule.Values {
			// Lowercased once, here. Hostnames are case-insensitive by definition, and
			// extensions arrive in both cases from real traffic — a rule that misses
			// ".PNG" looks like it works right up until it silently does not.
			if trimmed := strings.ToLower(strings.TrimSpace(value)); trimmed != "" {
				values = append(values, trimmed)
			}
		}
		// An all-empty rule would match everything under prefix or suffix and drop the
		// tenant's entire feed. Rejecting it is the difference between a config error and
		// an outage nobody notices until the data is gone.
		if len(values) == 0 {
			return Set{}, fmt.Errorf("rule %d: needs at least one non-empty value", i)
		}

		compiled = append(compiled, Rule{Field: rule.Field, Op: rule.Op, Values: values})
	}
	return Set{rules: compiled}, nil
}

// Drops reports whether this event should never be ingested.
func (s Set) Drops(event vendors.Event) bool {
	if len(s.rules) == 0 {
		return false
	}

	for _, rule := range s.rules {
		subject := event.RequestHost
		if rule.Field == FieldRequestPath {
			subject = event.RequestPath
		}
		// Absence is not an empty string that happens to be a prefix of everything: an
		// event whose host was never parsed must not be caught by a rule about hosts.
		if subject == "" {
			continue
		}
		if matches(rule, strings.ToLower(subject)) {
			return true
		}
	}
	return false
}

func matches(rule Rule, subject string) bool {
	for _, value := range rule.Values {
		var hit bool
		switch rule.Op {
		case OpEquals:
			hit = subject == value
		case OpSuffix:
			hit = strings.HasSuffix(subject, value)
		case OpPrefix:
			hit = strings.HasPrefix(subject, value)
		case OpContains:
			hit = strings.Contains(subject, value)
		}
		if hit {
			return true
		}
	}
	return false
}

// Encode renders rules for storage on the tenant row.
func Encode(rules []Rule) (string, error) {
	if len(rules) == 0 {
		return "[]", nil
	}
	encoded, err := json.Marshal(rules)
	if err != nil {
		return "", fmt.Errorf("encode ingest filters: %w", err)
	}
	return string(encoded), nil
}

// Decode reads rules back from storage.
//
// An unset or empty column means "no rules" rather than an error — that is every tenant
// who never configured a filter, and failing there would stop their ingestion outright.
// Malformed content IS an error: it may predate a validation rule or have been written by
// hand, and quietly treating it as "no filters" would ingest everything the operator
// believed they were excluding.
func Decode(encoded string) ([]Rule, error) {
	trimmed := strings.TrimSpace(encoded)
	if trimmed == "" || trimmed == "[]" {
		return nil, nil
	}

	var rules []Rule
	if err := json.Unmarshal([]byte(trimmed), &rules); err != nil {
		return nil, fmt.Errorf("decode ingest filters: %w", err)
	}
	return rules, nil
}
