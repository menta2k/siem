package filter_test

import (
	"testing"

	"github.com/menta2k/siem/internal/ingest/filter"
	"github.com/menta2k/siem/internal/vendors"
)

func compile(t *testing.T, rules ...filter.Rule) filter.Set {
	t.Helper()
	set, err := filter.Compile(rules)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return set
}

func event(host, path string) vendors.Event {
	return vendors.Event{RequestHost: host, RequestPath: path}
}

// THE DEFAULT MUST BE "KEEP EVERYTHING". A filter that drops by accident destroys
// evidence that cannot be recovered — the whole point of this component is that the event
// is never written anywhere, so an over-broad rule is not a display bug, it is data loss.
func TestAnEmptySetDropsNothing(t *testing.T) {
	set := compile(t)

	for _, e := range []vendors.Event{
		event("assets.example.com", "/logo.png"),
		event("", ""),
		event("shop.example.com", "/checkout"),
	} {
		if set.Drops(e) {
			t.Errorf("an empty filter set dropped %s%s", e.RequestHost, e.RequestPath)
		}
	}
}

// The first example from the brief: drop a whole hostname.
func TestAHostIsDroppedByExactMatch(t *testing.T) {
	set := compile(t, filter.Rule{
		Field: filter.FieldRequestHost, Op: filter.OpEquals,
		Values: []string{"assets.example.com"},
	})

	if !set.Drops(event("assets.example.com", "/anything")) {
		t.Error("assets.example.com was not dropped")
	}
	// Exact means exact. A rule naming one host must not take its parent or a sibling
	// with it, or a filter meant to trim noise silently removes the traffic that matters.
	for _, host := range []string{"example.com", "shop.example.com", "notassets.example.com"} {
		if set.Drops(event(host, "/anything")) {
			t.Errorf("exact rule on assets.example.com also dropped %s", host)
		}
	}
}

// The second example: drop static assets by extension.
func TestAPathIsDroppedBySuffix(t *testing.T) {
	set := compile(t, filter.Rule{
		Field: filter.FieldRequestPath, Op: filter.OpSuffix,
		Values: []string{".png", ".jpg", ".css"},
	})

	for _, path := range []string{"/logo.png", "/a/b/hero.jpg", "/assets/site.css"} {
		if !set.Drops(event("shop.example.com", path)) {
			t.Errorf("%s was not dropped", path)
		}
	}
	for _, path := range []string{"/checkout", "/api/png", "/style.css.map"} {
		if set.Drops(event("shop.example.com", path)) {
			t.Errorf("%s was dropped but does not end in a filtered extension", path)
		}
	}
}

// Rules are OR: any one matching drops the event. Requiring all of them would make two
// independent rules silently cancel each other out.
func TestAnyRuleMatchingIsEnough(t *testing.T) {
	set := compile(t,
		filter.Rule{Field: filter.FieldRequestHost, Op: filter.OpEquals,
			Values: []string{"assets.example.com"}},
		filter.Rule{Field: filter.FieldRequestPath, Op: filter.OpSuffix,
			Values: []string{".css"}},
	)

	if !set.Drops(event("assets.example.com", "/index.html")) {
		t.Error("the host rule alone did not drop")
	}
	if !set.Drops(event("shop.example.com", "/site.css")) {
		t.Error("the path rule alone did not drop")
	}
	if set.Drops(event("shop.example.com", "/checkout")) {
		t.Error("an event matching neither rule was dropped")
	}
}

// Hostnames are case-insensitive by definition, and extensions arrive in both cases from
// real traffic. A rule that misses ".PNG" would look like it works right up until it
// silently does not.
func TestMatchingIgnoresCase(t *testing.T) {
	set := compile(t,
		filter.Rule{Field: filter.FieldRequestHost, Op: filter.OpEquals,
			Values: []string{"Assets.Example.COM"}},
		filter.Rule{Field: filter.FieldRequestPath, Op: filter.OpSuffix,
			Values: []string{".PNG"}},
	)

	if !set.Drops(event("assets.example.com", "/x")) {
		t.Error("host match was case-sensitive")
	}
	if !set.Drops(event("shop.example.com", "/LOGO.png")) {
		t.Error("path match was case-sensitive")
	}
}

// A suffix rule on the host is how a whole subdomain tree is excluded.
func TestAHostSuffixDropsASubdomainTree(t *testing.T) {
	set := compile(t, filter.Rule{
		Field: filter.FieldRequestHost, Op: filter.OpSuffix,
		Values: []string{".cdn.example.com"},
	})

	if !set.Drops(event("eu.cdn.example.com", "/x")) {
		t.Error("a subdomain was not dropped")
	}
	if set.Drops(event("cdn.example.org", "/x")) {
		t.Error("a different domain was dropped")
	}
}

func TestPrefixAndContains(t *testing.T) {
	prefix := compile(t, filter.Rule{Field: filter.FieldRequestPath, Op: filter.OpPrefix,
		Values: []string{"/static/"}})
	if !prefix.Drops(event("h", "/static/app.js")) {
		t.Error("prefix rule did not match")
	}
	if prefix.Drops(event("h", "/api/static/x")) {
		t.Error("prefix rule matched in the middle of the path")
	}

	contains := compile(t, filter.Rule{Field: filter.FieldRequestPath, Op: filter.OpContains,
		Values: []string{"/healthz"}})
	if !contains.Drops(event("h", "/internal/healthz?x=1")) {
		t.Error("contains rule did not match")
	}
}

// An event with no host or path must not be caught by a rule about them. Absence is not
// an empty string that happens to be a prefix of everything.
func TestAnAbsentFieldNeverMatches(t *testing.T) {
	// Rules broad enough to catch anything that HAS the field: every path starts with
	// "/" and every host contains ".". An event missing the field must still survive.
	set := compile(t,
		filter.Rule{Field: filter.FieldRequestPath, Op: filter.OpPrefix, Values: []string{"/"}},
		filter.Rule{Field: filter.FieldRequestHost, Op: filter.OpContains, Values: []string{"."}},
	)

	if set.Drops(event("", "")) {
		t.Error("an event with no host and no path was dropped by rules about them")
	}
	// F5 events frequently arrive with no host at all, because ASM truncates the header
	// block it lives in. Those must still be filterable on path, and must not be dropped
	// by a host rule they cannot possibly match.
	if set.Drops(event("", "")) {
		t.Error("a host-less event was dropped by a host rule")
	}
	if !set.Drops(event("", "/logo.png")) {
		t.Error("a host-less event was not matched on its path")
	}
}

// Bad configuration must be rejected when it is SAVED, not silently ignored at runtime.
// A rule that does nothing looks identical to a rule that works until someone checks the
// volume, and by then the events it should have dropped are already stored — or worse,
// the events it wrongly dropped are already gone.
func TestInvalidRulesAreRejected(t *testing.T) {
	for name, rule := range map[string]filter.Rule{
		"unknown field":    {Field: "nonsense", Op: filter.OpEquals, Values: []string{"x"}},
		"unknown operator": {Field: filter.FieldRequestHost, Op: "regex", Values: []string{"x"}},
		"no values":        {Field: filter.FieldRequestHost, Op: filter.OpEquals},
		"only empty value": {Field: filter.FieldRequestHost, Op: filter.OpEquals, Values: []string{"  "}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := filter.Compile([]filter.Rule{rule}); err == nil {
				t.Errorf("%s was accepted", name)
			}
		})
	}
}

// The rule count is bounded because this runs on every event of every delivery. An
// unbounded list is a way to make ingestion arbitrarily slow through configuration.
func TestTooManyRulesAreRejected(t *testing.T) {
	rules := make([]filter.Rule, filter.MaxRules+1)
	for i := range rules {
		rules[i] = filter.Rule{Field: filter.FieldRequestHost, Op: filter.OpEquals,
			Values: []string{"x.example.com"}}
	}

	if _, err := filter.Compile(rules); err == nil {
		t.Errorf("a set of %d rules was accepted, over the %d bound", len(rules), filter.MaxRules)
	}
}

// Round-tripping through storage must preserve behaviour: the rules are held as JSON on
// the tenant row, and a set that decodes differently from how it was saved would drop
// different traffic after a restart than it did before.
func TestRulesRoundTripThroughJSON(t *testing.T) {
	original := []filter.Rule{
		{Field: filter.FieldRequestHost, Op: filter.OpEquals, Values: []string{"assets.example.com"}},
		{Field: filter.FieldRequestPath, Op: filter.OpSuffix, Values: []string{".png", ".css"}},
	}

	encoded, err := filter.Encode(original)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := filter.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	set, err := filter.Compile(decoded)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !set.Drops(event("assets.example.com", "/x")) || !set.Drops(event("h", "/a.css")) {
		t.Error("a round-tripped set does not drop what the original did")
	}
}

// An unset column is the common case on every tenant that never configured a filter, and
// it must mean "no rules" rather than an error that fails ingestion.
func TestAnEmptyEncodingDecodesToNoRules(t *testing.T) {
	for _, encoded := range []string{"", "[]", "  "} {
		rules, err := filter.Decode(encoded)
		if err != nil {
			t.Errorf("Decode(%q): %v", encoded, err)
		}
		if len(rules) != 0 {
			t.Errorf("Decode(%q) = %d rules, want 0", encoded, len(rules))
		}
	}
}

// Stored JSON is not necessarily trustworthy — it may predate a validation rule, or have
// been written by hand. Decoding must not hand back something Compile would reject
// without saying so.
func TestMalformedEncodingIsAnError(t *testing.T) {
	for _, encoded := range []string{"{", "null-ish", `{"field":"x"}`} {
		if _, err := filter.Decode(encoded); err == nil {
			t.Errorf("Decode(%q) accepted malformed JSON", encoded)
		}
	}
}
