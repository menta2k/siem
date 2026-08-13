// Package f5catalog explains why BIG-IP ASM blocked a request.
//
// An ASM log record says what fired but not what it means: violations arrive as bare
// titles ("Illegal file type") and signatures as bare numbers ("200004165"). Deciding
// whether a block was a real attack or a false positive then means leaving the console
// for the BIG-IP UI, and the analyst who does that has already lost the thread. This
// package holds the descriptions, severities, attack types and CVEs that turn those
// tokens into a finding.
//
// THE CATALOGUE IS EMBEDDED, not stored. It is BIG-IP product reference data — the same
// signature id means the same thing on every appliance — so it has no tenant dimension,
// it changes only when ASM ships a signature update, and at ~270 KiB gzipped it costs
// less to carry in the binary than a table would cost to migrate, import and keep in
// step across environments. There is no state in which one replica can answer and
// another cannot.
//
// Regenerate it with internal/f5catalog/gen after pulling fresh dumps from a BIG-IP.
package f5catalog

import (
	"compress/gzip"
	"embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

//go:embed catalog.json.gz
var embedded embed.FS

// Violation is one ASM policy check, as reported in a record's `violations` field.
type Violation struct {
	// Name is the VIOL_* constant, which is what BIG-IP documentation and support
	// cases refer to even though the logs do not carry it.
	Name string `json:"name"`
	// Title is the JOIN KEY: the human-readable string ASM actually writes into a log
	// record's violations field.
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	AttackType  string `json:"attack_type,omitempty"`
	Type        string `json:"type,omitempty"`
	Description string `json:"description,omitempty"`
	// Risk is what an attacker gains if this is a true positive — the sentence that
	// decides whether an alert is worth waking someone for.
	Risk     string `json:"risk,omitempty"`
	Examples string `json:"examples,omitempty"`
}

// Signature is one ASM attack signature, as reported in a record's `sig_ids` field.
type Signature struct {
	ID          uint64 `json:"id"`
	Name        string `json:"name"`
	Accuracy    string `json:"accuracy,omitempty"`
	Risk        string `json:"risk,omitempty"`
	Type        string `json:"type,omitempty"`
	AttackType  string `json:"attack_type,omitempty"`
	UserDefined bool   `json:"user_defined,omitempty"`
	Description string `json:"description,omitempty"`
	// CVEs are separated from References because they are what an analyst pivots on
	// into every other tool they own.
	CVEs       []string `json:"cves,omitempty"`
	References []string `json:"references,omitempty"`
}

// Catalog is the embedded file's shape. Exported so the generator can write it.
type Catalog struct {
	Violations []Violation `json:"violations"`
	Signatures []Signature `json:"signatures"`
}

// index is the parsed catalogue, built once on first use.
type index struct {
	byTitle map[string]Violation
	bySigID map[uint64]Signature
	err     error
}

var (
	once   sync.Once
	loaded index
)

// load parses the embedded catalogue exactly once.
//
// Lazily rather than in an init: a binary that never opens an F5 event — the ingest
// and processor services — should not pay 14 MiB of resident descriptions for a lookup
// table it will never read.
func load() index {
	once.Do(func() {
		loaded = parse()
	})
	return loaded
}

func parse() index {
	file, err := embedded.Open("catalog.json.gz")
	if err != nil {
		return index{err: fmt.Errorf("open embedded f5 catalogue: %w", err)}
	}
	defer func() { _ = file.Close() }()

	zr, err := gzip.NewReader(file)
	if err != nil {
		return index{err: fmt.Errorf("decompress f5 catalogue: %w", err)}
	}
	defer func() { _ = zr.Close() }()

	var catalog Catalog
	if err := json.NewDecoder(zr).Decode(&catalog); err != nil {
		return index{err: fmt.Errorf("parse f5 catalogue: %w", err)}
	}

	built := index{
		byTitle: make(map[string]Violation, len(catalog.Violations)),
		bySigID: make(map[uint64]Signature, len(catalog.Signatures)),
	}
	for _, v := range catalog.Violations {
		// Folded, because ASM's own casing of a title is not guaranteed to match the
		// catalogue's across versions and a case difference must not lose the lookup.
		built.byTitle[foldTitle(v.Title)] = v
	}
	for _, s := range catalog.Signatures {
		built.bySigID[s.ID] = s
	}
	return built
}

func foldTitle(title string) string {
	return strings.ToLower(strings.TrimSpace(title))
}

// Loaded reports whether the catalogue parsed, and why not if it did not.
//
// Enrichment is decoration: an event detail must still render when the catalogue is
// unreadable. Callers use this to log the failure once rather than to refuse the page.
func Loaded() error { return load().err }

// Counts reports the catalogue's size, for a startup log line that makes it obvious
// whether the binary carries the data or an empty file.
func Counts() (violations, signatures int) {
	idx := load()
	return len(idx.byTitle), len(idx.bySigID)
}

// LookupViolation resolves one violation title from a record's `violations` field.
func LookupViolation(title string) (Violation, bool) {
	idx := load()
	v, ok := idx.byTitle[foldTitle(title)]
	return v, ok
}

// LookupSignature resolves one numeric signature id from a record's `sig_ids` field.
func LookupSignature(id uint64) (Signature, bool) {
	idx := load()
	s, ok := idx.bySigID[id]
	return s, ok
}

// DescribeViolations resolves a record's violation titles, preserving order.
//
// An UNKNOWN title still yields an entry, carrying just the title. ASM reports
// violations this catalogue may not contain — a newer policy, a user-defined check —
// and silently dropping those would show an analyst four violations where the record
// says six, which is worse than showing one with no description.
func DescribeViolations(titles []string) []Violation {
	out := make([]Violation, 0, len(titles))
	for _, title := range titles {
		title = strings.TrimSpace(title)
		if title == "" || isNotApplicable(title) {
			continue
		}
		if v, ok := LookupViolation(title); ok {
			out = append(out, v)
			continue
		}
		out = append(out, Violation{Title: title})
	}
	return out
}

// DescribeSignatures resolves a record's `sig_ids` value, which is a comma-separated
// list of numbers. Unknown and unparseable ids are kept for the same reason unknown
// violations are.
func DescribeSignatures(sigIDs string) []Signature {
	fields := splitList(sigIDs)
	out := make([]Signature, 0, len(fields))

	for _, field := range fields {
		id, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			continue
		}
		if s, ok := LookupSignature(id); ok {
			out = append(out, s)
			continue
		}
		out = append(out, Signature{ID: id})
	}
	return out
}

// splitList splits an ASM comma-separated field.
func splitList(value string) []string {
	if value == "" || isNotApplicable(value) {
		return nil
	}

	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// isNotApplicable recognises ASM's placeholder for an absent value. It writes the
// literal string "N/A" rather than an empty field, and treating that as a real
// violation title would put a violation named "N/A" on a third of all events.
func isNotApplicable(value string) bool {
	return strings.EqualFold(strings.TrimSpace(value), "N/A")
}
