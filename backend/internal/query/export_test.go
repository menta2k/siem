package query_test

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/menta2k/siem/internal/query"
)

var exportColumns = []string{"event_id", "event_time", "user_agent", "score"}

func rowsFrom(rows []query.ExportRow) func(func(query.ExportRow) bool) {
	return func(yield func(query.ExportRow) bool) {
		for _, row := range rows {
			if !yield(row) {
				return
			}
		}
	}
}

func TestNDJSONWritesOneObjectPerLine(t *testing.T) {
	var buf bytes.Buffer
	exporter := query.NewExporter(query.FormatNDJSON, exportColumns, 100)

	err := exporter.Write(&buf, rowsFrom([]query.ExportRow{
		{"event_id": "e1", "score": 0.5},
		{"event_id": "e2", "score": 0.9},
	}))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2: %q", len(lines), buf.String())
	}
	for _, line := range lines {
		var decoded map[string]any
		if err := json.Unmarshal([]byte(line), &decoded); err != nil {
			t.Errorf("line is not valid JSON: %q", line)
		}
	}
	if exporter.Written() != 2 {
		t.Errorf("Written = %d, want 2", exporter.Written())
	}
}

// A CSV whose columns move between runs cannot be diffed or scripted against.
func TestCSVColumnOrderIsStable(t *testing.T) {
	var first, second bytes.Buffer

	rows := []query.ExportRow{{"event_id": "e1", "user_agent": "curl", "score": 0.5}}
	for _, buf := range []*bytes.Buffer{&first, &second} {
		if err := query.NewExporter(query.FormatCSV, exportColumns, 100).
			Write(buf, rowsFrom(rows)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	if first.String() != second.String() {
		t.Errorf("column order changed between runs:\n%q\n%q", first.String(), second.String())
	}

	header, err := csv.NewReader(strings.NewReader(first.String())).Read()
	if err != nil {
		t.Fatalf("read header: %v", err)
	}
	for i, want := range exportColumns {
		if header[i] != want {
			t.Errorf("column %d = %q, want %q", i, header[i], want)
		}
	}
}

// Log fields are attacker-controlled by definition, and a CSV is the one place the
// platform hands hostile text to a program that will interpret it. A user agent
// starting with `=` executes as a formula when the file is opened in a spreadsheet.
func TestCSVNeutralizesFormulaInjection(t *testing.T) {
	dangerous := []string{
		`=cmd|'/c calc'!A1`,
		`+1+1`,
		`-1+1`,
		`@SUM(1:1)`,
		"\tleading tab",
	}

	for _, payload := range dangerous {
		t.Run(payload, func(t *testing.T) {
			var buf bytes.Buffer
			err := query.NewExporter(query.FormatCSV, exportColumns, 100).
				Write(&buf, rowsFrom([]query.ExportRow{{"user_agent": payload}}))
			if err != nil {
				t.Fatalf("Write: %v", err)
			}

			records, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
			if err != nil {
				t.Fatalf("read csv: %v", err)
			}
			cell := records[1][2]
			if !strings.HasPrefix(cell, "'") {
				t.Errorf("cell %q was not neutralized; it would execute as a formula", cell)
			}
		})
	}
}

func TestOrdinaryTextIsNotMangled(t *testing.T) {
	var buf bytes.Buffer
	err := query.NewExporter(query.FormatCSV, exportColumns, 100).
		Write(&buf, rowsFrom([]query.ExportRow{
			{"user_agent": "Mozilla/5.0 (X11; Linux x86_64)"},
		}))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	records, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if got := records[1][2]; got != "Mozilla/5.0 (X11; Linux x86_64)" {
		t.Errorf("cell = %q, want it unchanged", got)
	}
}

// An export that silently stops at the cap looks like a complete extract, and the
// analyst concludes the attack ended at whatever row the limit fell on.
func TestRowCapIsReportedNotHidden(t *testing.T) {
	rows := make([]query.ExportRow, 50)
	for i := range rows {
		rows[i] = query.ExportRow{"event_id": "e"}
	}

	var buf bytes.Buffer
	exporter := query.NewExporter(query.FormatNDJSON, exportColumns, 10)
	if err := exporter.Write(&buf, rowsFrom(rows)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if exporter.Written() != 10 {
		t.Errorf("Written = %d, want 10", exporter.Written())
	}
	if !exporter.Truncated() {
		t.Error("the export hit its cap but did not report being truncated")
	}
	if got := strings.Count(strings.TrimSpace(buf.String()), "\n") + 1; got != 10 {
		t.Errorf("%d lines written, want 10", got)
	}
}

func TestCompleteExportIsNotMarkedTruncated(t *testing.T) {
	var buf bytes.Buffer
	exporter := query.NewExporter(query.FormatNDJSON, exportColumns, 10)
	if err := exporter.Write(&buf, rowsFrom([]query.ExportRow{{"event_id": "e"}})); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if exporter.Truncated() {
		t.Error("a complete export was reported as truncated")
	}
}

// A caller asking for a billion rows gets the platform cap, not an OOM.
func TestRequestedCapIsBounded(t *testing.T) {
	rows := make([]query.ExportRow, 5)
	for i := range rows {
		rows[i] = query.ExportRow{"event_id": "e"}
	}

	var buf bytes.Buffer
	exporter := query.NewExporter(query.FormatNDJSON, exportColumns, 1<<30)
	if err := exporter.Write(&buf, rowsFrom(rows)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if exporter.Written() != 5 {
		t.Errorf("Written = %d, want 5", exporter.Written())
	}
}

func TestFormatParsing(t *testing.T) {
	cases := map[string]query.Format{
		"":       query.FormatNDJSON,
		"ndjson": query.FormatNDJSON,
		"CSV":    query.FormatCSV,
		"  csv ": query.FormatCSV,
	}
	for input, want := range cases {
		got, err := query.FormatFromString(input)
		if err != nil {
			t.Errorf("FormatFromString(%q): %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("FormatFromString(%q) = %q, want %q", input, got, want)
		}
	}

	if _, err := query.FormatFromString("xlsx"); err == nil {
		t.Error("an unsupported format was accepted")
	}
}

func TestFilenameIsSortable(t *testing.T) {
	earlier := query.Filename("events",
		time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC), query.FormatCSV)
	later := query.Filename("events",
		time.Date(2026, 8, 6, 13, 0, 0, 0, time.UTC), query.FormatCSV)

	if earlier >= later {
		t.Errorf("filenames do not sort chronologically: %q then %q", earlier, later)
	}
	if !strings.HasSuffix(earlier, ".csv") {
		t.Errorf("filename %q has the wrong extension", earlier)
	}
}

func TestNilAndTypedValuesRender(t *testing.T) {
	var buf bytes.Buffer
	at := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)

	err := query.NewExporter(query.FormatCSV,
		[]string{"a", "b", "c", "d", "e"}, 100).
		Write(&buf, rowsFrom([]query.ExportRow{{
			"a": nil, "b": true, "c": at, "d": []string{"x", "y"}, "e": float32(0.25),
		}}))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	records, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	row := records[1]
	want := []string{"", "true", "2026-08-06T12:00:00Z", "x y", "0.25"}
	for i, expected := range want {
		if row[i] != expected {
			t.Errorf("column %d = %q, want %q", i, row[i], expected)
		}
	}
}
