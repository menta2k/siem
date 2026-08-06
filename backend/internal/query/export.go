package query

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	mw "github.com/menta2k/siem/internal/middleware"
)

// Format is the serialization an export produces.
type Format string

// The supported export formats.
const (
	FormatNDJSON Format = "ndjson"
	FormatCSV    Format = "csv"
)

// ContentType is the MIME type a format is served as.
func (f Format) ContentType() string {
	switch f {
	case FormatCSV:
		return "text/csv; charset=utf-8"
	default:
		return "application/x-ndjson"
	}
}

// Extension is the filename suffix for a format.
func (f Format) Extension() string {
	if f == FormatCSV {
		return "csv"
	}
	return "ndjson"
}

// DefaultMaxExportRows caps an export when configuration supplies nothing.
const DefaultMaxExportRows = 100_000

// ExportRow is one record in an export.
//
// A flat map rather than a struct so the writer stays independent of what is being
// exported. The column order comes from Columns, never from map iteration — a CSV
// whose columns move between runs is not a file anyone can diff or script against.
type ExportRow map[string]any

// Exporter streams rows into a writer.
type Exporter struct {
	format  Format
	columns []string
	maxRows int

	written   int
	truncated bool
}

// NewExporter builds an exporter.
func NewExporter(format Format, columns []string, maxRows int) *Exporter {
	if maxRows <= 0 || maxRows > DefaultMaxExportRows {
		maxRows = DefaultMaxExportRows
	}
	return &Exporter{format: format, columns: columns, maxRows: maxRows}
}

// FormatFromString parses a requested format.
func FormatFromString(value string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "ndjson", "":
		return FormatNDJSON, nil
	case "csv":
		return FormatCSV, nil
	default:
		return "", mw.ValidationFailed(fmt.Sprintf("unsupported export format %q", value))
	}
}

// Written reports how many rows were emitted, which the audit entry records.
func (e *Exporter) Written() int { return e.written }

// Truncated reports whether the row cap stopped the export early.
//
// This has to reach the caller. An export that silently stops at the cap looks like a
// complete extract, and the analyst who loads it into a spreadsheet concludes the
// attack ended at whatever row the limit fell on.
func (e *Exporter) Truncated() bool { return e.truncated }

// Write streams rows until they run out or the cap is reached.
//
// Streaming rather than buffering: an export is bounded at a hundred thousand rows, and
// assembling that in memory before the first byte reaches the client both delays the
// response and puts the whole file on the heap of a shared process.
func (e *Exporter) Write(w io.Writer, rows func(yield func(ExportRow) bool)) error {
	switch e.format {
	case FormatCSV:
		return e.writeCSV(w, rows)
	default:
		return e.writeNDJSON(w, rows)
	}
}

func (e *Exporter) writeNDJSON(w io.Writer, rows func(yield func(ExportRow) bool)) error {
	encoder := json.NewEncoder(w)
	var writeErr error

	rows(func(row ExportRow) bool {
		if e.written >= e.maxRows {
			e.truncated = true
			return false
		}
		if err := encoder.Encode(row); err != nil {
			writeErr = fmt.Errorf("write ndjson row %d: %w", e.written, err)
			return false
		}
		e.written++
		return true
	})

	return writeErr
}

func (e *Exporter) writeCSV(w io.Writer, rows func(yield func(ExportRow) bool)) error {
	writer := csv.NewWriter(w)
	if err := writer.Write(e.columns); err != nil {
		return fmt.Errorf("write csv header: %w", err)
	}

	var writeErr error
	record := make([]string, len(e.columns))

	rows(func(row ExportRow) bool {
		if e.written >= e.maxRows {
			e.truncated = true
			return false
		}
		for i, column := range e.columns {
			record[i] = csvValue(row[column])
		}
		if err := writer.Write(record); err != nil {
			writeErr = fmt.Errorf("write csv row %d: %w", e.written, err)
			return false
		}
		e.written++
		return true
	})

	writer.Flush()
	if writeErr != nil {
		return writeErr
	}
	return writer.Error()
}

// csvValue renders one cell.
//
// Formula injection is neutralized here. A user agent or rule name beginning with =,
// +, -, or @ is executed as a formula when the file is opened in Excel or Sheets, and
// log fields are attacker-controlled by definition — this is the one place in the
// system where hostile text is handed to another program that will interpret it.
func csvValue(value any) string {
	rendered := renderValue(value)
	if rendered == "" {
		return rendered
	}
	switch rendered[0] {
	case '=', '+', '-', '@', '\t', '\r':
		// A leading apostrophe is the spreadsheet convention for "this is text".
		return "'" + rendered
	default:
		return rendered
	}
}

func renderValue(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case uint32:
		return strconv.FormatUint(uint64(v), 10)
	case uint64:
		return strconv.FormatUint(v, 10)
	case float32:
		return strconv.FormatFloat(float64(v), 'f', -1, 32)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case time.Time:
		return v.UTC().Format(time.RFC3339Nano)
	case []string:
		return strings.Join(v, " ")
	default:
		return fmt.Sprint(v)
	}
}

// Filename builds a stable, sortable export filename.
func Filename(prefix string, at time.Time, format Format) string {
	return fmt.Sprintf("%s-%s.%s",
		prefix, at.UTC().Format("20060102T150405Z"), format.Extension())
}
