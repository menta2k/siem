// Package vendor_test fuzzes the three adapters against arbitrary bytes.
//
// Contract obligation 1: Parse never panics on arbitrary input. This is not a
// theoretical concern — an adapter reads bytes an attacker chose, delivered through
// a vendor that will forward whatever it was sent. A panic in one tenant's parser
// would take down ingestion for every tenant on that instance.
package vendor_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/menta2k/siem/internal/vendors"
	"github.com/menta2k/siem/internal/vendors/cloudflare"
	"github.com/menta2k/siem/internal/vendors/datadome"
	"github.com/menta2k/siem/internal/vendors/f5"
)

// adapters returns every adapter, so a new vendor is fuzzed automatically once it is
// added to this list.
func adapters() []vendors.Adapter {
	return []vendors.Adapter{cloudflare.New(), f5.New(), datadome.New()}
}

// seedFromFixtures adds every fixture as a fuzzing seed, so mutation starts from
// realistic input rather than from noise.
func seedFromFixtures(f *testing.F) {
	f.Helper()

	root := filepath.Join("..", "..", "fixtures")
	// Seeding is best-effort: one unreadable fixture must not stop the fuzz corpus.
	//nolint:nilerr // walk errors are deliberately skipped, not propagated
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		data, readErr := os.ReadFile(path) //nolint:gosec // test-controlled path
		if readErr != nil {
			return nil
		}
		f.Add(data)
		return nil
	})

	// Shapes that have historically broken hand-written parsers.
	f.Add([]byte(""))
	f.Add([]byte("{"))
	f.Add([]byte("["))
	f.Add([]byte("[]"))
	f.Add([]byte("{}"))
	f.Add([]byte("null"))
	f.Add([]byte("\x00\x00\x00"))
	f.Add([]byte("CEF:"))
	f.Add([]byte("CEF:0|"))
	f.Add([]byte("CEF:0|||||||"))
	f.Add([]byte("CEF:0|a|b|c|d|e|f|k="))
	f.Add([]byte("=value"))
	f.Add([]byte("support_id="))
	f.Add([]byte(`{"EdgeStartTimestamp":`))
	f.Add([]byte(`{"timestamp":1e999}`))
	f.Add([]byte(`{"ClientIP":"999.999.999.999"}`))
	f.Add([]byte(`{"botscore":"NaN"}`))
	f.Add([]byte("\n\n\n\n"))
	f.Add([]byte(`{"a":` + `[[[[[[[[[[` + `]]]]]]]]]]` + `}`))
}

// FuzzParseAndNormalize drives the whole adapter surface: detect, parse, normalize.
//
// It asserts no panic and no hang. Errors are entirely acceptable — an adapter
// SHOULD reject garbage. What it must never do is crash the process or corrupt state.
func FuzzParseAndNormalize(f *testing.F) {
	seedFromFixtures(f)

	f.Fuzz(func(t *testing.T, payload []byte) {
		for _, adapter := range adapters() {
			// Detect must not panic and must be safe to call on anything.
			format, recognized := adapter.Detect(payload)
			if !recognized {
				format = vendors.FormatUnknown
			}

			records, err := adapter.Parse(payload, format)
			if err != nil {
				continue // rejecting garbage is correct behaviour
			}

			for _, record := range records {
				event, err := adapter.Normalize(record)
				if err != nil {
					continue
				}
				assertEventInvariants(t, adapter.Vendor(), event)
			}
		}
	})
}

// assertEventInvariants checks the properties every successfully normalized event
// must hold, whatever bytes produced it. A parser that returns a structurally invalid
// event is as damaging as one that panics — it just fails further downstream.
func assertEventInvariants(t *testing.T, vendorName string, event vendors.Event) {
	t.Helper()

	if event.Vendor != vendorName {
		t.Fatalf("%s produced an event attributed to %q", vendorName, event.Vendor)
	}
	if !vendors.ValidVerdict(event.Verdict) {
		t.Fatalf("%s produced verdict %q, which is not one of the six defined values",
			vendorName, event.Verdict)
	}
	if event.EventTime.IsZero() {
		t.Fatalf("%s produced an event with a zero timestamp; it should have been rejected",
			vendorName)
	}
	// A correlation window keyed on a wildly out-of-range timestamp would either
	// never match or match everything.
	if year := event.EventTime.Year(); year < 1970 || year > 2200 {
		t.Fatalf("%s produced an implausible timestamp: %v", vendorName, event.EventTime)
	}
	if event.HTTPStatus > 599 {
		t.Fatalf("%s produced HTTP status %d, which is out of range",
			vendorName, event.HTTPStatus)
	}
	if event.Score != nil {
		score := *event.Score
		if score != score { // NaN
			t.Fatalf("%s produced a NaN score", vendorName)
		}
	}
	switch event.ScoreKind {
	case vendors.ScoreKindBot, vendors.ScoreKindThreat, vendors.ScoreKindNone:
	default:
		t.Fatalf("%s produced score kind %q, which is not defined", vendorName, event.ScoreKind)
	}
}

// FuzzDetect isolates format detection, which runs before any validation and is
// therefore the first thing arbitrary bytes touch.
func FuzzDetect(f *testing.F) {
	seedFromFixtures(f)

	f.Fuzz(func(t *testing.T, payload []byte) {
		for _, adapter := range adapters() {
			format, ok := adapter.Detect(payload)
			if ok {
				switch format {
				case vendors.FormatJSON, vendors.FormatNDJSON, vendors.FormatCEF, vendors.FormatSyslog:
				case vendors.FormatUnknown:
					t.Fatalf("%s reported a recognized payload with format unknown",
						adapter.Vendor())
				default:
					t.Fatalf("%s reported undefined format %q", adapter.Vendor(), format)
				}
			}
		}
	})
}
