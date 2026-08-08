package ingest_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/ingest"
	"github.com/menta2k/siem/internal/ingest/filter"
	"github.com/menta2k/siem/internal/vendors"
)

func filterMeta(t *testing.T, rules ...filter.Rule) ingest.EnvelopeMeta {
	t.Helper()
	set, err := filter.Compile(rules)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return ingest.EnvelopeMeta{
		TenantID: uuid.New(), FeedID: uuid.New(), BatchID: uuid.New(),
		ReceivedAt:  time.Now().UTC(),
		IdentityFor: func(vendorRequestID string, raw []byte) string { return string(raw) },
		Filters:     set,
	}
}

// A filtered event produces NO envelope, so it is never published, never stored as a raw
// payload and never normalized. That is the entire value: the cheapest event is the one
// that is never written, and static assets can be most of a WAF's volume while carrying
// no security signal.
func TestAFilteredEventIsNotEnvelopedAtAll(t *testing.T) {
	meta := filterMeta(t, filter.Rule{
		Field: filter.FieldRequestPath, Op: filter.OpSuffix, Values: []string{".png"},
	})

	envelopes, rejections, filtered := ingest.BuildEnvelopes(
		testAdapter{}, records(t, "/logo.png", "/checkout"), meta)

	if filtered != 1 {
		t.Errorf("filtered = %d, want 1", filtered)
	}
	if len(envelopes) != 1 {
		t.Fatalf("%d envelopes, want 1 — the filtered event must not be published", len(envelopes))
	}
	if len(rejections) != 0 {
		t.Errorf("%d rejections, want 0 — a filter is not a failure", len(rejections))
	}
}

// A DROP IS NOT A REJECTION. A rejection is dead-lettered with its payload because
// something went wrong and an operator must be able to see what; a filtered event was
// excluded on purpose and storing it would defeat the point. Conflating them would either
// fill the dead-letter view with intentional drops or make real failures invisible.
func TestAFilteredEventIsNotDeadLettered(t *testing.T) {
	meta := filterMeta(t, filter.Rule{
		Field: filter.FieldRequestHost, Op: filter.OpEquals,
		Values: []string{"assets.example.com"},
	})

	_, rejections, filtered := ingest.BuildEnvelopes(
		testAdapter{}, hostRecords(t, "assets.example.com"), meta)

	if filtered != 1 {
		t.Errorf("filtered = %d, want 1", filtered)
	}
	if len(rejections) != 0 {
		t.Errorf("a filtered event was dead-lettered as %v", rejections)
	}
}

// SILENT DROPS ARE THE REAL DANGER HERE. An operator who writes a rule slightly too broad
// gets no error and no stored evidence — the only thing standing between them and
// unexplained missing traffic is this count. It has to be reported even when it is the
// whole delivery.
func TestEveryDropIsCounted(t *testing.T) {
	meta := filterMeta(t, filter.Rule{
		Field: filter.FieldRequestPath, Op: filter.OpPrefix, Values: []string{"/"},
	})

	envelopes, _, filtered := ingest.BuildEnvelopes(
		testAdapter{}, records(t, "/a", "/b", "/c"), meta)

	if filtered != 3 {
		t.Errorf("filtered = %d, want 3", filtered)
	}
	if len(envelopes) != 0 {
		t.Errorf("%d envelopes survived a rule matching everything", len(envelopes))
	}
}

// The overwhelmingly common case is a tenant with no filters, and it must behave exactly
// as it did before this feature existed.
func TestNoFiltersChangesNothing(t *testing.T) {
	meta := filterMeta(t)

	envelopes, rejections, filtered := ingest.BuildEnvelopes(
		testAdapter{}, records(t, "/logo.png", "/checkout"), meta)

	if filtered != 0 {
		t.Errorf("filtered = %d with no rules configured, want 0", filtered)
	}
	if len(envelopes) != 2 || len(rejections) != 0 {
		t.Errorf("envelopes=%d rejections=%d, want 2 and 0", len(envelopes), len(rejections))
	}
}

// An event that cannot be normalized is dead-lettered rather than filtered: the filter
// needs a host and path to decide, and it has neither. Dropping what we failed to
// understand would hide parse failures behind a volume-reduction feature.
func TestAnUnnormalizableEventIsRejectedNotFiltered(t *testing.T) {
	meta := filterMeta(t, filter.Rule{
		Field: filter.FieldRequestPath, Op: filter.OpPrefix, Values: []string{"/"},
	})

	_, rejections, filtered := ingest.BuildEnvelopes(testAdapter{}, badRecords(t), meta)

	if len(rejections) != 1 {
		t.Errorf("%d rejections, want 1 — a parse failure is not a filter match", len(rejections))
	}
	if filtered != 0 {
		t.Errorf("filtered = %d, want 0", filtered)
	}
}

// testAdapter turns a record's bytes into an event whose host and path are whatever the
// test asked for, so filtering can be exercised without depending on a real vendor's
// parser. The encoding is "host path", and the empty string means "cannot normalize".
type testAdapter struct{}

func (testAdapter) Vendor() string { return "test" }

func (testAdapter) Detect(_ []byte) (vendors.Format, bool) { return vendors.Format("test"), true }

func (testAdapter) Parse(payload []byte, format vendors.Format) ([]vendors.RawRecord, error) {
	return []vendors.RawRecord{{Bytes: payload, Format: format}}, nil
}

func (testAdapter) Normalize(record vendors.RawRecord) (vendors.Event, error) {
	host, path, found := strings.Cut(string(record.Bytes), " ")
	if !found {
		return vendors.Event{}, errors.New("unparseable")
	}
	return vendors.Event{RequestHost: host, RequestPath: path}, nil
}

func records(t *testing.T, paths ...string) []vendors.RawRecord {
	t.Helper()
	out := make([]vendors.RawRecord, 0, len(paths))
	for _, path := range paths {
		out = append(out, vendors.RawRecord{
			Bytes: []byte("shop.example.com " + path), Format: vendors.Format("test"),
		})
	}
	return out
}

func hostRecords(t *testing.T, hosts ...string) []vendors.RawRecord {
	t.Helper()
	out := make([]vendors.RawRecord, 0, len(hosts))
	for _, host := range hosts {
		out = append(out, vendors.RawRecord{
			Bytes: []byte(host + " /index.html"), Format: vendors.Format("test"),
		})
	}
	return out
}

func badRecords(t *testing.T) []vendors.RawRecord {
	t.Helper()
	return []vendors.RawRecord{{Bytes: []byte("unparseable"), Format: vendors.Format("test")}}
}
