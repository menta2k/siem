//go:build integration

package integration

import (
	"fmt"
	"strings"
	"testing"
	"time"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/ingest/filter"
)

// cloudflareRequest builds a valid event for a specific host and path, so a filter can be
// aimed at it.
func cloudflareRequest(rayID, host, path string) string {
	return fmt.Sprintf(`{"RayID":%q,"EdgeStartTimestamp":%q,"ClientIP":"203.0.113.10",`+
		`"ClientRequestHost":%q,"ClientRequestURI":%q,`+
		`"ClientRequestMethod":"GET","EdgeResponseStatus":200,"SecurityAction":""}`,
		rayID, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339), host, path)
}

// setFilters stores a tenant's ingest rules the way the admin API does.
func setFilters(t *testing.T, h *ingestHarness, rules ...filter.Rule) {
	t.Helper()

	encoded, err := filter.Encode(rules)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := h.fixture.Tenants.Update(h.ctx, func(current chdata.Tenant) chdata.Tenant {
		current.IngestFilters = encoded
		return current
	}); err != nil {
		t.Fatalf("store ingest filters: %v", err)
	}
	// The write must be visible before the delivery reads it back. Without this the
	// receiver resolves an empty rule set and the test proves nothing.
	h.fixture.Sync(t, "tenants")

}

// rawEventCount reports how many raw payloads were stored whose bytes contain the marker.
//
// Queried against raw_events specifically: it is the FIRST thing written and the copy
// everything else is derived from, so its absence is what proves the event was dropped
// before the pipeline rather than somewhere along it.
func rawEventCount(t *testing.T, h *ingestHarness, marker string) uint64 {
	t.Helper()
	h.fixture.Sync(t, "raw_events")

	rows, err := h.fixture.ClickHouse.Query(h.ctx,
		"SELECT count() FROM raw_events WHERE tenant_id = ? AND position(payload, ?) > 0",
		h.feed.TenantID, marker)
	if err != nil {
		t.Fatalf("count raw events: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var count uint64
	if rows.Next() {
		if err := rows.Scan(&count); err != nil {
			t.Fatalf("scan count: %v", err)
		}
	}
	return count
}

// THE PROMISE THIS FEATURE MAKES, end to end: a filtered event is never stored anywhere.
//
// Every other test of this feature checks a function in isolation. This one posts a real
// delivery through the real receiver and then looks in the database, because the value of
// the filter is entirely about what is ABSENT afterwards — and absence is exactly what
// unit tests of the matcher cannot demonstrate.
func TestAFilteredEventIsNeverStored(t *testing.T) {
	h := newIngestHarness(t, 0)
	setFilters(t, h, filter.Rule{
		Field: filter.FieldRequestPath, Op: filter.OpSuffix, Values: []string{".png"},
	})

	body := strings.Join([]string{
		cloudflareRequest("filtered-ray", "shop.example.com", "/logo.png"),
		cloudflareRequest("kept-ray", "shop.example.com", "/checkout"),
	}, "\n")

	outcome := h.outcome(t, h.deliver(t, body))

	if outcome.Filtered != 1 {
		t.Errorf("Filtered = %d, want 1", outcome.Filtered)
	}
	if outcome.Accepted != 1 {
		t.Errorf("Accepted = %d, want 1", outcome.Accepted)
	}
	if len(outcome.Rejected) != 0 {
		t.Errorf("a filtered event was dead-lettered: %v", outcome.Rejected)
	}

	// Only the surviving event reaches the stream. If the filtered one were merely
	// excluded later, this drain would block waiting for a second record.
	h.drain(t, 1)

	if got := rawEventCount(t, h, "filtered-ray"); got != 0 {
		t.Errorf("the filtered event was stored in raw_events %d times, want 0 — "+
			"filtering must happen before anything is written", got)
	}
	if got := rawEventCount(t, h, "kept-ray"); got != 1 {
		t.Errorf("the unfiltered event was stored %d times, want 1 — the filter took "+
			"traffic it was not aimed at", got)
	}
}

// A tenant with no rules must behave exactly as it did before this feature existed. This
// is the control: without it, a filter that silently drops everything would still pass
// the test above.
func TestWithoutFiltersEverythingIsStored(t *testing.T) {
	h := newIngestHarness(t, 0)

	body := strings.Join([]string{
		cloudflareRequest("nofilter-a", "shop.example.com", "/logo.png"),
		cloudflareRequest("nofilter-b", "shop.example.com", "/checkout"),
	}, "\n")

	outcome := h.outcome(t, h.deliver(t, body))

	if outcome.Filtered != 0 {
		t.Errorf("Filtered = %d with no rules configured, want 0", outcome.Filtered)
	}
	if outcome.Accepted != 2 {
		t.Errorf("Accepted = %d, want 2", outcome.Accepted)
	}
	h.drain(t, 2)

	for _, marker := range []string{"nofilter-a", "nofilter-b"} {
		if got := rawEventCount(t, h, marker); got != 1 {
			t.Errorf("%s stored %d times, want 1", marker, got)
		}
	}
}

// Filtering on hostname, the other half of the brief. Aimed at a host the tenant also
// receives legitimate traffic from a sibling of, so an over-broad match would show up.
func TestAFilteredHostIsNeverStored(t *testing.T) {
	h := newIngestHarness(t, 0)
	setFilters(t, h, filter.Rule{
		Field: filter.FieldRequestHost, Op: filter.OpEquals,
		Values: []string{"assets.example.com"},
	})

	body := strings.Join([]string{
		cloudflareRequest("host-dropped", "assets.example.com", "/index.html"),
		cloudflareRequest("host-kept", "shop.example.com", "/index.html"),
	}, "\n")

	outcome := h.outcome(t, h.deliver(t, body))
	if outcome.Filtered != 1 || outcome.Accepted != 1 {
		t.Fatalf("Filtered=%d Accepted=%d, want 1 and 1", outcome.Filtered, outcome.Accepted)
	}
	h.drain(t, 1)

	if got := rawEventCount(t, h, "host-dropped"); got != 0 {
		t.Errorf("the filtered host was stored %d times, want 0", got)
	}
	if got := rawEventCount(t, h, "host-kept"); got != 1 {
		t.Errorf("a sibling host was dropped by an exact-match rule")
	}
}

// SILENT LOSS IS THE FAILURE MODE. A filtered event leaves no payload, no row and no
// rejection, so this count is the only evidence that a rule is working — and the only
// warning when it is working far too well. It has to survive the whole round trip to
// storage, not just exist in the response.
func TestTheFilteredCountReachesFeedHealth(t *testing.T) {
	h := newIngestHarness(t, 0)
	setFilters(t, h, filter.Rule{
		Field: filter.FieldRequestPath, Op: filter.OpSuffix, Values: []string{".css"},
	})

	body := strings.Join([]string{
		cloudflareRequest("health-a", "shop.example.com", "/site.css"),
		cloudflareRequest("health-b", "shop.example.com", "/app.css"),
		cloudflareRequest("health-c", "shop.example.com", "/checkout"),
	}, "\n")

	h.outcome(t, h.deliver(t, body))
	h.drain(t, 1)

	if err := h.health.Flush(h.ctx); err != nil {
		t.Fatalf("flush health: %v", err)
	}
	h.fixture.Sync(t, "feed_health")

	rows, err := h.fixture.ClickHouse.Query(h.ctx,
		"SELECT sum(events_filtered) FROM feed_health WHERE tenant_id = ? AND feed_id = ?",
		h.feed.TenantID, h.feed.ID)
	if err != nil {
		t.Fatalf("read feed health: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var filtered uint64
	if rows.Next() {
		if err := rows.Scan(&filtered); err != nil {
			t.Fatalf("scan filtered: %v", err)
		}
	}
	if filtered != 2 {
		t.Errorf("feed health recorded %d filtered events, want 2 — without this counter "+
			"a filtered event is indistinguishable from a lost one", filtered)
	}
}
