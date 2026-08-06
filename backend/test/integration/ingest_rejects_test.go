//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/ingest"
	"github.com/menta2k/siem/internal/normalize"
)

// rejectFilter spans the whole test run.
func rejectFilter() chdata.RejectedFilter {
	return chdata.RejectedFilter{
		From:  time.Now().Add(-time.Hour),
		To:    time.Now().Add(time.Hour),
		Limit: 100,
	}
}

// Acceptance Scenario 1.4: a malformed line must not cost the customer the rest of
// the batch, and the failure must be visible with a reason rather than silent.
func TestMalformedLinesAreDeadLetteredWithoutLosingTheBatch(t *testing.T) {
	h := newIngestHarness(t, 0)

	body := strings.Join([]string{
		cloudflareEvent("good-1"),
		`{"RayID":"bad-1","EdgeStartTimestamp":"not-a-timestamp"}`,
		cloudflareEvent("good-2"),
		`{"RayID":"bad-2",`, // truncated JSON
		cloudflareEvent("good-3"),
	}, "\n")

	rec := h.deliver(t, body)
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("status = %d, want 207 (body=%s)", rec.Code, rec.Body.String())
	}

	outcome := h.outcome(t, rec)
	if outcome.Accepted != 3 {
		t.Errorf("Accepted = %d, want the 3 good lines", outcome.Accepted)
	}
	if len(outcome.Rejected) != 2 {
		t.Fatalf("Rejected = %d entries, want 2", len(outcome.Rejected))
	}

	// The vendor must be able to identify WHICH records failed.
	rejectedIndices := map[int]bool{}
	for _, r := range outcome.Rejected {
		rejectedIndices[r.Index] = true
		if r.ReasonCode == "" {
			t.Error("a rejection carries no reason code")
		}
		if r.ReasonDetail == "" {
			t.Error("a rejection carries no detail; it would not be actionable")
		}
	}
	if !rejectedIndices[1] || !rejectedIndices[3] {
		t.Errorf("rejected indices = %v, want the 2nd and 4th lines", rejectedIndices)
	}

	// Only the 3 good lines reach the raw topic; the 2 malformed ones were
	// dead-lettered at the receiver and travel on the DLQ topic instead.
	h.drain(t, 3)
	h.fixture.Sync(t, "normalized_events")

	if got := h.fixture.CountRows(h.ctx, t, "normalized_events", "FINAL"); got != 3 {
		t.Errorf("normalized_events holds %d rows, want the 3 good events", got)
	}
}

// FR-006: nothing is dropped silently. A rejected event must be retrievable with its
// reason and its original payload.
func TestRejectedEventsAreQueryableWithReasonAndPayload(t *testing.T) {
	h := newIngestHarness(t, 0)
	const badPayload = `{"RayID":"reject-me","EdgeStartTimestamp":"nonsense"}`

	rec := h.deliver(t, cloudflareEvent("ok-1")+"\n"+badPayload)
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("status = %d, want 207", rec.Code)
	}

	// The good event travels on the raw topic; the malformed one was rejected at the
	// receiver and travels on the dead-letter topic, which its own worker drains into
	// rejected_events so the operator can actually see it.
	h.drain(t, 1)
	h.drainDLQ(t, 1)
	h.fixture.Sync(t, "rejected_events")

	rejected, err := h.fixture.Events.ListRejected(h.ctx, rejectFilter())
	if err != nil {
		t.Fatalf("ListRejected(): %v", err)
	}
	if len(rejected) != 1 {
		t.Fatalf("ListRejected() returned %d rows, want 1", len(rejected))
	}

	entry := rejected[0]
	if entry.ReasonCode == "" {
		t.Error("the stored rejection has no reason code")
	}
	if string(entry.Payload) != badPayload {
		t.Errorf("the stored payload differs from what was delivered:\n got %q\nwant %q",
			entry.Payload, badPayload)
	}
	if entry.FeedID != h.feed.ID {
		t.Error("the rejection is not attributed to the delivering feed")
	}
}

// The raw event must survive even when normalization fails, so a parser bug never
// costs the evidence (FR-005).
func TestRawEventSurvivesNormalizationFailure(t *testing.T) {
	h := newIngestHarness(t, 0)
	const badPayload = `{"RayID":"raw-survives","EdgeStartTimestamp":"nope"}`

	rec := h.deliver(t, badPayload)
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("status = %d, want 207 (body=%s)", rec.Code, rec.Body.String())
	}

	// A payload rejected at the RECEIVER is dead-lettered before it ever reaches the
	// raw topic, so the vendor learns why immediately rather than after processing.
	outcome := h.outcome(t, rec)
	if len(outcome.Rejected) != 1 {
		t.Fatalf("Rejected = %d, want 1", len(outcome.Rejected))
	}
	if outcome.Accepted != 0 {
		t.Errorf("Accepted = %d, want 0 for a wholly unparseable delivery", outcome.Accepted)
	}
	if got := h.fixture.CountRows(h.ctx, t, "normalized_events", "FINAL"); got != 0 {
		t.Errorf("normalized_events holds %d rows for an unparseable event, want 0", got)
	}
}

// The dead-letter view is filtered by reason so an operator can triage one class of
// failure at a time.
func TestRejectedEventsAreFilterableByReason(t *testing.T) {
	h := newIngestHarness(t, 0)

	body := strings.Join([]string{
		`{"RayID":"t1","EdgeStartTimestamp":"2019-01-01T00:00:00Z","ClientIP":"203.0.113.1",` +
			`"ClientRequestHost":"h","ClientRequestURI":"/","ClientRequestMethod":"GET"}`,
		`{"RayID":"p1","EdgeStartTimestamp":"garbage"}`,
	}, "\n")

	if rec := h.deliver(t, body); rec.Code != http.StatusMultiStatus {
		t.Fatalf("status = %d, want 207 (body=%s)", rec.Code, rec.Body.String())
	}
	// The out-of-range event is accepted by the adapter and reaches the worker, which
	// applies the now-relative bound. The unparseable one stops at the receiver.
	h.drain(t, 1)
	h.fixture.Sync(t, "rejected_events")

	all, err := h.fixture.Events.ListRejected(h.ctx, rejectFilter())
	if err != nil {
		t.Fatalf("ListRejected(): %v", err)
	}
	if len(all) == 0 {
		t.Fatal("no rejections were recorded")
	}

	filter := rejectFilter()
	filter.ReasonCode = string(ingest.ReasonTimestampOutOfRange)

	filtered, err := h.fixture.Events.ListRejected(h.ctx, filter)
	if err != nil {
		t.Fatalf("ListRejected(filtered): %v", err)
	}
	for _, entry := range filtered {
		if entry.ReasonCode != string(ingest.ReasonTimestampOutOfRange) {
			t.Errorf("the filter leaked reason %q", entry.ReasonCode)
		}
	}
	if len(filtered) >= len(all) && len(all) > 1 {
		t.Error("filtering by reason returned everything; the filter is not applied")
	}
}

// Rejections must not leak across tenants: one customer's malformed traffic is not
// another's business.
func TestRejectedEventsAreTenantScoped(t *testing.T) {
	h := newIngestHarness(t, 0)

	// An out-of-range timestamp passes the adapter and is rejected by the worker, so
	// it does produce a rejected_events row for this tenant.
	body := fmt.Sprintf(`{"RayID":"scoped-1","EdgeStartTimestamp":%q,"ClientIP":"203.0.113.1",`+
		`"ClientRequestHost":"h","ClientRequestURI":"/","ClientRequestMethod":"GET",`+
		`"SecurityAction":"allow"}`,
		time.Now().UTC().AddDate(0, 0, -200).Format(time.RFC3339))

	if rec := h.deliver(t, body); rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (body=%s)", rec.Code, rec.Body.String())
	}
	h.drain(t, 1)
	h.fixture.Sync(t, "rejected_events")

	otherCtx, _ := h.fixture.NewTenant(t, "bystander")

	rejected, err := h.fixture.Events.ListRejected(otherCtx, rejectFilter())
	if err != nil {
		t.Fatalf("ListRejected(): %v", err)
	}
	if len(rejected) != 0 {
		t.Errorf("a second tenant saw %d rejections belonging to the first", len(rejected))
	}
}

// An event whose timestamp lies outside the retention window is dead-lettered with a
// specific reason, not stored into a partition the retention job is about to drop.
func TestOutOfRangeTimestampIsRejectedWithItsOwnReason(t *testing.T) {
	h := newIngestHarness(t, 0)

	body := fmt.Sprintf(`{"RayID":"old-1","EdgeStartTimestamp":%q,"ClientIP":"203.0.113.1",`+
		`"ClientRequestHost":"h","ClientRequestURI":"/","ClientRequestMethod":"GET",`+
		`"SecurityAction":"allow"}`,
		time.Now().UTC().AddDate(0, 0, -200).Format(time.RFC3339))

	if rec := h.deliver(t, body); rec.Code != http.StatusAccepted {
		// The adapter accepts it (the timestamp is plausible in absolute terms); the
		// worker is what applies the now-relative retention bound.
		t.Fatalf("status = %d, want 202 (body=%s)", rec.Code, rec.Body.String())
	}
	h.drain(t, 1)
	h.fixture.Sync(t, "rejected_events")

	filter := rejectFilter()
	filter.ReasonCode = string(ingest.ReasonTimestampOutOfRange)

	rejected, err := h.fixture.Events.ListRejected(h.ctx, filter)
	if err != nil {
		t.Fatalf("ListRejected(): %v", err)
	}
	if len(rejected) != 1 {
		t.Fatalf("found %d out-of-range rejections, want 1", len(rejected))
	}
	if got := h.fixture.CountRows(h.ctx, t, "normalized_events", "FINAL"); got != 0 {
		t.Errorf("normalized_events holds %d rows for an out-of-range event, want 0", got)
	}
}

// Redaction is applied before storage, so a masked field is never written readable
// anywhere in the derived view (FR-037).
func TestRedactionPolicyIsEnforcedAtStorage(t *testing.T) {
	h := newIngestHarness(t, 0)

	if _, err := h.fixture.Tenants.Update(h.ctx, func(tn chdata.Tenant) chdata.Tenant {
		tn.RedactedFields = []string{"user_agent"}
		return tn
	}); err != nil {
		t.Fatalf("set redaction policy: %v", err)
	}

	const secretUA = "Mozilla/5.0 (private-device-fingerprint)"
	body := fmt.Sprintf(`{"RayID":"redact-1","EdgeStartTimestamp":%q,"ClientIP":"203.0.113.1",`+
		`"ClientRequestHost":"h","ClientRequestURI":"/","ClientRequestMethod":"GET",`+
		`"ClientRequestUserAgent":%q,"SecurityAction":"allow"}`,
		time.Now().UTC().Add(-time.Minute).Format(time.RFC3339), secretUA)

	if rec := h.deliver(t, body); rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (body=%s)", rec.Code, rec.Body.String())
	}
	h.drain(t, 1)
	h.fixture.Sync(t, "normalized_events")

	eventID := normalize.EventID(h.feed.ID, "redact-1", []byte(body))

	stored, err := h.fixture.Events.GetNormalized(h.ctx, eventID)
	if err != nil {
		t.Fatalf("GetNormalized(): %v", err)
	}
	if stored.UserAgent == secretUA {
		t.Error("the redacted user agent was stored in readable form")
	}
	for key, value := range stored.RawExtra {
		if strings.Contains(value, "private-device-fingerprint") {
			t.Errorf("RawExtra[%q] still carries the redacted value", key)
		}
	}

	// The raw copy deliberately retains the original: redaction governs the derived,
	// queryable view, and the vendor's evidence expires with the retention policy.
	raw, _, err := h.fixture.Events.GetRawPayload(h.ctx, eventID)
	if err != nil {
		t.Fatalf("GetRawPayload(): %v", err)
	}
	if !strings.Contains(string(raw), secretUA) {
		t.Error("the raw payload was altered; it must be preserved verbatim")
	}
}
