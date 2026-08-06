package normalize_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/data/stream"
	"github.com/menta2k/siem/internal/ingest"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/normalize"
	"github.com/menta2k/siem/internal/vendors"
	"github.com/menta2k/siem/internal/vendors/cloudflare"
	"github.com/menta2k/siem/internal/vendors/datadome"
	"github.com/menta2k/siem/internal/vendors/f5"
)

var (
	batchTenant = uuid.MustParse("00000000-0000-4000-8000-0000000000f1")
	batchFeed   = uuid.MustParse("00000000-0000-4000-8000-0000000000f2")
)

// countingStore records what each insert was given, so the tests can assert on the
// number of ROUND TRIPS as well as on the rows — the round-trip count is the entire
// point of batching.
type countingStore struct {
	raw        []chdata.RawEvent
	normalized []chdata.NormalizedEvent
	rejected   []chdata.RejectedEvent

	rawCalls        int
	normalizedCalls int
	rejectedCalls   int

	failRaw        error
	failNormalized error
}

func (s *countingStore) InsertRaw(_ context.Context, events []chdata.RawEvent) error {
	s.rawCalls++
	if s.failRaw != nil {
		return s.failRaw
	}
	s.raw = append(s.raw, events...)
	return nil
}

func (s *countingStore) InsertNormalized(
	_ context.Context, events []chdata.NormalizedEvent,
) error {
	s.normalizedCalls++
	if s.failNormalized != nil {
		return s.failNormalized
	}
	s.normalized = append(s.normalized, events...)
	return nil
}

func (s *countingStore) InsertRejected(
	_ context.Context, events []chdata.RejectedEvent,
) error {
	s.rejectedCalls++
	s.rejected = append(s.rejected, events...)
	return nil
}

type stubTenants struct {
	redacted []string
	calls    int
}

func (s *stubTenants) GetByID(context.Context, uuid.UUID) (chdata.Tenant, error) {
	s.calls++
	return chdata.Tenant{ID: batchTenant, RedactedFields: s.redacted}, nil
}

type capturingPublisher struct {
	published []stream.Record
	calls     int
	err       error
}

func (p *capturingPublisher) Publish(
	_ context.Context, _ string, records []stream.Record,
) error {
	p.calls++
	if p.err != nil {
		return p.err
	}
	p.published = append(p.published, records...)
	return nil
}

func newBatchWorker(
	t *testing.T, store *countingStore, tenants *stubTenants, pub *capturingPublisher,
) *normalize.Worker {
	t.Helper()

	registry, err := vendors.NewRegistry(cloudflare.New(), f5.New(), datadome.New())
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	return normalize.NewWorker(registry, store, tenants,
		normalize.NewDriftDetector(nil), pub, "siem.events.normalized",
		mw.NewLogger("error", "json"))
}

// cloudflareRecord builds one envelope carrying a real Cloudflare log line.
func cloudflareRecord(t *testing.T, rayID string, at time.Time) stream.Record {
	t.Helper()

	payload, err := json.Marshal(map[string]any{
		"RayID":                  rayID,
		"EdgeStartTimestamp":     at.Format(time.RFC3339Nano),
		"ClientIP":               "203.0.113.10",
		"ClientRequestHost":      "shop.example.com",
		"ClientRequestPath":      "/checkout",
		"ClientRequestMethod":    "GET",
		"ClientRequestUserAgent": "curl/8.0",
		"EdgeResponseStatus":     200,
		"SecurityAction":         "allow",
	})
	if err != nil {
		t.Fatalf("encode payload: %v", err)
	}

	envelope, err := json.Marshal(ingest.Envelope{
		TenantID: batchTenant, FeedID: batchFeed, Vendor: vendors.Cloudflare,
		EventID: rayID, ReceivedAt: at, Payload: payload,
		Format: string(vendors.FormatNDJSON), BatchID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
	return stream.Record{Key: []byte(rayID), Value: envelope}
}

func batchOf(t *testing.T, n int) []stream.Record {
	t.Helper()

	at := time.Now().UTC().Add(-time.Minute)
	records := make([]stream.Record, 0, n)
	for range n {
		records = append(records, cloudflareRecord(t, "ray-"+uuid.NewString(), at))
	}
	return records
}

// The whole point: one insert per batch, not one per event.
func TestABatchCostsOneInsertPerTable(t *testing.T) {
	store := &countingStore{}
	worker := newBatchWorker(t, store, &stubTenants{}, &capturingPublisher{})

	failures, err := worker.HandleBatch(context.Background(), batchOf(t, 500))
	if err != nil {
		t.Fatalf("HandleBatch: %v", err)
	}
	if len(failures) != 0 {
		t.Fatalf("%d failures on a clean batch", len(failures))
	}

	if store.rawCalls != 1 {
		t.Errorf("%d raw inserts for 500 events, want 1", store.rawCalls)
	}
	if store.normalizedCalls != 1 {
		t.Errorf("%d normalized inserts for 500 events, want 1", store.normalizedCalls)
	}
	if len(store.raw) != 500 || len(store.normalized) != 500 {
		t.Errorf("stored %d raw and %d normalized, want 500 of each",
			len(store.raw), len(store.normalized))
	}
}

// One publish for the whole batch, not one per event.
func TestABatchIsForwardedInOneCall(t *testing.T) {
	pub := &capturingPublisher{}
	worker := newBatchWorker(t, &countingStore{}, &stubTenants{}, pub)

	if _, err := worker.HandleBatch(context.Background(), batchOf(t, 200)); err != nil {
		t.Fatalf("HandleBatch: %v", err)
	}

	if pub.calls != 1 {
		t.Errorf("%d publish calls for 200 events, want 1", pub.calls)
	}
	if len(pub.published) != 200 {
		t.Errorf("forwarded %d events, want 200", len(pub.published))
	}
}

// Tenant policy is read once per tenant, not once per event.
func TestTenantPolicyIsReadOncePerBatch(t *testing.T) {
	tenants := &stubTenants{}
	worker := newBatchWorker(t, &countingStore{}, tenants, &capturingPublisher{})

	if _, err := worker.HandleBatch(context.Background(), batchOf(t, 300)); err != nil {
		t.Fatalf("HandleBatch: %v", err)
	}

	if tenants.calls != 1 {
		t.Errorf("%d tenant reads for a single-tenant batch of 300, want 1", tenants.calls)
	}
}

// THE DURABILITY GUARANTEE. A storage failure must fail the WHOLE batch so no offset
// is committed and every event is retried — the promise the 202 already made.
func TestAStorageFailureFailsTheWholeBatch(t *testing.T) {
	cases := map[string]*countingStore{
		"raw insert fails":        {failRaw: errors.New("clickhouse unavailable")},
		"normalized insert fails": {failNormalized: errors.New("clickhouse unavailable")},
	}

	for name, store := range cases {
		t.Run(name, func(t *testing.T) {
			worker := newBatchWorker(t, store, &stubTenants{}, &capturingPublisher{})

			failures, err := worker.HandleBatch(context.Background(), batchOf(t, 10))

			if err == nil {
				t.Fatal("a storage failure was reported as success; the offsets would " +
					"commit and the events would be unrecoverable")
			}
			if len(failures) != 0 {
				t.Error("a storage failure dead-lettered records that are not at fault")
			}
		})
	}
}

// A forward failure must also fail the batch: correlation is downstream of a durable
// write, but the offset must not advance past events the next stage never saw.
func TestAForwardFailureFailsTheBatch(t *testing.T) {
	pub := &capturingPublisher{err: errors.New("broker unavailable")}
	worker := newBatchWorker(t, &countingStore{}, &stubTenants{}, pub)

	if _, err := worker.HandleBatch(context.Background(), batchOf(t, 5)); err == nil {
		t.Error("a failed forward was reported as success")
	}
}

// The raw event is stored BEFORE normalization is attempted, so a parser bug costs
// only the derived view and never the vendor's original bytes (FR-005).
func TestRawIsStoredEvenWhenNormalizationFails(t *testing.T) {
	store := &countingStore{}
	worker := newBatchWorker(t, store, &stubTenants{}, &capturingPublisher{})

	// An envelope whose payload the adapter cannot parse.
	broken, err := json.Marshal(ingest.Envelope{
		TenantID: batchTenant, FeedID: batchFeed, Vendor: vendors.Cloudflare,
		EventID: "broken-1", ReceivedAt: time.Now().UTC(),
		Payload: []byte(`{"not":"a cloudflare record"}`),
		Format:  string(vendors.FormatNDJSON), BatchID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}

	records := append(batchOf(t, 3), stream.Record{Key: []byte("broken-1"), Value: broken})

	failures, err := worker.HandleBatch(context.Background(), records)
	if err != nil {
		t.Fatalf("HandleBatch: %v", err)
	}

	if len(store.raw) != 4 {
		t.Errorf("stored %d raw events, want all 4 including the unparseable one",
			len(store.raw))
	}
	// It is REJECTED (recorded with a reason), not dead-lettered: the raw bytes are
	// already safe, and retrying would fail identically every time.
	if len(store.rejected) != 1 {
		t.Errorf("%d rejected events, want the one that could not be normalized",
			len(store.rejected))
	}
	if len(failures) != 0 {
		t.Errorf("%d dead-lettered records; an unparseable payload belongs in "+
			"rejected_events where the feed's rejected view can show it", len(failures))
	}
}

// An undecodable ENVELOPE is our own bug rather than the vendor's, so it is
// dead-lettered to be visible rather than retried forever — and it must not take the
// rest of the batch down with it.
func TestAnUndecodableEnvelopeIsDeadLetteredAlone(t *testing.T) {
	store := &countingStore{}
	worker := newBatchWorker(t, store, &stubTenants{}, &capturingPublisher{})

	records := batchOf(t, 3)
	records = append(records, stream.Record{Key: []byte("junk"), Value: []byte("{not json")})

	failures, err := worker.HandleBatch(context.Background(), records)
	if err != nil {
		t.Fatalf("HandleBatch: %v", err)
	}

	if len(failures) != 1 {
		t.Fatalf("%d failures, want the single undecodable record", len(failures))
	}
	if failures[0].Index != 3 {
		t.Errorf("failure reported at index %d, want 3 — a wrong index dead-letters "+
			"an innocent record and drops the guilty one", failures[0].Index)
	}
	if len(store.normalized) != 3 {
		t.Errorf("stored %d normalized events, want the 3 good ones", len(store.normalized))
	}
}

// Redaction still applies on the batch path: a masked field must never be written in
// readable form (FR-037).
func TestRedactionAppliesOnTheBatchPath(t *testing.T) {
	store := &countingStore{}
	worker := newBatchWorker(t, store, &stubTenants{redacted: []string{"user_agent"}},
		&capturingPublisher{})

	if _, err := worker.HandleBatch(context.Background(), batchOf(t, 5)); err != nil {
		t.Fatalf("HandleBatch: %v", err)
	}

	for _, event := range store.normalized {
		if event.UserAgent == "curl/8.0" {
			t.Fatal("a redacted field was stored in readable form")
		}
	}
}

// An empty fetch must not issue writes.
func TestAnEmptyBatchDoesNothing(t *testing.T) {
	store := &countingStore{}
	worker := newBatchWorker(t, store, &stubTenants{}, &capturingPublisher{})

	failures, err := worker.HandleBatch(context.Background(), nil)
	if err != nil {
		t.Fatalf("HandleBatch: %v", err)
	}
	if len(failures) != 0 || store.rawCalls != 0 {
		t.Error("an empty batch issued writes")
	}
}
