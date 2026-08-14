package normalize_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/data/stream"
	"github.com/menta2k/siem/internal/ingest"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/normalize"
	"github.com/menta2k/siem/internal/vendors"
	"github.com/menta2k/siem/internal/vendors/cloudflare"
	"github.com/menta2k/siem/internal/vendors/datadome"
	"github.com/menta2k/siem/internal/vendors/f5"
)

// recordingHealth captures what the normalizer counted, which is the whole subject of
// these tests: the counter had a consumer, a column and a warning built on it, and no
// producer anywhere.
type recordingHealth struct {
	samples []ingest.HealthSample
}

func (r *recordingHealth) Record(_ context.Context, sample ingest.HealthSample) {
	r.samples = append(r.samples, sample)
}

// driftingRecord builds a Cloudflare envelope carrying a field no adapter maps, which
// is what "schema drift" means in practice: the vendor started sending something new.
func driftingRecord(t *testing.T, rayID string, at time.Time, feedID uuid.UUID) stream.Record {
	t.Helper()

	payload, err := json.Marshal(map[string]any{
		"RayID":               rayID,
		"EdgeStartTimestamp":  at.Format(time.RFC3339Nano),
		"ClientIP":            "203.0.113.10",
		"ClientRequestHost":   "shop.example.com",
		"ClientRequestPath":   "/checkout",
		"ClientRequestMethod": "GET",
		"EdgeResponseStatus":  200,
		"SecurityAction":      "allow",
		"SomeBrandNewFieldV9": "surprise",
	})
	if err != nil {
		t.Fatalf("encode payload: %v", err)
	}

	envelope, err := json.Marshal(ingest.Envelope{
		TenantID: batchTenant, FeedID: feedID, Vendor: vendors.Cloudflare,
		EventID: rayID, ReceivedAt: at, Payload: payload,
		Format: string(vendors.FormatNDJSON), BatchID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
	return stream.Record{Key: []byte(rayID), Value: envelope}
}

func healthWorker(t *testing.T, health normalize.HealthRecorder) *normalize.Worker {
	t.Helper()

	registry, err := vendors.NewRegistry(cloudflare.New(), f5.New(), datadome.New())
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	return normalize.NewWorker(registry, &countingStore{}, &stubTenants{},
		normalize.NewDriftDetector(nil), &capturingPublisher{}, "siem.events.normalized",
		mw.NewLogger("error", "json")).WithHealth(health)
}

// THE BUG THIS CATCHES. feed_health.unknown_field_events had a column, an aggregator, a
// SummingMergeTree behind it and a DriftWarning helper reading it — and no producer at
// all. Every feed of every vendor reported a drift ratio of exactly zero, so the FR-012
// warning could not fire however far a vendor's schema moved.
func TestUnrecognizedFieldsReachFeedHealth(t *testing.T) {
	health := &recordingHealth{}
	worker := healthWorker(t, health)

	at := time.Now().UTC().Add(-time.Minute)
	_, err := worker.HandleBatch(context.Background(), []stream.Record{
		driftingRecord(t, "ray-drift-1", at, batchFeed),
		driftingRecord(t, "ray-drift-2", at, batchFeed),
	})
	if err != nil {
		t.Fatalf("HandleBatch: %v", err)
	}

	if len(health.samples) != 1 {
		t.Fatalf("health samples = %d, want one per feed per batch", len(health.samples))
	}
	sample := health.samples[0]
	if sample.UnknownFieldEvents != 2 {
		t.Errorf("UnknownFieldEvents = %d, want 2", sample.UnknownFieldEvents)
	}
	if sample.FeedID != batchFeed || sample.TenantID != batchTenant {
		t.Errorf("sample attributed to tenant %s feed %s", sample.TenantID, sample.FeedID)
	}
}

// THE OTHER HALF OF THE SAME BUG, and the one that would do damage. feed_health is a
// SummingMergeTree and the INGEST service already records events_received for the same
// feed and minute. If the normalizer recorded it too, every feed's throughput would
// silently double — and DriftWarning divides one by the other, so the ratio it exists
// to compute would be halved at the same time.
func TestTheNormalizerDoesNotRecountThroughput(t *testing.T) {
	health := &recordingHealth{}
	worker := healthWorker(t, health)

	at := time.Now().UTC().Add(-time.Minute)
	if _, err := worker.HandleBatch(context.Background(), []stream.Record{
		driftingRecord(t, "ray-drift-3", at, batchFeed),
	}); err != nil {
		t.Fatalf("HandleBatch: %v", err)
	}

	for _, sample := range health.samples {
		if sample.EventsReceived != 0 {
			t.Errorf("EventsReceived = %d, want 0 — ingest already counts it",
				sample.EventsReceived)
		}
		if sample.BytesReceived != 0 || sample.EventsRejected != 0 ||
			sample.DuplicatesSuppressed != 0 || sample.EventsFiltered != 0 {
			t.Errorf("the normalizer recorded a counter ingest owns: %+v", sample)
		}
	}
}

// A clean batch must write nothing. A row of zeroes says exactly what no row says while
// adding a write per batch per feed for the lifetime of the deployment.
func TestACleanBatchRecordsNoHealth(t *testing.T) {
	health := &recordingHealth{}
	worker := healthWorker(t, health)

	at := time.Now().UTC().Add(-time.Minute)
	if _, err := worker.HandleBatch(context.Background(), []stream.Record{
		cloudflareRecord(t, "ray-clean-1", at),
	}); err != nil {
		t.Fatalf("HandleBatch: %v", err)
	}

	if len(health.samples) != 0 {
		t.Errorf("health samples = %+v, want none for a batch with no drift", health.samples)
	}
}

// A batch carries events from several feeds. Attributing them all to one would blame
// the wrong customer for another's vendor change.
func TestDriftIsAttributedPerFeed(t *testing.T) {
	health := &recordingHealth{}
	worker := healthWorker(t, health)

	other := uuid.MustParse("00000000-0000-4000-8000-0000000000f9")
	at := time.Now().UTC().Add(-time.Minute)

	if _, err := worker.HandleBatch(context.Background(), []stream.Record{
		driftingRecord(t, "ray-a", at, batchFeed),
		driftingRecord(t, "ray-b", at, other),
		driftingRecord(t, "ray-c", at, other),
	}); err != nil {
		t.Fatalf("HandleBatch: %v", err)
	}

	counts := map[uuid.UUID]int{}
	for _, sample := range health.samples {
		counts[sample.FeedID] += sample.UnknownFieldEvents
	}
	if counts[batchFeed] != 1 || counts[other] != 2 {
		t.Errorf("per-feed drift = %v, want 1 and 2", counts)
	}
}

// A nil recorder must stay harmless: most call sites do not exercise this signal.
func TestNoHealthRecorderIsNotAFailure(t *testing.T) {
	registry, err := vendors.NewRegistry(cloudflare.New(), f5.New(), datadome.New())
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	worker := normalize.NewWorker(registry, &countingStore{}, &stubTenants{},
		normalize.NewDriftDetector(nil), &capturingPublisher{}, "topic",
		mw.NewLogger("error", "json"))

	at := time.Now().UTC().Add(-time.Minute)
	if _, err := worker.HandleBatch(context.Background(), []stream.Record{
		driftingRecord(t, "ray-nil", at, batchFeed),
	}); err != nil {
		t.Fatalf("HandleBatch with no health recorder: %v", err)
	}
}

// capturingLogger records the warning the sink emits.
type capturingLogger struct {
	messages []string
	args     [][]any
}

func (c *capturingLogger) Warn(_ context.Context, msg string, args ...any) {
	c.messages = append(c.messages, msg)
	c.args = append(c.args, args)
}

// THE DETECTOR WAS WIRED WITH A NIL SINK, so Observe computed the window, decided the
// threshold had been crossed, and dropped the warning. The detector was never the
// missing piece — somewhere for its answer to go was.
func TestCrossingTheThresholdReachesTheOperator(t *testing.T) {
	log := &capturingLogger{}
	detector := normalize.NewDriftDetector(normalize.LogDriftSink(log))

	tenant, feed := uuid.New(), uuid.New()
	// Well past the 1% threshold: every event carries the new field, which is what a
	// real vendor schema change looks like.
	detector.Observe(context.Background(), tenant, feed, 200, 200, []string{"NewFieldV9"})

	if len(log.messages) == 0 {
		t.Fatal("crossing the drift threshold produced no warning")
	}

	var sawFields bool
	for _, arg := range log.args[0] {
		if fields, ok := arg.([]string); ok {
			for _, f := range fields {
				if f == "NewFieldV9" {
					sawFields = true
				}
			}
		}
	}
	if !sawFields {
		// The field names are what turn "something changed" into a one-line adapter fix.
		t.Errorf("the warning did not name the drifting fields: %v", log.args[0])
	}
}

// Below the threshold nothing is reported: an occasional optional field is not drift,
// and a warning that fires on noise is one an operator learns to ignore.
func TestAnOccasionalUnknownFieldIsNotReported(t *testing.T) {
	log := &capturingLogger{}
	detector := normalize.NewDriftDetector(normalize.LogDriftSink(log))

	detector.Observe(context.Background(), uuid.New(), uuid.New(), 1000, 1, []string{"Rare"})

	if len(log.messages) != 0 {
		t.Errorf("one event in a thousand produced a warning: %v", log.messages)
	}
}

// A nil logger must not produce a sink that panics on the ingest hot path.
func TestLogDriftSinkToleratesNoLogger(t *testing.T) {
	if sink := normalize.LogDriftSink(nil); sink != nil {
		t.Error("a nil logger produced a non-nil sink")
	}
}
