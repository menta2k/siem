package normalize

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/data/stream"
	"github.com/menta2k/siem/internal/ingest"
	"github.com/menta2k/siem/internal/tenancy"
	"github.com/menta2k/siem/internal/vendors"
)

// HandleBatch normalizes a whole fetch in one pass.
//
// This is the throughput path, and the shape is dictated by what actually costs time:
// a ClickHouse insert is a round trip whose latency barely changes between one row and
// a thousand. Handling records one at a time therefore pays the full round trip per
// event — and with the ingest profile's `wait_for_async_insert`, each of those blocks
// on the server's async buffer flush, capping the pipeline at single-digit events per
// second. One insert per batch removes that ceiling without weakening anything.
//
// The write ORDER from the single-record path is preserved exactly, because it is
// load-bearing: every raw event is stored BEFORE any normalization is attempted, so a
// parser bug costs only the derived view and never the vendor's original bytes
// (FR-005).
//
// The durability contract is preserved too. A storage failure returns an error for the
// whole batch, leaving offsets uncommitted so every record is retried; only events that
// are individually unprocessable come back as failures to be dead-lettered.
func (w *Worker) HandleBatch(
	ctx context.Context, records []stream.Record,
) ([]stream.RecordFailure, error) {
	decoded, failures := decodeEnvelopes(records)
	if len(decoded) == 0 {
		return failures, nil
	}

	// Raw first, in one insert. If this fails the batch is retried whole: nothing has
	// been written and nothing may be acknowledged.
	if err := w.store.InsertRaw(ctx, rawEvents(decoded)); err != nil {
		return nil, fmt.Errorf("store %d raw events: %w", len(decoded), err)
	}

	normalized, rejected := w.normalizeBatch(ctx, decoded)

	if err := w.store.InsertNormalized(ctx, normalized); err != nil {
		return nil, fmt.Errorf("store %d normalized events: %w", len(normalized), err)
	}

	// Rejections are stored, not dead-lettered: the raw event is already safe, and
	// this records WHY the derived view is missing so the feed's rejected view can
	// show it (FR-006). Their offsets advance — retrying would fail identically.
	if err := w.store.InsertRejected(ctx, rejected); err != nil {
		return nil, fmt.Errorf("store %d rejected events: %w", len(rejected), err)
	}

	if err := w.forwardBatch(ctx, normalized); err != nil {
		return nil, err
	}
	return failures, nil
}

// envelope pairs a decoded envelope with its position in the batch, so a failure can
// be reported against the right record.
type envelope struct {
	index int
	value ingest.Envelope
}

// decodeEnvelopes parses every record, separating the unreadable ones.
func decodeEnvelopes(records []stream.Record) ([]envelope, []stream.RecordFailure) {
	decoded := make([]envelope, 0, len(records))
	var failures []stream.RecordFailure

	for i, record := range records {
		var value ingest.Envelope
		if err := json.Unmarshal(record.Value, &value); err != nil {
			// An undecodable envelope is our own bug, not the vendor's, so it is
			// dead-lettered to be visible rather than retried forever.
			failures = append(failures, stream.RecordFailure{
				Index: i, Cause: fmt.Errorf("decode envelope: %w", err),
			})
			continue
		}
		decoded = append(decoded, envelope{index: i, value: value})
	}
	return decoded, failures
}

func rawEvents(decoded []envelope) []chdata.RawEvent {
	out := make([]chdata.RawEvent, 0, len(decoded))
	for _, e := range decoded {
		out = append(out, chdata.RawEvent{
			TenantID: e.value.TenantID, FeedID: e.value.FeedID, Vendor: e.value.Vendor,
			EventID: e.value.EventID, ReceivedAt: e.value.ReceivedAt,
			Payload: e.value.Payload, Format: e.value.Format, BatchID: e.value.BatchID,
		})
	}
	return out
}

// normalizeBatch maps every envelope onto the common model.
//
// Tenant policy is looked up once per tenant rather than once per event. A batch is
// usually one feed's delivery and therefore one tenant, so this turns what would be
// thousands of identical reads into a single one.
func (w *Worker) normalizeBatch(
	ctx context.Context, decoded []envelope,
) ([]chdata.NormalizedEvent, []chdata.RejectedEvent) {
	normalized := make([]chdata.NormalizedEvent, 0, len(decoded))
	var rejected []chdata.RejectedEvent

	policies := newPolicyCache(w.tenants)
	drift := map[driftKey]int{}

	for _, e := range decoded {
		scoped := tenancy.WithTenant(ctx, tenancy.Tenant{ID: e.value.TenantID})

		event, unrecognized, err := w.normalizeOne(scoped, e.value, policies)
		if err != nil {
			rejected = append(rejected, chdata.RejectedEvent{
				TenantID: e.value.TenantID, FeedID: e.value.FeedID,
				Vendor: e.value.Vendor, RejectedAt: time.Now().UTC(),
				ReasonCode:   string(classifyRejection(err)),
				ReasonDetail: err.Error(),
				Payload:      e.value.Payload,
				BatchID:      e.value.BatchID,
			})
			continue
		}
		if unrecognized {
			drift[driftKey{e.value.TenantID, e.value.FeedID}]++
		}
		normalized = append(normalized, event)
	}

	w.recordDrift(ctx, drift)

	if len(rejected) > 0 {
		w.log.Warn(ctx, "events rejected during normalization",
			"count", len(rejected), "batch", len(decoded))
	}
	return normalized, rejected
}

// driftKey buckets the batch's drift tally by the feed it belongs to. A batch can carry
// events from several feeds, and attributing them all to one would blame the wrong
// customer for another's vendor change.
type driftKey struct {
	tenantID uuid.UUID
	feedID   uuid.UUID
}

// recordDrift carries the batch's unrecognized-field tally into feed health.
//
// ONLY that counter is set. events_received is recorded by the INGEST service for the
// same feed and minute, and feed_health is a SummingMergeTree — writing it again here
// would double every feed's throughput figure. The two writes land in the same bucket
// and sum, which is what makes DriftWarning's ratio of one to the other meaningful.
//
// Nothing is written for a clean batch. A row of zeroes would say the same as no row at
// all while adding a write per batch per feed, forever.
func (w *Worker) recordDrift(ctx context.Context, drift map[driftKey]int) {
	if w.health == nil {
		return
	}
	for key, count := range drift {
		if count <= 0 {
			continue
		}
		w.health.Record(ctx, ingest.HealthSample{
			TenantID: key.tenantID, FeedID: key.feedID,
			UnknownFieldEvents: count,
			// True because this write says nothing about the credential. The column is a
			// min() aggregate, so a false recorded by ingest in the same minute still
			// wins — claiming validity here cannot mask a failure there.
			CredentialValid: true,
		})
	}
}

// normalizeOne applies the adapter and the tenant's redaction policy.
// normalizeOne reports whether the adapter met fields it did not recognise, alongside
// the row. The row itself cannot carry that: migration 0006 dropped unknown_fields from
// normalized_events, so the only place the answer exists is here, between the adapter
// returning it and the row being built without it.
func (w *Worker) normalizeOne(
	ctx context.Context, value ingest.Envelope, policies *policyCache,
) (chdata.NormalizedEvent, bool, error) {
	adapter, err := w.registry.Get(value.Vendor)
	if err != nil {
		return chdata.NormalizedEvent{}, false, err
	}

	records, err := adapter.Parse(value.Payload, vendors.Format(value.Format))
	if err != nil || len(records) == 0 {
		return chdata.NormalizedEvent{}, false, fmt.Errorf("reparse event: %w", err)
	}

	event, err := adapter.Normalize(records[0])
	if err != nil {
		return chdata.NormalizedEvent{}, false, err
	}
	if err := checkEventAge(event.EventTime, value.ReceivedAt); err != nil {
		return chdata.NormalizedEvent{}, false, err
	}

	redactedFields, err := policies.redactedFields(ctx, value.TenantID)
	if err != nil {
		return chdata.NormalizedEvent{}, false, fmt.Errorf("load tenant policy: %w", err)
	}

	// Redaction happens BEFORE the row is built, so a masked field is never written in
	// readable form anywhere (FR-037).
	event = Redact(event, redactedFields)

	unrecognized := len(event.UnknownFields) > 0
	w.drift.Observe(ctx, value.TenantID, value.FeedID, 1,
		boolToInt(unrecognized), event.UnknownFields)

	return toRow(value, event), unrecognized, nil
}

// forwardBatch publishes every normalized event to the correlation stage in one call.
func (w *Worker) forwardBatch(ctx context.Context, events []chdata.NormalizedEvent) error {
	if w.publisher == nil || len(events) == 0 {
		return nil
	}

	records := make([]stream.Record, 0, len(events))
	for _, event := range events {
		encoded, err := json.Marshal(event)
		if err != nil {
			// The event is already stored; failing the batch over an encoding error
			// would retry a write that already succeeded. Skip the forward instead —
			// correlation is derived and can be rebuilt, storage cannot.
			w.log.Error(ctx, "normalize: could not encode a normalized event for correlation",
				"event_id", event.EventID, "error", err)
			continue
		}
		records = append(records, stream.Record{
			Key:   []byte(event.EventID),
			Value: encoded,
			Headers: map[string]string{
				"tenant_id": event.TenantID.String(),
				"vendor":    event.Vendor,
			},
		})
	}

	if err := w.publisher.Publish(ctx, w.topic, records); err != nil {
		return fmt.Errorf("forward %d normalized events: %w", len(records), err)
	}
	return nil
}

// policyCache reads each tenant's redaction policy once per batch.
type policyCache struct {
	tenants TenantSettings
	byID    map[uuid.UUID][]string
}

func newPolicyCache(tenants TenantSettings) *policyCache {
	return &policyCache{tenants: tenants, byID: map[uuid.UUID][]string{}}
}

func (c *policyCache) redactedFields(ctx context.Context, tenantID uuid.UUID) ([]string, error) {
	if fields, ok := c.byID[tenantID]; ok {
		return fields, nil
	}

	tenant, err := c.tenants.GetByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	c.byID[tenantID] = tenant.RedactedFields
	return tenant.RedactedFields, nil
}
