package normalize

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/data/stream"
	"github.com/menta2k/siem/internal/ingest"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/tenancy"
	"github.com/menta2k/siem/internal/vendors"
)

// maxEventAge bounds how old an event may be and still be accepted.
//
// This is the now-relative check the adapters cannot make, since they must stay pure.
// An event older than the retention window would be written into a partition that the
// retention job is about to drop, which wastes the write and confuses the operator
// looking for it afterwards.
const (
	maxEventAge    = 90 * 24 * time.Hour
	maxEventFuture = 5 * time.Minute
)

// EventStore is the storage surface the worker writes through.
type EventStore interface {
	InsertRaw(ctx context.Context, events []chdata.RawEvent) error
	InsertNormalized(ctx context.Context, events []chdata.NormalizedEvent) error
	InsertRejected(ctx context.Context, events []chdata.RejectedEvent) error
}

// TenantSettings supplies the per-tenant redaction policy.
type TenantSettings interface {
	GetByID(ctx context.Context, tenantID uuid.UUID) (chdata.Tenant, error)
}

// DriftReporter records schema-drift observations (FR-012).
type DriftReporter interface {
	Observe(ctx context.Context, tenantID, feedID uuid.UUID, total, withUnknown int, fields []string)
}

// Publisher forwards normalized events to the correlation stage.
type Publisher interface {
	Publish(ctx context.Context, topic string, records []stream.Record) error
}

// Worker consumes raw envelopes, normalizes them, and writes them to storage.
type Worker struct {
	registry  *vendors.Registry
	store     EventStore
	tenants   TenantSettings
	drift     DriftReporter
	publisher Publisher
	topic     string
	log       mw.Logger
}

// NewWorker constructs the worker.
func NewWorker(
	registry *vendors.Registry, store EventStore, tenants TenantSettings,
	drift DriftReporter, publisher Publisher, topic string, log mw.Logger,
) *Worker {
	return &Worker{
		registry: registry, store: store, tenants: tenants, drift: drift,
		publisher: publisher, topic: topic, log: log,
	}
}

// Name identifies the worker in logs and metrics.
func (w *Worker) Name() string { return "normalizer" }

// Handle processes one envelope from the raw topic.
//
// The write order is deliberate and load-bearing: the RAW event is written first,
// before parsing is attempted. If normalization then fails, the vendor's original
// bytes are already safe in storage and the failure costs only the derived view
// (FR-005). Writing normalized-first would mean a parser bug loses the evidence.
func (w *Worker) Handle(ctx context.Context, record stream.Record) error {
	var envelope ingest.Envelope
	if err := json.Unmarshal(record.Value, &envelope); err != nil {
		// An undecodable envelope is our own bug, not the vendor's. Dead-letter it so
		// it is visible rather than silently retried forever.
		return fmt.Errorf("decode envelope: %w", err)
	}

	ctx = tenancy.WithTenant(ctx, tenancy.Tenant{ID: envelope.TenantID})

	rawEvent := chdata.RawEvent{
		TenantID: envelope.TenantID, FeedID: envelope.FeedID, Vendor: envelope.Vendor,
		EventID: envelope.EventID, ReceivedAt: envelope.ReceivedAt,
		Payload: envelope.Payload, Format: envelope.Format, BatchID: envelope.BatchID,
	}
	if err := w.store.InsertRaw(ctx, []chdata.RawEvent{rawEvent}); err != nil {
		// Storage is unavailable. Returning an error leaves the offset uncommitted so
		// the event is retried — losing it here would break the promise the 202 made.
		return fmt.Errorf("store raw event %s: %w", envelope.EventID, err)
	}

	normalized, err := w.normalize(ctx, envelope)
	if err != nil {
		return w.reject(ctx, envelope, err)
	}

	if err := w.store.InsertNormalized(ctx, []chdata.NormalizedEvent{normalized}); err != nil {
		return fmt.Errorf("store normalized event %s: %w", envelope.EventID, err)
	}

	return w.forward(ctx, normalized)
}

// normalize maps the envelope onto the common model and applies tenant policy.
func (w *Worker) normalize(
	ctx context.Context, envelope ingest.Envelope,
) (chdata.NormalizedEvent, error) {
	adapter, err := w.registry.Get(envelope.Vendor)
	if err != nil {
		return chdata.NormalizedEvent{}, err
	}

	record := vendors.RawRecord{Bytes: envelope.Payload, Format: vendors.Format(envelope.Format)}
	records, err := adapter.Parse(envelope.Payload, record.Format)
	if err != nil || len(records) == 0 {
		return chdata.NormalizedEvent{}, fmt.Errorf("reparse event: %w", err)
	}

	event, err := adapter.Normalize(records[0])
	if err != nil {
		return chdata.NormalizedEvent{}, err
	}
	if err := checkEventAge(event.EventTime, envelope.ReceivedAt); err != nil {
		return chdata.NormalizedEvent{}, err
	}

	tenant, err := w.tenants.GetByID(ctx, envelope.TenantID)
	if err != nil {
		return chdata.NormalizedEvent{}, fmt.Errorf("load tenant policy: %w", err)
	}

	// Redaction happens BEFORE the row is built, so a masked field is never written
	// in readable form anywhere (FR-037).
	event = Redact(event, tenant.RedactedFields)

	w.drift.Observe(ctx, envelope.TenantID, envelope.FeedID, 1,
		boolToInt(len(event.UnknownFields) > 0), event.UnknownFields)

	return toRow(envelope, event), nil
}

// reject dead-letters an event that cannot be normalized.
//
// The raw event is already stored, so nothing is lost — this records WHY the derived
// view is missing, which is what makes the dead-letter view actionable (FR-006).
func (w *Worker) reject(ctx context.Context, envelope ingest.Envelope, cause error) error {
	rejected := chdata.RejectedEvent{
		TenantID: envelope.TenantID, FeedID: envelope.FeedID, Vendor: envelope.Vendor,
		RejectedAt:   time.Now().UTC(),
		ReasonCode:   string(classifyRejection(cause)),
		ReasonDetail: cause.Error(),
		Payload:      envelope.Payload,
		BatchID:      envelope.BatchID,
	}

	if err := w.store.InsertRejected(ctx, []chdata.RejectedEvent{rejected}); err != nil {
		return fmt.Errorf("store rejected event %s: %w", envelope.EventID, err)
	}

	w.log.Warn(ctx, "event rejected during normalization",
		"event_id", envelope.EventID, "vendor", envelope.Vendor,
		"reason", rejected.ReasonCode)

	// The event is accounted for, so the offset may advance. Returning an error here
	// would retry an event that will fail identically every time.
	return nil
}

// forward publishes the normalized event to the correlation stage.
func (w *Worker) forward(ctx context.Context, event chdata.NormalizedEvent) error {
	if w.publisher == nil {
		return nil
	}

	encoded, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode normalized event %s: %w", event.EventID, err)
	}

	return w.publisher.Publish(ctx, w.topic, []stream.Record{{
		Key:   []byte(event.EventID),
		Value: encoded,
		Headers: map[string]string{
			"tenant_id": event.TenantID.String(),
			"vendor":    event.Vendor,
		},
	}})
}

// checkEventAge applies the now-relative bound the adapters cannot.
func checkEventAge(eventTime, receivedAt time.Time) error {
	if eventTime.Before(receivedAt.Add(-maxEventAge)) {
		return fmt.Errorf("%w: event is older than the %s retention window",
			errTimestampRange, maxEventAge)
	}
	if eventTime.After(receivedAt.Add(maxEventFuture)) {
		return fmt.Errorf("%w: event is dated in the future", errTimestampRange)
	}
	return nil
}

var errTimestampRange = errors.New("timestamp out of range")

// classifyRejection maps a failure to a dead-letter reason code.
func classifyRejection(err error) ingest.RejectionCode {
	switch {
	case errors.Is(err, errTimestampRange),
		errors.Is(err, vendors.ErrTimestampImplausible):
		return ingest.ReasonTimestampOutOfRange
	case errors.Is(err, vendors.ErrUnparseable):
		return ingest.ReasonParseError
	default:
		return ingest.ReasonParseError
	}
}

// toRow projects a common-model event onto its storage row.
func toRow(envelope ingest.Envelope, event vendors.Event) chdata.NormalizedEvent {
	return chdata.NormalizedEvent{
		TenantID:          envelope.TenantID,
		EventID:           envelope.EventID,
		EventTime:         event.EventTime,
		EventTimeOriginal: event.EventTimeOriginal,
		ReceivedAt:        envelope.ReceivedAt,

		Vendor:          event.Vendor,
		FeedID:          envelope.FeedID,
		VendorAccount:   event.VendorAccount,
		VendorRequestID: event.VendorRequestID,

		ClientIP:       event.ClientIP,
		ClientIPShared: event.ClientIPShared,
		ClientASN:      event.ClientASN,
		ClientCountry:  event.ClientCountry,

		RequestHost:   event.RequestHost,
		RequestPath:   event.RequestPath,
		RequestQuery:  event.RequestQuery,
		RequestMethod: event.RequestMethod,
		UserAgent:     event.UserAgent,
		HTTPStatus:    event.HTTPStatus,

		Verdict:       event.Verdict,
		VerdictReason: event.VerdictReason,
		RuleID:        event.RuleID,
		RuleIDs:       event.RuleIDs,
		Score:         event.Score,
		ScoreKind:     event.ScoreKind,

		RawExtra:      event.RawExtra,
		UnknownFields: event.UnknownFields,
		// Version 1 on first write. A reprocessing pass increments it, and
		// ReplacingMergeTree keeps the newest.
		IngestVersion: uint64(envelope.ReceivedAt.UnixNano()), //nolint:gosec // monotonic
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
