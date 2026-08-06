package normalize

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/data/stream"
	"github.com/menta2k/siem/internal/ingest"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/tenancy"
)

// DeadLetterWorker drains the dead-letter topic into the rejected_events table.
//
// Without it, an event rejected AT THE RECEIVER — a malformed line, an unparseable
// timestamp — is published to the dead-letter topic and goes no further. It never
// reaches storage, so `GET /feeds/{id}/rejected` cannot show it and FR-006's promise
// that nothing is dropped silently holds only for failures that happen later in the
// pipeline. This worker closes that gap.
//
// It is deliberately separate from the normalization worker: the two consume
// different topics and must be able to fall behind independently. A backlog of
// malformed records must never delay good events.
type DeadLetterWorker struct {
	store EventStore
	log   mw.Logger
}

// NewDeadLetterWorker constructs the worker.
func NewDeadLetterWorker(store EventStore, log mw.Logger) *DeadLetterWorker {
	return &DeadLetterWorker{store: store, log: log}
}

// Name identifies the worker in logs and metrics.
func (w *DeadLetterWorker) Name() string { return "dead-letter" }

// Handle writes one dead-lettered envelope to the rejected_events table.
func (w *DeadLetterWorker) Handle(ctx context.Context, record stream.Record) error {
	var envelope ingest.Envelope
	if err := json.Unmarshal(record.Value, &envelope); err != nil {
		// The dead-letter topic is the end of the line: there is nowhere further to
		// park an entry we cannot read. Returning an error would retry it forever, so
		// it is logged loudly and the offset advances.
		w.log.Error(ctx, "undecodable dead-letter envelope, dropping",
			"cause", err.Error())
		return nil
	}

	ctx = tenancy.WithTenant(ctx, tenancy.Tenant{ID: envelope.TenantID})

	rejected := clickhouse.RejectedEvent{
		TenantID: envelope.TenantID,
		FeedID:   envelope.FeedID,
		Vendor:   envelope.Vendor,
		// The receipt time, not now: the operator wants to know when the vendor sent
		// the bad record, not when the worker happened to drain the backlog.
		RejectedAt:   rejectedAt(envelope),
		ReasonCode:   reasonCode(record),
		ReasonDetail: record.Headers["reason_detail"],
		Payload:      envelope.Payload,
		BatchID:      envelope.BatchID,
	}

	if err := w.store.InsertRejected(ctx, []clickhouse.RejectedEvent{rejected}); err != nil {
		// Storage is unavailable. Retrying is correct here: the rejection record is
		// the only trace this event ever existed in a queryable form.
		return fmt.Errorf("store dead-lettered event %s: %w", envelope.EventID, err)
	}
	return nil
}

func rejectedAt(envelope ingest.Envelope) time.Time {
	if envelope.ReceivedAt.IsZero() {
		return time.Now().UTC()
	}
	return envelope.ReceivedAt
}

// reasonCode reads the code the publisher set, falling back to a parse error rather
// than an empty string — a rejection with no reason is not actionable.
func reasonCode(record stream.Record) string {
	if code := record.Headers["reason_code"]; code != "" {
		return code
	}
	return string(ingest.ReasonParseError)
}
