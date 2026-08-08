// Package ingest receives vendor deliveries and commits them durably.
//
// This package makes the platform's central promise (Constitution Principle II):
// a vendor is answered 202 ONLY after the broker has confirmed the write. Every
// failure path returns a retryable status instead. A duplicate delivery is absorbed
// by deduplication; a false acknowledgement loses the event permanently.
package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/data/stream"
	"github.com/menta2k/siem/internal/ingest/filter"
	"github.com/menta2k/siem/internal/vendors"
)

// RejectionCode classifies why an event was dead-lettered (FR-006).
type RejectionCode string

// The rejection codes, matching the `reason_code` column and the ingest contract.
const (
	ReasonParseError          RejectionCode = "PARSE_ERROR"
	ReasonSchemaUnknown       RejectionCode = "SCHEMA_UNKNOWN"
	ReasonQuotaExceeded       RejectionCode = "QUOTA_EXCEEDED"
	ReasonTimestampOutOfRange RejectionCode = "TIMESTAMP_OUT_OF_RANGE"
	ReasonTenantUnknown       RejectionCode = "TENANT_UNKNOWN"
	ReasonPayloadTooLarge     RejectionCode = "PAYLOAD_TOO_LARGE"
)

// Rejection is one event that could not be accepted, reported back to the vendor and
// written to the dead-letter store.
type Rejection struct {
	// Index is the event's position in the delivered batch, so a vendor can identify
	// which record failed.
	Index      int           `json:"index"`
	ReasonCode RejectionCode `json:"reason_code"`
	// ReasonDetail explains the failure. It must never contain a secret.
	ReasonDetail string `json:"reason_detail"`
}

// Envelope is what travels on the raw topic: one event plus the routing metadata a
// consumer needs without re-parsing the payload.
type Envelope struct {
	TenantID   uuid.UUID `json:"tenant_id"`
	FeedID     uuid.UUID `json:"feed_id"`
	Vendor     string    `json:"vendor"`
	EventID    string    `json:"event_id"`
	BatchID    uuid.UUID `json:"batch_id"`
	ReceivedAt time.Time `json:"received_at"`
	Format     string    `json:"format"`
	// Payload is the vendor's bytes, verbatim (FR-005).
	Payload []byte `json:"payload"`
}

// Outcome is the result of accepting one delivery, mirroring the ingest contract's
// response body.
type Outcome struct {
	BatchID              uuid.UUID `json:"batch_id"`
	Accepted             int       `json:"accepted"`
	DuplicatesSuppressed int       `json:"duplicates_suppressed"`
	// Filtered is how many events the tenant's ingest filters excluded. Reported back
	// to the sender because a filtered event is stored nowhere: without this number a
	// vendor cannot tell "you dropped it on purpose" from "you lost it".
	Filtered int         `json:"filtered"`
	Rejected []Rejection `json:"rejected"`
}

// HasRejections reports whether any event was dead-lettered, which turns a 202 into
// a 207.
func (o Outcome) HasRejections() bool { return len(o.Rejected) > 0 }

// Producer publishes durably. Narrowed to what this package needs.
type Producer interface {
	Publish(ctx context.Context, topic string, records []stream.Record) error
}

// Publisher commits accepted events to the durable queue.
type Publisher struct {
	producer Producer
	topicRaw string
	topicDLQ string
}

// NewPublisher constructs a publisher.
func NewPublisher(producer Producer, topicRaw, topicDLQ string) *Publisher {
	return &Publisher{producer: producer, topicRaw: topicRaw, topicDLQ: topicDLQ}
}

// PublishBatch durably commits every envelope, returning an error if ANY fails.
//
// A partial success is treated as total failure on purpose. The alternative —
// acknowledging the events that made it and silently losing the rest — breaks the
// promise every 202 makes. Returning an error makes the vendor retry the whole batch,
// and deduplication absorbs the events that were already committed.
func (p *Publisher) PublishBatch(ctx context.Context, envelopes []Envelope) error {
	if len(envelopes) == 0 {
		return nil
	}

	records := make([]stream.Record, 0, len(envelopes))
	for _, envelope := range envelopes {
		encoded, err := json.Marshal(envelope)
		if err != nil {
			return fmt.Errorf("encode envelope for event %s: %w", envelope.EventID, err)
		}

		records = append(records, stream.Record{
			// Keying on the event id keeps every redelivery of one event on the same
			// partition, so ordering and deduplication behave predictably.
			Key:   []byte(envelope.EventID),
			Value: encoded,
			Headers: map[string]string{
				"tenant_id": envelope.TenantID.String(),
				"feed_id":   envelope.FeedID.String(),
				"vendor":    envelope.Vendor,
				"batch_id":  envelope.BatchID.String(),
			},
		})
	}

	if err := p.producer.Publish(ctx, p.topicRaw, records); err != nil {
		// The caller MUST translate this into a retryable 503, never a 2xx.
		return fmt.Errorf("durable commit of %d events failed: %w", len(records), err)
	}
	return nil
}

// PublishRejections parks unusable events on the dead-letter topic.
//
// A dead-letter failure is reported but must NOT fail the request: the accepted
// events are already durably committed, and forcing a retry of the whole batch to
// re-park a malformed record would be worse than losing the record's dead-letter copy
// — which is itself already counted in the rejection metrics.
func (p *Publisher) PublishRejections(
	ctx context.Context, envelopes []Envelope, rejections []Rejection,
) error {
	if len(rejections) == 0 {
		return nil
	}

	records := make([]stream.Record, 0, len(rejections))
	for _, rejection := range rejections {
		if rejection.Index < 0 || rejection.Index >= len(envelopes) {
			continue
		}
		envelope := envelopes[rejection.Index]

		encoded, err := json.Marshal(envelope)
		if err != nil {
			continue
		}
		records = append(records, stream.Record{
			Key:   []byte(envelope.EventID),
			Value: encoded,
			Headers: map[string]string{
				"tenant_id":     envelope.TenantID.String(),
				"feed_id":       envelope.FeedID.String(),
				"vendor":        envelope.Vendor,
				"reason_code":   string(rejection.ReasonCode),
				"reason_detail": rejection.ReasonDetail,
			},
		})
	}

	if err := p.producer.Publish(ctx, p.topicDLQ, records); err != nil {
		return fmt.Errorf("dead-letter %d events: %w", len(records), err)
	}
	return nil
}

// BuildEnvelopes turns parsed records into envelopes, separating those that cannot be
// normalized into rejections rather than dropping them.
//
// Normalization runs here only to derive the event identity and to detect records
// that will never be usable. The full normalized event is produced downstream by the
// processor, so a change to the common model does not require re-ingesting.
// The returned `filtered` count is the number of events excluded by the tenant's ingest
// filters. It is returned rather than logged because a filtered event leaves NO other
// trace — no payload, no row, no rejection — so this count is the only thing standing
// between an operator with a slightly too broad rule and traffic that vanishes without
// explanation.
func BuildEnvelopes(
	adapter vendors.Adapter,
	records []vendors.RawRecord,
	meta EnvelopeMeta,
) (envelopes []Envelope, rejections []Rejection, filtered int) {
	envelopes = make([]Envelope, 0, len(records))

	for i, record := range records {
		event, err := adapter.Normalize(record)
		if err != nil {
			// The record is still carried into the envelope list so its position is
			// preserved and the dead-letter copy retains the original bytes.
			envelopes = append(envelopes, Envelope{
				TenantID: meta.TenantID, FeedID: meta.FeedID, Vendor: adapter.Vendor(),
				EventID: meta.IdentityFor(adapter.Vendor(), "", record.Bytes),
				BatchID: meta.BatchID, ReceivedAt: meta.ReceivedAt,
				Format: string(record.Format), Payload: record.Bytes,
			})
			rejections = append(rejections, Rejection{
				Index:        i,
				ReasonCode:   classify(err),
				ReasonDetail: err.Error(),
			})
			continue
		}

		// Applied only to events that NORMALIZED. A parse failure has no host or path
		// for a rule to test, and dead-lettering it is the right answer — dropping what
		// we failed to understand would hide parse failures behind a volume feature.
		if meta.Filters.Drops(event) {
			filtered++
			continue
		}

		envelopes = append(envelopes, Envelope{
			TenantID: meta.TenantID, FeedID: meta.FeedID, Vendor: adapter.Vendor(),
			EventID: meta.IdentityFor(event.Vendor, event.VendorRequestID, record.Bytes),
			BatchID: meta.BatchID, ReceivedAt: meta.ReceivedAt,
			Format: string(record.Format), Payload: record.Bytes,
		})
	}

	return envelopes, rejections, filtered
}

// EnvelopeMeta carries the per-delivery context BuildEnvelopes needs.
type EnvelopeMeta struct {
	TenantID   uuid.UUID
	FeedID     uuid.UUID
	BatchID    uuid.UUID
	ReceivedAt time.Time
	// IdentityFor derives the stable event id. Injected so the identity scheme lives
	// in one place and this package stays testable without it.
	//
	// The VENDOR is an input because a vendor request id identifies a REQUEST, not a
	// record of one. Once a single feed can produce events for more than one vendor —
	// which deriving DataDome's verdict from Cloudflare's log introduced — two
	// genuinely different records legitimately share that id, and hashing it alone
	// made them collide. The deduper then read the second as a redelivery and dropped
	// it: a quarter of all received events, silently.
	IdentityFor func(vendor, vendorRequestID string, rawBytes []byte) string
	// Filters excludes events from ingestion entirely. Compiled once per delivery by
	// the caller, because the preparation is the same for every event in it.
	Filters filter.Set
}

// classify maps a normalization failure to a rejection code, so the dead-letter
// reason is actionable rather than a generic "failed".
func classify(err error) RejectionCode {
	switch {
	case err == nil:
		return ""
	case isTimestampError(err):
		return ReasonTimestampOutOfRange
	default:
		return ReasonParseError
	}
}

func isTimestampError(err error) bool {
	return errors.Is(err, vendors.ErrTimestampImplausible)
}
