// Package stream wraps Redpanda (Kafka API) as the platform's durable ingest queue.
//
// This package holds the single most important guarantee in the system: an event is
// acknowledged to a vendor ONLY after the broker has durably committed it
// (Constitution Principle II). Producers therefore run with acks=all and idempotent
// production, and Publish blocks until the broker confirms. A failed or timed-out
// publish surfaces as an error so the caller can return 503 — never a 2xx the system
// cannot honour.
package stream

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/menta2k/siem/internal/conf"
)

// Record is one message destined for a topic.
type Record struct {
	// Key drives partitioning. Using the event id keeps retries of the same event on
	// one partition, so ordering and dedup behave predictably.
	Key   []byte
	Value []byte
	// Headers carry routing metadata (tenant, vendor, feed, batch) so a consumer can
	// filter without parsing the payload.
	Headers map[string]string
}

// Producer publishes durably to Redpanda.
type Producer struct {
	client  *kgo.Client
	timeout time.Duration
}

// NewProducer opens an idempotent, acks=all producer.
func NewProducer(cfg conf.Redpanda) (*Producer, error) {
	client, err := kgo.NewClient(
		kgo.SeedBrokers(cfg.Brokers...),
		// Durability, not throughput, is the priority here.
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.ProducerBatchCompression(kgo.Lz4Compression()),
		// Idempotent production means a broker-side retry cannot duplicate a record.
		kgo.ProducerLinger(5*time.Millisecond),
		kgo.RecordRetries(5),
		kgo.RetryTimeout(cfg.ProduceTimeout),
	)
	if err != nil {
		return nil, fmt.Errorf("create redpanda producer for %v: %w", cfg.Brokers, err)
	}
	return &Producer{client: client, timeout: cfg.ProduceTimeout}, nil
}

// Publish writes every record and blocks until the broker has committed all of them.
//
// It returns an error if ANY record fails. Callers must treat a partial success as a
// total failure and let the vendor retry: duplicate delivery is absorbed by
// deduplication, whereas a false acknowledgement loses data permanently.
func (p *Producer) Publish(ctx context.Context, topic string, records []Record) error {
	if len(records) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	krecords := make([]*kgo.Record, 0, len(records))
	for _, r := range records {
		krecords = append(krecords, toKafkaRecord(topic, r))
	}

	results := p.client.ProduceSync(ctx, krecords...)
	if err := results.FirstErr(); err != nil {
		return fmt.Errorf("publish %d records to %s: %w", len(records), topic, err)
	}
	return nil
}

// Ping reports broker reachability. Used by /readyz.
func (p *Producer) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := p.client.Ping(ctx); err != nil {
		return fmt.Errorf("redpanda unreachable: %w", err)
	}
	return nil
}

// Close flushes buffered records and shuts the client down.
func (p *Producer) Close(ctx context.Context) error {
	if err := p.client.Flush(ctx); err != nil {
		return fmt.Errorf("flush redpanda producer: %w", err)
	}
	p.client.Close()
	return nil
}

// Handler processes one fetched record. Returning an error routes the record to the
// dead-letter topic rather than stalling the partition — a single poison message must
// not halt a tenant's entire feed.
type Handler func(ctx context.Context, r Record) error

// BatchHandler processes a whole fetch at once.
//
// Batching exists for throughput, and the reason is arithmetic rather than taste: a
// per-record handler that writes to ClickHouse pays one insert round trip per event.
// With the ingest profile's `wait_for_async_insert`, each of those blocks on the
// server's async buffer flush, which bounds the pipeline at single-digit events per
// second regardless of how much traffic arrives.
//
// The return convention keeps the durability guarantee intact while still letting one
// poison record be parked:
//
//	error != nil      the WHOLE batch failed (storage down). No offset is committed,
//	                  so every record is retried. Nothing is dead-lettered, because
//	                  the records are not at fault.
//	failures != nil   those specific records cannot be processed. They are
//	                  dead-lettered individually and the batch's offsets advance.
//
// A handler must not report a record as succeeded until it is durably stored, because
// the commit that follows is what makes the event unrecoverable from the topic.
type BatchHandler func(ctx context.Context, records []Record) ([]RecordFailure, error)

// RecordFailure names one record in a batch that could not be processed.
type RecordFailure struct {
	// Index is the position in the slice the handler was given.
	Index int
	// Cause is recorded on the dead-lettered record so the failure is visible.
	Cause error
}

// Consumer reads a topic as part of a consumer group.
type Consumer struct {
	client   *kgo.Client
	dlq      *Producer
	dlqTopic string
}

// NewConsumer joins a consumer group on the given topics.
func NewConsumer(
	cfg conf.Redpanda, group string, topics []string, dlq *Producer,
) (*Consumer, error) {
	client, err := kgo.NewClient(
		kgo.SeedBrokers(cfg.Brokers...),
		kgo.ConsumerGroup(group),
		kgo.ConsumeTopics(topics...),
		// Offsets commit only after a record is handled, so a crash replays rather
		// than skips. At-least-once plus idempotent event ids gives effective
		// exactly-once at the storage layer.
		kgo.DisableAutoCommit(),
		// A group with no committed offset starts at the BEGINNING, not the end.
		// The default (end) would make a newly deployed consumer group silently skip
		// every event already durably committed but not yet processed — which is
		// exactly the data loss the 202 promised would not happen. Reprocessing is
		// harmless here because event ids are idempotent.
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
		kgo.FetchMaxWait(500*time.Millisecond),
	)
	if err != nil {
		return nil, fmt.Errorf("create redpanda consumer group %s: %w", group, err)
	}
	return &Consumer{client: client, dlq: dlq, dlqTopic: cfg.TopicDLQ}, nil
}

// Run polls and dispatches until ctx is cancelled.
func (c *Consumer) Run(ctx context.Context, handle Handler) error {
	for {
		// A cancelled context is a graceful shutdown, not a failure: the worker was
		// asked to stop, so Run returns cleanly rather than propagating the
		// cancellation as an error the supervisor would log as a crash.
		if ctx.Err() != nil {
			return nil //nolint:nilerr // cancellation is the shutdown signal
		}

		fetches := c.client.PollFetches(ctx)
		if err := fetchError(fetches); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}

		if err := c.dispatch(ctx, fetches, handle); err != nil {
			return err
		}
		if err := c.client.CommitUncommittedOffsets(ctx); err != nil {
			return fmt.Errorf("commit offsets: %w", err)
		}
	}
}

// RunBatch polls and dispatches whole fetches until ctx is cancelled.
//
// Offsets are committed only after the handler reports the batch stored, so a crash
// mid-batch replays it rather than skipping it. Event ids are idempotent, so the
// replay is harmless — which is what lets at-least-once delivery stand in for
// exactly-once at the storage layer.
func (c *Consumer) RunBatch(ctx context.Context, handle BatchHandler) error {
	for {
		if ctx.Err() != nil {
			return nil //nolint:nilerr // cancellation is the shutdown signal
		}

		fetches := c.client.PollFetches(ctx)
		if err := fetchError(fetches); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}

		if err := c.dispatchBatch(ctx, fetches, handle); err != nil {
			return err
		}
		if err := c.client.CommitUncommittedOffsets(ctx); err != nil {
			return fmt.Errorf("commit offsets: %w", err)
		}
	}
}

func (c *Consumer) dispatchBatch(
	ctx context.Context, fetches kgo.Fetches, handle BatchHandler,
) error {
	var (
		records []Record
		raw     []*kgo.Record
	)
	fetches.EachRecord(func(kr *kgo.Record) {
		records = append(records, fromKafkaRecord(kr))
		raw = append(raw, kr)
	})
	if len(records) == 0 {
		return nil
	}

	failures, err := handle(ctx, records)
	if err != nil {
		// The batch as a whole failed. Returning here leaves the offsets uncommitted,
		// so every record is retried — losing them would break the promise the 202
		// already made to the vendor.
		return err
	}

	for _, failure := range failures {
		if failure.Index < 0 || failure.Index >= len(raw) {
			continue
		}
		if dlqErr := c.deadLetter(ctx, raw[failure.Index], failure.Cause); dlqErr != nil {
			// The dead-letter write itself failed, so this record is not accounted for
			// anywhere. Do not commit: retrying is the only option that does not drop it.
			return dlqErr
		}
	}
	return nil
}

func (c *Consumer) dispatch(ctx context.Context, fetches kgo.Fetches, handle Handler) error {
	var handlerErr error
	fetches.EachRecord(func(kr *kgo.Record) {
		if handlerErr != nil {
			return
		}
		if err := handle(ctx, fromKafkaRecord(kr)); err != nil {
			// A record we cannot process is dead-lettered with its reason, never
			// dropped silently (Constitution Principle II).
			if dlqErr := c.deadLetter(ctx, kr, err); dlqErr != nil {
				handlerErr = dlqErr
			}
		}
	})
	return handlerErr
}

func (c *Consumer) deadLetter(ctx context.Context, kr *kgo.Record, cause error) error {
	if c.dlq == nil {
		return fmt.Errorf("no dead-letter producer configured, cannot park record: %w", cause)
	}
	record := Record{
		Key:   kr.Key,
		Value: kr.Value,
		Headers: map[string]string{
			"dlq_reason":       cause.Error(),
			"dlq_source_topic": kr.Topic,
		},
	}
	for _, h := range kr.Headers {
		record.Headers[h.Key] = string(h.Value)
	}
	if err := c.dlq.Publish(ctx, c.dlqTopic, []Record{record}); err != nil {
		return fmt.Errorf("dead-letter record from %s: %w", kr.Topic, err)
	}
	return nil
}

// Lag reports the consumer group's total lag, which is the platform's backpressure
// and ingest-freshness signal (FR-007, FR-008).
func (c *Consumer) Lag(ctx context.Context) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := c.client.Ping(ctx); err != nil {
		return 0, fmt.Errorf("redpanda unreachable while reading lag: %w", err)
	}
	// Detailed per-partition lag is exported by the metrics worker; this reports
	// reachability plus buffered depth for readiness checks.
	return int64(c.client.BufferedFetchRecords()), nil
}

// Close leaves the consumer group cleanly.
func (c *Consumer) Close() { c.client.Close() }

func toKafkaRecord(topic string, r Record) *kgo.Record {
	kr := &kgo.Record{Topic: topic, Key: r.Key, Value: r.Value}
	for k, v := range r.Headers {
		kr.Headers = append(kr.Headers, kgo.RecordHeader{Key: k, Value: []byte(v)})
	}
	return kr
}

func fromKafkaRecord(kr *kgo.Record) Record {
	headers := make(map[string]string, len(kr.Headers))
	for _, h := range kr.Headers {
		headers[h.Key] = string(h.Value)
	}
	return Record{Key: kr.Key, Value: kr.Value, Headers: headers}
}

func fetchError(fetches kgo.Fetches) error {
	var errs []error
	fetches.EachError(func(topic string, partition int32, err error) {
		errs = append(errs, fmt.Errorf("fetch %s[%d]: %w", topic, partition, err))
	})
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// EnsureTopics creates the pipeline topics if they do not exist.
//
// Called at startup rather than relying on the broker's auto-creation, which RACES the
// first produce: the broker begins creating the topic and rejects the in-flight batch
// with UNKNOWN_TOPIC_OR_PARTITION. On the ingest path that surfaces as a 503 and a
// vendor retry — correct behaviour, but for a reason that never resolves on a fresh
// deployment, because every first delivery hits the same race.
//
// Idempotent: an already-existing topic is not an error, so this is safe to run on
// every start and from every replica.
func (p *Producer) EnsureTopics(ctx context.Context, topics ...string) error {
	admin := kadm.NewClient(p.client)

	// One partition and one replica match the single-node development broker. A real
	// deployment provisions topics through its own tooling; this exists so that a
	// fresh stack works, not to express a production topology.
	resp, err := admin.CreateTopics(ctx, 1, 1, nil, topics...)
	if err != nil {
		return fmt.Errorf("create topics: %w", err)
	}

	for _, result := range resp {
		if result.Err != nil && !errors.Is(result.Err, kerr.TopicAlreadyExists) {
			return fmt.Errorf("create topic %s: %w", result.Topic, result.Err)
		}
	}
	return nil
}
