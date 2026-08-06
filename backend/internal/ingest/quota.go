package ingest

import (
	"context"
	"fmt"
	"time"
)

// Counter is the shared counting primitive quotas need.
//
// IncrBy rather than Incr: quotas are expressed in events and bytes, so they must
// accumulate by the actual amount delivered. Counting requests would let one
// 50,000-event delivery consume the same budget as a single event.
type Counter interface {
	IncrBy(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error)
}

// QuotaDecision reports whether a delivery may proceed.
type QuotaDecision struct {
	Allowed bool
	// RetryAfter tells the vendor when to come back. A 429 without it invites an
	// immediate retry, which makes the overload worse.
	RetryAfter time.Duration
	// Reason explains the refusal, for the response and the metric label.
	Reason string
}

// QuotaEnforcer applies per-feed event-rate and daily-byte limits.
//
// This is distinct from the API rate limiter: that one bounds requests, this one
// bounds ingested VOLUME, which is what a customer is actually provisioned for. A
// vendor can deliver 50,000 events in one request and stay under any request limit.
type QuotaEnforcer struct {
	counter Counter
}

// NewQuotaEnforcer constructs an enforcer.
func NewQuotaEnforcer(counter Counter) *QuotaEnforcer {
	return &QuotaEnforcer{counter: counter}
}

// Check charges a delivery against the feed's quotas.
//
// Like the rate limiter, it fails OPEN on a counter error: a Redis outage must not
// stop a customer's log ingestion. The broker's own backpressure and the per-feed
// health metrics remain as the backstop, and the error is returned so the caller can
// record the degradation rather than let it pass silently.
func (q *QuotaEnforcer) Check(
	ctx context.Context, feedID string, eventCount int, byteCount int64,
	eventsPerSec uint32, bytesPerDay uint64,
) (QuotaDecision, error) {
	if eventsPerSec > 0 {
		decision, err := q.checkEventRate(ctx, feedID, eventCount, eventsPerSec)
		if err != nil || !decision.Allowed {
			return decision, err
		}
	}

	if bytesPerDay > 0 {
		decision, err := q.checkDailyBytes(ctx, feedID, byteCount, bytesPerDay)
		if err != nil || !decision.Allowed {
			return decision, err
		}
	}

	return QuotaDecision{Allowed: true}, nil
}

func (q *QuotaEnforcer) checkEventRate(
	ctx context.Context, feedID string, eventCount int, limit uint32,
) (QuotaDecision, error) {
	// A one-second fixed window. A sliding window would cost several Redis round
	// trips per delivery, which at 15k events/sec would itself become the bottleneck.
	bucket := time.Now().UTC().Unix()
	key := fmt.Sprintf("quota:events:%s:%d", feedID, bucket)

	total, err := q.counter.IncrBy(ctx, key, int64(eventCount), 2*time.Second)
	if err != nil {
		return QuotaDecision{Allowed: true},
			fmt.Errorf("event-rate quota for feed %s: %w", feedID, err)
	}

	if total > int64(limit) {
		return QuotaDecision{
			Allowed:    false,
			RetryAfter: time.Second,
			Reason:     fmt.Sprintf("feed exceeds its limit of %d events/sec", limit),
		}, nil
	}
	return QuotaDecision{Allowed: true}, nil
}

func (q *QuotaEnforcer) checkDailyBytes(
	ctx context.Context, feedID string, byteCount int64, limit uint64,
) (QuotaDecision, error) {
	day := time.Now().UTC().Format("2006-01-02")
	key := fmt.Sprintf("quota:bytes:%s:%s", feedID, day)

	total, err := q.counter.IncrBy(ctx, key, byteCount, 25*time.Hour)
	if err != nil {
		return QuotaDecision{Allowed: true},
			fmt.Errorf("byte quota for feed %s: %w", feedID, err)
	}

	// The running daily total is what the limit applies to, not this one delivery.
	if total > 0 && uint64(total) > limit {
		return QuotaDecision{
			Allowed: false,
			// Back off until the next UTC day, when the budget resets.
			RetryAfter: untilNextDay(),
			Reason:     fmt.Sprintf("feed exceeds its daily limit of %d bytes", limit),
		}, nil
	}
	return QuotaDecision{Allowed: true}, nil
}

// untilNextDay returns the time remaining until the UTC day rolls over.
func untilNextDay() time.Duration {
	now := time.Now().UTC()
	next := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1)
	return next.Sub(now)
}
