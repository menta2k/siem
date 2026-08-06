package ingest

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Ingest metrics.
//
// Labelled by vendor and feed rather than by tenant: a feed already identifies its
// tenant to an operator, and adding tenant would multiply cardinality for no
// operational gain. Per-tenant questions are better answered from ClickHouse.
//
// Every alert rule in deploy/prometheus/alerts.yml reads one of these, so a rename
// here breaks alerting silently — the metric name is part of the operational contract.
var (
	EventsReceived = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "siem_ingest_events_received_total",
		Help: "Events durably committed, by vendor and feed.",
	}, []string{"vendor", "feed_id"})

	EventsRejected = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "siem_ingest_events_rejected_total",
		Help: "Events dead-lettered, by vendor, feed, and reason.",
	}, []string{"vendor", "feed_id", "reason"})

	DuplicatesSuppressed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "siem_ingest_duplicates_suppressed_total",
		Help: "Redelivered events suppressed at the ingest boundary.",
	}, []string{"vendor", "feed_id"})

	BytesReceived = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "siem_ingest_bytes_received_total",
		Help: "Payload bytes accepted, by vendor and feed.",
	}, []string{"vendor", "feed_id"})

	// PublishFailures is the signal that the durability promise is under strain.
	// Any sustained non-zero rate means vendors are being told to retry.
	PublishFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "siem_ingest_publish_failures_total",
		Help: "Durable commits that could not be confirmed, forcing a 503.",
	}, []string{"vendor", "feed_id"})

	QuotaRejections = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "siem_ingest_quota_rejections_total",
		Help: "Deliveries refused because a feed exceeded its quota.",
	}, []string{"vendor", "feed_id"})

	// LastEventTimestamp backs the FeedSilent alert. A gauge rather than a counter
	// because the alert asks "how long since", not "how many".
	LastEventTimestamp = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "siem_ingest_last_event_timestamp_seconds",
		Help: "Unix time of the most recent event accepted for a feed.",
	}, []string{"vendor", "feed_id"})

	// IngestLag is the gap between a vendor's event time and our receipt time. It is
	// the leading indicator for the 60-second searchability budget (SC-003).
	IngestLag = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "siem_ingest_lag_seconds",
		Help: "Seconds between a vendor's event timestamp and platform receipt.",
	}, []string{"vendor", "feed_id"})

	SchemaDriftRatio = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "siem_ingest_schema_drift_ratio",
		Help: "Fraction of events carrying unrecognized vendor fields.",
	}, []string{"vendor", "feed_id"})

	DeliveryDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "siem_ingest_delivery_duration_seconds",
		Help: "Time to accept and durably commit one vendor delivery.",
		// Buckets straddle the point where a vendor's own client would time out.
		Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30},
	}, []string{"vendor"})
)

// ObserveDelivery records the outcome of one accepted delivery.
func ObserveDelivery(
	vendorName, feedID string, outcome Outcome, bytes int64, elapsed time.Duration,
) {
	labels := prometheus.Labels{"vendor": vendorName, "feed_id": feedID}

	EventsReceived.With(labels).Add(float64(outcome.Accepted))
	DuplicatesSuppressed.With(labels).Add(float64(outcome.DuplicatesSuppressed))
	BytesReceived.With(labels).Add(float64(bytes))
	DeliveryDuration.WithLabelValues(vendorName).Observe(elapsed.Seconds())

	for _, rejection := range outcome.Rejected {
		EventsRejected.WithLabelValues(vendorName, feedID, string(rejection.ReasonCode)).Inc()
	}
	if outcome.Accepted > 0 {
		LastEventTimestamp.With(labels).SetToCurrentTime()
	}
}

// ObservePublishFailure records a durability failure.
func ObservePublishFailure(vendorName, feedID string) {
	PublishFailures.WithLabelValues(vendorName, feedID).Inc()
}

// ObserveQuotaRejection records a refused delivery.
func ObserveQuotaRejection(vendorName, feedID string) {
	QuotaRejections.WithLabelValues(vendorName, feedID).Inc()
}

// ObserveLag records how far behind a feed is running.
func ObserveLag(vendorName, feedID string, lag time.Duration) {
	if lag < 0 {
		// A negative lag means the vendor's clock is ahead of ours. Recording it would
		// make the gauge meaningless, and the timestamp validation already flags
		// genuinely future-dated events.
		return
	}
	IngestLag.WithLabelValues(vendorName, feedID).Set(lag.Seconds())
}

// ObserveDrift records the unrecognized-field ratio for a feed.
func ObserveDrift(vendorName, feedID string, ratio float64) {
	SchemaDriftRatio.WithLabelValues(vendorName, feedID).Set(ratio)
}
