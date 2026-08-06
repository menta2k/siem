package alerting

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Alerting metrics.
//
// The pair worth watching together is Fired and Suppressed. Fired alone cannot
// distinguish "the platform is quiet" from "the cooldown is swallowing everything",
// and those call for opposite responses.
//
// Not labelled by rule id: rule ids are unbounded and operator-created, so a per-rule
// label lets one tenant's rule sprawl become the largest metric in the system. Per-rule
// questions are answered from the alerts table, where the rows already live.
var (
	RulesEvaluated = promauto.NewCounter(prometheus.CounterOpts{
		Name: "siem_alerting_rules_evaluated_total",
		Help: "Rule evaluations completed.",
	})

	// EvaluationFailures counts rules that could not be measured. A rule failing to
	// evaluate is silent in exactly the way a rule below its threshold is, so without
	// this a broken rule is indistinguishable from a quiet one.
	EvaluationFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "siem_alerting_evaluation_failures_total",
		Help: "Rule evaluations that failed, by reason.",
	}, []string{"reason"})

	Fired = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "siem_alerting_alerts_fired_total",
		Help: "Alerts created, by severity.",
	}, []string{"severity"})

	Suppressed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "siem_alerting_alerts_suppressed_total",
		Help: "Qualifying windows suppressed by a rule's cooldown.",
	})

	// DeliveryAttempts counts webhook posts, including retries, by outcome.
	DeliveryAttempts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "siem_alerting_delivery_attempts_total",
		Help: "Webhook delivery attempts, by outcome.",
	}, []string{"outcome"})

	// DeliveryFailures counts alerts that exhausted their retries. Every one of these
	// is an operator who believes they were notified and was not, which is why it is
	// separate from the attempt counter and alerted on directly.
	DeliveryFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "siem_alerting_delivery_failures_total",
		Help: "Alerts that exhausted their delivery retries.",
	})

	// DeliveryDuration is the webhook's own latency. A receiver that has become slow
	// but not yet failing is the leading indicator of the failures above.
	DeliveryDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "siem_alerting_delivery_duration_seconds",
		Help:    "Time spent posting to a webhook.",
		Buckets: []float64{0.05, 0.1, 0.5, 1, 2, 5, 10},
	})

	// PendingDeliveries is the retry backlog. A backlog that only grows means the
	// worker is falling behind rather than that one endpoint is down.
	PendingDeliveries = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "siem_alerting_pending_deliveries",
		Help: "Alerts awaiting a webhook delivery attempt.",
	})
)
