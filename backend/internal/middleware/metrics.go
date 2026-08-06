package middleware

import (
	"context"
	"strconv"
	"time"

	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// HTTP-layer metrics. Pipeline metrics (ingest, correlation, alerting) are declared
// alongside the code that emits them; only the request-level signals live here.
//
// Labels deliberately exclude tenant id: with 50 tenants across ~30 operations the
// cardinality would multiply for little operational value, and per-tenant behaviour
// is better answered from ClickHouse than from Prometheus.
var (
	requestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "siem_http_requests_total",
		Help: "Total HTTP requests by operation and result code.",
	}, []string{"operation", "code", "status"})

	requestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "siem_http_request_duration_seconds",
		Help: "HTTP request latency by operation.",
		// Buckets straddle the 3s p95 search budget (SC-005) so the SLO is
		// directly observable rather than interpolated.
		Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 3, 5, 10},
	}, []string{"operation"})

	requestsInFlight = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "siem_http_requests_in_flight",
		Help: "HTTP requests currently being served.",
	})

	rateLimitedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "siem_rate_limited_total",
		Help: "Requests rejected by the rate limiter.",
	}, []string{"scope"})
)

// Metrics records latency, in-flight count, and outcome for every request.
func Metrics() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (any, error) {
			operation, _ := operationOf(ctx)

			requestsInFlight.Inc()
			defer requestsInFlight.Dec()

			start := time.Now()
			reply, err := handler(ctx, req)
			requestDuration.WithLabelValues(operation).Observe(time.Since(start).Seconds())

			code, status := "OK", "200"
			if err != nil {
				apiErr := AsError(err)
				code, status = apiErr.Code, strconv.Itoa(apiErr.HTTPStatus())
			}
			requestsTotal.WithLabelValues(operation, code, status).Inc()

			return reply, err
		}
	}
}

// ObserveRateLimited records a rejection for the given scope ("tenant" or "credential").
func ObserveRateLimited(scope string) {
	rateLimitedTotal.WithLabelValues(scope).Inc()
}
