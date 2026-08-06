package query

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	mw "github.com/menta2k/siem/internal/middleware"
)

// Query metrics.
//
// Labelled by endpoint rather than by tenant. Per-tenant latency is a question for
// ClickHouse's own query log; adding a tenant label here multiplies every series by
// the tenant count and turns a latency histogram into the largest metric in the system.
//
// Every alert rule in deploy/prometheus/alerts.yml reads one of these, so a rename here
// breaks alerting silently — the metric name is part of the operational contract.
var (
	// Duration is the SC-002 read: search p95 under three seconds.
	//
	// The buckets are placed around that target rather than spread evenly. A histogram
	// whose boundaries straddle the SLO gives a p95 that can be computed accurately;
	// default buckets put the answer inside one enormous bucket and the number becomes
	// an interpolation of an interpolation.
	Duration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "siem_query_duration_seconds",
		Help:    "Query wall-clock time, by endpoint.",
		Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 3, 5, 10},
	}, []string{"endpoint"})

	// RowsReturned is the companion to Duration. A query that got fast because it
	// started returning nothing looks identical on a latency graph alone.
	RowsReturned = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "siem_query_rows_returned",
		Help:    "Rows in a query response, by endpoint.",
		Buckets: []float64{0, 1, 10, 100, 500, 1000},
	}, []string{"endpoint"})

	// Rejected counts queries refused before execution, by the reason. A climbing
	// time_range_required means a client is constructing requests wrongly, which is a
	// different problem from a climbing query_timeout.
	Rejected = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "siem_query_rejected_total",
		Help: "Queries refused before execution, by endpoint and reason.",
	}, []string{"endpoint", "reason"})

	// Timeouts is the SC-002 breach counter: every one of these is an analyst who
	// waited the full budget and got nothing.
	Timeouts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "siem_query_timeouts_total",
		Help: "Queries that exceeded the execution deadline, by endpoint.",
	}, []string{"endpoint"})

	// ExportRows tracks export volume. Exports move data outside the platform, so the
	// operational question is how much left, not how long it took.
	ExportRows = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "siem_query_export_rows_total",
		Help: "Rows written to exports, by format.",
	}, []string{"format"})

	// ExportsTruncated counts exports that stopped at the row cap. A sustained rate
	// means the cap is below what analysts actually need, and they are working from
	// partial extracts.
	ExportsTruncated = promauto.NewCounter(prometheus.CounterOpts{
		Name: "siem_query_exports_truncated_total",
		Help: "Exports that stopped at the row cap.",
	})
)

// Observe records one completed query.
//
// Row counts are int64 to match the API's own types, so no caller has to narrow a
// response field just to report it.
func Observe(endpoint string, started time.Time, rows int64, err error) {
	Duration.WithLabelValues(endpoint).Observe(time.Since(started).Seconds())
	RowsReturned.WithLabelValues(endpoint).Observe(float64(rows))

	if err != nil {
		ObserveFailure(endpoint, err)
	}
}

// ObserveFailure records a query that did not return a result.
func ObserveFailure(endpoint string, err error) {
	if err == nil {
		return
	}
	if code := errorCode(err); code != "" {
		Rejected.WithLabelValues(endpoint, code).Inc()
		if code == mw.CodeQueryTimeout {
			Timeouts.WithLabelValues(endpoint).Inc()
		}
	}
}

// errorCode extracts the stable API code a failure will be reported under, so the
// metric label matches what the client actually sees.
func errorCode(err error) string {
	if apiErr := mw.AsError(err); apiErr != nil {
		return apiErr.Code
	}
	return ""
}

// ObserveExport records one completed export.
func ObserveExport(format Format, rows int, truncated bool) {
	ExportRows.WithLabelValues(string(format)).Add(float64(rows))
	if truncated {
		ExportsTruncated.Inc()
	}
}
