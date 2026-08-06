package correlate

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Correlation metrics.
//
// These are the operational read on SC-004. The corpus harness proves the join logic
// against ground truth at build time; production has no ground truth, so what can be
// watched instead is the SHAPE of the output — the tier mix, the single-vendor rate,
// how often records get amended. A sudden move in any of them means the input changed
// even though the code did not, which is exactly how a vendor's silent format change
// announces itself.
//
// Deliberately not labelled by tenant. At a few thousand tenants that multiplies every
// series by the tenant count for no operational gain; per-tenant questions are answered
// from ClickHouse, where the records already live.
//
// Every alert rule in deploy/prometheus/alerts.yml reads one of these, so a rename here
// breaks alerting silently — the metric name is part of the operational contract.
var (
	// RecordsEmitted is the denominator for most of the ratios below.
	RecordsEmitted = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "siem_correlate_records_emitted_total",
		Help: "Correlated records written, by join tier and confidence.",
	}, []string{"tier", "confidence"})

	// VendorsPerRecord is the join-rate signal. A healthy multi-vendor tenant sits
	// well above 1; a drift toward 1 means joins are being missed, not that traffic
	// changed — and that distinction is invisible from a plain event-count graph.
	VendorsPerRecord = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "siem_correlate_vendors_per_record",
		Help:    "Distinct vendors contributing to each correlated record.",
		Buckets: []float64{1, 2, 3, 4},
	})

	// SingleVendorRecords counts records no other vendor corroborated. Normal in
	// itself (FR-016), but a rising share is the clearest early warning that one
	// vendor's feed has stalled while the others keep flowing.
	SingleVendorRecords = promauto.NewCounter(prometheus.CounterOpts{
		Name: "siem_correlate_single_vendor_records_total",
		Help: "Records built from exactly one vendor's observation.",
	})

	// RecordsAmended counts late arrivals that amended an existing record.
	RecordsAmended = promauto.NewCounter(prometheus.CounterOpts{
		Name: "siem_correlate_records_amended_total",
		Help: "Records re-emitted at a higher version after a late arrival.",
	})

	// LateArrivalsDropped counts events that arrived past the lateness bound, so the
	// window they belonged to was already gone. These are not lost — the event is in
	// ClickHouse — but the correlation opportunity is, which is worth knowing about.
	LateArrivalsDropped = promauto.NewCounter(prometheus.CounterOpts{
		Name: "siem_correlate_late_arrivals_dropped_total",
		Help: "Closed windows whose state had already expired, so nothing was emitted.",
	})

	// WindowSize is the ambiguity signal. A window holding many events for one key is
	// either NAT or an attack, and both mean the heuristic is picking among several
	// plausible partners — the condition that spends the false-join budget.
	WindowSize = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "siem_correlate_window_size",
		Help:    "Events held in a correlation window when it closed.",
		Buckets: []float64{1, 2, 5, 10, 50, 250, 1000},
	})

	// CloseFailures is the durability signal for the closer: a sustained non-zero rate
	// means records are not being written and the window state behind them is ticking
	// toward its TTL.
	CloseFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "siem_correlate_close_failures_total",
		Help: "Window close passes that failed, by stage.",
	}, []string{"stage"})

	// EventsFiled counts events accepted into windows, giving the correlator its own
	// throughput reading independent of the ingest counters upstream.
	EventsFiled = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "siem_correlate_events_filed_total",
		Help: "Normalized events filed into a correlation window, by vendor.",
	}, []string{"vendor"})
)

// observeRecord records the metrics for one emitted record.
func observeRecord(tier uint8, confidence string, vendorCount uint8, windowSize int, amended bool) {
	RecordsEmitted.WithLabelValues(strconv.Itoa(int(tier)), confidence).Inc()
	VendorsPerRecord.Observe(float64(vendorCount))
	WindowSize.Observe(float64(windowSize))

	if vendorCount <= 1 {
		SingleVendorRecords.Inc()
	}
	if amended {
		RecordsAmended.Inc()
	}
}
