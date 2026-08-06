package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// WorkerRestarts counts pipeline stages that failed and were restarted.
//
// Worth alerting on even though the restart succeeds. Every stage here is unattended
// background work, so a stage that keeps dying is invisible in the product: events
// still arrive, the API still answers, and correlation quietly falls behind. A rising
// restart count is the only early signal that something underneath is unhealthy.
var WorkerRestarts = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "siem_worker_restarts_total",
	Help: "Pipeline workers that exited with an error and were restarted.",
}, []string{"worker"})
