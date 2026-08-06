// Package server holds transport bootstrap shared by the three service binaries:
// health probes, readiness checks, and the metrics endpoint.
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Checker reports whether one dependency is usable.
type Checker interface {
	Ping(ctx context.Context) error
}

// namedChecker pairs a dependency with the name reported in the probe response.
type namedChecker struct {
	name    string
	checker Checker
}

// Health serves liveness and readiness.
//
// The distinction matters operationally: liveness answers "is this process wedged"
// and must NOT depend on ClickHouse, or a store outage would make Kubernetes restart
// every healthy service instance and turn a degradation into an outage. Readiness
// answers "can this instance serve traffic" and does check dependencies.
type Health struct {
	mu       sync.RWMutex
	checkers []namedChecker
	timeout  time.Duration
}

// NewHealth builds a health reporter.
func NewHealth() *Health {
	return &Health{timeout: 3 * time.Second}
}

// Register adds a dependency to the readiness check.
func (h *Health) Register(name string, checker Checker) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checkers = append(h.checkers, namedChecker{name: name, checker: checker})
}

// LivenessHandler reports process health only. Always 200 while the process runs.
func (h *Health) LivenessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// ReadinessHandler probes every dependency in parallel and reports each by name, so
// an operator sees which one is failing rather than an opaque "not ready".
func (h *Health) ReadinessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
		defer cancel()

		results, ready := h.probe(ctx)

		status := http.StatusOK
		if !ready {
			status = http.StatusServiceUnavailable
		}
		writeJSON(w, status, map[string]any{
			"status":       readyLabel(ready),
			"dependencies": results,
		})
	}
}

func (h *Health) probe(ctx context.Context) (map[string]string, bool) {
	h.mu.RLock()
	checkers := append([]namedChecker{}, h.checkers...)
	h.mu.RUnlock()

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results = make(map[string]string, len(checkers))
		ready   = true
	)

	for _, c := range checkers {
		wg.Add(1)
		go func(c namedChecker) {
			defer wg.Done()
			err := c.checker.Ping(ctx)

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				// The dependency name and failure are operational detail on an
				// internal endpoint, so the cause is safe to include here.
				results[c.name] = "unavailable: " + err.Error()
				ready = false
				return
			}
			results[c.name] = "ok"
		}(c)
	}
	wg.Wait()

	return results, ready
}

// MetricsHandler exposes Prometheus metrics.
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}

func readyLabel(ready bool) string {
	if ready {
		return "ready"
	}
	return "not_ready"
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		// The status line is already written, so the response cannot be changed.
		// The connection will simply be truncated; nothing useful remains to do.
		return
	}
}
