package correlate

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/correlate/window"
	"github.com/menta2k/siem/internal/data/stream"
	mw "github.com/menta2k/siem/internal/middleware"
)

// Worker files normalized events into their correlation windows.
//
// It does not emit anything. Deciding that a window is complete needs the passage of
// time, not the arrival of an event, so emission belongs to the Closer. Trying to do
// both here would mean emitting a record on every event and amending it repeatedly —
// several writes per request, most of them immediately superseded.
type Worker struct {
	windows  *window.Windows
	settings SettingsSource
	log      mw.Logger

	// health is optional, as it is on the Closer: filing events works without it.
	health HealthRecorder
}

// WithHealth attaches a health recorder, returning the worker so construction reads as
// one expression.
func (w *Worker) WithHealth(health HealthRecorder) *Worker {
	w.health = health
	return w
}

// NewWorker constructs the correlation worker.
func NewWorker(windows *window.Windows, settings SettingsSource, log mw.Logger) *Worker {
	return &Worker{windows: windows, settings: settings, log: log}
}

// Name identifies the worker in logs and metrics.
func (w *Worker) Name() string { return "correlator" }

// Handle files one normalized event into every window it could join.
//
// The event is filed under BOTH its keys when it has both. That is not redundancy: the
// exact bucket is how a second vendor reporting the same request id is ever noticed,
// and the heuristic bucket is what the window closes on. Filing only under the exact
// key would leave events with unmatched ids uncorrelated; filing only under the
// heuristic would throw away the one signal that carries no false-join risk.
func (w *Worker) Handle(ctx context.Context, record stream.Record) error {
	event, ok := w.decodeEvent(ctx, record)
	if !ok {
		return nil
	}

	for _, write := range w.writesFor(ctx, event) {
		err := w.windows.Add(ctx, write.TenantID, write.Key, write.Member, write.Settings)
		if err != nil {
			return fmt.Errorf("file event %s under %s: %w", event.EventID, write.Key, err)
		}
		if write.ScheduleAt.IsZero() {
			continue
		}
		err = w.windows.Schedule(
			ctx, write.TenantID, write.Key, write.ScheduleAt, write.Settings)
		if err != nil {
			return fmt.Errorf("schedule window for event %s: %w", event.EventID, err)
		}
	}

	EventsFiled.WithLabelValues(event.Vendor).Inc()
	w.recordFiled(map[uuid.UUID]int{event.TenantID: 1})
	return nil
}
