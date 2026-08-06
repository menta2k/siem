package normalize

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Schema-drift thresholds.
//
// A vendor adding a field must NOT take a customer's logging offline, so drift is a
// warning rather than a failure. The 1% threshold over a 10-minute window is chosen so
// a genuine schema change (which affects nearly every event) trips it quickly, while
// an occasional record carrying an optional extra field does not.
const (
	DriftThreshold = 0.01
	DriftWindow    = 10 * time.Minute
	// driftFieldLimit bounds how many distinct field names are reported, so a vendor
	// emitting high-cardinality keys cannot turn a warning into a memory leak.
	driftFieldLimit = 50
)

// DriftWarning describes an observed schema change.
type DriftWarning struct {
	TenantID uuid.UUID
	FeedID   uuid.UUID
	// Ratio is the fraction of events in the window carrying unrecognized fields.
	Ratio float64
	// Fields names the unrecognized keys, sorted for stable reporting.
	Fields     []string
	ObservedAt time.Time
}

// DriftSink receives warnings when a feed crosses the threshold.
type DriftSink func(ctx context.Context, warning DriftWarning)

// DriftDetector tracks unrecognized fields per feed over a rolling window.
//
// State is in-process rather than in Redis on purpose: drift is a per-instance
// observation used to raise an operator warning, not a correctness signal. Paying a
// Redis round trip per event to make it exact would cost far more than the warning is
// worth, and a feed genuinely drifting will trip the threshold on every instance.
type DriftDetector struct {
	mu      sync.Mutex
	windows map[string]*driftWindow
	sink    DriftSink
	now     func() time.Time
}

type driftWindow struct {
	tenantID    uuid.UUID
	feedID      uuid.UUID
	windowStart time.Time
	total       int
	withUnknown int
	fields      map[string]int
	warned      bool
}

// NewDriftDetector constructs a detector. sink may be nil in tests.
func NewDriftDetector(sink DriftSink) *DriftDetector {
	return &DriftDetector{
		windows: map[string]*driftWindow{},
		sink:    sink,
		now:     time.Now,
	}
}

// Observe records one batch of events for a feed.
func (d *DriftDetector) Observe(
	ctx context.Context, tenantID, feedID uuid.UUID, total, withUnknown int, fields []string,
) {
	if total <= 0 {
		return
	}

	d.mu.Lock()
	window, crossed := d.record(tenantID, feedID, total, withUnknown, fields)
	var warning DriftWarning
	if crossed {
		warning = d.buildWarning(window)
	}
	d.mu.Unlock()

	// The sink is called outside the lock: it writes feed health and may block, and
	// holding the mutex across that would stall every other feed's ingestion.
	if crossed && d.sink != nil {
		d.sink(ctx, warning)
	}
}

// record updates the window and reports whether the threshold was newly crossed.
func (d *DriftDetector) record(
	tenantID, feedID uuid.UUID, total, withUnknown int, fields []string,
) (*driftWindow, bool) {
	key := tenantID.String() + ":" + feedID.String()
	now := d.now()

	window, ok := d.windows[key]
	if !ok || now.Sub(window.windowStart) > DriftWindow {
		window = &driftWindow{
			tenantID: tenantID, feedID: feedID,
			windowStart: now, fields: map[string]int{},
		}
		d.windows[key] = window
	}

	window.total += total
	window.withUnknown += withUnknown
	for _, field := range fields {
		if len(window.fields) >= driftFieldLimit {
			break
		}
		window.fields[field]++
	}

	// Warn once per window: a drifting feed would otherwise raise a warning on every
	// batch and bury everything else in the operator's view.
	if window.warned || window.total == 0 {
		return window, false
	}
	if float64(window.withUnknown)/float64(window.total) <= DriftThreshold {
		return window, false
	}
	window.warned = true
	return window, true
}

func (d *DriftDetector) buildWarning(window *driftWindow) DriftWarning {
	fields := make([]string, 0, len(window.fields))
	for field := range window.fields {
		fields = append(fields, field)
	}
	sort.Strings(fields)

	return DriftWarning{
		TenantID:   window.tenantID,
		FeedID:     window.feedID,
		Ratio:      float64(window.withUnknown) / float64(window.total),
		Fields:     fields,
		ObservedAt: d.now(),
	}
}

// Reset clears all tracked windows. Used by tests and on configuration reload.
func (d *DriftDetector) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.windows = map[string]*driftWindow{}
}
