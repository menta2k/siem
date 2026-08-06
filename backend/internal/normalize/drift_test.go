package normalize

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// collector captures warnings raised by the detector.
type collector struct {
	mu       sync.Mutex
	warnings []DriftWarning
}

func (c *collector) sink(_ context.Context, w DriftWarning) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.warnings = append(c.warnings, w)
}

func (c *collector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.warnings)
}

func (c *collector) last() DriftWarning {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.warnings) == 0 {
		return DriftWarning{}
	}
	return c.warnings[len(c.warnings)-1]
}

func newTestDetector(c *collector, now func() time.Time) *DriftDetector {
	d := NewDriftDetector(c.sink)
	if now != nil {
		d.now = now
	}
	return d
}

// An occasional record with an optional extra field is normal and must not warn, or
// the signal is buried in noise.
func TestNoWarningBelowThreshold(t *testing.T) {
	c := &collector{}
	d := newTestDetector(c, nil)
	tenant, feed := uuid.New(), uuid.New()

	// 5 events with unknown fields out of 1000 = 0.5%, under the 1% threshold.
	d.Observe(context.Background(), tenant, feed, 1000, 5, []string{"NewField"})

	if c.count() != 0 {
		t.Errorf("raised %d warnings below the threshold, want 0", c.count())
	}
}

// A genuine schema change affects nearly every event and must be noticed quickly.
func TestWarnsWhenThresholdCrossed(t *testing.T) {
	c := &collector{}
	d := newTestDetector(c, nil)
	tenant, feed := uuid.New(), uuid.New()

	d.Observe(context.Background(), tenant, feed, 1000, 200, []string{"BrandNewFieldV2"})

	if c.count() != 1 {
		t.Fatalf("raised %d warnings, want 1", c.count())
	}

	warning := c.last()
	if warning.TenantID != tenant || warning.FeedID != feed {
		t.Error("the warning does not identify the drifting feed")
	}
	if warning.Ratio < 0.19 || warning.Ratio > 0.21 {
		t.Errorf("Ratio = %v, want ~0.20", warning.Ratio)
	}
	if len(warning.Fields) != 1 || warning.Fields[0] != "BrandNewFieldV2" {
		t.Errorf("Fields = %v, want the unrecognized field named", warning.Fields)
	}
}

// A drifting feed would otherwise warn on every batch and bury everything else in the
// operator's view.
func TestWarnsOncePerWindow(t *testing.T) {
	c := &collector{}
	d := newTestDetector(c, nil)
	tenant, feed := uuid.New(), uuid.New()
	ctx := context.Background()

	for range 10 {
		d.Observe(ctx, tenant, feed, 100, 50, []string{"NewField"})
	}

	if c.count() != 1 {
		t.Errorf("raised %d warnings for one drifting window, want exactly 1", c.count())
	}
}

// After the window rolls over, a still-drifting feed warns again — otherwise a
// long-running drift would be reported once and then go quiet.
func TestWarnsAgainInANewWindow(t *testing.T) {
	c := &collector{}
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	d := newTestDetector(c, func() time.Time { return now })
	tenant, feed := uuid.New(), uuid.New()
	ctx := context.Background()

	d.Observe(ctx, tenant, feed, 100, 50, []string{"NewField"})
	if c.count() != 1 {
		t.Fatalf("first window raised %d warnings, want 1", c.count())
	}

	now = now.Add(DriftWindow + time.Minute)
	d.Observe(ctx, tenant, feed, 100, 50, []string{"NewField"})

	if c.count() != 2 {
		t.Errorf("raised %d warnings across two windows, want 2", c.count())
	}
}

// One feed's drift must not implicate another's.
func TestWindowsAreIsolatedPerFeed(t *testing.T) {
	c := &collector{}
	d := newTestDetector(c, nil)
	tenant := uuid.New()
	drifting, healthy := uuid.New(), uuid.New()
	ctx := context.Background()

	d.Observe(ctx, tenant, drifting, 100, 50, []string{"NewField"})
	d.Observe(ctx, tenant, healthy, 100, 0, nil)

	if c.count() != 1 {
		t.Fatalf("raised %d warnings, want only the drifting feed's", c.count())
	}
	if c.last().FeedID != drifting {
		t.Error("the warning names the wrong feed")
	}
}

func TestWindowsAreIsolatedPerTenant(t *testing.T) {
	c := &collector{}
	d := newTestDetector(c, nil)
	feedID := uuid.New()
	tenantA, tenantB := uuid.New(), uuid.New()
	ctx := context.Background()

	// Same feed id in two tenants — implausible in practice, but the key must still
	// separate them or one tenant's drift silences the other's.
	d.Observe(ctx, tenantA, feedID, 100, 50, []string{"NewField"})
	d.Observe(ctx, tenantB, feedID, 100, 50, []string{"NewField"})

	if c.count() != 2 {
		t.Errorf("raised %d warnings, want one per tenant", c.count())
	}
}

// A vendor emitting high-cardinality keys must not turn a warning into a memory leak.
func TestFieldTrackingIsBounded(t *testing.T) {
	c := &collector{}
	d := newTestDetector(c, nil)
	tenant, feed := uuid.New(), uuid.New()

	fields := make([]string, 0, 500)
	for i := range 500 {
		fields = append(fields, "field-"+string(rune('a'+i%26))+string(rune('0'+i%10))+
			string(rune('A'+i%26)))
	}
	d.Observe(context.Background(), tenant, feed, 100, 50, fields)

	if got := len(c.last().Fields); got > driftFieldLimit {
		t.Errorf("reported %d distinct fields, want at most %d", got, driftFieldLimit)
	}
}

func TestObserveIgnoresEmptyBatches(t *testing.T) {
	c := &collector{}
	d := newTestDetector(c, nil)

	d.Observe(context.Background(), uuid.New(), uuid.New(), 0, 0, nil)

	if c.count() != 0 {
		t.Error("an empty batch raised a warning")
	}
}

func TestReset(t *testing.T) {
	c := &collector{}
	d := newTestDetector(c, nil)
	tenant, feed := uuid.New(), uuid.New()
	ctx := context.Background()

	d.Observe(ctx, tenant, feed, 100, 50, []string{"NewField"})
	d.Reset()
	d.Observe(ctx, tenant, feed, 100, 50, []string{"NewField"})

	if c.count() != 2 {
		t.Errorf("raised %d warnings after a reset, want 2", c.count())
	}
}

// The detector is called from every consumer goroutine, so concurrent use must be
// safe — a data race here would corrupt counters or panic in production.
func TestConcurrentObserveIsSafe(t *testing.T) {
	c := &collector{}
	d := newTestDetector(c, nil)
	tenant := uuid.New()
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			feed := uuid.New()
			for range 50 {
				d.Observe(ctx, tenant, feed, 10, i%3, []string{"F"})
			}
		}(i)
	}
	wg.Wait()
}

// A nil sink must not panic: drift reporting is optional wiring.
func TestNilSinkIsSafe(t *testing.T) {
	d := NewDriftDetector(nil)
	d.Observe(context.Background(), uuid.New(), uuid.New(), 100, 50, []string{"F"})
}
