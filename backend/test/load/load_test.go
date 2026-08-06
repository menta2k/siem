//go:build load

// Package load asserts the throughput and latency targets (SC-002, SC-003).
//
// Behind its own build tag because it is slow and resource-hungry: run by `make
// loadtest` and the nightly job, never by `make test`. A load test in the default
// suite is a load test people learn to skip.
//
// These are ASSERTIONS, not benchmarks. A benchmark reports a number and leaves the
// judgement to a human who may not look; these fail the build when the platform stops
// meeting the target it promised.
package load

import (
	"fmt"
	"net"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/query"
	"github.com/menta2k/siem/internal/vendors"
	"github.com/menta2k/siem/test/support"
)

// The targets, from the success criteria.
const (
	// SustainedEPS is SC-002's steady-state rate.
	SustainedEPS = 5_000
	// PeakEPS is SC-002's burst rate.
	PeakEPS = 15_000
	// SearchP95 is SC-003's read latency budget.
	SearchP95 = 3 * time.Second
	// SearchableWithin is SC-003's ingest-to-searchable budget.
	SearchableWithin = 60 * time.Second
)

func TestMain(m *testing.M) { os.Exit(support.RunSuite(m)) }

// TestSustainedIngestThroughput asserts SC-002's steady-state rate.
//
// Measured against the STORAGE layer rather than the HTTP boundary. The HTTP path is
// covered by its own tests; what is at risk at this volume is the write path, and
// putting a load generator and a server in the same process measures the generator as
// much as the platform.
func TestSustainedIngestThroughput(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "load-sustained")

	repo := chdata.NewEventRepo(f.ClickHouse)

	const (
		workers   = 8
		batchSize = 1_000
		batches   = 40 // 40k events total
	)

	var written atomic.Int64
	started := time.Now()

	var wg sync.WaitGroup
	for worker := range workers {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for batch := range batches / workers {
				events := makeEvents(tenant.ID, worker, batch, batchSize)
				if err := repo.InsertNormalized(ctx, events); err != nil {
					t.Errorf("worker %d batch %d: %v", worker, batch, err)
					return
				}
				written.Add(int64(len(events)))
			}
		}(worker)
	}
	wg.Wait()

	elapsed := time.Since(started)
	eps := float64(written.Load()) / elapsed.Seconds()

	t.Logf("wrote %d events in %s (%.0f eps)", written.Load(), elapsed.Round(time.Millisecond), eps)

	if eps < SustainedEPS {
		t.Errorf("sustained throughput %.0f eps is below the SC-002 target of %d",
			eps, SustainedEPS)
	}
}

// TestPeakIngestThroughput asserts SC-002's burst rate over a short window.
func TestPeakIngestThroughput(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "load-peak")

	repo := chdata.NewEventRepo(f.ClickHouse)

	const (
		workers   = 16
		batchSize = 2_000
		batches   = 32 // 64k events
	)

	var written atomic.Int64
	started := time.Now()

	var wg sync.WaitGroup
	for worker := range workers {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for batch := range batches / workers {
				events := makeEvents(tenant.ID, worker+100, batch, batchSize)
				if err := repo.InsertNormalized(ctx, events); err != nil {
					t.Errorf("worker %d batch %d: %v", worker, batch, err)
					return
				}
				written.Add(int64(len(events)))
			}
		}(worker)
	}
	wg.Wait()

	elapsed := time.Since(started)
	eps := float64(written.Load()) / elapsed.Seconds()

	t.Logf("peak: %d events in %s (%.0f eps)", written.Load(),
		elapsed.Round(time.Millisecond), eps)

	if eps < PeakEPS {
		t.Errorf("peak throughput %.0f eps is below the SC-002 target of %d", eps, PeakEPS)
	}
}

// TestSearchLatencyUnderLoad asserts SC-003's p95.
//
// The p95 is computed from many runs rather than one: a single timing is dominated by
// whatever else the machine was doing, and a target asserted from one sample fails
// randomly until someone raises it to a number that means nothing.
func TestSearchLatencyUnderLoad(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "load-search")

	repo := chdata.NewEventRepo(f.ClickHouse)
	for batch := range 20 {
		if err := repo.InsertNormalized(ctx, makeEvents(tenant.ID, 0, batch, 1_000)); err != nil {
			t.Fatalf("seed batch %d: %v", batch, err)
		}
	}
	f.Sync(t, "normalized_events")

	search := chdata.NewSearchRepo(f.ClickHouse)
	rng := query.TimeRange{
		From: time.Now().UTC().Add(-2 * time.Hour), To: time.Now().UTC().Add(time.Hour),
	}

	const runs = 40
	durations := make([]time.Duration, 0, runs)

	for range runs {
		started := time.Now()
		if _, err := search.SearchEvents(ctx, chdata.EventQuery{
			Range: rng, PageSize: 100,
		}); err != nil {
			t.Fatalf("search: %v", err)
		}
		durations = append(durations, time.Since(started))
	}

	p95 := percentile(durations, 0.95)
	t.Logf("search p50=%s p95=%s", percentile(durations, 0.5).Round(time.Millisecond),
		p95.Round(time.Millisecond))

	if p95 > SearchP95 {
		t.Errorf("search p95 %s exceeds the SC-003 budget of %s", p95, SearchP95)
	}
}

// TestEventsAreSearchableQuickly asserts SC-003's ingest-to-searchable budget.
func TestEventsAreSearchableQuickly(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "load-freshness")

	marker := "freshness-" + uuid.NewString()
	events := makeEvents(tenant.ID, 0, 0, 1)
	events[0].EventID = marker

	written := time.Now()
	if err := chdata.NewEventRepo(f.ClickHouse).InsertNormalized(ctx, events); err != nil {
		t.Fatalf("insert: %v", err)
	}

	search := chdata.NewSearchRepo(f.ClickHouse)
	rng := query.TimeRange{
		From: time.Now().UTC().Add(-time.Hour), To: time.Now().UTC().Add(time.Hour),
	}

	deadline := time.Now().Add(SearchableWithin)
	for time.Now().Before(deadline) {
		page, err := search.SearchEvents(ctx, chdata.EventQuery{Range: rng, PageSize: 1000})
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		for _, item := range page.Items {
			if item.EventID == marker {
				t.Logf("searchable after %s", time.Since(written).Round(time.Millisecond))
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}

	t.Errorf("an event was not searchable within the SC-003 budget of %s", SearchableWithin)
}

// makeEvents builds a batch of distinct events.
func makeEvents(tenantID uuid.UUID, worker, batch, size int) []chdata.NormalizedEvent {
	events := make([]chdata.NormalizedEvent, 0, size)
	now := time.Now().UTC()

	for i := range size {
		events = append(events, chdata.NormalizedEvent{
			TenantID:  tenantID,
			EventID:   fmt.Sprintf("load-%d-%d-%d", worker, batch, i),
			EventTime: now.Add(-time.Duration(i%3600) * time.Second),
			// ReceivedAt is now, so the freshness measurement is not confused by the
			// backdated event times used to spread rows across partitions.
			ReceivedAt:    now,
			Vendor:        vendors.Cloudflare,
			ClientIP:      net.ParseIP(fmt.Sprintf("203.0.113.%d", i%254+1)),
			ClientCountry: "DE",
			RequestHost:   "shop.example.com",
			RequestPath:   fmt.Sprintf("/checkout/%d", i%100),
			RequestMethod: "GET",
			Verdict:       vendors.VerdictAllowed,
			IngestVersion: 1,
		})
	}
	return events
}

// percentile returns the value at a quantile, sorting a copy.
func percentile(durations []time.Duration, q float64) time.Duration {
	if len(durations) == 0 {
		return 0
	}

	sorted := slices.Clone(durations)
	slices.Sort(sorted)

	index := int(float64(len(sorted)-1) * q)
	return sorted[index]
}
