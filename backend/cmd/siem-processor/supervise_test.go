package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/server"
)

// flakyWorker fails a fixed number of times before blocking until cancelled.
type flakyWorker struct {
	failures int32
	runs     atomic.Int32
	started  chan struct{}
}

func (w *flakyWorker) Name() string { return "flaky" }

func (w *flakyWorker) Run(ctx context.Context) error {
	if w.runs.Add(1) <= w.failures {
		select {
		case w.started <- struct{}{}:
		default:
		}
		return errors.New("dependency unavailable")
	}
	select {
	case w.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return ctx.Err()
}

func testDeps() *server.Deps {
	return &server.Deps{Log: mw.NewLogger("error", "json"), Health: server.NewHealth()}
}

// THE REGRESSION TEST. A worker that fails must be restarted, not abandoned.
//
// This is the defect the V6 load run exposed: the correlator died on a single transient
// Redis timeout and was never restarted, so the service kept running and reporting
// healthy while correlation silently stopped for the rest of the run. Every stage here
// is unattended background work — nothing else notices a dead one.
func TestAFailedWorkerIsRestarted(t *testing.T) {
	worker := &flakyWorker{failures: 3, started: make(chan struct{}, 8)}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		superviseWorker(ctx, testDeps(), worker)
	}()

	// Four starts: the three failures plus the run that finally sticks.
	for i := range 4 {
		select {
		case <-worker.started:
		case <-ctx.Done():
			t.Fatalf("worker was abandoned after %d starts; a dead pipeline stage "+
				"leaves the service healthy and silently not processing", i)
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the supervisor did not return after cancellation")
	}

	if got := worker.runs.Load(); got < 4 {
		t.Errorf("worker ran %d times, want at least 4", got)
	}
}

// Cancellation is shutdown, not failure: it must not be retried.
func TestACancelledWorkerIsNotRestarted(t *testing.T) {
	worker := &flakyWorker{failures: 0, started: make(chan struct{}, 4)}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		superviseWorker(ctx, testDeps(), worker)
	}()

	<-worker.started
	cancel()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the supervisor kept restarting a worker that was cancelled")
	}

	if got := worker.runs.Load(); got != 1 {
		t.Errorf("worker ran %d times after cancellation, want exactly 1", got)
	}
}

// The backoff must be bounded, or a long outage pushes the retry interval past any
// useful recovery time and the stage stays down long after its dependency returns.
func TestTheRestartBackoffIsBounded(t *testing.T) {
	backoff := workerRetryMin
	for range 100 {
		backoff = min(backoff*2, workerRetryMax)
	}
	if backoff != workerRetryMax {
		t.Errorf("backoff settled at %s, want the %s ceiling", backoff, workerRetryMax)
	}
}
