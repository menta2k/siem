package correlate_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/correlate"
)

// recordingHealth captures what the closer reported about itself.
type recordingHealth struct {
	samples []correlate.HealthSample
}

func (r *recordingHealth) Record(sample correlate.HealthSample) {
	r.samples = append(r.samples, sample)
}

func (r *recordingHealth) total() correlate.HealthSample {
	var out correlate.HealthSample
	for _, s := range r.samples {
		out.EventsFiled += s.EventsFiled
		out.WindowsClosed += s.WindowsClosed
		out.WindowsDropped += s.WindowsDropped
		out.RecordsEmitted += s.RecordsEmitted
		out.CloseFailures += s.CloseFailures
		out.WindowTTL = max(out.WindowTTL, s.WindowTTL)
	}
	return out
}

// A working pipeline must report itself as working — events filed, windows closed,
// records emitted — because the console reads "no records" as an outage and would
// otherwise read a healthy tenant that way on every deployment.
func TestTheCloserReportsAWorkingPass(t *testing.T) {
	windowStore := newCountingWindowStore()
	records := &countingCorrelatedStore{}
	health := &recordingHealth{}

	batch := recordBatch(t, 20)
	if _, err := newBatchWorker(windowStore).WithHealth(health).
		HandleBatch(context.Background(), batch); err != nil {
		t.Fatalf("HandleBatch: %v", err)
	}

	future := time.Now().UTC().Add(time.Hour)
	closer := newCloser(windowStore, records).WithHealth(health)
	if err := closer.Tick(context.Background(), future); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	got := health.total()
	if got.EventsFiled != 20 {
		t.Errorf("filed %d events, want 20", got.EventsFiled)
	}
	if got.WindowsClosed == 0 {
		t.Error("no windows reported closed, so a healthy pipeline reads as stalled")
	}
	if got.RecordsEmitted != records.records {
		t.Errorf("reported %d records emitted, %d were written",
			got.RecordsEmitted, records.records)
	}
	if got.WindowsDropped != 0 {
		t.Errorf("reported %d expired windows in a pass that had none", got.WindowsDropped)
	}
	// Without the TTL beside the lag there is nothing to compare it against, and the
	// console cannot tell "behind" from "losing data".
	if got.WindowTTL <= 0 {
		t.Error("no window TTL reported, so the claim lag cannot be judged")
	}
}

// THE FAILURE THAT WENT UNSEEN FOR HOURS, TWICE. The closer keeps claiming windows
// whose member state has expired, closes them empty, and writes nothing — while the API
// goes on serving the records stored before the fall, so the console looks healthy.
//
// Every window here is expired, which is the production shape exactly. What must come
// out of it is a report that says so.
func TestTheCloserReportsWindowsThatExpiredBeforeTheyClosed(t *testing.T) {
	windowStore := newCountingWindowStore()
	records := &countingCorrelatedStore{}
	health := &recordingHealth{}

	batch := recordBatch(t, 10)
	if _, err := newBatchWorker(windowStore).
		HandleBatch(context.Background(), batch); err != nil {
		t.Fatalf("HandleBatch: %v", err)
	}

	// The window state expires; the schedule entries do not. That asymmetry IS the
	// incident: Redis drops the members on their TTL while the schedule keeps handing
	// the closer windows to open.
	windowStore.expireMembers()

	future := time.Now().UTC().Add(time.Hour)
	closer := newCloser(windowStore, records).WithHealth(health)
	if err := closer.Tick(context.Background(), future); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	got := health.total()
	if got.WindowsDropped == 0 {
		t.Fatal("windows closed empty and nothing said so — this is the state that " +
			"ran for hours on production while the console showed a healthy pipeline")
	}
	if got.RecordsEmitted != 0 {
		t.Errorf("reported %d records emitted by expired windows", got.RecordsEmitted)
	}
	if got.WindowsClosed != 0 {
		t.Errorf("reported %d windows closed with members, want 0", got.WindowsClosed)
	}
}

// A sample is reported per tenant, because the console is tenant-scoped and a shared
// closer serves all of them: one tenant's healthy minute must not stand in for
// another's stalled one.
func TestHealthIsReportedPerTenant(t *testing.T) {
	health := &recordingHealth{}
	first, second := uuid.New(), uuid.New()

	health.Record(correlate.HealthSample{TenantID: first, EventsFiled: 3})
	health.Record(correlate.HealthSample{TenantID: second, EventsFiled: 5})

	if len(health.samples) != 2 {
		t.Fatalf("got %d samples for two tenants", len(health.samples))
	}
	if health.samples[0].TenantID == health.samples[1].TenantID {
		t.Error("both samples carry the same tenant")
	}
}
