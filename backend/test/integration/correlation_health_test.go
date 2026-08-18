//go:build integration

package integration

import (
	"testing"
	"time"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/test/support"
)

// WHY THIS SUITE EXISTS. GetCorrelationHealth shipped with eight Scan destinations
// against nine selected columns and returned 500 for every request — taking the whole
// dashboard down with it, because the console fetched it in the same batch as the
// panels that worked. Nothing before this could catch it: the column list and the Scan
// are only compared by the driver, at runtime, against a real server. It is the same
// fault 8c32245 fixed in the closer, and the same reason that one needed a test.
//
// The unit tests either side of this cover the VERDICT — what the counters mean. This
// covers the query that produces them.

// healthRow builds one minute of pipeline activity.
func healthRow(
	tenantID interface{ String() string }, minute time.Time, emitted uint64,
) chdata.CorrelationHealthRow {
	return chdata.CorrelationHealthRow{
		Minute: minute, EventsFiled: 1_000, WindowsClosed: 400,
		RecordsEmitted: emitted, WindowsDroppedEmpty: 3, CloseFailures: 0,
		WindowsDue: 42, MaxClaimLagMS: 90_000, WindowTTLMS: 1_115_000,
	}
}

// Every column selected must land in a field. A mismatch is not a wrong number, it is
// a failed request — which is how this reached production the first time.
func TestCorrelationHealthReadsBackEveryColumn(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "correlation-health")

	repo := chdata.NewCorrelationHealthRepo(f.ClickHouse)
	minute := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Minute)

	row := healthRow(tenant.ID, minute, 380)
	row.TenantID = tenant.ID
	row.Minute = minute
	if err := repo.InsertCorrelationHealth(ctx, []chdata.CorrelationHealthRow{row}); err != nil {
		t.Fatalf("InsertCorrelationHealth(): %v", err)
	}

	health, err := repo.GetCorrelationHealth(ctx)
	if err != nil {
		t.Fatalf("GetCorrelationHealth(): %v", err)
	}

	if health.EventsFiled != 1_000 || health.WindowsClosed != 400 {
		t.Errorf("filed %d, closed %d — want 1000 and 400",
			health.EventsFiled, health.WindowsClosed)
	}
	if health.RecordsEmitted != 380 || health.WindowsDroppedEmpty != 3 {
		t.Errorf("emitted %d, dropped %d — want 380 and 3",
			health.RecordsEmitted, health.WindowsDroppedEmpty)
	}
	if health.WindowsDue != 42 {
		t.Errorf("windows due = %d, want 42", health.WindowsDue)
	}
	if health.ClaimLag != 90*time.Second {
		t.Errorf("claim lag = %s, want 90s", health.ClaimLag)
	}
	// Without this the console cannot tell "behind" from "losing data".
	if health.WindowTTL != 1_115_000*time.Millisecond {
		t.Errorf("window ttl = %s, want 1115s", health.WindowTTL)
	}
	if !health.LastRecordAt.Equal(minute) {
		t.Errorf("last record at = %s, want %s", health.LastRecordAt, minute)
	}
	if health.Status() != chdata.CorrelationHealthy {
		t.Errorf("status = %q, want healthy", health.Status())
	}
}

// Counters SUM across the window and levels take their highest, which is how the
// columns are aggregated in the table itself. A reader that averaged the lag, or took
// the last minute's counters alone, would report a pipeline that recovered in the most
// recent minute as though the outage never happened.
func TestCorrelationHealthAggregatesTheWindow(t *testing.T) {
	f := support.Shared(t)
	ctx, tenant := f.NewTenant(t, "correlation-health-window")

	repo := chdata.NewCorrelationHealthRepo(f.ClickHouse)
	minute := time.Now().UTC().Truncate(time.Minute).Add(-3 * time.Minute)

	rows := make([]chdata.CorrelationHealthRow, 0, 3)
	for i := range 3 {
		row := healthRow(tenant.ID, minute.Add(time.Duration(i)*time.Minute), 100)
		row.TenantID = tenant.ID
		row.MaxClaimLagMS = uint64(60_000 * (i + 1))
		rows = append(rows, row)
	}
	if err := repo.InsertCorrelationHealth(ctx, rows); err != nil {
		t.Fatalf("InsertCorrelationHealth(): %v", err)
	}

	health, err := repo.GetCorrelationHealth(ctx)
	if err != nil {
		t.Fatalf("GetCorrelationHealth(): %v", err)
	}

	if health.RecordsEmitted != 300 {
		t.Errorf("emitted = %d across three minutes, want 300", health.RecordsEmitted)
	}
	if health.ClaimLag != 3*time.Minute {
		t.Errorf("claim lag = %s, want the highest of the three (3m)", health.ClaimLag)
	}
}

// A tenant that has never emitted a record must come back with NO last-record time.
// maxIf over no rows returns the epoch, and a Go zero time is year 1 — so the unset
// check has to be against the epoch, or the console shows "last record 01/01/1970" for
// a pipeline that has simply never run.
func TestCorrelationHealthReportsAnAbsentLastRecordAsUnset(t *testing.T) {
	f := support.Shared(t)
	ctx, _ := f.NewTenant(t, "correlation-health-empty")

	health, err := chdata.NewCorrelationHealthRepo(f.ClickHouse).GetCorrelationHealth(ctx)
	if err != nil {
		t.Fatalf("GetCorrelationHealth(): %v", err)
	}

	if !health.LastRecordAt.IsZero() {
		t.Errorf("last record at = %s, want the zero time", health.LastRecordAt)
	}
	if health.Status() != chdata.CorrelationIdle {
		t.Errorf("status = %q for a tenant that filed nothing, want idle", health.Status())
	}
}
