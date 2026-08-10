//go:build integration

package integration

import (
	"testing"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/test/support"
)

// The storage panel reads ClickHouse's OWN accounting — system.disks and system.parts —
// rather than anything this platform writes, so nothing but a real server can tell us the
// query is valid. The column names, the partition filter and the privileges the app user
// holds are all only checked here.
func TestStorageReadsWhatClickHouseReports(t *testing.T) {
	f := support.Shared(t)
	ctx, _ := f.NewTenant(t, "storage-panel")

	storage, err := chdata.NewStorageRepo(f.ClickHouse, f.Database).Read(ctx)
	if err != nil {
		t.Fatalf("Read(): %v", err)
	}

	if storage.DiskTotalBytes == 0 {
		t.Error("disk total is zero; system.disks was not readable")
	}
	if storage.DiskFreeBytes == 0 {
		t.Error("disk free is zero, which no working container reports")
	}
	if storage.DiskFreeBytes > storage.DiskTotalBytes {
		t.Errorf("free (%d) exceeds total (%d)", storage.DiskFreeBytes, storage.DiskTotalBytes)
	}

	// The suite has written events by the time this runs, so the tables exist and hold
	// something. A zero here means the database filter matched nothing — the most likely
	// way this query silently returns an empty panel in production.
	if len(storage.Tables) == 0 {
		t.Fatal("no tables reported; the database filter matched nothing")
	}
	if storage.DatabaseBytes == 0 {
		t.Error("database size is zero despite tables being present")
	}

	// Largest first, which is what makes the list useful without reading all of it.
	for i := 1; i < len(storage.Tables); i++ {
		if storage.Tables[i].Bytes > storage.Tables[i-1].Bytes {
			t.Errorf("tables are not ordered by size: %+v", storage.Tables)
			break
		}
	}
}

// Only date-shaped partitions may enter the daily series. The reference tables partition
// by tuple() or by month, and folding those in would attribute a whole table to whichever
// day its partition happened to parse as.
func TestDailyGrowthCountsOnlyDatePartitions(t *testing.T) {
	f := support.Shared(t)
	ctx, _ := f.NewTenant(t, "storage-daily")

	storage, err := chdata.NewStorageRepo(f.ClickHouse, f.Database).Read(ctx)
	if err != nil {
		t.Fatalf("Read(): %v", err)
	}

	for _, day := range storage.Daily {
		if day.Day.IsZero() {
			t.Errorf("a partition with no date entered the daily series: %+v", day)
		}
	}

	// The daily series describes a subset of the database — the date-partitioned tables —
	// so it can never exceed the whole.
	var total uint64
	for _, day := range storage.Daily {
		total += day.Bytes
	}
	if total > storage.DatabaseBytes {
		t.Errorf("daily bytes (%d) exceed the database total (%d)", total, storage.DatabaseBytes)
	}
}
