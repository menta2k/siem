package service

import (
	"testing"
	"time"

	chdata "github.com/menta2k/siem/internal/data/clickhouse"
)

var storageNow = time.Date(2026, 8, 10, 9, 0, 0, 0, time.UTC)

func day(offset int, bytes uint64) chdata.DayBytes {
	return chdata.DayBytes{
		Day:   storageNow.UTC().Truncate(24*time.Hour).AddDate(0, 0, offset),
		Bytes: bytes,
	}
}

const gib = uint64(1) << 30

func TestProjectDividesFreeSpaceByTheDailyRate(t *testing.T) {
	storage := chdata.Storage{
		DiskFreeBytes: 100 * gib,
		Daily: []chdata.DayBytes{
			day(-3, 10*gib),
			day(-2, 10*gib),
			day(-1, 10*gib),
		},
	}

	got := project(storage, storageNow)

	if got.BytesPerDay != 10*gib {
		t.Errorf("bytes/day = %d, want %d", got.BytesPerDay, 10*gib)
	}
	if got.MeasuredDays != 3 {
		t.Errorf("measured days = %d, want 3", got.MeasuredDays)
	}
	if got.DaysRemaining != 10 {
		t.Errorf("days remaining = %v, want 10", got.DaysRemaining)
	}
	if got.Steady {
		t.Error("a growing platform was reported as steady")
	}
}

// The panel exists to warn EARLY, so an estimate that is optimistic by construction is
// worse than none. Today's partition is still being written: averaging a part-day
// against whole ones would halve the apparent rate and double the apparent headroom.
func TestProjectIgnoresTodaysPartialDay(t *testing.T) {
	storage := chdata.Storage{
		DiskFreeBytes: 100 * gib,
		Daily: []chdata.DayBytes{
			day(-2, 10*gib),
			day(-1, 10*gib),
			day(0, 1*gib), // today, three hours in
		},
	}

	got := project(storage, storageNow)

	if got.BytesPerDay != 10*gib {
		t.Errorf("bytes/day = %d, want %d — today's partial partition must not count",
			got.BytesPerDay, 10*gib)
	}
	if got.MeasuredDays != 2 {
		t.Errorf("measured days = %d, want 2", got.MeasuredDays)
	}
}

// A vendor whose clock runs fast writes a partition dated tomorrow. It is not a whole
// day either, and counting it would drag the average down.
func TestProjectIgnoresAPartitionDatedAhead(t *testing.T) {
	storage := chdata.Storage{
		DiskFreeBytes: 50 * gib,
		Daily: []chdata.DayBytes{
			day(-1, 10*gib),
			day(1, 1*gib),
		},
	}

	got := project(storage, storageNow)

	if got.MeasuredDays != 1 || got.BytesPerDay != 10*gib {
		t.Errorf("got %d days at %d bytes, want 1 day at %d",
			got.MeasuredDays, got.BytesPerDay, 10*gib)
	}
}

// A brand-new deployment has nothing whole to measure. It must say so rather than
// divide by zero and report an infinite or nonsensical horizon.
func TestProjectReportsSteadyWhenThereIsNothingToMeasure(t *testing.T) {
	tests := map[string]chdata.Storage{
		"no partitions at all": {DiskFreeBytes: 100 * gib},
		"only today":           {DiskFreeBytes: 100 * gib, Daily: []chdata.DayBytes{day(0, 5*gib)}},
		"whole days holding nothing": {
			DiskFreeBytes: 100 * gib,
			Daily:         []chdata.DayBytes{day(-2, 0), day(-1, 0)},
		},
	}

	for name, storage := range tests {
		t.Run(name, func(t *testing.T) {
			got := project(storage, storageNow)

			if !got.Steady {
				t.Errorf("got %+v, want steady", got)
			}
			if got.DaysRemaining != 0 {
				t.Errorf("days remaining = %v, want 0 alongside the steady flag",
					got.DaysRemaining)
			}
		})
	}
}

// Growth is the MEAN of the days present, never the difference between the first and the
// last: differencing would read a retention expiry as a collapse in traffic and project
// that the disk is emptying.
func TestProjectAveragesRatherThanDifferences(t *testing.T) {
	storage := chdata.Storage{
		DiskFreeBytes: 60 * gib,
		Daily: []chdata.DayBytes{
			day(-3, 20*gib), // an older day, partly expired
			day(-2, 10*gib),
			day(-1, 10*gib),
		},
	}

	got := project(storage, storageNow)

	// (20 + 10 + 10) / 3 = 13.33 GiB, which is 4.5 days of the 60 GiB free.
	if got.BytesPerDay == 0 || got.DaysRemaining <= 0 {
		t.Fatalf("got %+v, want a positive rate and horizon", got)
	}
	if got.DaysRemaining > 5 {
		t.Errorf("days remaining = %v; a shrinking oldest day must not read as growth "+
			"reversing", got.DaysRemaining)
	}
}

// A full disk is the case the panel exists for. It must produce zero days, not a
// negative or absurd number.
func TestProjectReportsNoHeadroomOnAFullDisk(t *testing.T) {
	storage := chdata.Storage{
		DiskFreeBytes: 0,
		Daily:         []chdata.DayBytes{day(-2, 10*gib), day(-1, 10*gib)},
	}

	got := project(storage, storageNow)

	if got.DaysRemaining != 0 {
		t.Errorf("days remaining = %v, want 0", got.DaysRemaining)
	}
	if got.Steady {
		t.Error("a full disk with active ingestion is not steady")
	}
}
