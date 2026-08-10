package clickhouse

import (
	"context"
	"fmt"
	"time"
)

// TableSize is one table's footprint.
type TableSize struct {
	Table string
	Bytes uint64
	Rows  uint64
}

// DayBytes is one day's partitions across every table.
type DayBytes struct {
	Day   time.Time
	Bytes uint64
}

// Storage is what the disk-headroom panel is computed from.
type Storage struct {
	DiskTotalBytes uint64
	DiskFreeBytes  uint64
	DatabaseBytes  uint64
	Tables         []TableSize
	// Daily is oldest-first, one entry per date-partitioned day present on disk.
	Daily []DayBytes
}

// StorageRepo reads ClickHouse's own accounting of what it has written.
//
// NOT TENANT-SCOPED, and it cannot be: a part on disk holds rows for every tenant in the
// partition, and ClickHouse's system tables report bytes per part, not per tenant. There
// is no honest way to attribute a byte here to a customer, which is exactly why the
// endpoint above it is restricted to administrators rather than filtered.
type StorageRepo struct {
	client *Client
	// database is the schema this platform owns, so the panel reports OUR footprint
	// rather than everything the server happens to host.
	database string
}

// NewStorageRepo constructs the repository.
func NewStorageRepo(client *Client, database string) *StorageRepo {
	return &StorageRepo{client: client, database: database}
}

// Read gathers disk capacity, per-table sizes and per-day growth.
func (r *StorageRepo) Read(ctx context.Context) (Storage, error) {
	var out Storage

	if err := r.readDisk(ctx, &out); err != nil {
		return Storage{}, err
	}
	if err := r.readTables(ctx, &out); err != nil {
		return Storage{}, err
	}
	if err := r.readDaily(ctx, &out); err != nil {
		return Storage{}, err
	}
	return out, nil
}

// readDisk reads the filesystem ClickHouse stores parts on.
//
// Summed across disks because a multi-disk storage policy is one pool from the
// platform's point of view: what an operator needs is whether there is room, not which
// volume it is on.
func (r *StorageRepo) readDisk(ctx context.Context, out *Storage) error {
	rows, err := r.client.Query(ctx,
		`SELECT sum(total_space), sum(free_space) FROM system.disks`)
	if err != nil {
		return fmt.Errorf("read disk capacity: %w", err)
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		if err := rows.Scan(&out.DiskTotalBytes, &out.DiskFreeBytes); err != nil {
			return fmt.Errorf("scan disk capacity: %w", err)
		}
	}
	return rows.Err()
}

// readTables reports what each table occupies, largest first.
//
// ACTIVE parts only. Inactive parts are the pre-merge copies ClickHouse has not yet
// removed, so counting them would report a table as several times its real size for a
// few minutes after every merge — and that reading would move on its own while an
// operator watched it.
func (r *StorageRepo) readTables(ctx context.Context, out *Storage) error {
	rows, err := r.client.Query(ctx, `
		SELECT table, sum(bytes_on_disk) AS bytes, sum(rows) AS rows
		FROM system.parts
		WHERE database = ? AND active
		GROUP BY table
		ORDER BY bytes DESC`, r.database)
	if err != nil {
		return fmt.Errorf("read table sizes: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var t TableSize
		if err := rows.Scan(&t.Table, &t.Bytes, &t.Rows); err != nil {
			return fmt.Errorf("scan table size: %w", err)
		}
		out.Tables = append(out.Tables, t)
		out.DatabaseBytes += t.Bytes
	}
	return rows.Err()
}

// readDaily reports bytes per calendar day.
//
// Read from the PARTITION rather than from a timestamp column, which makes it a property
// of what is on disk rather than of what was ingested — the two differ exactly when it
// matters, because a day whose data has partly expired is smaller on disk than the events
// it once held.
//
// Only date-shaped partitions are counted. The event tables partition by day, which is
// what this measures; the small reference tables use tuple() or a month, and folding
// those into a daily series would attribute a whole table to whichever day it parsed as.
func (r *StorageRepo) readDaily(ctx context.Context, out *Storage) error {
	rows, err := r.client.Query(ctx, `
		SELECT toDate(partition) AS day, sum(bytes_on_disk) AS bytes
		FROM system.parts
		WHERE database = ? AND active AND match(partition, '^\\d{4}-\\d{2}-\\d{2}$')
		GROUP BY day
		ORDER BY day`, r.database)
	if err != nil {
		return fmt.Errorf("read daily growth: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var d DayBytes
		if err := rows.Scan(&d.Day, &d.Bytes); err != nil {
			return fmt.Errorf("scan daily growth: %w", err)
		}
		out.Daily = append(out.Daily, d)
	}
	return rows.Err()
}
