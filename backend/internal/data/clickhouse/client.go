// Package clickhouse provides the ClickHouse connection and the base repository all
// concrete repositories build on.
//
// ClickHouse is the sole persistent store of record. Two rules hold everywhere in
// this package and are enforced by review:
//
//  1. Every query is bounded — a context deadline plus a server-side
//     max_execution_time. An unbounded scan is rejected, never queued.
//  2. Every read of a ReplacingMergeTree table uses FINAL or argMax(..., version).
//     Deduplication is eventual; a naive read returns both the pre- and
//     post-amendment row and is a defect, not a race.
package clickhouse

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/menta2k/siem/internal/conf"
)

// Client wraps a ClickHouse connection with the platform's bounded-query defaults.
type Client struct {
	conn             driver.Conn
	maxExecutionTime time.Duration
}

// Options configures a Client beyond what conf provides.
type Options struct {
	// UseTLS enables TLS to the server. Required outside local development.
	UseTLS bool
	// Profile selects a ClickHouse settings profile ("default" for readers,
	// "ingest" for pipeline writers).
	Profile string
}

// profileSettings expands a profile name into the settings it stands for.
//
// The profile is applied as EXPLICIT SETTINGS rather than by sending `profile=name`.
// ClickHouse assigns profiles to users in its own configuration; `profile` is not a
// per-connection setting, and sending it is rejected outright with "Unknown setting
// 'profile'" — which takes down every service at startup.
//
// The names and values mirror deploy/clickhouse/config/limits.xml, which remains the
// server-side backstop. Duplication is the lesser evil here: the alternative is a
// separate ClickHouse user per profile, and a client that cannot state its own limits.
func profileSettings(profile string, maxExecution time.Duration) clickhouse.Settings {
	settings := clickhouse.Settings{
		"max_execution_time": int(maxExecution.Seconds()),
	}

	if profile == ProfileIngest {
		// Writers need longer-running inserts and no result caps.
		settings["max_execution_time"] = 60
		settings["max_result_rows"] = 0
		settings["async_insert"] = 1
		settings["wait_for_async_insert"] = 1
		settings["async_insert_busy_timeout_ms"] = 200
	}
	return settings
}

// The settings profiles a connection may request.
const (
	ProfileDefault = "default"
	ProfileIngest  = "ingest"
)

// New opens a pooled connection and verifies it is reachable. It returns an error
// rather than a half-usable client: a service that cannot reach its store must fail
// its readiness check, not serve empty results.
func New(ctx context.Context, cfg conf.ClickHouse, opts Options) (*Client, error) {
	settings := profileSettings(opts.Profile, cfg.MaxExecutionTime)

	chOpts := &clickhouse.Options{
		Addr: []string{cfg.Addr},
		Auth: clickhouse.Auth{
			Database: cfg.Database,
			Username: cfg.Username,
			Password: cfg.Password,
		},
		Settings:        settings,
		MaxOpenConns:    cfg.MaxOpenConns,
		MaxIdleConns:    cfg.MaxOpenConns / 4,
		ConnMaxLifetime: time.Hour,
		DialTimeout:     10 * time.Second,
		Compression:     &clickhouse.Compression{Method: clickhouse.CompressionLZ4},
	}
	if opts.UseTLS {
		chOpts.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	conn, err := clickhouse.Open(chOpts)
	if err != nil {
		return nil, fmt.Errorf("open clickhouse connection to %s: %w", cfg.Addr, err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := conn.Ping(pingCtx); err != nil {
		// The connection is already unusable; a close failure here would only mask
		// the ping error the caller actually needs.
		if closeErr := conn.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
		return nil, fmt.Errorf("ping clickhouse at %s: %w", cfg.Addr, err)
	}

	return &Client{conn: conn, maxExecutionTime: cfg.MaxExecutionTime}, nil
}

// Conn exposes the underlying connection for repositories in this package.
func (c *Client) Conn() driver.Conn { return c.conn }

// Close releases the connection pool.
func (c *Client) Close() error {
	if err := c.conn.Close(); err != nil {
		return fmt.Errorf("close clickhouse connection: %w", err)
	}
	return nil
}

// Ping reports whether the store is reachable. Used by /readyz.
func (c *Client) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := c.conn.Ping(ctx); err != nil {
		return fmt.Errorf("clickhouse unreachable: %w", err)
	}
	return nil
}

// Query runs a bounded read.
//
// The cancel function is deliberately NOT deferred here. ClickHouse rows are fetched
// lazily as the caller iterates, so cancelling when Query returns would kill the
// result set before a single row is read. Instead the cancel is tied to the rows'
// lifetime and fires on Close, which callers already defer.
func (c *Client) Query(ctx context.Context, query string, args ...any) (driver.Rows, error) {
	boundCtx, cancel := c.bound(ctx)

	rows, err := c.conn.Query(boundCtx, query, args...)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("clickhouse query: %w", err)
	}
	return &cancellingRows{Rows: rows, cancel: cancel}, nil
}

// cancellingRows releases the query's context when the result set is closed.
type cancellingRows struct {
	driver.Rows
	cancel context.CancelFunc
}

func (r *cancellingRows) Close() error {
	defer r.cancel()
	if err := r.Rows.Close(); err != nil {
		return fmt.Errorf("close clickhouse rows: %w", err)
	}
	return nil
}

// QueryRow runs a bounded single-row read.
//
// The row is scanned by the caller after this returns, so the context must outlive
// the call. It is bounded by the server-side max_execution_time and by the caller's
// own deadline rather than by a cancel here.
func (c *Client) QueryRow(ctx context.Context, query string, args ...any) driver.Row {
	return c.conn.QueryRow(ctx, query, args...)
}

// Select runs a bounded read into dest.
func (c *Client) Select(ctx context.Context, dest any, query string, args ...any) error {
	ctx, cancel := c.bound(ctx)
	defer cancel()

	if err := c.conn.Select(ctx, dest, query, args...); err != nil {
		return fmt.Errorf("clickhouse select: %w", err)
	}
	return nil
}

// Exec runs a statement that returns no rows.
func (c *Client) Exec(ctx context.Context, query string, args ...any) error {
	if err := c.conn.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("clickhouse exec: %w", err)
	}
	return nil
}

// PrepareBatch starts a batch insert. Batching is how this system writes: per-row
// inserts create one part each and trigger merge storms at ingest volume.
func (c *Client) PrepareBatch(ctx context.Context, query string) (driver.Batch, error) {
	batch, err := c.conn.PrepareBatch(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("prepare clickhouse batch: %w", err)
	}
	return batch, nil
}

// bound caps the caller's deadline at the configured maximum execution time.
func (c *Client) bound(ctx context.Context) (context.Context, context.CancelFunc) {
	if c.maxExecutionTime <= 0 {
		return context.WithCancel(ctx)
	}
	deadline, ok := ctx.Deadline()
	limit := time.Now().Add(c.maxExecutionTime)
	if ok && deadline.Before(limit) {
		return context.WithCancel(ctx)
	}
	return context.WithDeadline(ctx, limit)
}
