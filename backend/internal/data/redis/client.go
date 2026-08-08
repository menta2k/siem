// Package redis provides ephemeral state: session revocation, the ingest dedup
// window, rate-limit counters, correlation window state, and per-entity write locks.
//
// Redis is NEVER a system of record. Every key here is reconstructible from
// ClickHouse or is safe to lose (at worst a duplicate is re-counted or a lock is
// re-acquired). Anything whose loss would lose customer data belongs in ClickHouse.
package redis

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/menta2k/siem/internal/conf"
	"github.com/menta2k/siem/internal/correlate/window"
)

// ErrNotFound is returned when a key is absent, so callers do not depend on the
// driver's own sentinel value.
var ErrNotFound = errors.New("redis: key not found")

// Client wraps the Redis driver with the platform's key conventions.
type Client struct {
	rdb *goredis.Client
}

// New opens a connection pool and verifies reachability.
func New(ctx context.Context, cfg conf.Redis) (*Client, error) {
	rdb := goredis.NewClient(&goredis.Options{
		Addr:            cfg.Addr,
		Password:        cfg.Password,
		DB:              cfg.DB,
		PoolSize:        64,
		MinIdleConns:    8,
		ConnMaxIdleTime: 5 * time.Minute,
		DialTimeout:     5 * time.Second,
		ReadTimeout:     3 * time.Second,
		WriteTimeout:    3 * time.Second,
	})

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := rdb.Ping(pingCtx).Err(); err != nil {
		if closeErr := rdb.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
		return nil, fmt.Errorf("ping redis at %s: %w", cfg.Addr, err)
	}

	return &Client{rdb: rdb}, nil
}

// Raw exposes the underlying client for operations not wrapped here.
func (c *Client) Raw() *goredis.Client { return c.rdb }

// Close releases the pool.
func (c *Client) Close() error {
	if err := c.rdb.Close(); err != nil {
		return fmt.Errorf("close redis: %w", err)
	}
	return nil
}

// Ping reports reachability. Used by /readyz.
func (c *Client) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := c.rdb.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis unreachable: %w", err)
	}
	return nil
}

// SetNX sets a key only if absent, reporting whether it was set. This is the
// primitive behind ingest deduplication: the first writer of an event id wins and
// every later delivery is reported as a suppressed duplicate.
func (c *Client) SetNX(ctx context.Context, key, value string, ttl time.Duration) (bool, error) {
	ok, err := c.rdb.SetNX(ctx, key, value, ttl).Result()
	if err != nil {
		return false, fmt.Errorf("redis setnx %s: %w", key, err)
	}
	return ok, nil
}

// Lookup reads a key, reporting whether it exists instead of failing when it does not.
//
// Get treats absence as an error, which suits callers that already know a key is there.
// The correlation identity lookup is the opposite case: it asks about identifiers that
// have usually never been claimed, so a missing key is the expected answer rather than
// a fault.
func (c *Client) Lookup(ctx context.Context, key string) (string, bool, error) {
	value, err := c.Get(ctx, key)
	if errors.Is(err, ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

// Get reads a key, returning ErrNotFound when absent.
func (c *Client) Get(ctx context.Context, key string) (string, error) {
	v, err := c.rdb.Get(ctx, key).Result()
	if errors.Is(err, goredis.Nil) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("redis get %s: %w", key, err)
	}
	return v, nil
}

// Set writes a key with a TTL. A zero TTL is rejected: an unbounded key in an
// ephemeral store is a memory leak waiting for a traffic spike.
func (c *Client) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("redis set %s: a positive TTL is required", key)
	}
	if err := c.rdb.Set(ctx, key, value, ttl).Err(); err != nil {
		return fmt.Errorf("redis set %s: %w", key, err)
	}
	return nil
}

// Del removes keys, reporting how many existed.
func (c *Client) Del(ctx context.Context, keys ...string) (int64, error) {
	n, err := c.rdb.Del(ctx, keys...).Result()
	if err != nil {
		return 0, fmt.Errorf("redis del: %w", err)
	}
	return n, nil
}

// Incr increments a counter and applies the TTL on first creation. Used for
// per-tenant and per-credential rate limiting.
func (c *Client) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	pipe := c.rdb.TxPipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, fmt.Errorf("redis incr %s: %w", key, err)
	}
	return incr.Val(), nil
}

// IncrBy adds delta to a counter and applies the TTL on first creation.
//
// Quotas are expressed in events and bytes, not in requests, so they must accumulate
// by the actual amount. Counting calls instead would let one 50,000-event delivery
// consume the same budget as a single event.
func (c *Client) IncrBy(
	ctx context.Context, key string, delta int64, ttl time.Duration,
) (int64, error) {
	pipe := c.rdb.TxPipeline()
	incr := pipe.IncrBy(ctx, key, delta)
	pipe.Expire(ctx, key, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, fmt.Errorf("redis incrby %s: %w", key, err)
	}
	return incr.Val(), nil
}

// Exists reports how many of the given keys are present.
func (c *Client) Exists(ctx context.Context, keys ...string) (int64, error) {
	n, err := c.rdb.Exists(ctx, keys...).Result()
	if err != nil {
		return 0, fmt.Errorf("redis exists: %w", err)
	}
	return n, nil
}

// RPush appends a value to a list and applies the TTL on every write.
//
// The TTL is refreshed rather than set once, because a correlation window must stay
// alive for the lateness bound measured from its LAST member, not its first. Setting
// it only on creation would expire a bucket that is still receiving events.
func (c *Client) RPush(ctx context.Context, key, value string, ttl time.Duration) (int64, error) {
	if ttl <= 0 {
		return 0, fmt.Errorf("redis rpush %s: a positive TTL is required", key)
	}
	pipe := c.rdb.TxPipeline()
	push := pipe.RPush(ctx, key, value)
	pipe.Expire(ctx, key, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, fmt.Errorf("redis rpush %s: %w", key, err)
	}
	return push.Val(), nil
}

// pipelineChunk bounds how many entries share one round trip.
//
// A whole Kafka fetch can be thousands of records, and each entry costs TWO commands
// (the write and its TTL refresh). Pipelining all of them into one Exec builds a single
// enormous request whose response cannot arrive inside the client's 3s ReadTimeout —
// which manifests as `i/o timeout` under sustained load, not in any short test.
// Chunking keeps the round trips ~1/500th of the per-event cost while keeping each one
// small enough to complete comfortably.
const pipelineChunk = 500

// RPushMany appends many values across many keys, pipelined in bounded chunks.
//
// Correlation files every event under up to two keys and a schedule, so a per-call
// round trip puts three network hops on every event. Each key still has its TTL
// refreshed on write, so a window stays alive for the lateness bound measured from its
// LAST member.
func (c *Client) RPushMany(ctx context.Context, entries []window.ListEntry) error {
	for _, entry := range entries {
		if entry.TTL <= 0 {
			return fmt.Errorf("redis rpush %s: a positive TTL is required", entry.Key)
		}
	}

	for chunk := range slices.Chunk(entries, pipelineChunk) {
		pipe := c.rdb.Pipeline()
		for _, entry := range chunk {
			pipe.RPush(ctx, entry.Key, entry.Value)
			pipe.Expire(ctx, entry.Key, entry.TTL)
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return fmt.Errorf("redis rpush %d entries: %w", len(chunk), err)
		}
	}
	return nil
}

// ZAddMany scores many members, pipelined in bounded chunks for the same reason.
func (c *Client) ZAddMany(ctx context.Context, entries []window.ScoreEntry) error {
	for _, entry := range entries {
		if entry.TTL <= 0 {
			return fmt.Errorf("redis zadd %s: a positive TTL is required", entry.Key)
		}
	}

	for chunk := range slices.Chunk(entries, pipelineChunk) {
		pipe := c.rdb.Pipeline()
		for _, entry := range chunk {
			pipe.ZAdd(ctx, entry.Key, goredis.Z{Score: entry.Score, Member: entry.Member})
			pipe.Expire(ctx, entry.Key, entry.TTL)
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return fmt.Errorf("redis zadd %d entries: %w", len(chunk), err)
		}
	}
	return nil
}

// LRange returns every element of a list. A missing key yields an empty slice, not an
// error: an expired correlation window is an ordinary outcome, not a fault.
func (c *Client) LRange(ctx context.Context, key string) ([]string, error) {
	values, err := c.rdb.LRange(ctx, key, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("redis lrange %s: %w", key, err)
	}
	return values, nil
}

// ZAdd schedules a member at a score, applying the TTL to the whole set.
func (c *Client) ZAdd(
	ctx context.Context, key, member string, score float64, ttl time.Duration,
) error {
	if ttl <= 0 {
		return fmt.Errorf("redis zadd %s: a positive TTL is required", key)
	}
	pipe := c.rdb.TxPipeline()
	pipe.ZAdd(ctx, key, goredis.Z{Score: score, Member: member})
	pipe.Expire(ctx, key, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redis zadd %s: %w", key, err)
	}
	return nil
}

// ZPopDue atomically removes and returns up to limit members scored at or below max.
//
// Pop rather than range-then-delete: several correlation workers read the same
// schedule, and a non-atomic read would hand the same closed window to two of them,
// producing two records for one request.
func (c *Client) ZPopDue(
	ctx context.Context, key string, max float64, limit int64,
) ([]string, error) {
	const script = `
local due = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', ARGV[1], 'LIMIT', 0, ARGV[2])
if #due > 0 then redis.call('ZREM', KEYS[1], unpack(due)) end
return due`
	values, err := goredis.NewScript(script).Run(ctx, c.rdb, []string{key}, max, limit).StringSlice()
	if err != nil {
		return nil, fmt.Errorf("redis zpopdue %s: %w", key, err)
	}
	return values, nil
}
