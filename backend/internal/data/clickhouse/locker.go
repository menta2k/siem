package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrLockUnavailable is returned when another writer holds the lock.
var ErrLockUnavailable = errors.New("clickhouse: entity is being modified by another request")

// Locker serialises control-plane writes on a single entity key.
//
// This exists because ClickHouse has no unique constraints and no transactions
// (research.md R6). Every control-plane write funnels through one path that takes a
// short lock on the entity key, so concurrent creates of the same email or feed
// cannot both pass their uniqueness check and both insert.
//
// It is a mitigation, not a guarantee: if Redis is unavailable the lock cannot be
// taken and the write is refused rather than racing.
type Locker interface {
	// Lock acquires the named lock and returns a release function. The release
	// function is safe to call more than once.
	Lock(ctx context.Context, key string) (release func(), err error)
}

// SetNXLocker implements Locker over a Redis-style SETNX primitive.
type SetNXLocker struct {
	store    LockStore
	ttl      time.Duration
	attempts int
	backoff  time.Duration
}

// LockStore is the subset of Redis the locker needs.
type LockStore interface {
	SetNX(ctx context.Context, key, value string, ttl time.Duration) (bool, error)
	Del(ctx context.Context, keys ...string) (int64, error)
}

// NewLocker builds a locker.
//
// The TTL is a safety valve: if a process dies holding a lock, the key expires rather
// than blocking that entity's writes forever. It must comfortably exceed the longest
// write it guards.
func NewLocker(store LockStore) *SetNXLocker {
	return &SetNXLocker{
		store:    store,
		ttl:      10 * time.Second,
		attempts: 20,
		backoff:  50 * time.Millisecond,
	}
}

// Lock acquires the named lock, retrying briefly before giving up.
func (l *SetNXLocker) Lock(ctx context.Context, key string) (func(), error) {
	fullKey := "lock:" + key

	for attempt := range l.attempts {
		acquired, err := l.store.SetNX(ctx, fullKey, "held", l.ttl)
		if err != nil {
			return nil, fmt.Errorf("acquire lock %s: %w", key, err)
		}
		if acquired {
			return l.releaser(fullKey), nil
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("acquire lock %s: %w", key, ctx.Err())
		case <-time.After(l.backoff * time.Duration(attempt+1)):
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrLockUnavailable, key)
}

func (l *SetNXLocker) releaser(fullKey string) func() {
	var released bool
	return func() {
		if released {
			return
		}
		released = true

		// A fresh context: the request's context may already be cancelled, and
		// failing to release would leave the entity locked until the TTL expires.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = l.store.Del(ctx, fullKey)
	}
}

// NoopLocker performs no locking. It exists only for single-writer contexts such as
// the seed tool, and must never be used to serve requests.
type NoopLocker struct{}

// Lock returns immediately without acquiring anything.
func (NoopLocker) Lock(context.Context, string) (func(), error) {
	return func() {}, nil
}

// isNoRows reports whether an error means "no rows matched".
//
// The ClickHouse driver reports this as a plain error rather than a typed sentinel,
// so string matching is the available option. It is centralised here so the fragility
// lives in exactly one place.
func isNoRows(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no rows") || strings.Contains(msg, "sql: no rows in result set")
}
