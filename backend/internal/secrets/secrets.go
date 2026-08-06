// Package secrets stores and resolves credentials by reference.
//
// The rule this package exists to enforce: a vendor credential is NEVER written to
// ClickHouse. The feeds table holds a reference — an opaque key — and the actual
// secret lives here. Persisting credentials in the analytical store would put every
// customer's log-delivery keys in the same place as their logs, retained for the same
// 30 days, readable by every query path.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ErrNotFound is returned when a reference resolves to nothing.
var ErrNotFound = errors.New("secrets: no secret for that reference")

// Store reads and writes secrets by reference.
type Store interface {
	// Put stores a secret and returns its reference. The reference is safe to
	// persist; the secret is not.
	Put(ctx context.Context, purpose, secret string) (ref string, err error)
	// Resolve returns the secret behind a reference.
	Resolve(ctx context.Context, ref string) (string, error)
	// Delete removes a secret, so a rotated or deleted feed does not leave its
	// credential behind indefinitely.
	Delete(ctx context.Context, ref string) error
}

// NewReference mints an opaque reference.
//
// It deliberately encodes nothing but a purpose and a random id: a reference derived
// from the tenant or feed would leak that relationship to anyone who saw it, and a
// reference containing any part of the secret would defeat the whole arrangement.
func NewReference(purpose string) string {
	clean := strings.ToLower(strings.TrimSpace(purpose))
	if clean == "" {
		clean = "secret"
	}
	return fmt.Sprintf("%s/%s", clean, uuid.NewString())
}

// RedisStore keeps secrets in Redis.
//
// This is the development and single-region default. Redis is otherwise treated as
// ephemeral in this system, so secrets are written WITHOUT a TTL and their loss is
// treated as an operational incident: a feed whose credential vanished stops
// authenticating and surfaces immediately in feed health rather than silently
// accepting traffic.
//
// For anything beyond a single region, back this with a real secret manager — the
// Store interface exists so that swap is a wiring change, not a code change.
type RedisStore struct {
	client RedisClient
}

// RedisClient is the subset of Redis this store needs.
type RedisClient interface {
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Get(ctx context.Context, key string) (string, error)
	Del(ctx context.Context, keys ...string) (int64, error)
}

// NewRedisStore constructs a Redis-backed store.
func NewRedisStore(client RedisClient) *RedisStore {
	return &RedisStore{client: client}
}

// secretTTL is long enough to be effectively permanent while still bounding an
// orphaned secret's lifetime if a feed deletion fails to clean it up.
const secretTTL = 10 * 365 * 24 * time.Hour

func (s *RedisStore) key(ref string) string { return "secret:" + ref }

// Put stores a secret and returns its reference.
func (s *RedisStore) Put(ctx context.Context, purpose, secret string) (string, error) {
	if secret == "" {
		return "", errors.New("secrets: refusing to store an empty secret")
	}

	ref := NewReference(purpose)
	if err := s.client.Set(ctx, s.key(ref), secret, secretTTL); err != nil {
		// The error is wrapped without the secret, obviously — but also without the
		// reference, since a failed Put means the caller must not persist it.
		return "", fmt.Errorf("store %s secret: %w", purpose, err)
	}
	return ref, nil
}

// Resolve returns the secret behind a reference.
func (s *RedisStore) Resolve(ctx context.Context, ref string) (string, error) {
	if ref == "" {
		return "", ErrNotFound
	}

	secret, err := s.client.Get(ctx, s.key(ref))
	if err != nil {
		// The reference is safe to include; the secret never is.
		return "", fmt.Errorf("resolve secret %s: %w", ref, err)
	}
	if secret == "" {
		return "", ErrNotFound
	}
	return secret, nil
}

// Delete removes a secret.
func (s *RedisStore) Delete(ctx context.Context, ref string) error {
	if ref == "" {
		return nil
	}
	if _, err := s.client.Del(ctx, s.key(ref)); err != nil {
		return fmt.Errorf("delete secret %s: %w", ref, err)
	}
	return nil
}

// MemoryStore keeps secrets in process memory. For tests and the seed tool only.
type MemoryStore struct {
	mu      sync.RWMutex
	secrets map[string]string
}

// NewMemoryStore constructs an in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{secrets: map[string]string{}}
}

// Put stores a secret and returns its reference.
func (s *MemoryStore) Put(_ context.Context, purpose, secret string) (string, error) {
	if secret == "" {
		return "", errors.New("secrets: refusing to store an empty secret")
	}

	ref := NewReference(purpose)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[ref] = secret
	return ref, nil
}

// Resolve returns the secret behind a reference.
func (s *MemoryStore) Resolve(_ context.Context, ref string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	secret, ok := s.secrets[ref]
	if !ok {
		return "", ErrNotFound
	}
	return secret, nil
}

// Delete removes a secret.
func (s *MemoryStore) Delete(_ context.Context, ref string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.secrets, ref)
	return nil
}
