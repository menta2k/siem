package auth

import (
	"context"
	"fmt"
	"time"
)

// RevocationCache is the ephemeral store revocations live in.
type RevocationCache interface {
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Exists(ctx context.Context, keys ...string) (int64, error)
}

// RedisRevocations records logged-out refresh tokens.
//
// Only refresh tokens are tracked. Access tokens are deliberately not revocable: doing
// so would put a Redis read on every authenticated request, and their lifetime is
// already short enough that the exposure window is bounded. Logout invalidates the
// refresh token, so the session cannot be extended past the current access token.
//
// Entries expire with the token itself. A revocation list that outlives the tokens it
// names grows without bound and never rejects anything a signature check would not
// have rejected anyway.
type RedisRevocations struct {
	cache RevocationCache
	ttl   time.Duration
}

// NewRedisRevocations builds the store. The TTL should be the refresh-token lifetime.
func NewRedisRevocations(cache RevocationCache, refreshTTL time.Duration) *RedisRevocations {
	if refreshTTL <= 0 {
		refreshTTL = 30 * 24 * time.Hour
	}
	return &RedisRevocations{cache: cache, ttl: refreshTTL}
}

// Revoke marks a token id unusable.
func (r *RedisRevocations) Revoke(ctx context.Context, tokenID string, ttl time.Duration) error {
	if tokenID == "" {
		return fmt.Errorf("auth: cannot revoke an empty token id")
	}
	if ttl <= 0 {
		ttl = r.ttl
	}
	return r.cache.Set(ctx, revocationKey(tokenID), "1", ttl)
}

// IsRevoked reports whether a token id has been revoked.
//
// A store failure returns the error rather than false. Treating an unreachable Redis
// as "not revoked" would silently re-enable every logged-out session for the duration
// of the outage, which is the opposite of what a revocation list is for.
func (r *RedisRevocations) IsRevoked(ctx context.Context, tokenID string) (bool, error) {
	if tokenID == "" {
		return true, nil
	}
	n, err := r.cache.Exists(ctx, revocationKey(tokenID))
	if err != nil {
		return false, fmt.Errorf("check revocation for %s: %w", tokenID, err)
	}
	return n > 0, nil
}

func revocationKey(tokenID string) string { return "auth:revoked:" + tokenID }
