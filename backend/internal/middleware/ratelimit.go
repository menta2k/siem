package middleware

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"

	"github.com/menta2k/siem/internal/tenancy"
)

// Counter is the shared counting primitive the limiter needs. Backed by Redis in
// production; the narrow interface keeps the limiter testable without it.
type Counter interface {
	Incr(ctx context.Context, key string, ttl time.Duration) (int64, error)
}

// LimitScope describes one bucket a request is charged against.
type LimitScope struct {
	// Name labels the metric and the returned Retry-After reason.
	Name string
	// Limit is the number of requests permitted per Window.
	Limit int64
	// Window is the fixed period the limit applies over.
	Window time.Duration
}

// RateLimiter enforces per-tenant and per-credential limits.
//
// The algorithm is a fixed window, chosen over a sliding window deliberately: it
// costs one Redis INCR per request, and at ingest volume the extra round trips of a
// sliding window would themselves become the bottleneck. The cost is that a burst
// straddling a window boundary can briefly reach 2x the limit, which the quota
// accounting downstream absorbs.
type RateLimiter struct {
	counter Counter
	scopes  []LimitScope
}

// NewRateLimiter builds a limiter for the given scopes.
func NewRateLimiter(counter Counter, scopes ...LimitScope) (*RateLimiter, error) {
	if counter == nil {
		return nil, fmt.Errorf("middleware: a counter is required to rate limit")
	}
	for _, s := range scopes {
		if s.Limit <= 0 || s.Window <= 0 {
			return nil, fmt.Errorf("middleware: scope %q needs a positive limit and window", s.Name)
		}
	}
	return &RateLimiter{counter: counter, scopes: append([]LimitScope{}, scopes...)}, nil
}

// Allow charges a request against every scope, returning the first that is exhausted.
func (rl *RateLimiter) Allow(
	ctx context.Context, subject string,
) (retryAfter time.Duration, err error) {
	if subject == "" {
		return 0, nil
	}

	for _, scope := range rl.scopes {
		bucket := time.Now().UTC().Truncate(scope.Window).Unix()
		key := fmt.Sprintf("ratelimit:%s:%s:%d", scope.Name, subject, bucket)

		count, err := rl.counter.Incr(ctx, key, scope.Window+time.Second)
		if err != nil {
			// Fail OPEN here, unlike token revocation. A Redis outage must not stop
			// a customer's log ingestion; the per-feed quota accounting and the
			// broker's own backpressure remain as the backstop.
			return 0, fmt.Errorf("rate limit check for %s: %w", scope.Name, err)
		}
		if count > scope.Limit {
			ObserveRateLimited(scope.Name)
			return scope.Window, nil
		}
	}
	return 0, nil
}

// Middleware enforces the limit, charging the tenant when authenticated and falling
// back to the transport-supplied subject otherwise.
func (rl *RateLimiter) Middleware(log Logger) middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (any, error) {
			subject := rateLimitSubject(ctx)

			retryAfter, err := rl.Allow(ctx, subject)
			if err != nil {
				// Failing open is a decision, so it is recorded rather than silent.
				log.Warn(ctx, "rate limiter unavailable, allowing request", "cause", err.Error())
				return handler(ctx, req)
			}
			if retryAfter > 0 {
				setRetryAfter(ctx, retryAfter)
				return nil, RateLimited()
			}
			return handler(ctx, req)
		}
	}
}

// rateLimitSubject picks the identity a request is charged to.
func rateLimitSubject(ctx context.Context) string {
	if t, err := tenancy.FromContext(ctx); err == nil {
		return "tenant:" + t.ID.String()
	}
	// Pre-authentication (login, ingest with a feed token) there is no tenant yet, so
	// charge the peer address to bound credential-stuffing attempts.
	if tr, ok := transport.FromServerContext(ctx); ok {
		if peer := tr.RequestHeader().Get("X-Forwarded-For"); peer != "" {
			return "peer:" + peer
		}
		return "operation:" + tr.Operation()
	}
	return ""
}

// setRetryAfter tells the caller when to come back. A 429 without it invites an
// immediate retry, which makes the overload worse.
func setRetryAfter(ctx context.Context, d time.Duration) {
	if tr, ok := transport.FromServerContext(ctx); ok {
		tr.ReplyHeader().Set("Retry-After", strconv.Itoa(int(d.Seconds())))
	}
}
