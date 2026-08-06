package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/tenancy"
)

// ---------------------------------------------------------------- errors

func TestErrorCodesMapToExpectedStatuses(t *testing.T) {
	tests := []struct {
		name       string
		err        *Error
		wantCode   string
		wantStatus int
	}{
		{"unauthenticated", Unauthenticated("no token"), CodeUnauthenticated, http.StatusUnauthorized},
		{"permission denied", PermissionDenied(), CodePermissionDenied, http.StatusForbidden},
		{"tenant suspended", TenantSuspended(), CodeTenantSuspended, http.StatusForbidden},
		{"validation", ValidationFailed("bad"), CodeValidationFailed, http.StatusBadRequest},
		{"time range", TimeRangeRequired(), CodeTimeRangeRequired, http.StatusBadRequest},
		{"query timeout", QueryTimeout(), CodeQueryTimeout, http.StatusRequestTimeout},
		{"not found", NotFound("feed"), CodeNotFound, http.StatusNotFound},
		{"conflict", Conflict("exists"), CodeConflict, http.StatusConflict},
		{"rate limited", RateLimited(), CodeRateLimited, http.StatusTooManyRequests},
		{"payload too large", PayloadTooLarge(100), CodePayloadTooLarge,
			http.StatusRequestEntityTooLarge},
		{"internal", Internal(), CodeInternal, http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Code != tt.wantCode {
				t.Errorf("Code = %q, want %q", tt.err.Code, tt.wantCode)
			}
			if tt.err.HTTPStatus() != tt.wantStatus {
				t.Errorf("HTTPStatus() = %d, want %d", tt.err.HTTPStatus(), tt.wantStatus)
			}
		})
	}
}

// A failure to durably commit must surface as 503, never a 2xx. Acknowledging an
// event the broker did not accept loses it permanently (Constitution Principle II).
func TestBrokerUnavailableIsRetryable503(t *testing.T) {
	err := BrokerUnavailable()

	if err.HTTPStatus() != http.StatusServiceUnavailable {
		t.Errorf("HTTPStatus() = %d, want 503 so the vendor retries", err.HTTPStatus())
	}
	if err.HTTPStatus() < 400 {
		t.Fatal("a failed durable write must never map to a success status")
	}
}

// The user-facing message must not leak the internal cause.
func TestErrorMessageDoesNotLeakCause(t *testing.T) {
	internal := errors.New("clickhouse: connection refused at 10.0.0.5:9000")
	err := Internal().WithCause(internal)

	if strings.Contains(err.Message, "clickhouse") || strings.Contains(err.Message, "10.0.0.5") {
		t.Errorf("Message = %q leaks internal detail", err.Message)
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Error("Error() should carry the cause for the server-side log")
	}
	if !errors.Is(err, internal) {
		t.Error("errors.Is() should find the wrapped cause")
	}
}

// With* must not mutate the shared sentinel, or one request's details would leak
// into another's response.
func TestErrorBuildersDoNotMutateOriginal(t *testing.T) {
	base := ValidationFailed("bad input")

	withDetails := base.WithDetails(Detail{Field: "email", Issue: "required"})
	withTrace := base.WithTraceID("abc123")
	withCause := base.WithCause(errors.New("boom"))

	if len(base.Details) != 0 {
		t.Error("WithDetails() mutated the original error")
	}
	if base.TraceID != "" {
		t.Error("WithTraceID() mutated the original error")
	}
	if base.Unwrap() != nil {
		t.Error("WithCause() mutated the original error")
	}
	if len(withDetails.Details) != 1 || withTrace.TraceID != "abc123" || withCause.Unwrap() == nil {
		t.Error("builders did not apply their change to the returned copy")
	}
}

func TestAsErrorMapsUnknownErrorsToInternal(t *testing.T) {
	got := AsError(errors.New("some internal failure"))

	if got.Code != CodeInternal {
		t.Errorf("Code = %q, want %q for an unrecognized error", got.Code, CodeInternal)
	}
	if strings.Contains(got.Message, "some internal failure") {
		t.Error("AsError() exposed an unrecognized error's text to the caller")
	}
}

func TestAsErrorRecognizesKnownConditions(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"missing tenant", tenancy.ErrNoTenant, CodeUnauthenticated},
		{"deadline exceeded", context.DeadlineExceeded, CodeQueryTimeout},
		{"already an envelope", NotFound("feed"), CodeNotFound},
		{"wrapped envelope", fmt.Errorf("loading: %w", NotFound("feed")), CodeNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AsError(tt.err); got.Code != tt.want {
				t.Errorf("AsError() code = %q, want %q", got.Code, tt.want)
			}
		})
	}
}

func TestAsErrorHandlesNil(t *testing.T) {
	if got := AsError(nil); got != nil {
		t.Errorf("AsError(nil) = %v, want nil", got)
	}
}

// PermissionDenied must be uniform: a message naming the missing permission maps out
// the authorization model for an attacker.
func TestPermissionDeniedIsUniform(t *testing.T) {
	first := PermissionDenied()
	second := PermissionDenied()

	if first.Message != second.Message {
		t.Error("PermissionDenied() messages differ; they must not reveal " +
			"which permission was missing")
	}
	for _, word := range []string{"admin", "analyst", "role", "/api/"} {
		if strings.Contains(strings.ToLower(first.Message), word) {
			t.Errorf("PermissionDenied() message mentions %q, revealing policy detail", word)
		}
	}
}

// ---------------------------------------------------------------- logging

func TestRedactRemovesSensitiveValues(t *testing.T) {
	kv := []any{
		"password", "hunter2",
		"access_token", "eyJhbGci...",
		"refresh_token", "secret-refresh",
		"mfa_secret", "JBSWY3DPEHPK3PXP",
		"Authorization", "Bearer abc",
		"user_email", "analyst@example.com",
		"count", 42,
	}

	got := redact(kv)

	for i := 0; i+1 < len(got); i += 2 {
		key, ok := got[i].(string)
		if !ok {
			continue
		}
		if redactedKeys[strings.ToLower(key)] {
			if got[i+1] != "[REDACTED]" {
				t.Errorf("key %q was not redacted, value = %v", key, got[i+1])
			}
		}
	}
	if got[11] != "analyst@example.com" {
		t.Error("a non-sensitive value was redacted")
	}
	if got[13] != 42 {
		t.Error("a non-sensitive value was redacted")
	}
}

func TestRedactDoesNotMutateInput(t *testing.T) {
	kv := []any{"password", "hunter2"}
	_ = redact(kv)

	if kv[1] != "hunter2" {
		t.Error("redact() mutated the caller's slice")
	}
}

func TestRedactHandlesOddLengthAndNonStringKeys(t *testing.T) {
	// Must not panic on malformed input — a logging call is not worth a crash.
	_ = redact([]any{"password"})
	_ = redact([]any{42, "value"})
	_ = redact(nil)
}

// A crafted trace header must not inject newlines or unbounded text into the logs.
func TestIsValidTraceIDRejectsInjection(t *testing.T) {
	valid := []string{uuid.NewString(), "abc123", "DEADBEEF-0000"}
	invalid := []string{
		"", strings.Repeat("a", 65),
		"trace\nINJECTED level=error", "trace id", "trace;drop", "../../etc/passwd", "zzz",
	}

	for _, id := range valid {
		if !isValidTraceID(id) {
			t.Errorf("isValidTraceID(%q) = false, want true", id)
		}
	}
	for _, id := range invalid {
		if isValidTraceID(id) {
			t.Errorf("isValidTraceID(%q) = true, want false", id)
		}
	}
}

func TestTraceIDContextRoundTrip(t *testing.T) {
	if got := TraceIDFromContext(context.Background()); got != "" {
		t.Errorf("TraceIDFromContext() on a bare context = %q, want empty", got)
	}

	ctx := WithTraceID(context.Background(), "abc123")
	if got := TraceIDFromContext(ctx); got != "abc123" {
		t.Errorf("TraceIDFromContext() = %q, want %q", got, "abc123")
	}
}

// ---------------------------------------------------------------- rate limiting

type fakeCounter struct {
	mu     sync.Mutex
	counts map[string]int64
	err    error
}

func newFakeCounter() *fakeCounter { return &fakeCounter{counts: map[string]int64{}} }

func (f *fakeCounter) Incr(_ context.Context, key string, _ time.Duration) (int64, error) {
	if f.err != nil {
		return 0, f.err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counts[key]++
	return f.counts[key], nil
}

func TestRateLimiterAllowsUpToLimitThenRejects(t *testing.T) {
	counter := newFakeCounter()
	rl, err := NewRateLimiter(counter, LimitScope{Name: "tenant", Limit: 3, Window: time.Minute})
	if err != nil {
		t.Fatalf("NewRateLimiter() error = %v", err)
	}
	ctx := context.Background()

	for i := 1; i <= 3; i++ {
		retryAfter, err := rl.Allow(ctx, "tenant:acme")
		if err != nil {
			t.Fatalf("Allow() call %d error = %v", i, err)
		}
		if retryAfter != 0 {
			t.Fatalf("Allow() rejected call %d, which is within the limit of 3", i)
		}
	}

	retryAfter, err := rl.Allow(ctx, "tenant:acme")
	if err != nil {
		t.Fatalf("Allow() error = %v", err)
	}
	if retryAfter == 0 {
		t.Error("Allow() permitted a 4th call against a limit of 3")
	}
}

// Exhausting one subject's bucket must not affect another's.
func TestRateLimiterIsolatesSubjects(t *testing.T) {
	counter := newFakeCounter()
	rl, err := NewRateLimiter(counter, LimitScope{Name: "tenant", Limit: 1, Window: time.Minute})
	if err != nil {
		t.Fatalf("NewRateLimiter() error = %v", err)
	}
	ctx := context.Background()

	if _, err := rl.Allow(ctx, "tenant:a"); err != nil {
		t.Fatalf("Allow() error = %v", err)
	}
	if retryAfter, _ := rl.Allow(ctx, "tenant:a"); retryAfter == 0 { //nolint:errcheck
		t.Fatal("tenant:a should be exhausted")
	}
	if retryAfter, _ := rl.Allow(ctx, "tenant:b"); retryAfter != 0 { //nolint:errcheck
		t.Error("tenant:b was limited by tenant:a's usage; buckets must be isolated")
	}
}

// Unlike token revocation, the limiter fails OPEN: a Redis outage must not stop a
// customer's log ingestion. The error is surfaced so the caller can log the decision.
func TestRateLimiterSurfacesStoreFailureRatherThanBlocking(t *testing.T) {
	counter := newFakeCounter()
	counter.err = errors.New("redis unavailable")
	rl, err := NewRateLimiter(counter, LimitScope{Name: "tenant", Limit: 1, Window: time.Minute})
	if err != nil {
		t.Fatalf("NewRateLimiter() error = %v", err)
	}

	retryAfter, err := rl.Allow(context.Background(), "tenant:acme")
	if err == nil {
		t.Fatal("Allow() hid a counter failure; the caller must be able to log the fail-open decision")
	}
	if retryAfter != 0 {
		t.Error("Allow() returned a retry-after on a store failure; it must fail open")
	}
}

func TestNewRateLimiterRejectsInvalidConfiguration(t *testing.T) {
	valid := LimitScope{Name: "t", Limit: 1, Window: time.Minute}
	if _, err := NewRateLimiter(nil, valid); err == nil {
		t.Error("NewRateLimiter() accepted a nil counter")
	}
	counter := newFakeCounter()
	for _, scope := range []LimitScope{
		{Name: "zero limit", Limit: 0, Window: time.Minute},
		{Name: "negative limit", Limit: -1, Window: time.Minute},
		{Name: "zero window", Limit: 10, Window: 0},
	} {
		if _, err := NewRateLimiter(counter, scope); err == nil {
			t.Errorf("NewRateLimiter() accepted scope %q", scope.Name)
		}
	}
}

func TestRateLimiterIgnoresEmptySubject(t *testing.T) {
	rl, err := NewRateLimiter(newFakeCounter(),
		LimitScope{Name: "tenant", Limit: 1, Window: time.Minute})
	if err != nil {
		t.Fatalf("NewRateLimiter() error = %v", err)
	}

	for range 5 {
		if retryAfter, err := rl.Allow(context.Background(), ""); err != nil || retryAfter != 0 {
			t.Fatal("Allow() with no subject should not charge a bucket")
		}
	}
}

// Every scope is charged, so exhausting a narrow one limits even when a wide one has room.
func TestRateLimiterEnforcesEveryScope(t *testing.T) {
	counter := newFakeCounter()
	rl, err := NewRateLimiter(counter,
		LimitScope{Name: "burst", Limit: 2, Window: time.Second},
		LimitScope{Name: "sustained", Limit: 1000, Window: time.Hour},
	)
	if err != nil {
		t.Fatalf("NewRateLimiter() error = %v", err)
	}
	ctx := context.Background()

	for range 2 {
		if _, err := rl.Allow(ctx, "tenant:acme"); err != nil {
			t.Fatalf("Allow() error = %v", err)
		}
	}

	if retryAfter, _ := rl.Allow(ctx, "tenant:acme"); retryAfter == 0 { //nolint:errcheck
		t.Error("the narrow burst scope was not enforced")
	}
}
