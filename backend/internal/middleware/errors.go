// Package middleware holds the cross-cutting concerns applied to every request:
// error shaping, structured logging, metrics, and rate limiting.
//
// These are installed once on the transport, so they apply to routes added later
// without anyone remembering to opt in. That default-on property is the point.
package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-kratos/kratos/v2/middleware"

	"github.com/menta2k/siem/internal/tenancy"
)

// Stable, machine-readable error codes. These are part of the published contract:
// clients branch on them, so a code may be added but never repurposed or removed.
const (
	CodeUnauthenticated       = "UNAUTHENTICATED"
	CodeMFARequired           = "MFA_REQUIRED"
	CodePermissionDenied      = "PERMISSION_DENIED"
	CodeTenantSuspended       = "TENANT_SUSPENDED"
	CodeValidationFailed      = "VALIDATION_FAILED"
	CodeTimeRangeRequired     = "TIME_RANGE_REQUIRED"
	CodeTimeRangeTooLarge     = "TIME_RANGE_TOO_LARGE"
	CodeResultLimitExceeded   = "RESULT_LIMIT_EXCEEDED"
	CodeQueryTimeout          = "QUERY_TIMEOUT"
	CodeCursorInvalid         = "CURSOR_INVALID"
	CodeNotFound              = "NOT_FOUND"
	CodeConflict              = "CONFLICT"
	CodeRateLimited           = "RATE_LIMITED"
	CodeFeedCredentialInvalid = "FEED_CREDENTIAL_INVALID" //nolint:gosec // an error code, not a secret
	// CodeFeedCredentialUnavailable means the stored secret could not be read, so the
	// presented one could not be checked. A platform fault, not a sender fault.
	//nolint:gosec // an error code, not a secret
	CodeFeedCredentialUnavailable = "FEED_CREDENTIAL_UNAVAILABLE"
	CodeFeedTokenMismatch         = "FEED_TOKEN_MISMATCH" //nolint:gosec // an error code, not a secret
	CodePayloadTooLarge           = "PAYLOAD_TOO_LARGE"
	CodeRuleConditionInvalid      = "RULE_CONDITION_INVALID"
	CodeExportTooLarge            = "EXPORT_TOO_LARGE"
	CodeBrokerUnavailable         = "BROKER_UNAVAILABLE"
	CodeInternal                  = "INTERNAL"
)

// Detail identifies a specific field that failed validation.
type Detail struct {
	Field string `json:"field"`
	Issue string `json:"issue"`
}

// Error is the wire envelope for every non-2xx response.
//
// The split between Message and cause is deliberate: Message is shown to a user and
// must never reveal internals, while cause carries the full context to the server log
// under the same trace id. An operator correlates the two by trace id.
type Error struct {
	Code    string   `json:"code"`
	Message string   `json:"message"`
	Details []Detail `json:"details,omitempty"`
	TraceID string   `json:"trace_id,omitempty"`
	status  int
	cause   error
}

// Error implements error.
func (e *Error) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap exposes the underlying cause for errors.Is/As.
func (e *Error) Unwrap() error { return e.cause }

// HTTPStatus returns the status this error maps to.
func (e *Error) HTTPStatus() int { return e.status }

// WithCause attaches server-side context. It returns a copy — the original is not
// mutated, so a shared sentinel cannot accumulate one request's details.
func (e *Error) WithCause(cause error) *Error {
	clone := *e
	clone.cause = cause
	return &clone
}

// WithDetails attaches field-level validation detail. Returns a copy.
func (e *Error) WithDetails(details ...Detail) *Error {
	clone := *e
	clone.Details = append(append([]Detail{}, e.Details...), details...)
	return &clone
}

// WithTraceID stamps the trace id used to find the server-side log. Returns a copy.
func (e *Error) WithTraceID(traceID string) *Error {
	clone := *e
	clone.TraceID = traceID
	return &clone
}

// newError builds an envelope. Kept unexported so every error in the system comes
// from one of the named constructors below and therefore has a stable code.
func newError(status int, code, message string) *Error {
	return &Error{Code: code, Message: message, status: status}
}

// Constructors for each code. A caller cannot invent an ad-hoc code.

// Unauthenticated reports a missing or unusable credential.
func Unauthenticated(msg string) *Error {
	return newError(http.StatusUnauthorized, CodeUnauthenticated, msg)
}

// MFARequired reports that the password step succeeded but MFA is still outstanding.
func MFARequired() *Error {
	return newError(http.StatusUnauthorized, CodeMFARequired,
		"multi-factor authentication is required")
}

// PermissionDenied reports that the caller's role does not grant this action.
func PermissionDenied() *Error {
	// Deliberately uniform: telling a caller which permission they lack maps out the
	// authorization model for them.
	return newError(http.StatusForbidden, CodePermissionDenied,
		"you do not have permission to perform this action")
}

// TenantSuspended reports that the tenant is not permitted to operate.
func TenantSuspended() *Error {
	return newError(http.StatusForbidden, CodeTenantSuspended, "this tenant is suspended")
}

// ValidationFailed reports malformed input at the request boundary.
func ValidationFailed(msg string) *Error {
	return newError(http.StatusBadRequest, CodeValidationFailed, msg)
}

// TimeRangeRequired reports a query submitted without the mandatory time bounds.
func TimeRangeRequired() *Error {
	return newError(http.StatusBadRequest, CodeTimeRangeRequired,
		"a time range is required; unbounded queries are not permitted")
}

// TimeRangeTooLarge reports a query whose span exceeds the configured maximum.
func TimeRangeTooLarge(maxDays int) *Error {
	return newError(http.StatusBadRequest, CodeTimeRangeTooLarge,
		fmt.Sprintf("the requested time range exceeds the maximum of %d days", maxDays))
}

// ResultLimitExceeded reports a request for more rows than the cap allows.
func ResultLimitExceeded(maxRows int32) *Error {
	return newError(http.StatusBadRequest, CodeResultLimitExceeded,
		fmt.Sprintf("the requested result size exceeds the maximum of %d rows", maxRows))
}

// QueryTimeout reports a query that exceeded the server-side execution budget.
func QueryTimeout() *Error {
	return newError(http.StatusRequestTimeout, CodeQueryTimeout,
		"the query took too long; narrow the time range or add filters")
}

// CursorInvalid reports an unusable pagination cursor.
func CursorInvalid() *Error {
	return newError(http.StatusBadRequest, CodeCursorInvalid,
		"the pagination cursor is invalid or expired")
}

// NotFound reports an absent resource.
func NotFound(what string) *Error {
	// Reports "not found" for another tenant's resource too, so existence in a
	// neighbouring tenant is not observable.
	return newError(http.StatusNotFound, CodeNotFound, fmt.Sprintf("%s not found", what))
}

// Conflict reports a uniqueness or concurrent-modification failure.
func Conflict(msg string) *Error {
	return newError(http.StatusConflict, CodeConflict, msg)
}

// RateLimited reports an exhausted rate-limit bucket.
func RateLimited() *Error {
	return newError(http.StatusTooManyRequests, CodeRateLimited, "rate limit exceeded")
}

// FeedCredentialUnavailable reports that the platform cannot check a credential at all.
//
// Distinct from FeedCredentialInvalid, and the distinction is the point: one says the
// sender presented the wrong token, the other says this platform lost the token it was
// meant to compare against. They look identical from the outside and lead to opposite
// fixes — reconfigure the vendor, or restore the secret store.
//
// 503 rather than 500 because a sender that honours it retries: a store restored within
// the retry window then loses nothing.
func FeedCredentialUnavailable() *Error {
	return newError(http.StatusServiceUnavailable, CodeFeedCredentialUnavailable,
		"this platform cannot verify the feed credential right now")
}

// FeedCredentialInvalid reports a feed token that does not authenticate.
func FeedCredentialInvalid() *Error {
	return newError(http.StatusUnauthorized, CodeFeedCredentialInvalid,
		"the feed credential is invalid")
}

// FeedTokenMismatch reports a valid token presented against the wrong feed.
func FeedTokenMismatch() *Error {
	return newError(http.StatusForbidden, CodeFeedTokenMismatch,
		"the token does not match the requested feed")
}

// PayloadTooLarge reports an ingest body beyond the configured limit.
func PayloadTooLarge(maxBytes int64) *Error {
	return newError(http.StatusRequestEntityTooLarge, CodePayloadTooLarge,
		fmt.Sprintf("the payload exceeds the maximum of %d bytes", maxBytes))
}

// RuleConditionInvalid reports an alert rule condition that will not parse.
func RuleConditionInvalid(msg string) *Error {
	return newError(http.StatusBadRequest, CodeRuleConditionInvalid, msg)
}

// ExportTooLarge reports an export beyond the row cap.
func ExportTooLarge(maxRows int) *Error {
	return newError(http.StatusBadRequest, CodeExportTooLarge,
		fmt.Sprintf("the export exceeds the maximum of %d rows; narrow the query", maxRows))
}

// BrokerUnavailable is returned when a durable write could not be confirmed.
//
// This is a 503 and NEVER a 2xx: acknowledging an event the broker did not commit
// would lose it permanently, whereas a 503 makes the vendor retry and dedup absorbs
// the duplicate (Constitution Principle II).
func BrokerUnavailable() *Error {
	return newError(http.StatusServiceUnavailable, CodeBrokerUnavailable,
		"the platform cannot durably accept events right now; please retry")
}

// Internal reports an unexpected server-side failure with nothing safe to disclose.
func Internal() *Error {
	return newError(http.StatusInternalServerError, CodeInternal, "an internal error occurred")
}

// AsError maps any error to an envelope. Errors that are not already envelopes become
// a generic INTERNAL, keeping their cause for the server-side log but exposing nothing.
func AsError(err error) *Error {
	if err == nil {
		return nil
	}

	var apiErr *Error
	if errors.As(err, &apiErr) {
		return apiErr
	}
	if errors.Is(err, tenancy.ErrNoTenant) {
		return Unauthenticated("authentication is required").WithCause(err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return QueryTimeout().WithCause(err)
	}
	if errors.Is(err, context.Canceled) {
		return newError(499, "CLIENT_CLOSED_REQUEST", "the client closed the request").WithCause(err)
	}
	return Internal().WithCause(err)
}

// Recovery converts a panic into a logged INTERNAL error rather than a dropped
// connection. A panic in one request must not take down a service ingesting for
// every other tenant.
func Recovery(log Logger) middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (reply any, err error) {
			defer func() {
				if r := recover(); r != nil {
					log.Error(ctx, "panic recovered", "panic", fmt.Sprint(r))
					err = Internal().WithCause(fmt.Errorf("panic: %v", r))
				}
			}()
			return handler(ctx, req)
		}
	}
}
