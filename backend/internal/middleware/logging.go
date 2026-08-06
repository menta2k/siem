package middleware

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
	"github.com/google/uuid"

	"github.com/menta2k/siem/internal/tenancy"
)

// traceIDKey carries the request trace id. Unexported so it cannot be forged.
type traceIDKey struct{}

// TraceHeader is the header the SPA sends and the API echoes, so a user reporting a
// failed search can be matched to the exact server-side log line.
const TraceHeader = "X-Trace-Id"

// redactedKeys are never written to a log, whatever their value.
//
// Constitution: logs must never contain secrets. Redaction lives here, at the single
// point every log line passes through, rather than being remembered at each call.
var redactedKeys = map[string]bool{
	"password":      true,
	"password_hash": true,
	"token":         true,
	"access_token":  true,
	"refresh_token": true,
	"authorization": true,
	"mfa_secret":    true,
	"mfa_code":      true,
	"credential":    true,
	"secret":        true,
	"api_key":       true,
	"cookie":        true,
	"set-cookie":    true,
}

// Logger is the structured logging surface used across the platform.
type Logger interface {
	Debug(ctx context.Context, msg string, kv ...any)
	Info(ctx context.Context, msg string, kv ...any)
	Warn(ctx context.Context, msg string, kv ...any)
	Error(ctx context.Context, msg string, kv ...any)
}

// SlogLogger implements Logger over log/slog with JSON output.
type SlogLogger struct {
	logger *slog.Logger
}

// NewLogger builds a JSON logger at the given level. Format is always JSON in
// production; "text" is accepted only for local readability.
func NewLogger(level, format string) *SlogLogger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}
	var handler slog.Handler = slog.NewJSONHandler(os.Stdout, opts)
	if strings.EqualFold(format, "text") {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	return &SlogLogger{logger: slog.New(handler)}
}

// Debug logs at debug level with trace and tenant context attached.
func (l *SlogLogger) Debug(ctx context.Context, msg string, kv ...any) {
	l.log(ctx, slog.LevelDebug, msg, kv...)
}

// Info logs at info level with trace and tenant context attached.
func (l *SlogLogger) Info(ctx context.Context, msg string, kv ...any) {
	l.log(ctx, slog.LevelInfo, msg, kv...)
}

// Warn logs at warn level with trace and tenant context attached.
func (l *SlogLogger) Warn(ctx context.Context, msg string, kv ...any) {
	l.log(ctx, slog.LevelWarn, msg, kv...)
}

func (l *SlogLogger) Error(ctx context.Context, msg string, kv ...any) {
	l.log(ctx, slog.LevelError, msg, kv...)
}

// log enriches every line with the trace id and tenant, then redacts.
func (l *SlogLogger) log(ctx context.Context, level slog.Level, msg string, kv ...any) {
	attrs := make([]any, 0, len(kv)+4)

	if traceID := TraceIDFromContext(ctx); traceID != "" {
		attrs = append(attrs, "trace_id", traceID)
	}
	if t, err := tenancy.FromContext(ctx); err == nil {
		attrs = append(attrs, "tenant_id", t.ID.String())
	}
	attrs = append(attrs, redact(kv)...)

	l.logger.Log(ctx, level, msg, attrs...)
}

// redact replaces the values of sensitive keys. Returns a new slice; the caller's
// arguments are not modified.
func redact(kv []any) []any {
	out := make([]any, len(kv))
	copy(out, kv)

	for i := 0; i+1 < len(out); i += 2 {
		key, ok := out[i].(string)
		if !ok {
			continue
		}
		if redactedKeys[strings.ToLower(key)] {
			out[i+1] = "[REDACTED]"
		}
	}
	return out
}

// WithTraceID returns a derived context carrying a trace id.
func WithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, traceIDKey{}, traceID)
}

// TraceIDFromContext returns the trace id, or "" when absent.
func TraceIDFromContext(ctx context.Context) string {
	id, ok := ctx.Value(traceIDKey{}).(string)
	if !ok {
		return ""
	}
	return id
}

// Tracing accepts a client-supplied trace id or mints one, so a single identifier
// spans the SPA request and every server-side log line it produces.
func Tracing() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (any, error) {
			traceID := ""
			if tr, ok := transport.FromServerContext(ctx); ok {
				traceID = tr.RequestHeader().Get(TraceHeader)
			}
			// A client-supplied id is accepted for correlation only. It is never
			// trusted for authorization, so a forged value costs nothing.
			if !isValidTraceID(traceID) {
				traceID = uuid.NewString()
			}

			ctx = WithTraceID(ctx, traceID)
			if tr, ok := transport.FromServerContext(ctx); ok {
				tr.ReplyHeader().Set(TraceHeader, traceID)
			}
			return handler(ctx, req)
		}
	}
}

// isValidTraceID bounds what a client may put in a log field, so a crafted header
// cannot inject newlines or unbounded text into the log stream.
func isValidTraceID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for _, r := range id {
		isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
		if !isHex && r != '-' {
			return false
		}
	}
	return true
}

// Logging records one structured line per request, including failures with their
// full server-side cause.
func Logging(log Logger) middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (any, error) {
			start := time.Now()
			operation, method := operationOf(ctx)

			reply, err := handler(ctx, req)
			elapsed := time.Since(start)

			if err != nil {
				apiErr := AsError(err)
				// The user-facing message is safe; the cause is what an operator needs
				// and is written only here, never returned.
				log.Error(ctx, "request failed",
					"operation", operation,
					"method", method,
					"code", apiErr.Code,
					"status", apiErr.HTTPStatus(),
					"duration_ms", elapsed.Milliseconds(),
					"cause", apiErr.Error(),
				)
				return nil, err
			}

			log.Info(ctx, "request completed",
				"operation", operation,
				"method", method,
				"duration_ms", elapsed.Milliseconds(),
			)
			return reply, nil
		}
	}
}

func operationOf(ctx context.Context) (operation, method string) {
	tr, ok := transport.FromServerContext(ctx)
	if !ok {
		return "", ""
	}
	operation = tr.Operation()
	if ht, ok := tr.(interface {
		Request() interface{ Method() string }
	}); ok {
		method = ht.Request().Method()
	}
	return operation, method
}
