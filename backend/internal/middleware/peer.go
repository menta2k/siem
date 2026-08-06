package middleware

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/go-kratos/kratos/v2/middleware"
	kratoshttp "github.com/go-kratos/kratos/v2/transport/http"
)

// sourceIPKey carries the caller's address. Unexported so it cannot be forged.
type sourceIPKey struct{}

// WithSourceIP returns a derived context carrying the caller address.
func WithSourceIP(ctx context.Context, ip net.IP) context.Context {
	return context.WithValue(ctx, sourceIPKey{}, ip)
}

// SourceIPFromContext returns the caller address, if one was determined.
func SourceIPFromContext(ctx context.Context) (net.IP, bool) {
	ip, ok := ctx.Value(sourceIPKey{}).(net.IP)
	return ip, ok && ip != nil
}

// SourceIP extracts the caller address for audit records and rate limiting.
//
// X-Forwarded-For is honoured because the platform runs behind a load balancer, but
// only the LEFTMOST entry is taken and it is treated as advisory. A client can set
// this header to anything, so the value is recorded as claimed provenance, never used
// for an authorization decision.
func SourceIP() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (any, error) {
			if r, ok := kratoshttp.RequestFromServerContext(ctx); ok {
				if ip := extractIP(r); ip != nil {
					ctx = WithSourceIP(ctx, ip)
				}
			}
			return handler(ctx, req)
		}
	}
}

func extractIP(r *http.Request) net.IP {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		first, _, _ := strings.Cut(forwarded, ",")
		if ip := net.ParseIP(strings.TrimSpace(first)); ip != nil {
			return ip
		}
	}
	if realIP := r.Header.Get("X-Real-Ip"); realIP != "" {
		if ip := net.ParseIP(strings.TrimSpace(realIP)); ip != nil {
			return ip
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}
