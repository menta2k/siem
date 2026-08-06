package server

import (
	"context"
	"encoding/json"
	"fmt"
	nethttp "net/http"

	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/transport/http"

	"github.com/google/uuid"

	pb "github.com/menta2k/siem/api/gen/siem/v1"
	"github.com/menta2k/siem/internal/conf"
	chdata "github.com/menta2k/siem/internal/data/clickhouse"
	mw "github.com/menta2k/siem/internal/middleware"
)

// Services are the API implementations the HTTP server exposes.
//
// Passed as one struct rather than as eight parameters so that adding a service is a
// field, not a change to every call site — and so a nil service is visible at the
// assembly point instead of surfacing as a panic on the first request.
type Services struct {
	Auth        pb.AuthHTTPServer
	Feeds       pb.FeedsHTTPServer
	Search      pb.SearchHTTPServer
	Correlation pb.CorrelationHTTPServer
	Dashboards  pb.DashboardsHTTPServer
	Alerts      pb.AlertsHTTPServer
	Admin       pb.AdminHTTPServer
}

// HTTPOptions are the cross-cutting concerns every route shares.
type HTTPOptions struct {
	Config      *conf.Config
	Health      *Health
	Log         mw.Logger
	TokenParser mw.TokenParser
	Authorizer  mw.Authorizer
	Tenants     mw.TenantLoader
	RateLimiter *mw.RateLimiter
}

// NewHTTPServer assembles the API transport.
//
// The middleware order is deliberate and each step depends on the one before it:
//
//	recovery   a panic must become a 500, not a dropped connection
//	tracing    every later log line and error envelope carries the trace id
//	metrics    latency is measured around the real work, including auth
//	source ip  the audit trail and the rate limiter both need the caller
//	rate limit runs BEFORE auth so an unauthenticated flood is cheap to refuse
//	auth       authenticates, scopes to the tenant, and enforces the policy
//
// Rate limiting ahead of authentication is the one that is easy to get backwards.
// Verifying a JWT signature on every request of a flood is exactly the work an
// attacker wants the server doing.
func NewHTTPServer(services Services, opts HTTPOptions) *http.Server {
	chain := []http.ServerOption{
		http.Address(addr(opts.Config)),
		http.Timeout(opts.Config.ClickHouse.MaxExecutionTime),
		http.ErrorEncoder(errorEncoder(opts.Log)),
	}

	middlewares := []middleware.Middleware{
		recovery.Recovery(),
		mw.Tracing(),
		mw.Metrics(),
		mw.SourceIP(),
	}
	if opts.RateLimiter != nil {
		middlewares = append(middlewares, opts.RateLimiter.Middleware(opts.Log))
	}
	middlewares = append(middlewares,
		mw.Auth(opts.TokenParser, opts.Authorizer, opts.Tenants, opts.Log))

	chain = append(chain, http.Middleware(middlewares...))

	srv := http.NewServer(chain...)

	// Registration is explicit per service. A loop over a registry would be shorter and
	// would also make it possible to ship a service that is implemented but never
	// mounted — reachable in the OpenAPI document and 404 in production.
	pb.RegisterAuthHTTPServer(srv, services.Auth)
	pb.RegisterFeedsHTTPServer(srv, services.Feeds)
	pb.RegisterSearchHTTPServer(srv, services.Search)
	pb.RegisterCorrelationHTTPServer(srv, services.Correlation)
	pb.RegisterDashboardsHTTPServer(srv, services.Dashboards)
	pb.RegisterAlertsHTTPServer(srv, services.Alerts)
	pb.RegisterAdminHTTPServer(srv, services.Admin)

	mountOperational(srv, opts.Health)
	return srv
}

// mountOperational adds the probe and metrics endpoints to the API listener.
//
// Deliberately registered with Handle rather than through a service: Kratos applies
// its middleware chain inside the generated per-operation handlers, so these routes
// bypass authentication — which is required. A readiness probe that needs a token
// cannot be used by an orchestrator, and a metrics endpoint that needs one cannot be
// scraped.
//
// They share the API's listener because that is what the deployment expects: the
// compose file publishes one port and Prometheus scrapes /metrics on it. A second
// listener would be more isolated but would be unreachable as configured, which is a
// worse property than the isolation is worth.
func mountOperational(srv *http.Server, health *Health) {
	if health == nil {
		return
	}
	srv.Handle("/healthz", health.LivenessHandler())
	srv.Handle("/readyz", health.ReadinessHandler())
	srv.Handle("/metrics", MetricsHandler())
}

func addr(cfg *conf.Config) string {
	return fmt.Sprintf("%s:%d", cfg.Server.MetricsBind, cfg.Server.APIPort)
}

// errorEncoder renders the platform's error envelope.
//
// Every failure leaves the server through here, which is what makes the contract's
// stable error codes actually stable. The cause is logged and NOT sent: the message a
// user sees must never reveal internals, and the trace id is what lets an operator
// find the full detail in the log.
func errorEncoder(log mw.Logger) http.EncodeErrorFunc {
	return func(w nethttp.ResponseWriter, r *nethttp.Request, err error) {
		apiErr := mw.AsError(err)
		if apiErr == nil {
			apiErr = mw.Internal().WithCause(err)
		}

		ctx := r.Context()
		if traceID := mw.TraceIDFromContext(ctx); traceID != "" {
			apiErr = apiErr.WithTraceID(traceID)
		}

		if apiErr.HTTPStatus() >= nethttp.StatusInternalServerError {
			// Only server faults are logged at error level. A 400 is the client being
			// told what it did wrong, and logging those as errors makes the error rate
			// a measure of user confusion rather than of service health.
			log.Error(ctx, "request failed",
				"code", apiErr.Code, "path", r.URL.Path, "error", err.Error())
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(apiErr.HTTPStatus())
		if encodeErr := json.NewEncoder(w).Encode(apiErr); encodeErr != nil {
			log.Error(ctx, "failed to write error response", "error", encodeErr.Error())
		}
	}
}

// TenantGate adapts the tenant repository to the middleware's loader.
//
// The middleware cannot depend on the storage package — internal/query imports the
// middleware, so that edge would close a cycle — so the adapter lives here, where
// both sides are already in scope.
type TenantGate struct {
	Tenants *chdata.TenantRepo
}

// Active reports the tenant's name and whether it may currently operate.
func (g TenantGate) Active(ctx context.Context, tenantID uuid.UUID) (string, bool, error) {
	tenant, err := g.Tenants.GetByID(ctx, tenantID)
	if err != nil {
		return "", false, err
	}
	return tenant.Name, tenant.Active(), nil
}
