// Command siem-api serves the OpenAPI surface the Vue console consumes.
//
// This binary is latency-sensitive and read-heavy. It holds no pipeline state: it
// reads ClickHouse, writes control-plane records through a single guarded path, and
// never touches the ingest hot path.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"time"

	khttp "github.com/go-kratos/kratos/v2/transport/http"

	"github.com/menta2k/siem/internal/alerting"
	"github.com/menta2k/siem/internal/auth"
	"github.com/menta2k/siem/internal/conf"
	"github.com/menta2k/siem/internal/correlate"
	"github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/data/redis"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/query"
	"github.com/menta2k/siem/internal/retention"
	"github.com/menta2k/siem/internal/secrets"
	"github.com/menta2k/siem/internal/server"
	"github.com/menta2k/siem/internal/service"
	"github.com/menta2k/siem/internal/vendors"
	"github.com/menta2k/siem/internal/vendors/cloudflare"
	"github.com/menta2k/siem/internal/vendors/datadome"
	"github.com/menta2k/siem/internal/vendors/f5"
	"github.com/menta2k/siem/internal/vendors/nginx"
)

const serviceName = "siem-api"

func main() {
	healthcheck := flag.Bool("healthcheck", false, "probe the local readiness endpoint and exit")
	flag.Parse()

	if *healthcheck {
		runHealthcheck()
		return
	}

	deps, err := server.Bootstrap(serviceName)
	if err != nil {
		server.Fatal(nil, "startup failed", err)
	}
	ctx := context.Background()

	if err := run(ctx, deps); err != nil {
		server.Fatal(deps.Log, "service failed", err)
	}
}

func run(ctx context.Context, deps *server.Deps) error {
	cfg := deps.Config

	chClient, err := clickhouse.New(ctx, cfg.ClickHouse, clickhouse.Options{Profile: "default"})
	if err != nil {
		return fmt.Errorf("connect clickhouse: %w", err)
	}
	deps.AddCloser(func(context.Context) error { return chClient.Close() })
	deps.Health.Register("clickhouse", chClient)

	redisClient, err := redis.New(ctx, cfg.Redis)
	if err != nil {
		return fmt.Errorf("connect redis: %w", err)
	}
	deps.AddCloser(func(context.Context) error { return redisClient.Close() })
	deps.Health.Register("redis", redisClient)

	// Built here so a bad signing key or malformed policy fails startup rather than
	// the first request that needs it.
	tokens, err := auth.NewTokenIssuer(
		cfg.Auth.JWTSigningKey, cfg.Auth.AccessTTL, cfg.Auth.RefreshTTL,
		auth.NewRedisRevocations(redisClient, cfg.Auth.RefreshTTL),
	)
	if err != nil {
		return fmt.Errorf("build token issuer: %w", err)
	}
	enforcer, err := auth.NewEnforcer()
	if err != nil {
		return fmt.Errorf("build authorization enforcer: %w", err)
	}

	srv, err := buildAPIServer(deps, chClient, redisClient, tokens, enforcer)
	if err != nil {
		return err
	}

	go func() {
		deps.Log.Info(ctx, "api listening", "port", cfg.Server.APIPort)
		if err := srv.Start(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			deps.Log.Error(ctx, "api server stopped", "cause", err.Error())
		}
	}()

	deps.Log.Info(ctx, "service started", "service", serviceName, "port", cfg.Server.APIPort)

	return server.RunUntilSignal(deps, func(shutdownCtx context.Context) error {
		return srv.Stop(shutdownCtx)
	})
}

// retentionWorker builds the purge path the admin API calls into.
//
// The same worker the processor runs on a timer. Sharing it means the audited purge
// behaves identically whether it was triggered by an operator or by a schedule.
func retentionWorker(
	deps *server.Deps, ch *clickhouse.Client, locker clickhouse.Locker,
	tenants *clickhouse.TenantRepo, events *clickhouse.EventRepo,
) *retention.Worker {
	return retention.NewWorker(tenants,
		retention.Repos{Events: events, Correlated: clickhouse.NewCorrelatedRepo(ch)},
		clickhouse.NewAuditRepo(ch, locker), deps.Log)
}

// buildServices constructs every API implementation.
//
// Split from the transport wiring so the dependency graph is readable in one place:
// each service below is built from repositories constructed by the caller, and
// threading that through the transport assembly would bury it.
func buildServices(
	deps *server.Deps, ch *clickhouse.Client, rdb *redis.Client,
	locker clickhouse.Locker, tokens *auth.TokenIssuer, limits query.Limits,
) server.Services {
	cfg := deps.Config

	tenants := clickhouse.NewTenantRepo(ch, locker)
	users := clickhouse.NewUserRepo(ch, locker)
	auditLog := clickhouse.NewAuditRepo(ch, locker)
	feeds := clickhouse.NewFeedRepo(ch, locker)
	events := clickhouse.NewEventRepo(ch)
	health := clickhouse.NewHealthRepo(ch)
	alertingRepo := clickhouse.NewAlertingRepo(ch, locker)
	searchRepo := clickhouse.NewSearchRepo(ch)
	correlated := clickhouse.NewCorrelatedRepo(ch)
	panels := clickhouse.NewDashboardRepo(ch)

	adapters, err := vendors.NewRegistry(cloudflare.New(), f5.New(), datadome.New(), nginx.New())
	if err != nil {
		// The registry is built from compile-time constants; a failure here is a
		// programming error, not a runtime condition.
		server.Fatal(deps.Log, "build vendor registry", err)
	}

	return server.Services{
		Auth: service.NewAuthService(users, tenants, auditLog, tokens, users,
			cfg.Auth.MFAIssuer),
		Feeds: service.NewFeedsService(feeds, events, health,
			secrets.NewRedisStore(rdb), auditLog, adapters),
		Search:      service.NewSearchService(searchRepo, events, auditLog, limits, adapters, tenants),
		Correlation: service.NewCorrelationService(correlated),
		Dashboards:  service.NewDashboardsService(panels, feeds, health, limits),
		Admin: service.NewAdminService(users, tenants, auditLog,
			retentionWorker(deps, ch, locker, tenants, events),
			correlate.NewSettingsCache(tenants, correlate.DefaultSettingsTTL)),
		Alerts: service.NewAlertsService(
			alertingRepo,
			alerting.NewEvaluator(alerting.NewRepoStore(alertingRepo)),
			secrets.NewRedisStore(rdb), auditLog,
		),
	}
}

// apiRateLimiter builds the API's request limits.
//
// Without this the API has NO rate limit: the server treats a nil limiter as
// "unlimited", so forgetting to pass one fails silently. An unauthenticated flood
// against /auth/login is the case that matters — it is the one route an attacker can
// reach without credentials, and every request there costs a password hash.
func apiRateLimiter(rdb *redis.Client) (*mw.RateLimiter, error) {
	limiter, err := mw.NewRateLimiter(rdb,
		mw.LimitScope{Name: "tenant", Limit: 600, Window: time.Minute},
		mw.LimitScope{Name: "peer", Limit: 120, Window: time.Minute},
	)
	if err != nil {
		return nil, fmt.Errorf("build rate limiter: %w", err)
	}
	return limiter, nil
}

// queryLimits derives the read bounds every query service shares.
func queryLimits(cfg *conf.Config) query.Limits {
	return query.Limits{
		MaxResultRows: cfg.Limits.QueryMaxResultRows,
		MaxRangeDays:  cfg.Limits.QueryMaxRangeDays,
		MaxExecution:  cfg.ClickHouse.MaxExecutionTime,
	}
}

// buildAPIServer wires the repositories, services, and transport.
//
// Kept apart from run() so the dependency graph is readable in one place: every
// service below is constructed from repositories that are themselves constructed here,
// and threading that through the startup sequence would bury it.
func buildAPIServer(
	deps *server.Deps, ch *clickhouse.Client, rdb *redis.Client,
	tokens *auth.TokenIssuer, enforcer *auth.Enforcer,
) (*khttp.Server, error) {
	cfg := deps.Config
	locker := clickhouse.NewLocker(rdb)
	tenants := clickhouse.NewTenantRepo(ch, locker)

	services := buildServices(deps, ch, rdb, locker, tokens, queryLimits(cfg))

	limiter, err := apiRateLimiter(rdb)
	if err != nil {
		return nil, err
	}

	return server.NewHTTPServer(services, server.HTTPOptions{
		Config:      cfg,
		Health:      deps.Health,
		Log:         deps.Log,
		TokenParser: tokens,
		Authorizer:  enforcer,
		Tenants:     server.TenantGate{Tenants: tenants},
		RateLimiter: limiter,
	}), nil
}

// runHealthcheck backs the container HEALTHCHECK, so the image needs no shell or
// curl and can stay on a distroless base.
func runHealthcheck() {
	client := &http.Client{Timeout: 3 * time.Second}

	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodGet, "http://127.0.0.1:8000/readyz", nil)
	if err != nil {
		server.Fatal(nil, "healthcheck failed", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		server.Fatal(nil, "healthcheck failed", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			server.Fatal(nil, "healthcheck failed", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		server.Fatal(nil, "healthcheck failed",
			fmt.Errorf("readiness returned %d", resp.StatusCode))
	}
}
