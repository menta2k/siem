package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/menta2k/siem/internal/conf"
	"github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/secrets"
	"github.com/menta2k/siem/internal/version"
)

// Deps holds the shared infrastructure every service opens at startup. A service
// closes exactly what it opened, in reverse order.
type Deps struct {
	Config *conf.Config
	Log    *middleware.SlogLogger
	Health *Health

	closers []func(context.Context) error
}

// AddCloser registers a shutdown function, run in reverse registration order.
func (d *Deps) AddCloser(fn func(context.Context) error) {
	d.closers = append(d.closers, fn)
}

// Close shuts dependencies down in reverse order, collecting every failure rather
// than stopping at the first — a stuck ClickHouse connection must not prevent the
// Redpanda producer from flushing.
func (d *Deps) Close(ctx context.Context) error {
	var errs []error
	for _, closer := range slices.Backward(d.closers) {
		if err := closer(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Bootstrap loads configuration and builds the logger.
//
// Configuration is validated here, before anything connects. A service with a
// missing secret exits immediately with a message naming the variable, rather than
// starting and failing later under load (Constitution: secrets validated at startup).
func Bootstrap(serviceName string) (*Deps, error) {
	cfg, err := conf.Load()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", serviceName, err)
	}

	log := middleware.NewLogger(cfg.Log.Level, cfg.Log.Format)
	// The build identity goes in the FIRST line every service writes. When a
	// correlation looks wrong, "which build produced it" is the first question, and
	// the answer has to be in the same log the evidence is in.
	build := version.Get()
	log.Info(context.Background(), "configuration loaded",
		"service", serviceName, "version", build.Version, "commit", build.Commit,
		"built", build.BuildDate)

	return &Deps{Config: cfg, Log: log, Health: NewHealth()}, nil
}

// OperationalServer serves the probe and metrics endpoints.
//
// These live on their own listener so they stay reachable when the main transport is
// saturated — an overloaded ingest port must not make the service look dead.
func OperationalServer(addr string, health *Health, extra ...http.Handler) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", health.LivenessHandler())
	mux.Handle("GET /readyz", health.ReadinessHandler())
	mux.Handle("GET /metrics", MetricsHandler())
	// Unauthenticated on purpose, and it sits on the OPERATIONAL listener rather than
	// the public API: this port is how a deployment identifies its own builds, and a
	// rollout check that needs a token is a rollout check nobody runs.
	mux.Handle("GET /version", VersionHandler())

	// Additional handlers share this listener. The ingest receiver uses it: the
	// deployment publishes one port per service, so a second listener would be
	// unreachable as configured — and a receiver that is built but never mounted
	// returns 404 for every delivery while the service reports itself healthy.
	for _, handler := range extra {
		mux.Handle("/", handler)
	}

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

// RunUntilSignal blocks until SIGINT or SIGTERM, then runs shutdown with a bounded
// grace period.
//
// Graceful shutdown is not cosmetic here: the ingest service must finish flushing
// acknowledged events to the broker before exiting, or it breaks the promise made by
// every 202 it has already returned.
func RunUntilSignal(deps *Deps, shutdown func(context.Context) error) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	<-ctx.Done()
	deps.Log.Info(context.Background(), "shutdown signal received, draining")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var errs []error
	if shutdown != nil {
		if err := shutdown(shutdownCtx); err != nil {
			errs = append(errs, fmt.Errorf("shutdown: %w", err))
		}
	}
	if err := deps.Close(shutdownCtx); err != nil {
		errs = append(errs, fmt.Errorf("close dependencies: %w", err))
	}

	if err := errors.Join(errs...); err != nil {
		deps.Log.Error(context.Background(), "shutdown completed with errors", "cause", err.Error())
		return err
	}
	deps.Log.Info(context.Background(), "shutdown complete")
	return nil
}

// Fatal reports a startup failure and exits non-zero.
//
// Exiting from a helper rather than main is deliberate: every binary shares this
// startup-failure path, and duplicating it per service is how one of them ends up
// logging the error and then carrying on with a half-built dependency graph.
//
//nolint:revive // deep-exit is intentional for the shared startup-failure path
func Fatal(log *middleware.SlogLogger, msg string, err error) {
	if log != nil {
		log.Error(context.Background(), msg, "cause", err.Error())
	} else {
		fmt.Fprintf(os.Stderr, "%s: %v\n", msg, err)
	}
	os.Exit(1)
}

// SecretStore assembles the credential store every service reads and writes through.
//
// One place, because the failure it guards against is service-wide: the ingest path
// resolving a credential, the console rotating one, and the alerting webhook reading one
// all lost their secrets together when the cache was emptied, and a durability fix that
// covered only one of them would have looked like a fix while leaving the outage
// reachable from the other two.
//
// A missing key is reported and the service continues on the cache alone — that is the
// arrangement every existing deployment already has, and refusing to start would turn an
// upgrade into an outage. It is logged as a WARNING with the consequence spelled out,
// because the alternative is finding out at the next restart.
func SecretStore(
	log *middleware.SlogLogger, cache secrets.CacheWriter, db secrets.DB, encodedKey string,
) (secrets.Store, error) {
	store, err := secrets.Build(cache, db, encodedKey, func(ctx context.Context, ref string) {
		// A refill means the cache had been emptied. Not an error — the platform just
		// healed itself — but the operator has to be able to see that it happened.
		log.Warn(ctx, "feed credential refilled from the durable copy: the cache was empty",
			"ref", ref)
	})

	switch {
	case errors.Is(err, secrets.ErrNoDurableCopy):
		log.Warn(context.Background(),
			"feed credentials have NO durable copy: a Redis restart will lose every one of "+
				"them and stop all ingestion until each is restored by hand",
			"fix", "set SECRETS_ENCRYPTION_KEY to base64 of 32 random bytes")
		return store, nil
	case err != nil:
		return nil, err
	}
	return store, nil
}
