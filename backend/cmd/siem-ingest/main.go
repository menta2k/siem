// Command siem-ingest receives vendor log deliveries and commits them durably.
//
// This binary makes the platform's central promise: it answers a vendor only after
// Redpanda has confirmed the write. Every failure path here returns a retryable
// status rather than a 2xx the system cannot honour (Constitution Principle II).
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/menta2k/siem/internal/conf"
	"github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/data/redis"
	"github.com/menta2k/siem/internal/data/stream"
	"github.com/menta2k/siem/internal/ingest"
	"github.com/menta2k/siem/internal/ingest/dedup"
	"github.com/menta2k/siem/internal/ingest/filter"
	"github.com/menta2k/siem/internal/ingest/receiver"
	"github.com/menta2k/siem/internal/secrets"
	"github.com/menta2k/siem/internal/server"
	"github.com/menta2k/siem/internal/vendors"
	"github.com/menta2k/siem/internal/vendors/cloudflare"
	"github.com/menta2k/siem/internal/vendors/datadome"
	"github.com/menta2k/siem/internal/vendors/f5"
	"github.com/menta2k/siem/internal/vendors/nginx"
)

const serviceName = "siem-ingest"

func main() {
	deps, err := server.Bootstrap(serviceName)
	if err != nil {
		server.Fatal(nil, "startup failed", err)
	}

	if err := run(context.Background(), deps); err != nil {
		server.Fatal(deps.Log, "service failed", err)
	}
}

func run(ctx context.Context, deps *server.Deps) error {
	cfg := deps.Config

	// The producer is the durability boundary. If it cannot be created the service
	// must not start: an ingest endpoint that accepts events it cannot commit is
	// worse than one that is plainly down.
	producer, err := stream.NewProducer(cfg.Redpanda)
	if err != nil {
		return fmt.Errorf("connect redpanda: %w", err)
	}
	deps.AddCloser(producer.Close)
	deps.Health.Register("redpanda", producer)

	// Created before anything produces. Auto-creation races the first batch, and on a
	// fresh deployment every first delivery loses that race.
	if err := producer.EnsureTopics(ctx,
		cfg.Redpanda.TopicRaw, cfg.Redpanda.TopicNormalized, cfg.Redpanda.TopicDLQ,
	); err != nil {
		return fmt.Errorf("ensure topics: %w", err)
	}

	// Backs the short-window dedup set and per-feed quota counters.
	redisClient, err := redis.New(ctx, cfg.Redis)
	if err != nil {
		return fmt.Errorf("connect redis: %w", err)
	}
	deps.AddCloser(func(context.Context) error { return redisClient.Close() })
	deps.Health.Register("redis", redisClient)

	// Needed to resolve feed credentials and write per-minute feed health.
	chClient, err := clickhouse.New(ctx, cfg.ClickHouse, clickhouse.Options{Profile: "ingest"})
	if err != nil {
		return fmt.Errorf("connect clickhouse: %w", err)
	}
	deps.AddCloser(func(context.Context) error { return chClient.Close() })
	deps.Health.Register("clickhouse", chClient)

	rx, health, err := buildReceiver(cfg, deps, chClient, redisClient, producer)
	if err != nil {
		return err
	}

	startHealthAggregator(ctx, deps, health)

	opsAddr := fmt.Sprintf("%s:%d", cfg.Server.MetricsBind, cfg.Server.IngestPort)
	ops := server.OperationalServer(opsAddr, deps.Health, rx.Handler())

	serve(ctx, deps, ops, opsAddr)
	profiling := server.StartProfiling(ctx, deps, cfg.Server.PprofBind)

	deps.Log.Info(ctx, "service started", "service", serviceName, "port", cfg.Server.IngestPort)

	return server.RunUntilSignal(deps, func(shutdownCtx context.Context) error {
		// Stop accepting first, then let the producer flush in Close. Draining in
		// this order keeps the promise made by every 202 already returned.
		if profiling != nil {
			_ = profiling.Shutdown(shutdownCtx)
		}
		return ops.Shutdown(shutdownCtx)
	})
}

// buildReceiver assembles the ingest HTTP handler.
//
// Split out so the startup sequence stays readable. The dependency list is long
// because the receiver has to authenticate a feed, deduplicate, enforce a quota,
// publish durably, and record health before it can answer a single delivery.
func buildReceiver(
	cfg *conf.Config, deps *server.Deps, chClient *clickhouse.Client,
	redisClient *redis.Client, producer *stream.Producer,
) (*receiver.Receiver, *ingest.HealthAggregator, error) {
	adapters, err := vendors.NewRegistry(cloudflare.New(), f5.New(), datadome.New(), nginx.New())
	if err != nil {
		return nil, nil, fmt.Errorf("build vendor registry: %w", err)
	}

	// Returned alongside the receiver, not hidden inside it: this aggregator only
	// persists anything while its own loop is running, and the caller is the only place
	// that can start it.
	health := ingest.NewHealthAggregator(clickhouse.NewHealthRepo(chClient))

	// The store the delivery path resolves every credential through. Built here so a
	// deployment without a durable copy says so once, at start-up, rather than never.
	secretStore, err := server.SecretStore(deps.Log, secrets.NewRedisStore(redisClient),
		clickhouse.NewSecretVault(chClient), cfg.Secrets.EncryptionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("build secret store: %w", err)
	}

	return receiver.New(
		clickhouse.NewFeedRepo(chClient, clickhouse.NewLocker(redisClient)),
		secretStore,
		adapters,
		ingest.NewPublisher(producer, cfg.Redpanda.TopicRaw, cfg.Redpanda.TopicDLQ),
		dedup.New(redisClient, dedup.DefaultWindow),
		ingest.NewQuotaEnforcer(redisClient),
		filter.NewCache(clickhouse.NewTenantRepo(chClient, nil), filter.DefaultCacheTTL),
		health,
		deps.Log,
		receiver.Options{
			MaxBodyBytes:   cfg.Limits.IngestMaxBodyBytes,
			MaxBatchEvents: cfg.Limits.IngestMaxBatchEvents,
			CommitTimeout:  cfg.Limits.IngestCommitTimeout,
		},
	), health, nil
}

// startHealthAggregator runs the per-minute feed-health flush loop.
//
// The aggregator buffers counters IN MEMORY and only writes them when this loop ticks, so
// constructing it without running it discards everything the receiver records — silently,
// because recording a sample cannot fail. That is exactly what happened: feed_health held
// no rows at all while ingestion itself looked perfectly healthy. buildReceiver returns
// the aggregator rather than hiding it so it cannot be built without a caller deciding
// what starts it.
func startHealthAggregator(
	ctx context.Context, deps *server.Deps, health *ingest.HealthAggregator,
) {
	go func() {
		// Health is observability, not customer data: a failed write is reported and
		// the service keeps ingesting.
		if err := health.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			deps.Log.Error(ctx, "feed health aggregator stopped", "cause", err.Error())
		}
	}()
}

// serve starts the ingest and operational listener in the background.
func serve(ctx context.Context, deps *server.Deps, ops *http.Server, addr string) {
	go func() {
		deps.Log.Info(ctx, "operational endpoints listening", "addr", addr)
		if err := ops.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			deps.Log.Error(ctx, "operational server stopped", "cause", err.Error())
		}
	}()
}
