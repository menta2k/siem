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

	rx, err := buildReceiver(cfg, deps, chClient, redisClient, producer)
	if err != nil {
		return err
	}

	opsAddr := fmt.Sprintf("%s:%d", cfg.Server.MetricsBind, cfg.Server.IngestPort)
	ops := server.OperationalServer(opsAddr, deps.Health, rx.Handler())

	go func() {
		deps.Log.Info(ctx, "operational endpoints listening", "addr", opsAddr)
		if err := ops.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			deps.Log.Error(ctx, "operational server stopped", "cause", err.Error())
		}
	}()

	deps.Log.Info(ctx, "service started", "service", serviceName, "port", cfg.Server.IngestPort)

	return server.RunUntilSignal(deps, func(shutdownCtx context.Context) error {
		// Stop accepting first, then let the producer flush in Close. Draining in
		// this order keeps the promise made by every 202 already returned.
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
) (*receiver.Receiver, error) {
	adapters, err := vendors.NewRegistry(cloudflare.New(), f5.New(), datadome.New())
	if err != nil {
		return nil, fmt.Errorf("build vendor registry: %w", err)
	}

	return receiver.New(
		clickhouse.NewFeedRepo(chClient, clickhouse.NewLocker(redisClient)),
		secrets.NewRedisStore(redisClient),
		adapters,
		ingest.NewPublisher(producer, cfg.Redpanda.TopicRaw, cfg.Redpanda.TopicDLQ),
		dedup.New(redisClient, dedup.DefaultWindow),
		ingest.NewQuotaEnforcer(redisClient),
		filter.NewCache(clickhouse.NewTenantRepo(chClient, nil), filter.DefaultCacheTTL),
		ingest.NewHealthAggregator(clickhouse.NewHealthRepo(chClient)),
		deps.Log,
		receiver.Options{
			MaxBodyBytes:   cfg.Limits.IngestMaxBodyBytes,
			MaxBatchEvents: cfg.Limits.IngestMaxBatchEvents,
		},
	), nil
}
