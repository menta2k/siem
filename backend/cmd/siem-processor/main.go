// Command siem-processor runs the pipeline workers: normalization, correlation,
// alert evaluation, and retention.
//
// Workers are registered rather than hard-wired so a deployment can run them all in
// one process (local development) or scale them independently (production) without a
// code change.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/menta2k/siem/internal/alerting"
	"github.com/menta2k/siem/internal/conf"
	"github.com/menta2k/siem/internal/correlate"
	"github.com/menta2k/siem/internal/correlate/window"
	"github.com/menta2k/siem/internal/data/clickhouse"
	"github.com/menta2k/siem/internal/data/redis"
	"github.com/menta2k/siem/internal/data/stream"
	"github.com/menta2k/siem/internal/ingest"
	"github.com/menta2k/siem/internal/ingest/dedup"
	"github.com/menta2k/siem/internal/ingest/filter"
	"github.com/menta2k/siem/internal/ingest/puller"
	mw "github.com/menta2k/siem/internal/middleware"
	"github.com/menta2k/siem/internal/normalize"
	"github.com/menta2k/siem/internal/retention"
	"github.com/menta2k/siem/internal/secrets"
	"github.com/menta2k/siem/internal/server"
	"github.com/menta2k/siem/internal/vendors"
	"github.com/menta2k/siem/internal/vendors/cloudflare"
	"github.com/menta2k/siem/internal/vendors/datadome"
	"github.com/menta2k/siem/internal/vendors/f5"
)

// consumerWorker adapts a stream consumer to the Worker interface.
//
// Exactly one of handle or batch is set. Batch dispatch exists for the stages that
// write to ClickHouse: an insert round trip costs about the same for one row as for a
// thousand, so per-record handling pays that cost per event and caps throughput far
// below what the broker delivers.
type consumerWorker struct {
	name   string
	cfg    conf.Redpanda
	group  string
	topics []string
	dlq    *stream.Producer
	log    mw.Logger
	handle stream.Handler
	batch  stream.BatchHandler
}

func newConsumerWorker(
	name string, cfg conf.Redpanda, group string, topics []string,
	dlq *stream.Producer, log mw.Logger, handle stream.Handler,
) *consumerWorker {
	return &consumerWorker{
		name: name, cfg: cfg, group: group, topics: topics,
		dlq: dlq, log: log, handle: handle,
	}
}

// newBatchConsumerWorker builds a worker that processes whole fetches.
func newBatchConsumerWorker(
	name string, cfg conf.Redpanda, group string, topics []string,
	dlq *stream.Producer, log mw.Logger, batch stream.BatchHandler,
) *consumerWorker {
	return &consumerWorker{
		name: name, cfg: cfg, group: group, topics: topics,
		dlq: dlq, log: log, batch: batch,
	}
}

func (w *consumerWorker) Name() string { return w.name }

func (w *consumerWorker) Run(ctx context.Context) error {
	consumer, err := stream.NewConsumer(w.cfg, w.group, w.topics, w.dlq)
	if err != nil {
		return fmt.Errorf("create %s consumer: %w", w.name, err)
	}
	defer consumer.Close()

	if w.batch != nil {
		return consumer.RunBatch(ctx, w.batch)
	}
	return consumer.Run(ctx, w.handle)
}

const serviceName = "siem-processor"

// Worker is one long-running pipeline stage.
type Worker interface {
	// Name identifies the worker in logs and metrics.
	Name() string
	// Run blocks until ctx is cancelled. A returned error stops the whole service:
	// a pipeline stage that has silently died is worse than one that is visibly down.
	Run(ctx context.Context) error
}

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

	chClient, redisClient, producer, err := connectDependencies(ctx, deps)
	if err != nil {
		return err
	}

	workers, err := buildWorkers(cfg, deps, chClient, redisClient, producer)
	if err != nil {
		return err
	}

	workerCtx, stopWorkers := context.WithCancel(ctx)
	defer stopWorkers()
	wg := startWorkers(workerCtx, deps, workers)

	opsAddr := fmt.Sprintf("%s:%d", cfg.Server.MetricsBind, cfg.Server.ProcessorPort)
	ops := server.OperationalServer(opsAddr, deps.Health)

	go func() {
		deps.Log.Info(ctx, "operational endpoints listening", "addr", opsAddr)
		if err := ops.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			deps.Log.Error(ctx, "operational server stopped", "cause", err.Error())
		}
	}()

	deps.Log.Info(ctx, "service started", "service", serviceName, "workers", len(workers))

	return server.RunUntilSignal(deps, func(shutdownCtx context.Context) error {
		stopWorkers()
		wg.Wait()
		return ops.Shutdown(shutdownCtx)
	})
}

// buildWorkers assembles the pipeline stages this service runs.
func buildWorkers(
	cfg *conf.Config, deps *server.Deps,
	chClient *clickhouse.Client, redisClient *redis.Client, producer *stream.Producer,
) ([]Worker, error) {
	locker := clickhouse.NewLocker(redisClient)
	events := clickhouse.NewEventRepo(chClient)
	tenants := clickhouse.NewTenantRepo(chClient, locker)
	feeds := clickhouse.NewFeedRepo(chClient, locker)

	adapters, err := vendors.NewRegistry(cloudflare.New(), f5.New(), datadome.New())
	if err != nil {
		return nil, fmt.Errorf("build vendor registry: %w", err)
	}

	healthAggregator := ingest.NewHealthAggregator(clickhouse.NewHealthRepo(chClient))
	deduper := dedup.New(redisClient, dedup.DefaultWindow)

	workers := []Worker{
		// Drains the raw topic into raw_events and normalized_events.
		newBatchConsumerWorker("normalizer", cfg.Redpanda, cfg.Redpanda.ConsumerGroupRaw,
			[]string{cfg.Redpanda.TopicRaw}, producer, deps.Log,
			normalize.NewWorker(adapters, events, tenants,
				normalize.NewDriftDetector(nil), producer,
				cfg.Redpanda.TopicNormalized, deps.Log).HandleBatch),

		// Drains the dead-letter topic into rejected_events. Deliberately a separate
		// consumer group from the normalizer, so a backlog of malformed records can
		// never delay good events.
		newConsumerWorker("dead-letter", cfg.Redpanda, cfg.Redpanda.ConsumerGroupRaw+"-dlq",
			[]string{cfg.Redpanda.TopicDLQ}, nil, deps.Log,
			normalize.NewDeadLetterWorker(events, deps.Log).Handle),

		// Polls vendors that cannot push to us.
		puller.NewWorker(feeds,
			puller.NewRegistry(puller.NewCloudflareSource(), puller.NewF5Source(),
				puller.NewDataDomeSource()),
			adapters,
			ingest.NewPublisher(producer, cfg.Redpanda.TopicRaw, cfg.Redpanda.TopicDLQ),
			deduper, secrets.NewRedisStore(redisClient),
			filter.NewCache(tenants, filter.DefaultCacheTTL), healthAggregator, deps.Log),

		// Evaluates alert rules and delivers the alerts they produce.
		buildAlertingWorker(cfg, deps, chClient, redisClient, locker),

		// Applies each tenant's retention window. The table TTL is the platform
		// default; this closes the gap for tenants configured shorter than it.
		buildRetentionWorker(deps, chClient, locker, tenants, events),

		// Flushes accumulated feed-health counters once a minute.
		healthAggregator,
	}

	return append(workers,
		buildCorrelationWorkers(cfg, deps, chClient, redisClient, tenants)...), nil
}

// buildCorrelationWorkers builds the two halves of correlation.
//
// They are deliberately separate workers. Filing happens on arrival; emitting happens
// on the passage of time, because "no further event will arrive" is a statement about
// time that no arriving event can make.
func buildCorrelationWorkers(
	cfg *conf.Config, deps *server.Deps, chClient *clickhouse.Client,
	redisClient *redis.Client, tenants *clickhouse.TenantRepo,
) []Worker {
	windows := window.New(redisClient)
	settings := correlate.NewSettingsCache(tenants, correlate.DefaultSettingsTTL)

	return []Worker{
		// Files normalized events into their correlation windows. A separate consumer
		// group from the normalizer so correlation can fall behind without applying
		// backpressure to ingestion.
		//
		// Filing is batched because it is dominated by Redis round trips — up to three
		// per event — and at correlation volumes those round trips, not Redis itself,
		// are the ceiling.
		newBatchConsumerWorker("correlator", cfg.Redpanda,
			cfg.Redpanda.ConsumerGroupNormalized,
			[]string{cfg.Redpanda.TopicNormalized}, nil, deps.Log,
			correlate.NewWorker(windows, settings, deps.Log).HandleBatch),

		// Emits correlated records for windows whose deadline has passed.
		correlate.NewCloser(windows, clickhouse.NewCorrelatedRepo(chClient),
			settings, deps.Log),
	}
}

// connectDependencies opens every store this service needs and registers them with
// the readiness check, so a service that cannot reach one fails its probe rather than
// running and silently doing nothing.
func connectDependencies(ctx context.Context, deps *server.Deps) (
	*clickhouse.Client, *redis.Client, *stream.Producer, error,
) {
	cfg := deps.Config

	chClient, err := clickhouse.New(ctx, cfg.ClickHouse,
		clickhouse.Options{Profile: clickhouse.ProfileIngest})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("connect clickhouse: %w", err)
	}
	deps.AddCloser(func(context.Context) error { return chClient.Close() })
	deps.Health.Register("clickhouse", chClient)

	redisClient, err := redis.New(ctx, cfg.Redis)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("connect redis: %w", err)
	}
	deps.AddCloser(func(context.Context) error { return redisClient.Close() })
	deps.Health.Register("redis", redisClient)

	// Used for dead-lettering and for republishing normalized events downstream.
	producer, err := stream.NewProducer(cfg.Redpanda)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("connect redpanda: %w", err)
	}
	deps.AddCloser(producer.Close)
	deps.Health.Register("redpanda", producer)

	if err := ensureTopics(ctx, cfg, producer); err != nil {
		return nil, nil, nil, err
	}

	return chClient, redisClient, producer, nil
}

// ensureTopics creates the pipeline topics before anything produces.
//
// Auto-creation races the first batch, and on a fresh deployment every first delivery
// loses that race.
func ensureTopics(ctx context.Context, cfg *conf.Config, producer *stream.Producer) error {
	err := producer.EnsureTopics(ctx,
		cfg.Redpanda.TopicRaw, cfg.Redpanda.TopicNormalized, cfg.Redpanda.TopicDLQ)
	if err != nil {
		return fmt.Errorf("ensure topics: %w", err)
	}
	return nil
}

// buildRetentionWorker assembles the per-tenant retention reconciler.
func buildRetentionWorker(
	deps *server.Deps, chClient *clickhouse.Client, locker clickhouse.Locker,
	tenants *clickhouse.TenantRepo, events *clickhouse.EventRepo,
) *retention.Worker {
	return retention.NewWorker(tenants,
		retention.Repos{Events: events, Correlated: clickhouse.NewCorrelatedRepo(chClient)},
		clickhouse.NewAuditRepo(chClient, locker), deps.Log)
}

// buildAlertingWorker assembles the evaluate-suppress-persist-deliver pipeline.
func buildAlertingWorker(
	cfg *conf.Config, deps *server.Deps, chClient *clickhouse.Client,
	redisClient *redis.Client, locker clickhouse.Locker,
) *alerting.Worker {
	repo := clickhouse.NewAlertingRepo(chClient, locker)

	return alerting.NewWorker(
		repo,
		alerting.NewEvaluator(alerting.NewRepoStore(repo)),
		alerting.NewCooldown(redisClient),
		alerting.NewWebhook(secrets.NewRedisStore(redisClient), cfg.Redpanda.ConsoleURL),
		deps.Log,
	)
}

// Worker restart backoff. A failing worker is usually failing on a dependency that is
// briefly unavailable, so it is retried quickly at first and then progressively slower
// rather than either giving up or hot-looping against a store that is still down.
const (
	workerRetryMin = time.Second
	workerRetryMax = time.Minute
)

// startWorkers launches each worker and RESTARTS any that exit early.
//
// Restarting is the point. A worker returning an error means a pipeline stage has
// stopped — and every stage here is unattended background work, so nothing else
// notices. Correlation dying on one transient Redis timeout used to leave the service
// running, reporting healthy, and silently not correlating anything until someone
// happened to read the logs. A stage that cannot recover on its own is a stage that
// stays down for as long as it takes a human to look.
func startWorkers(ctx context.Context, deps *server.Deps, workers []Worker) *sync.WaitGroup {
	var wg sync.WaitGroup

	for _, w := range workers {
		wg.Add(1)
		go func(w Worker) {
			defer wg.Done()
			superviseWorker(ctx, deps, w)
		}(w)
	}
	return &wg
}

// superviseWorker runs one worker, restarting it with backoff until the context ends.
func superviseWorker(ctx context.Context, deps *server.Deps, w Worker) {
	backoff := workerRetryMin

	for {
		deps.Log.Info(ctx, "worker started", "worker", w.Name())

		err := w.Run(ctx)
		switch {
		case ctx.Err() != nil, errors.Is(err, context.Canceled):
			// A cancelled context is the shutdown path, not a failure.
			deps.Log.Info(ctx, "worker stopped", "worker", w.Name())
			return
		case err == nil:
			// A worker that returns cleanly on its own has finished its job; the
			// consumers and tickers here only return on cancellation.
			deps.Log.Info(ctx, "worker stopped", "worker", w.Name())
			return
		}

		WorkerRestarts.WithLabelValues(w.Name()).Inc()
		deps.Log.Error(ctx, "worker failed, restarting",
			"worker", w.Name(), "cause", err.Error(), "retry_in", backoff.String())

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		backoff = min(backoff*2, workerRetryMax)
	}
}
