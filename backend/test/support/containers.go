// Package support provides shared infrastructure for integration tests.
//
// Integration tests run against real ClickHouse, Redis, and Redpanda rather than
// mocks. This is deliberate: ReplacingMergeTree's eventual deduplication and
// Redpanda's acknowledgement semantics are exactly the behaviours this system's
// correctness rests on, and a mock would hide both.
//
// Containers are started once per package via RunSuite — see shared.go for why.
package support

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcclickhouse "github.com/testcontainers/testcontainers-go/modules/clickhouse"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
	tcredpanda "github.com/testcontainers/testcontainers-go/modules/redpanda"
)

const (
	clickhouseImage = "clickhouse/clickhouse-server:24.8-alpine"
	redisImage      = "redis:7.4-alpine"
	redpandaImage   = "redpandadata/redpanda:v24.2.9"

	testDatabase = "siem_test"
	testUser     = "siem"
	// Fixed credentials for a throwaway container that exists only for the lifetime
	// of one test binary and is never reachable outside the Docker network.
	testPassword = "siem-test-password" //nolint:gosec // ephemeral test container

	startupTimeout = 5 * time.Minute
)

// Stack holds connection details for the containers backing one test run.
type Stack struct {
	ClickHouseDSN  string
	ClickHouseAddr string
	RedisAddr      string
	RedpandaBroker string
}

// teardown stops a set of containers, collecting every failure rather than stopping
// at the first — a stuck container must not leak the others.
type teardown []func(context.Context) error

func (t teardown) run() error {
	ctx, cancel := context.WithTimeout(context.Background(), terminateTimeout)
	defer cancel()

	var errs []error
	for _, stop := range slices.Backward(t) {
		if err := stop(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// startStack brings up the three containers.
//
// It takes no *testing.T so it can be called from TestMain, where there is no test to
// attach cleanup to.
func startStack(ctx context.Context) (*Stack, teardown, error) {
	var down teardown

	chAddr, chDSN, chStop, err := startClickHouse(ctx)
	if err != nil {
		return nil, down, err
	}
	down = append(down, chStop)

	redisAddr, redisStop, err := startRedis(ctx)
	if err != nil {
		return nil, down, err
	}
	down = append(down, redisStop)

	broker, redpandaStop, err := startRedpanda(ctx)
	if err != nil {
		return nil, down, err
	}
	down = append(down, redpandaStop)

	return &Stack{
		ClickHouseAddr: chAddr,
		ClickHouseDSN:  chDSN,
		RedisAddr:      redisAddr,
		RedpandaBroker: broker,
	}, down, nil
}

// StartStack brings up a dedicated stack for one test.
//
// Prefer SharedTenant: this pays the full container startup cost and is only worth it
// for a test that genuinely needs a pristine server, such as one asserting on
// migration behaviour.
func StartStack(t *testing.T) *Stack {
	t.Helper()

	if skipContainers() {
		t.Skip("docker unavailable — skipping container-backed test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()

	stack, down, err := startStack(ctx)
	t.Cleanup(func() {
		if err := down.run(); err != nil {
			t.Logf("teardown: %v", err)
		}
	})
	if err != nil {
		t.Fatalf("start test stack: %v", err)
	}
	return stack
}

func startClickHouse(
	ctx context.Context,
) (addr, dsn string, stop func(context.Context) error, err error) {
	container, err := tcclickhouse.Run(ctx, clickhouseImage,
		tcclickhouse.WithDatabase(testDatabase),
		tcclickhouse.WithUsername(testUser),
		tcclickhouse.WithPassword(testPassword),
	)
	if err != nil {
		return "", "", noopStop, fmt.Errorf("run clickhouse container: %w", err)
	}
	stop = terminator(container)

	host, err := container.Host(ctx)
	if err != nil {
		return "", "", stop, fmt.Errorf("clickhouse host: %w", err)
	}
	port, err := container.MappedPort(ctx, "9000/tcp")
	if err != nil {
		return "", "", stop, fmt.Errorf("clickhouse port: %w", err)
	}

	addr = fmt.Sprintf("%s:%s", host, port.Port())
	dsn = fmt.Sprintf("clickhouse://%s:%s@%s/%s?x-multi-statement=true",
		testUser, testPassword, addr, testDatabase)
	return addr, dsn, stop, nil
}

func startRedis(ctx context.Context) (addr string, stop func(context.Context) error, err error) {
	container, err := tcredis.Run(ctx, redisImage)
	if err != nil {
		return "", noopStop, fmt.Errorf("run redis container: %w", err)
	}
	stop = terminator(container)

	host, err := container.Host(ctx)
	if err != nil {
		return "", stop, fmt.Errorf("redis host: %w", err)
	}
	port, err := container.MappedPort(ctx, "6379/tcp")
	if err != nil {
		return "", stop, fmt.Errorf("redis port: %w", err)
	}
	return fmt.Sprintf("%s:%s", host, port.Port()), stop, nil
}

func startRedpanda(
	ctx context.Context,
) (broker string, stop func(context.Context) error, err error) {
	container, err := tcredpanda.Run(ctx, redpandaImage, tcredpanda.WithAutoCreateTopics())
	if err != nil {
		return "", noopStop, fmt.Errorf("run redpanda container: %w", err)
	}
	stop = terminator(container)

	broker, err = container.KafkaSeedBroker(ctx)
	if err != nil {
		return "", stop, fmt.Errorf("redpanda seed broker: %w", err)
	}
	return broker, stop, nil
}

func terminator(c testcontainers.Container) func(context.Context) error {
	return func(ctx context.Context) error {
		if err := c.Terminate(ctx); err != nil {
			return fmt.Errorf("terminate container: %w", err)
		}
		return nil
	}
}

func noopStop(context.Context) error { return nil }

// MigrationsDir resolves deploy/clickhouse/migrations relative to the working
// directory, so tests apply the same schema the running system does rather than a
// copy that can silently drift.
func MigrationsDir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getwd: %w", err)
	}
	for range 6 {
		candidate := filepath.Join(dir, "deploy", "clickhouse", "migrations")
		if info, statErr := os.Stat(candidate); statErr == nil && info.IsDir() {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", errors.New("could not locate deploy/clickhouse/migrations")
}
