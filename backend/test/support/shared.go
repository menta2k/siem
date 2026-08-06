package support

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// Container lifecycle is per PACKAGE, not per test.
//
// Starting ClickHouse, Redis, and Redpanda takes roughly ten seconds. Paying that per
// test made a twenty-test package take several minutes, which is long enough that
// people stop running it — and an integration suite nobody runs is worse than none,
// because it looks like coverage.
//
// Isolation is preserved a different way: every test gets its own TENANT, and tenant
// scoping is a physical property of every table's sort key. Two tests sharing a
// ClickHouse instance cannot see each other's rows any more than two customers can.
//
// The trade-off this accepts: tests within a package are no longer isolated from each
// other's *schema* changes or from global server state. Nothing here changes either,
// and a test that needs a pristine instance can still call StartStack directly.
var (
	sharedMu      sync.Mutex
	sharedFixture *Fixture
	sharedErr     error
)

// RunSuite starts the shared stack, runs the package's tests, and tears the
// containers down. Integration packages call it from TestMain:
//
//	func TestMain(m *testing.M) { os.Exit(support.RunSuite(m)) }
//
// Returning the exit code rather than calling os.Exit keeps the deferred teardown
// reachable — os.Exit inside this function would skip it and leak containers.
func RunSuite(m *testing.M) int {
	if skipContainers() {
		fmt.Fprintln(os.Stderr, "container tests disabled; skipping integration suite")
		return 0
	}

	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()

	fixture, teardown, err := newSharedFixture(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start shared test stack: %v\n", err)
		return 1
	}
	defer teardown()

	sharedMu.Lock()
	sharedFixture, sharedErr = fixture, nil
	sharedMu.Unlock()

	return m.Run()
}

// Shared returns the package's stack, already migrated and wired.
//
// It fails the test rather than returning nil if RunSuite was not called, because a
// nil fixture would surface as a confusing panic deep inside an unrelated assertion.
func Shared(t *testing.T) *Fixture {
	t.Helper()

	sharedMu.Lock()
	fixture, err := sharedFixture, sharedErr
	sharedMu.Unlock()

	if err != nil {
		t.Fatalf("shared test stack unavailable: %v", err)
	}
	if fixture == nil {
		t.Fatal("shared test stack not started — the package needs " +
			"func TestMain(m *testing.M) { os.Exit(support.RunSuite(m)) }")
	}
	return fixture
}

// SharedTenant returns the shared stack plus a context scoped to a fresh tenant.
//
// This is the entry point almost every test wants: containers are reused, but the
// tenant is unique, so tests remain isolated from each other's data while paying the
// container cost only once per package.
func SharedTenant(t *testing.T, name string) (*Fixture, context.Context) {
	t.Helper()

	fixture := Shared(t)
	ctx, _ := fixture.NewTenant(t, name)
	return fixture, ctx
}

// skipContainers reports whether container-backed tests should be skipped.
func skipContainers() bool {
	if os.Getenv("SIEM_SKIP_CONTAINER_TESTS") != "" {
		return true
	}
	if os.Getenv("DOCKER_HOST") != "" {
		return false
	}
	_, err := os.Stat("/var/run/docker.sock")
	return err != nil
}

// terminateTimeout bounds how long teardown waits for containers to stop.
const terminateTimeout = 60 * time.Second
