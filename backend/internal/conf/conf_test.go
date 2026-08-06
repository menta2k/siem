package conf

import (
	"strings"
	"testing"
	"time"
)

// validEnv is the minimum set that must produce a usable configuration.
func validEnv() map[string]string {
	return map[string]string{
		"CLICKHOUSE_ADDR":     "clickhouse:9000",
		"CLICKHOUSE_DATABASE": "siem",
		"CLICKHOUSE_USERNAME": "siem",
		"REDPANDA_BROKERS":    "redpanda:9092",
		"REDIS_ADDR":          "redis:6379",
		"JWT_SIGNING_KEY":     strings.Repeat("k", 48),
	}
}

func setEnv(t *testing.T, env map[string]string) {
	t.Helper()
	for k, v := range env {
		t.Setenv(k, v)
	}
}

func TestLoadValidConfiguration(t *testing.T) {
	setEnv(t, validEnv())

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error for valid environment: %v", err)
	}

	if cfg.ClickHouse.Addr != "clickhouse:9000" {
		t.Errorf("ClickHouse.Addr = %q, want %q", cfg.ClickHouse.Addr, "clickhouse:9000")
	}
	if got, want := cfg.Correlation.Window, 5*time.Second; got != want {
		t.Errorf("Correlation.Window = %v, want %v (documented default)", got, want)
	}
	if got, want := cfg.Correlation.LatenessBound, 15*time.Minute; got != want {
		t.Errorf("Correlation.LatenessBound = %v, want %v (documented default)", got, want)
	}
	if got, want := cfg.Limits.QueryMaxResultRows, int32(1000); got != want {
		t.Errorf("Limits.QueryMaxResultRows = %d, want %d", got, want)
	}
	if len(cfg.Redpanda.Brokers) != 1 {
		t.Errorf("Redpanda.Brokers = %v, want one entry", cfg.Redpanda.Brokers)
	}
}

// Constitution: required secrets are validated at startup, not discovered at runtime.
func TestLoadFailsFastOnMissingRequiredValues(t *testing.T) {
	tests := []struct {
		name    string
		unset   string
		wantErr string
	}{
		{"missing clickhouse addr", "CLICKHOUSE_ADDR", "CLICKHOUSE_ADDR is required"},
		{"missing clickhouse database", "CLICKHOUSE_DATABASE", "CLICKHOUSE_DATABASE is required"},
		{"missing brokers", "REDPANDA_BROKERS", "REDPANDA_BROKERS is required"},
		{"missing redis addr", "REDIS_ADDR", "REDIS_ADDR is required"},
		{"missing signing key", "JWT_SIGNING_KEY", "JWT_SIGNING_KEY is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := validEnv()
			delete(env, tt.unset)
			setEnv(t, env)
			t.Setenv(tt.unset, "")

			_, err := Load()
			if err == nil {
				t.Fatalf("Load() succeeded with %s unset; it must fail at startup", tt.unset)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Load() error = %q, want it to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// A short signing key silently weakens every token in the system, so it is rejected
// rather than accepted with a warning.
func TestLoadRejectsShortSigningKey(t *testing.T) {
	env := validEnv()
	env["JWT_SIGNING_KEY"] = "too-short"
	setEnv(t, env)

	_, err := Load()
	if err == nil {
		t.Fatal("Load() accepted a 9-character signing key; it must be rejected")
	}
	if !strings.Contains(err.Error(), "at least 32 characters") {
		t.Errorf("Load() error = %q, want it to explain the minimum length", err.Error())
	}
}

// Every validation problem should surface in one startup failure, not one per restart.
func TestLoadReportsAllErrorsTogether(t *testing.T) {
	setEnv(t, map[string]string{
		"CLICKHOUSE_ADDR":     "",
		"CLICKHOUSE_DATABASE": "",
		"CLICKHOUSE_USERNAME": "",
		"REDPANDA_BROKERS":    "",
		"REDIS_ADDR":          "",
		"JWT_SIGNING_KEY":     "",
	})

	_, err := Load()
	if err == nil {
		t.Fatal("Load() succeeded with an empty environment")
	}
	wanted := []string{"CLICKHOUSE_ADDR", "REDPANDA_BROKERS", "REDIS_ADDR", "JWT_SIGNING_KEY"}
	for _, want := range wanted {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Load() error is missing %s; all problems should be reported at once:\n%v", want, err)
		}
	}
}

func TestLoadRejectsLatenessBoundBelowWindow(t *testing.T) {
	env := validEnv()
	env["CORRELATION_WINDOW_MS"] = "5000"
	env["CORRELATION_LATENESS_BOUND_MS"] = "1000"
	setEnv(t, env)

	_, err := Load()
	if err == nil {
		t.Fatal("Load() accepted a lateness bound narrower than the correlation window")
	}
	if !strings.Contains(err.Error(), "CORRELATION_LATENESS_BOUND_MS") {
		t.Errorf("Load() error = %q, want it to name the offending variable", err.Error())
	}
}

func TestLoadRejectsNonNumericValues(t *testing.T) {
	env := validEnv()
	env["CLICKHOUSE_MAX_OPEN_CONNS"] = "many"
	setEnv(t, env)

	_, err := Load()
	if err == nil {
		t.Fatal("Load() accepted a non-numeric integer value")
	}
	if !strings.Contains(err.Error(), "CLICKHOUSE_MAX_OPEN_CONNS") {
		t.Errorf("Load() error = %q, want it to name the offending variable", err.Error())
	}
}

func TestSecretBackendRequiresEndpointWhenNotEnv(t *testing.T) {
	env := validEnv()
	env["SECRET_BACKEND"] = "vault"
	setEnv(t, env)
	t.Setenv("SECRET_BACKEND_ENDPOINT", "")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() accepted SECRET_BACKEND=vault with no endpoint configured")
	}
}

func TestSplitListDiscardsBlanks(t *testing.T) {
	got := splitList("a:9092, ,b:9092,")
	want := []string{"a:9092", "b:9092"}

	if len(got) != len(want) {
		t.Fatalf("splitList() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("splitList()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// A limit above 2^31 must be REJECTED, not silently wrapped to a negative number that
// reads as "unset" and falls back to a default the operator did not choose.
func TestOversizedResultRowLimitIsRejected(t *testing.T) {
	setEnv(t, validEnv())
	t.Setenv("QUERY_MAX_RESULT_ROWS", "9999999999")

	if _, err := Load(); err == nil {
		t.Fatal("a result-row limit above the int32 range was accepted")
	}
}

func TestResultRowLimitAtTheBoundaryIsAccepted(t *testing.T) {
	setEnv(t, validEnv())
	t.Setenv("QUERY_MAX_RESULT_ROWS", "2147483647")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("the maximum int32 was rejected: %v", err)
	}
	if cfg.Limits.QueryMaxResultRows != 2147483647 {
		t.Errorf("limit = %d, want the configured value", cfg.Limits.QueryMaxResultRows)
	}
}
