// Package conf loads and validates service configuration from the environment.
//
// Configuration is immutable once loaded: Load returns a fully-populated value and
// nothing mutates it afterwards. Validation happens once, at startup, and a missing
// secret is a hard failure rather than a nil dereference under load
// (Constitution: required secrets validated at startup).
package conf

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// Config is the complete configuration for any of the three services. Each binary
// validates only the sections it uses, via the Require* methods.
type Config struct {
	ClickHouse      ClickHouse
	Redpanda        Redpanda
	Redis           Redis
	Auth            Auth
	Secrets         Secrets
	Server          Server
	Limits          Limits
	Correlation     Correlation
	ASNOwners       ASNOwners
	CloudflareRules CloudflareRules
	Log             Log
}

// ClickHouse holds the analytical store connection settings.
type ClickHouse struct {
	Addr             string
	Database         string
	Username         string
	Password         string
	MaxExecutionTime time.Duration
	MaxOpenConns     int
}

// Redpanda holds the durable ingest queue settings.
type Redpanda struct {
	Brokers         []string
	TopicRaw        string
	TopicNormalized string
	// ConsoleURL is the base address evidence deep links are built from, so an alert
	// in a chat channel links to the record rather than to a dashboard.
	ConsoleURL string
	// ConsumerGroupNormalized is the correlator's group. Separate from the raw group
	// so correlation can fall behind without stalling normalization.
	ConsumerGroupNormalized string
	TopicDLQ                string
	ProduceTimeout          time.Duration
	ConsumerGroupRaw        string
}

// Redis holds ephemeral-state settings. Redis is never a system of record.
type Redis struct {
	Addr     string
	Password string
	DB       int
}

// Auth holds token and MFA settings.
type Auth struct {
	JWTSigningKey string
	AccessTTL     time.Duration
	RefreshTTL    time.Duration
	MFAIssuer     string
}

// Secrets points at the backend holding feed credentials. Credentials are stored by
// reference; the platform never persists a vendor secret inline.
type Secrets struct {
	Backend  string
	Endpoint string
	Token    string
}

// Server holds bind settings for the running service.
type Server struct {
	APIPort       int
	IngestPort    int
	ProcessorPort int
	MetricsBind   string
}

// Limits are the bounds that keep ingestion and querying from running unbounded.
type Limits struct {
	IngestMaxBodyBytes   int64
	IngestMaxBatchEvents int
	// IngestCommitTimeout bounds the durable commit, which deliberately outlives the
	// sender's connection. See receiver.Options.CommitTimeout.
	IngestCommitTimeout time.Duration
	QueryMaxResultRows  int32
	QueryMaxRangeDays   int
	ExportMaxRows       int
}

// Correlation holds platform defaults; per-tenant settings override these at runtime.
type Correlation struct {
	Window        time.Duration
	LatenessBound time.Duration
}

// ASNOwners holds the AS-number-to-owner lookup table settings.
//
// The one place this platform reaches out to the public internet on a schedule, so it
// is configurable in full and can be switched off outright — an air-gapped deployment
// gets bare AS numbers rather than a worker that retries a host it can never reach.
type ASNOwners struct {
	Enabled   bool
	SourceURL string
	Interval  time.Duration
}

// CloudflareRules holds the WAF rule-name lookup settings.
//
// No enable flag, unlike ASNOwners: the refresh does nothing for a tenant that has not
// configured a token, so "off" is the default state without a switch to set.
type CloudflareRules struct {
	// APIBase overrides Cloudflare's API, for a test or an enterprise gateway.
	APIBase  string
	Interval time.Duration
}

// Log holds observability settings.
type Log struct {
	Level  string
	Format string
}

// Load reads configuration from the environment and validates it. The returned
// Config is safe to share; callers must treat it as read-only.
func Load() (*Config, error) {
	var errs []error
	collect := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	cfg := &Config{}
	cfg.ClickHouse, cfg.Redpanda = loadClickHouse(collect), loadRedpanda(collect)
	cfg.Redis, cfg.Auth = loadRedis(collect), loadAuth(collect)
	cfg.Secrets, cfg.Server = loadSecrets(collect), loadServer(collect)
	cfg.Limits, cfg.Correlation = loadLimits(collect), loadCorrelation(collect)
	cfg.ASNOwners = loadASNOwners(collect)
	cfg.CloudflareRules = loadCloudflareRules(collect)
	cfg.Log = Log{
		Level:  optional("LOG_LEVEL", "info"),
		Format: optional("LOG_FORMAT", "json"),
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid configuration: %w", errors.Join(errs...))
	}
	return cfg, nil
}

func loadClickHouse(collect func(error)) ClickHouse {
	addr, err := required("CLICKHOUSE_ADDR")
	collect(err)
	db, err := required("CLICKHOUSE_DATABASE")
	collect(err)
	user, err := required("CLICKHOUSE_USERNAME")
	collect(err)
	// Password may legitimately be empty for a local trust-auth instance, so it is
	// read but not required. Every other field is mandatory.
	maxExec, err := durationSeconds("CLICKHOUSE_MAX_EXECUTION_TIME_SECONDS", 10)
	collect(err)
	conns, err := integer("CLICKHOUSE_MAX_OPEN_CONNS", 32)
	collect(err)

	return ClickHouse{
		Addr:             addr,
		Database:         db,
		Username:         user,
		Password:         os.Getenv("CLICKHOUSE_PASSWORD"),
		MaxExecutionTime: maxExec,
		MaxOpenConns:     conns,
	}
}

func loadRedpanda(collect func(error)) Redpanda {
	brokers, err := required("REDPANDA_BROKERS")
	collect(err)
	timeout, err := durationMillis("REDPANDA_PRODUCE_TIMEOUT_MS", 5000)
	collect(err)

	return Redpanda{
		Brokers:         splitList(brokers),
		TopicRaw:        optional("REDPANDA_TOPIC_RAW", "siem.events.raw"),
		TopicNormalized: optional("REDPANDA_TOPIC_NORMALIZED", "siem.events.normalized"),
		ConsumerGroupNormalized: optional("REDPANDA_CONSUMER_GROUP_NORMALIZED",
			"siem-correlator"),
		TopicDLQ:         optional("REDPANDA_TOPIC_DLQ", "siem.events.dlq"),
		ProduceTimeout:   timeout,
		ConsumerGroupRaw: optional("REDPANDA_CONSUMER_GROUP", "siem-processor"),
		ConsoleURL:       optional("CONSOLE_URL", "http://localhost:5173"),
	}
}

func loadRedis(collect func(error)) Redis {
	addr, err := required("REDIS_ADDR")
	collect(err)
	db, err := integer("REDIS_DB", 0)
	collect(err)

	return Redis{Addr: addr, Password: os.Getenv("REDIS_PASSWORD"), DB: db}
}

func loadAuth(collect func(error)) Auth {
	key, err := required("JWT_SIGNING_KEY")
	collect(err)
	if err == nil && len(key) < minSigningKeyLen {
		collect(fmt.Errorf("JWT_SIGNING_KEY must be at least %d characters", minSigningKeyLen))
	}
	access, err := durationMinutes("JWT_ACCESS_TTL_MINUTES", 15)
	collect(err)
	refresh, err := durationHours("JWT_REFRESH_TTL_HOURS", 168)
	collect(err)

	return Auth{
		JWTSigningKey: key,
		AccessTTL:     access,
		RefreshTTL:    refresh,
		MFAIssuer:     optional("MFA_ISSUER", "SIEM"),
	}
}

func loadSecrets(collect func(error)) Secrets {
	backend := optional("SECRET_BACKEND", "env")
	s := Secrets{
		Backend:  backend,
		Endpoint: os.Getenv("SECRET_BACKEND_ENDPOINT"),
		Token:    os.Getenv("SECRET_BACKEND_TOKEN"),
	}
	// The "env" backend is development-only; anything else must be reachable.
	if backend != "env" && s.Endpoint == "" {
		collect(fmt.Errorf("SECRET_BACKEND_ENDPOINT is required when SECRET_BACKEND is %q", backend))
	}
	return s
}

func loadServer(collect func(error)) Server {
	api, err := integer("API_HTTP_PORT", 8000)
	collect(err)
	ingest, err := integer("INGEST_HTTP_PORT", 8001)
	collect(err)
	processor, err := integer("PROCESSOR_HTTP_PORT", 8002)
	collect(err)

	return Server{
		APIPort:       api,
		IngestPort:    ingest,
		ProcessorPort: processor,
		MetricsBind:   optional("METRICS_BIND", "0.0.0.0"),
	}
}

func loadLimits(collect func(error)) Limits {
	// 128 MiB. A LIVE batch is a fraction of this — the size that matters is a
	// RECOVERY batch, where a vendor that has been buffering for an hour delivers
	// everything at once. Sizing this for the steady state is what turns a provider
	// outage into a permanent one: the oversized batch is refused, the vendor retries
	// the same bytes, and the backlog can never drain. Observed on production at 36,000
	// events, comfortably past the previous 32 MiB.
	body, err := integer64("INGEST_MAX_BODY_BYTES", 128<<20)
	collect(err)
	batch, err := integer("INGEST_MAX_BATCH_EVENTS", 50000)
	collect(err)
	commit, err := durationSeconds("INGEST_COMMIT_TIMEOUT_SECONDS", 120)
	collect(err)
	rows, err := integer32("QUERY_MAX_RESULT_ROWS", 1000)
	collect(err)
	rangeDays, err := integer("QUERY_MAX_RANGE_DAYS", 90)
	collect(err)
	exportRows, err := integer("EXPORT_MAX_ROWS", 100000)
	collect(err)

	return Limits{
		IngestMaxBodyBytes:   body,
		IngestMaxBatchEvents: batch,
		IngestCommitTimeout:  commit,
		QueryMaxResultRows:   rows,
		QueryMaxRangeDays:    rangeDays,
		ExportMaxRows:        exportRows,
	}
}

// loadASNOwners reads the AS-owner lookup settings.
//
// Enabled by DEFAULT. The data is public domain and the failure mode is a logged
// warning with the previous table still being served, so the cost of it being on for a
// deployment that did not want it is one failed request a day — while the cost of it
// being off by default is that every install shows bare AS numbers until someone finds
// the flag.
func loadASNOwners(collect func(error)) ASNOwners {
	interval, err := durationHours("ASN_OWNERS_REFRESH_HOURS", 24)
	collect(err)

	return ASNOwners{
		Enabled:   optional("ASN_OWNERS_ENABLED", "true") != "false",
		SourceURL: optional("ASN_OWNERS_SOURCE_URL", ""),
		Interval:  interval,
	}
}

// loadCloudflareRules reads the rule-name refresh settings.
func loadCloudflareRules(collect func(error)) CloudflareRules {
	interval, err := durationMinutes("CLOUDFLARE_RULES_REFRESH_MINUTES", 60)
	collect(err)

	return CloudflareRules{
		APIBase:  optional("CLOUDFLARE_API_BASE", ""),
		Interval: interval,
	}
}

func loadCorrelation(collect func(error)) Correlation {
	window, err := durationMillis("CORRELATION_WINDOW_MS", 5000)
	collect(err)
	lateness, err := durationMillis("CORRELATION_LATENESS_BOUND_MS", 900000)
	collect(err)

	if window > 0 && lateness > 0 && lateness < window {
		collect(errors.New("CORRELATION_LATENESS_BOUND_MS must be at least CORRELATION_WINDOW_MS"))
	}
	return Correlation{Window: window, LatenessBound: lateness}
}
