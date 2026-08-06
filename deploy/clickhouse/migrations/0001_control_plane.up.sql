-- Control-plane tables.
--
-- ClickHouse is the sole store of record (see research.md R6). Mutable entities use
-- ReplacingMergeTree keyed by entity id with a monotonically increasing `version`, and
-- MUST be read with FINAL. ClickHouse has no unique constraints, so uniqueness is
-- enforced in the single siem-api write path under a per-entity Redis lock.
--
-- `tenant_id` leads every sort key, so tenant isolation is a physical property of the
-- data layout rather than a filter the application has to remember.

CREATE TABLE IF NOT EXISTS tenants
(
    tenant_id                 UUID,
    name                      String,
    status                    LowCardinality(String) DEFAULT 'active',

    -- Retention is per data class and tenant-configurable (FR-036).
    raw_retention_days        UInt16 DEFAULT 30,
    correlated_retention_days UInt16 DEFAULT 90,
    alert_retention_days      UInt16 DEFAULT 365,

    -- Fields masked at ingest so they are never stored readable (FR-037).
    redacted_fields           Array(String) DEFAULT [],

    -- Correlation tuning, overriding the platform defaults (FR-020).
    correlation_window_ms     UInt32 DEFAULT 5000,
    lateness_bound_ms         UInt32 DEFAULT 900000,
    score_conflict_threshold  Float32 DEFAULT 0.8,

    created_at                DateTime64(3, 'UTC') DEFAULT now64(3),
    updated_at                DateTime64(3, 'UTC') DEFAULT now64(3),
    version                   UInt64
)
ENGINE = ReplacingMergeTree(version)
ORDER BY (tenant_id);

CREATE TABLE IF NOT EXISTS users
(
    tenant_id     UUID,
    user_id       UUID,
    email         String,
    -- argon2id encoded hash. Never a plaintext or reversible value.
    password_hash String,
    -- Encrypted at rest by the application before it reaches this column.
    mfa_secret    String DEFAULT '',
    mfa_enabled   Bool DEFAULT false,
    -- Deny-by-default RBAC: admin | analyst | auditor | ingest_only.
    role          LowCardinality(String),
    status        LowCardinality(String) DEFAULT 'active',
    last_login_at Nullable(DateTime64(3, 'UTC')),
    created_at    DateTime64(3, 'UTC') DEFAULT now64(3),
    version       UInt64
)
ENGINE = ReplacingMergeTree(version)
ORDER BY (tenant_id, user_id);

-- Supports the application-enforced uniqueness check on (tenant, lower(email)).
ALTER TABLE users ADD INDEX IF NOT EXISTS idx_users_email lower(email) TYPE bloom_filter GRANULARITY 1;

CREATE TABLE IF NOT EXISTS feeds
(
    tenant_id             UUID,
    feed_id               UUID,
    vendor                LowCardinality(String),
    name                  String,
    -- push | pull
    delivery_mode         LowCardinality(String) DEFAULT 'push',
    enabled               Bool DEFAULT true,

    -- A POINTER into the secret manager. The vendor credential itself is NEVER
    -- stored here, because persisting it would put every customer's log
    -- credentials in the analytical store.
    credential_ref        String,
    -- Optional HMAC verification key reference for vendors that sign their payloads.
    signing_secret_ref    String DEFAULT '',

    -- JSON: endpoint, bucket, prefix, poll interval. Pull mode only.
    pull_config           String DEFAULT '{}',
    -- Watermark for pull mode: last fully-processed object key or cursor.
    pull_watermark        String DEFAULT '',

    quota_events_per_sec  UInt32 DEFAULT 5000,
    quota_bytes_per_day   UInt64 DEFAULT 107374182400,

    created_at            DateTime64(3, 'UTC') DEFAULT now64(3),
    updated_at            DateTime64(3, 'UTC') DEFAULT now64(3),
    version               UInt64
)
ENGINE = ReplacingMergeTree(version)
ORDER BY (tenant_id, feed_id);

-- Per-minute feed health (FR-008). SummingMergeTree so concurrent writers from
-- several ingest replicas add up rather than overwrite.
--
-- Feed-silence detection is a query over THIS table. Detecting silence by the absence
-- of rows elsewhere would make a dead feed indistinguishable from clean traffic.
CREATE TABLE IF NOT EXISTS feed_health
(
    tenant_id             UUID,
    feed_id               UUID,
    minute                DateTime('UTC'),
    events_received       UInt64,
    events_rejected       UInt64,
    duplicates_suppressed UInt64,
    bytes_received        UInt64,
    max_ingest_lag_ms     SimpleAggregateFunction(max, UInt32),
    unknown_field_events  UInt64,
    credential_valid      SimpleAggregateFunction(min, UInt8)
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(minute)
ORDER BY (tenant_id, feed_id, minute)
TTL minute + INTERVAL 30 DAY DELETE;

-- Append-only audit trail (FR-035).
--
-- Plain MergeTree with NO version column: there is deliberately no update or delete
-- path the application can reach. `prev_hash`/`entry_hash` chain entries per tenant so
-- a deletion or edit is detectable by walking the chain.
CREATE TABLE IF NOT EXISTS audit_entries
(
    tenant_id     UUID,
    entry_id      UUID,
    occurred_at   DateTime64(3, 'UTC'),
    actor_user_id Nullable(UUID),
    actor_email   String,
    source_ip     IPv6,
    action        LowCardinality(String),
    target_type   LowCardinality(String),
    target_id     String,
    before_value  String DEFAULT '',
    after_value   String DEFAULT '',
    -- success | denied
    result        LowCardinality(String),
    detail        String DEFAULT '',
    prev_hash     String,
    entry_hash    String
)
ENGINE = MergeTree
PARTITION BY toDate(occurred_at)
ORDER BY (tenant_id, occurred_at, entry_id)
TTL toDateTime(occurred_at) + INTERVAL 365 DAY DELETE;
