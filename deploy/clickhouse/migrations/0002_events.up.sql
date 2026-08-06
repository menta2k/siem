-- Event pipeline tables.
--
-- Sort-key design follows the ClickHouse rule that high-cardinality columns must not
-- lead the ORDER BY: `event_id` is required in the key for ReplacingMergeTree
-- deduplication to work at all, so it sits LAST, behind low-cardinality
-- tenant/date/vendor columns that carry the actual query filters.
--
-- Retention is expressed as TTL, so expiry is a partition drop rather than a
-- row-level mutation (FR-036). The interval below is the platform default, and the
-- retention worker applies per-tenant overrides.

-- The vendor payload exactly as received. Written BEFORE any parsing is attempted, so
-- a parse failure can never cost the original data (FR-005). Immutable, append-only.
CREATE TABLE IF NOT EXISTS raw_events
(
    tenant_id      UUID,
    feed_id        UUID,
    vendor         LowCardinality(String),
    event_id       String,
    received_at    DateTime64(3, 'UTC'),
    payload        String CODEC(ZSTD(3)),
    -- json | ndjson | cef | syslog
    payload_format LowCardinality(String),
    batch_id       UUID
)
ENGINE = MergeTree
PARTITION BY toDate(received_at)
ORDER BY (tenant_id, vendor, received_at, event_id)
TTL toDateTime(received_at) + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 8192;

-- The common event model (FR-009): three vendor vocabularies on one set of names.
CREATE TABLE IF NOT EXISTS normalized_events
(
    tenant_id           UUID,
    event_id            String,
    event_time          DateTime64(3, 'UTC'),
    event_date          Date MATERIALIZED toDate(event_time),
    -- The vendor's original time value, preserved verbatim (FR-011).
    event_time_original String,
    received_at         DateTime64(3, 'UTC'),

    vendor              LowCardinality(String),
    feed_id             UUID,
    vendor_account      String,
    -- Cloudflare RayID / F5 support_id / DataDome request id. The basis of tier-1
    -- exact correlation.
    vendor_request_id   String,

    client_ip           IPv6,
    -- NAT / proxy / carrier heuristic. Downgrades join confidence rather than
    -- silently weakening the match.
    client_ip_shared    Bool DEFAULT false,
    client_asn          UInt32 DEFAULT 0,
    client_country      LowCardinality(String) DEFAULT '',

    request_host        String,
    request_path        String,
    request_query       String DEFAULT '',
    request_method      LowCardinality(String),
    user_agent          String DEFAULT '',
    http_status         UInt16 DEFAULT 0,

    -- allowed | blocked | challenged | rate_limited | monitored | unknown
    verdict             LowCardinality(String),
    verdict_reason      String DEFAULT '',
    rule_id             String DEFAULT '',
    rule_ids            Array(String) DEFAULT [],
    score               Nullable(Float32),
    -- bot | threat | none
    score_kind          LowCardinality(String) DEFAULT 'none',

    -- Vendor fields with no common-model home, preserved rather than discarded (FR-010).
    raw_extra           Map(String, String),
    -- Drives schema-drift warnings (FR-012).
    unknown_fields      Array(String) DEFAULT [],

    ingest_version      UInt64
)
ENGINE = ReplacingMergeTree(ingest_version)
PARTITION BY toDate(event_time)
ORDER BY (tenant_id, event_date, vendor, event_id)
TTL toDateTime(event_time) + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 8192;

-- Skip indexes for the filters analysts actually reach for during an incident.
ALTER TABLE normalized_events ADD INDEX IF NOT EXISTS idx_client_ip client_ip TYPE bloom_filter(0.01) GRANULARITY 4;
ALTER TABLE normalized_events ADD INDEX IF NOT EXISTS idx_host request_host TYPE bloom_filter(0.01) GRANULARITY 4;
ALTER TABLE normalized_events ADD INDEX IF NOT EXISTS idx_rule rule_id TYPE bloom_filter(0.01) GRANULARITY 4;
ALTER TABLE normalized_events ADD INDEX IF NOT EXISTS idx_vendor_request_id vendor_request_id TYPE bloom_filter(0.01) GRANULARITY 4;
ALTER TABLE normalized_events ADD INDEX IF NOT EXISTS idx_user_agent user_agent TYPE tokenbf_v1(8192, 3, 0) GRANULARITY 4;
ALTER TABLE normalized_events ADD INDEX IF NOT EXISTS idx_path request_path TYPE tokenbf_v1(8192, 3, 0) GRANULARITY 4;

-- Dead-letter store. Nothing is dropped silently (FR-006).
CREATE TABLE IF NOT EXISTS rejected_events
(
    tenant_id     UUID,
    feed_id       UUID,
    vendor        LowCardinality(String),
    rejected_at   DateTime64(3, 'UTC'),
    -- PARSE_ERROR | SCHEMA_UNKNOWN | QUOTA_EXCEEDED | TIMESTAMP_OUT_OF_RANGE
    -- | TENANT_UNKNOWN | PAYLOAD_TOO_LARGE
    reason_code   LowCardinality(String),
    -- Parser message. Must never contain secrets.
    reason_detail String,
    payload       String CODEC(ZSTD(3)),
    batch_id      UUID
)
ENGINE = MergeTree
PARTITION BY toDate(rejected_at)
ORDER BY (tenant_id, feed_id, rejected_at)
TTL toDateTime(rejected_at) + INTERVAL 14 DAY DELETE;

-- One client request as observed by one or more vendors (FR-013 - FR-018).
--
-- READ RULE: every query against this table MUST use FINAL or argMax(..., version).
-- Deduplication is eventual, so a naive read returns both the pre- and
-- post-amendment row. This is a review-blocking defect, not a race to tolerate.
CREATE TABLE IF NOT EXISTS correlated_requests
(
    tenant_id          UUID,
    -- Deterministic from the join key, so a late-arrival amendment targets the same
    -- row instead of creating a second one.
    correlation_id     UUID,

    window_start       DateTime64(3, 'UTC'),
    first_event_time   DateTime64(3, 'UTC'),
    last_event_time    DateTime64(3, 'UTC'),

    vendors            Array(LowCardinality(String)),
    -- 1 for single-vendor records, which are normal, not errors (FR-016).
    vendor_count       UInt8,
    event_ids          Array(String),

    client_ip          IPv6,
    client_ip_shared   Bool DEFAULT false,
    client_asn         UInt32 DEFAULT 0,
    client_country     LowCardinality(String) DEFAULT '',
    request_host       String,
    request_path       String,
    request_method     LowCardinality(String),

    verdicts           Map(LowCardinality(String), LowCardinality(String)),
    rule_ids           Map(LowCardinality(String), String),
    scores             Map(LowCardinality(String), Float32),

    -- Most restrictive verdict across the participating vendors.
    combined_outcome   LowCardinality(String),
    has_disagreement   Bool DEFAULT false,
    -- none | allow_vs_block | allow_vs_challenge | score_conflict
    disagreement_kind  LowCardinality(String) DEFAULT 'none',

    -- vendor_request_id | ip_host_path_method | time_window
    join_signals       Array(LowCardinality(String)),
    -- 1 = exact, 2 = heuristic
    join_tier          UInt8,
    -- high | medium | low (FR-015)
    confidence         LowCardinality(String),
    -- >1 means the window was ambiguous, which downgrades confidence.
    candidate_count    UInt8 DEFAULT 1,

    version            UInt64,
    amended            Bool DEFAULT false
)
ENGINE = ReplacingMergeTree(version)
PARTITION BY toDate(window_start)
ORDER BY (tenant_id, toDate(window_start), correlation_id)
TTL toDateTime(window_start) + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

ALTER TABLE correlated_requests ADD INDEX IF NOT EXISTS idx_corr_client_ip client_ip TYPE bloom_filter(0.01) GRANULARITY 4;
ALTER TABLE correlated_requests ADD INDEX IF NOT EXISTS idx_corr_host request_host TYPE bloom_filter(0.01) GRANULARITY 4;
-- Disagreements are a first-class search category, so they get their own index.
ALTER TABLE correlated_requests ADD INDEX IF NOT EXISTS idx_corr_disagreement has_disagreement TYPE set(2) GRANULARITY 4;
