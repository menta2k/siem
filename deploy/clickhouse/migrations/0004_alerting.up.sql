-- Alerting: rules and the alerts they produce.
--
-- Both are ReplacingMergeTree keyed on version, because both are MUTABLE in a store
-- that has no UPDATE: a rule is edited, and an alert moves new -> acknowledged ->
-- resolved. Every write is a full new row at a higher version, and every read uses
-- FINAL. Reading without it returns the alert in each state it has ever held, which
-- for a triage queue means resolved alerts reappearing as new.

CREATE TABLE IF NOT EXISTS alert_rules
(
    tenant_id           UUID,
    rule_id             UUID,
    name                String,
    enabled             Bool DEFAULT true,
    -- low | medium | high | critical
    severity            LowCardinality(String),

    -- The condition as validated JSON: filters, aggregate, threshold, comparator,
    -- window, group-by, cooldown. Stored as a document rather than as columns because
    -- it is read and written whole, and validated by one schema on both sides.
    condition           String,

    window_seconds      UInt32,
    group_by            Array(LowCardinality(String)),
    cooldown_seconds    UInt32,

    webhook_url         String DEFAULT '',
    -- A REFERENCE into the secret manager, never the secret. The signing key must not
    -- sit in a table that analysts and auditors can read.
    webhook_secret_ref  String DEFAULT '',

    created_by          UUID,
    created_at          DateTime64(3, 'UTC'),
    updated_at          DateTime64(3, 'UTC'),
    version             UInt64
)
ENGINE = ReplacingMergeTree(version)
ORDER BY (tenant_id, rule_id)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS alerts
(
    tenant_id                UUID,
    alert_id                 UUID,
    rule_id                  UUID,
    fired_at                 DateTime64(3, 'UTC'),
    severity                 LowCardinality(String),

    -- new | acknowledged | resolved
    state                    LowCardinality(String) DEFAULT 'new',

    -- The group-by values this alert fired for, so one rule grouped by host produces
    -- one alert per host rather than one alert naming several.
    group_values             Map(LowCardinality(String), String),

    observed_value           Float64,
    threshold                Float64,

    -- Links to the correlated records that caused the alert. Without these an operator
    -- receives a number and has to reconstruct the query that produced it, which is
    -- the difference between a three-click investigation and a twenty-minute one.
    evidence_correlation_ids Array(UUID),

    acknowledged_by          Nullable(UUID),
    acknowledged_at          Nullable(DateTime64(3, 'UTC')),
    resolved_by              Nullable(UUID),
    resolved_at              Nullable(DateTime64(3, 'UTC')),

    -- pending | delivered | failed
    --
    -- Tracked on the alert itself, not only in logs: a webhook that silently fails
    -- leaves the operator believing they were notified. The console shows this state
    -- so a delivery failure is visible where the alert is (FR-032).
    notify_status            LowCardinality(String) DEFAULT 'pending',
    notify_attempts          UInt8 DEFAULT 0,
    notify_last_error        String DEFAULT '',

    version                  UInt64
)
ENGINE = ReplacingMergeTree(version)
PARTITION BY toDate(fired_at)
ORDER BY (tenant_id, alert_id)
TTL toDateTime(fired_at) + INTERVAL 365 DAY DELETE
SETTINGS index_granularity = 8192;

-- Triage reads the queue by state and recency far more often than by id, and the sort
-- key leads with alert_id because ReplacingMergeTree needs it there for deduplication.
ALTER TABLE alerts ADD INDEX IF NOT EXISTS idx_alert_state state TYPE set(4) GRANULARITY 4;
ALTER TABLE alerts ADD INDEX IF NOT EXISTS idx_alert_rule rule_id TYPE bloom_filter(0.01) GRANULARITY 4;
-- Delivery failures are the operator's other entry point: "what did we fail to send".
ALTER TABLE alerts ADD INDEX IF NOT EXISTS idx_notify_status notify_status TYPE set(4) GRANULARITY 4;
