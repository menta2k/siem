-- Restores the uniq-state rollups of 0003.
--
-- Symmetrical with the up migration, and lossy in the same way and for the same reason:
-- a uniqCombined state cannot be converted back into a uniq state any more than it could
-- be converted forward, so the tables are rebuilt from source. Anything older than
-- normalized_events' 30-day window does not come back.
--
-- Rolling back also restores the cost this migration exists to remove — ~45,000 merges,
-- 43 GiB written and ~1,660 CPU-seconds per six hours across these five tables. Worth
-- doing only if the ~1% counting error turns out to matter somewhere, which would mean a
-- consumer needs exact figures and should read normalized_events rather than a rollup.

-- ---------------------------------------------------------------- vendor volume

DROP VIEW IF EXISTS mv_vendor_volume_5m;
DROP TABLE IF EXISTS rollup_vendor_volume_5m;

CREATE TABLE rollup_vendor_volume_5m
(
    tenant_id     UUID,
    bucket        DateTime('UTC'),
    vendor        LowCardinality(String),
    events        AggregateFunction(uniq, String),
    bytes         SimpleAggregateFunction(sum, UInt64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toDate(bucket)
ORDER BY (tenant_id, bucket, vendor)
TTL bucket + INTERVAL 400 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW mv_vendor_volume_5m
TO rollup_vendor_volume_5m
AS SELECT
    tenant_id,
    toStartOfFiveMinute(event_time) AS bucket,
    vendor,
    uniqState(event_id)             AS events,
    toUInt64(0)                     AS bytes
FROM normalized_events
GROUP BY tenant_id, bucket, vendor;

-- ---------------------------------------------------------------- verdict mix

DROP VIEW IF EXISTS mv_verdict_mix_5m;
DROP TABLE IF EXISTS rollup_verdict_mix_5m;

CREATE TABLE rollup_verdict_mix_5m
(
    tenant_id     UUID,
    bucket        DateTime('UTC'),
    vendor        LowCardinality(String),
    verdict       LowCardinality(String),
    events        AggregateFunction(uniq, String)
)
ENGINE = AggregatingMergeTree
PARTITION BY toDate(bucket)
ORDER BY (tenant_id, bucket, vendor, verdict)
TTL bucket + INTERVAL 400 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW mv_verdict_mix_5m
TO rollup_verdict_mix_5m
AS SELECT
    tenant_id,
    toStartOfFiveMinute(event_time) AS bucket,
    vendor,
    verdict,
    uniqState(event_id)             AS events
FROM normalized_events
GROUP BY tenant_id, bucket, vendor, verdict;

-- ---------------------------------------------------------------- top rules

DROP VIEW IF EXISTS mv_top_rules_1h;
DROP TABLE IF EXISTS rollup_top_rules_1h;

CREATE TABLE rollup_top_rules_1h
(
    tenant_id     UUID,
    bucket        DateTime('UTC'),
    vendor        LowCardinality(String),
    rule_id       String,
    events        AggregateFunction(uniq, String)
)
ENGINE = AggregatingMergeTree
PARTITION BY toDate(bucket)
ORDER BY (tenant_id, bucket, vendor, rule_id)
TTL bucket + INTERVAL 400 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW mv_top_rules_1h
TO rollup_top_rules_1h
AS SELECT
    tenant_id,
    toStartOfHour(event_time) AS bucket,
    vendor,
    rule_id,
    uniqState(event_id)       AS events
FROM normalized_events
WHERE rule_id != ''
GROUP BY tenant_id, bucket, vendor, rule_id;

-- ---------------------------------------------------------------- top sources

DROP VIEW IF EXISTS mv_top_sources_1h;
DROP TABLE IF EXISTS rollup_top_sources_1h;

CREATE TABLE rollup_top_sources_1h
(
    tenant_id      UUID,
    bucket         DateTime('UTC'),
    client_ip      IPv6,
    client_country LowCardinality(String),
    client_asn     UInt32,
    events         AggregateFunction(uniq, String),
    blocked        AggregateFunction(uniq, String)
)
ENGINE = AggregatingMergeTree
PARTITION BY toDate(bucket)
ORDER BY (tenant_id, bucket, client_ip, client_country, client_asn)
TTL bucket + INTERVAL 400 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW mv_top_sources_1h
TO rollup_top_sources_1h
AS SELECT
    tenant_id,
    toStartOfHour(event_time) AS bucket,
    client_ip,
    client_country,
    client_asn,
    uniqState(event_id)       AS events,
    uniqStateIf(event_id, verdict IN ('blocked', 'rate_limited')) AS blocked
FROM normalized_events
GROUP BY tenant_id, bucket, client_ip, client_country, client_asn;

-- ---------------------------------------------------------------- disagreements

DROP VIEW IF EXISTS mv_disagreement_5m;
DROP TABLE IF EXISTS rollup_disagreement_5m;

CREATE TABLE rollup_disagreement_5m
(
    tenant_id         UUID,
    bucket            DateTime('UTC'),
    disagreement_kind LowCardinality(String),
    records           AggregateFunction(uniq, String),
    total             AggregateFunction(uniq, String)
)
ENGINE = AggregatingMergeTree
PARTITION BY toDate(bucket)
ORDER BY (tenant_id, bucket, disagreement_kind)
TTL bucket + INTERVAL 400 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW mv_disagreement_5m
TO rollup_disagreement_5m
AS SELECT
    tenant_id,
    toStartOfFiveMinute(window_start) AS bucket,
    disagreement_kind,
    uniqStateIf(toString(correlation_id), has_disagreement) AS records,
    uniqState(toString(correlation_id))                     AS total
FROM correlated_requests
GROUP BY tenant_id, bucket, disagreement_kind;

-- ---------------------------------------------------------------- backfill

INSERT INTO rollup_vendor_volume_5m
SELECT tenant_id, toStartOfFiveMinute(event_time) AS bucket, vendor,
       uniqState(event_id), toUInt64(0)
FROM normalized_events GROUP BY tenant_id, bucket, vendor;

INSERT INTO rollup_verdict_mix_5m
SELECT tenant_id, toStartOfFiveMinute(event_time) AS bucket, vendor, verdict,
       uniqState(event_id)
FROM normalized_events GROUP BY tenant_id, bucket, vendor, verdict;

INSERT INTO rollup_top_rules_1h
SELECT tenant_id, toStartOfHour(event_time) AS bucket, vendor, rule_id,
       uniqState(event_id)
FROM normalized_events WHERE rule_id != '' GROUP BY tenant_id, bucket, vendor, rule_id;

INSERT INTO rollup_top_sources_1h
SELECT tenant_id, toStartOfHour(event_time) AS bucket, client_ip, client_country,
       client_asn, uniqState(event_id),
       uniqStateIf(event_id, verdict IN ('blocked', 'rate_limited'))
FROM normalized_events GROUP BY tenant_id, bucket, client_ip, client_country, client_asn;

INSERT INTO rollup_disagreement_5m
SELECT tenant_id, toStartOfFiveMinute(window_start) AS bucket, disagreement_kind,
       uniqStateIf(toString(correlation_id), has_disagreement),
       uniqState(toString(correlation_id))
FROM correlated_requests GROUP BY tenant_id, bucket, disagreement_kind;
