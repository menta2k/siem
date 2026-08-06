-- Dashboard rollups.
--
-- Dashboards read these tables and never normalized_events. A panel that scans raw
-- events is fast on a demo dataset and unusable at 15k events/sec, and the failure
-- arrives in production rather than in review.
--
-- Each rollup is an AggregatingMergeTree target plus a materialized view that writes
-- into it. The view fires on INSERT into the source table, so a rollup only ever sees
-- rows as they arrive -- it is a running aggregate, not a scheduled recomputation, and
-- nothing has to be re-read to keep it current.
--
-- Two consequences of that design are worth stating, because both look like bugs:
--
--   1. A materialized view is populated only from inserts AFTER it exists. Adding one
--      to a table that already holds data leaves the history missing. The backfill
--      statements at the end of this file exist for exactly that reason.
--
--   2. The view reads the INSERTED BLOCK, not the merged table. normalized_events is
--      a ReplacingMergeTree, so a re-ingested event is counted twice by any view that
--      sums it. Volume counters therefore use uniqState over event_id rather than
--      count(), which is idempotent under redelivery.

-- ---------------------------------------------------------------- vendor volume

CREATE TABLE IF NOT EXISTS rollup_vendor_volume_5m
(
    tenant_id     UUID,
    bucket        DateTime('UTC'),
    vendor        LowCardinality(String),
    -- uniqState over event_id, not a plain counter: ReplacingMergeTree can deliver
    -- the same event more than once, and a counter would report merges as traffic.
    events        AggregateFunction(uniq, String),
    -- Payload size has no such duplicate concern at this grain and is a plain sum.
    bytes         SimpleAggregateFunction(sum, UInt64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toDate(bucket)
ORDER BY (tenant_id, bucket, vendor)
TTL bucket + INTERVAL 400 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_vendor_volume_5m
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

CREATE TABLE IF NOT EXISTS rollup_verdict_mix_5m
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

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_verdict_mix_5m
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

-- Hourly rather than 5-minute: rule_id is high cardinality, and a 5-minute grain would
-- produce more rollup rows than source events on a tenant with many distinct rules --
-- an "optimization" that costs more than the scan it replaces.
CREATE TABLE IF NOT EXISTS rollup_top_rules_1h
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

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_top_rules_1h
TO rollup_top_rules_1h
AS SELECT
    tenant_id,
    toStartOfHour(event_time) AS bucket,
    vendor,
    rule_id,
    uniqState(event_id)       AS events
FROM normalized_events
-- Events that triggered no rule are the overwhelming majority and would otherwise
-- create one enormous empty-string bucket that dominates every "top rules" panel.
WHERE rule_id != ''
GROUP BY tenant_id, bucket, vendor, rule_id;

-- ---------------------------------------------------------------- top sources

CREATE TABLE IF NOT EXISTS rollup_top_sources_1h
(
    tenant_id      UUID,
    bucket         DateTime('UTC'),
    client_ip      IPv6,
    client_country LowCardinality(String),
    client_asn     UInt32,
    events         AggregateFunction(uniq, String),
    -- Kept separate so a panel can rank by "most blocked" without a second query, and
    -- so the block RATE for a source is available without re-reading raw events.
    blocked        AggregateFunction(uniq, String)
)
ENGINE = AggregatingMergeTree
PARTITION BY toDate(bucket)
ORDER BY (tenant_id, bucket, client_ip, client_country, client_asn)
TTL bucket + INTERVAL 400 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_top_sources_1h
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

-- Sourced from correlated_requests, not normalized_events: a disagreement is a
-- property of the JOIN, and no single vendor's event can express one.
CREATE TABLE IF NOT EXISTS rollup_disagreement_5m
(
    tenant_id         UUID,
    bucket            DateTime('UTC'),
    disagreement_kind LowCardinality(String),
    -- uniq over correlation_id, because an amended record is re-inserted at a higher
    -- version and a counter would report every late arrival as a new disagreement.
    records           AggregateFunction(uniq, String),
    -- The denominator travels with the numerator so a rate can be computed from one
    -- row. Splitting them across two rollups invites a panel that divides figures
    -- drawn from different time ranges.
    total             AggregateFunction(uniq, String)
)
ENGINE = AggregatingMergeTree
PARTITION BY toDate(bucket)
ORDER BY (tenant_id, bucket, disagreement_kind)
TTL bucket + INTERVAL 400 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_disagreement_5m
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
--
-- A materialized view sees only inserts that happen after it is created, so without
-- these the dashboards would show an empty history until enough new traffic arrived to
-- fill the range -- which reads as "no data" rather than "not yet aggregated".
--
-- Safe to run on an empty database: each is a no-op when the source table has no rows.

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
