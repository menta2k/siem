-- Shrink the rollup aggregate states.
--
-- The rollups were the most expensive thing in the database, by a wide margin, and it
-- did not show up as disk: measured over six hours, the five rollup tables performed
-- ~45,000 merges, wrote 43 GiB and burned ~1,660 CPU-seconds — 3.7x the CPU of
-- normalized_events — while holding 280 MiB and ~489,000 rows between them.
--
-- The cause is the state type, not the design. `uniq` keeps an adaptive structure that
-- GROWS with cardinality, and at these volumes it pins at maximum size:
--
--     distinct values        uniq state      uniqCombined(12) state
--     10                     42 B            82 B
--     1,000                  3,963 B         3,291 B
--     1,000,000              248,736 B       3,291 B     <-- capped
--
-- rollup_disagreement_5m held 276 rows in 43 MiB — ~112 KB per row — and every one of
-- its 26,330 merges deserialized both states, merged them, and serialized them back.
-- AggregatingMergeTree rewrites each part repeatedly, so a fat state is paid for over
-- and over regardless of whether anything reads it.
--
-- uniqCombined(12) caps at ~3.2 KB no matter the cardinality, measured at -1.14% error
-- on a million distinct values merged across twenty partial states. These figures drive
-- dashboard panels that render counts in the millions, and the exact values remain
-- available from normalized_events directly.
--
-- WHY uniqCombined(12) AND NOT uniqHLL12: uniqHLL12 is smaller still at the top end, but
-- rollup_top_sources_1h holds ~487,000 rows, most covering a single client with a handful
-- of events. uniqCombined stores small sets exactly and only switches to the sketch when
-- it has to, so those rows stay tiny. A dense sketch per row would have made that table
-- larger, not smaller — the opposite of the point.
--
-- THE IDEMPOTENCY PROPERTY IS PRESERVED, and it is the reason these are uniq states at
-- all rather than counters: normalized_events is a ReplacingMergeTree and
-- correlated_requests re-inserts amended records at a higher version, so a redelivered
-- row must not register as new traffic. uniqCombined keeps set semantics, so it stays
-- immune to redelivery. That property also makes the backfill below safe to overlap with
-- the live view: a row counted by both is still counted once.
--
-- HISTORY. There is no conversion from a uniq state to a uniqCombined state, so the old
-- rollups cannot be migrated in place — they are dropped and rebuilt from source. The
-- rollups keep 400 days but normalized_events keeps 30, so anything older than the source
-- window would be lost for good. At the time of writing the rollups hold ~1 day and the
-- source covers all of it, so the rebuild is complete. This gets strictly more expensive
-- to do the longer it is deferred.

-- ---------------------------------------------------------------- vendor volume

DROP VIEW IF EXISTS mv_vendor_volume_5m;
DROP TABLE IF EXISTS rollup_vendor_volume_5m;

CREATE TABLE rollup_vendor_volume_5m
(
    tenant_id     UUID,
    bucket        DateTime('UTC'),
    vendor        LowCardinality(String),
    -- A set state, not a counter: ReplacingMergeTree can deliver the same event more
    -- than once, and a counter would report merges as traffic.
    events        AggregateFunction(uniqCombined(12), String),
    -- Payload size has no such duplicate concern at this grain and is a plain sum.
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
    toStartOfFiveMinute(event_time)  AS bucket,
    vendor,
    uniqCombinedState(12)(event_id)  AS events,
    toUInt64(0)                      AS bytes
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
    events        AggregateFunction(uniqCombined(12), String)
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
    toStartOfFiveMinute(event_time)  AS bucket,
    vendor,
    verdict,
    uniqCombinedState(12)(event_id)  AS events
FROM normalized_events
GROUP BY tenant_id, bucket, vendor, verdict;

-- ---------------------------------------------------------------- top rules

-- Hourly rather than 5-minute: rule_id is high cardinality, and a 5-minute grain would
-- produce more rollup rows than source events on a tenant with many distinct rules.
DROP VIEW IF EXISTS mv_top_rules_1h;
DROP TABLE IF EXISTS rollup_top_rules_1h;

CREATE TABLE rollup_top_rules_1h
(
    tenant_id     UUID,
    bucket        DateTime('UTC'),
    vendor        LowCardinality(String),
    rule_id       String,
    events        AggregateFunction(uniqCombined(12), String)
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
    toStartOfHour(event_time)        AS bucket,
    vendor,
    rule_id,
    uniqCombinedState(12)(event_id)  AS events
FROM normalized_events
-- Events that triggered no rule are the overwhelming majority and would otherwise
-- create one enormous empty-string bucket that dominates every "top rules" panel.
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
    events         AggregateFunction(uniqCombined(12), String),
    -- Kept separate so a panel can rank by "most blocked" without a second query, and
    -- so the block RATE for a source is available without re-reading raw events.
    blocked        AggregateFunction(uniqCombined(12), String)
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
    toStartOfHour(event_time)        AS bucket,
    client_ip,
    client_country,
    client_asn,
    uniqCombinedState(12)(event_id)  AS events,
    uniqCombinedStateIf(12)(event_id, verdict IN ('blocked', 'rate_limited')) AS blocked
FROM normalized_events
GROUP BY tenant_id, bucket, client_ip, client_country, client_asn;

-- ---------------------------------------------------------------- disagreements

-- The worst offender: 276 rows, 43 MiB, 26,330 merges and 26.52 GiB written in six hours.
DROP VIEW IF EXISTS mv_disagreement_5m;
DROP TABLE IF EXISTS rollup_disagreement_5m;

CREATE TABLE rollup_disagreement_5m
(
    tenant_id         UUID,
    bucket            DateTime('UTC'),
    disagreement_kind LowCardinality(String),
    -- A set over correlation_id, because an amended record is re-inserted at a higher
    -- version and a counter would report every late arrival as a new disagreement.
    records           AggregateFunction(uniqCombined(12), String),
    -- The denominator travels with the numerator so a rate can be computed from one
    -- row. Splitting them across two rollups invites a panel that divides figures
    -- drawn from different time ranges.
    total             AggregateFunction(uniqCombined(12), String)
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
    uniqCombinedStateIf(12)(toString(correlation_id), has_disagreement) AS records,
    uniqCombinedState(12)(toString(correlation_id))                     AS total
FROM correlated_requests
GROUP BY tenant_id, bucket, disagreement_kind;

-- ---------------------------------------------------------------- backfill
--
-- Rebuilds the history the dropped tables held. Deliberately runs AFTER the views exist:
-- rows arriving during the backfill are then captured by both, and because these are set
-- states rather than counters, a row counted twice is still counted once. Ordering it the
-- other way would leave a gap for whatever arrived in between.
--
-- Safe on an empty database: each is a no-op when the source table has no rows.
--
-- EVERY ONE SPILLS TO DISK RATHER THAN SIZING ITSELF AGAINST AVAILABLE RAM. These group
-- the whole source table at once, so their peak memory scales with retained history and
-- distinct-key count, neither of which a migration can predict. The first run of this
-- file died on exactly that -- the top-sources backfill asked for 6.12 GiB against a
-- 4 GiB server limit, halfway through, leaving the migration dirty.
--
-- max_bytes_before_external_group_by makes the aggregation spill once it passes the
-- threshold instead of failing, so the backfill completes on a small server and merely
-- takes longer. The threshold sits well under max_memory_usage because the query needs
-- headroom above it to merge the spilled buckets back together.

INSERT INTO rollup_vendor_volume_5m
SELECT tenant_id, toStartOfFiveMinute(event_time) AS bucket, vendor,
       uniqCombinedState(12)(event_id), toUInt64(0)
FROM normalized_events GROUP BY tenant_id, bucket, vendor
SETTINGS max_bytes_before_external_group_by = 1000000000, max_memory_usage = 3000000000;

INSERT INTO rollup_verdict_mix_5m
SELECT tenant_id, toStartOfFiveMinute(event_time) AS bucket, vendor, verdict,
       uniqCombinedState(12)(event_id)
FROM normalized_events GROUP BY tenant_id, bucket, vendor, verdict
SETTINGS max_bytes_before_external_group_by = 1000000000, max_memory_usage = 3000000000;

INSERT INTO rollup_top_rules_1h
SELECT tenant_id, toStartOfHour(event_time) AS bucket, vendor, rule_id,
       uniqCombinedState(12)(event_id)
FROM normalized_events WHERE rule_id != '' GROUP BY tenant_id, bucket, vendor, rule_id
SETTINGS max_bytes_before_external_group_by = 1000000000, max_memory_usage = 3000000000;

-- The heaviest of the five: hourly buckets keyed by client address, so the group count
-- grows with the number of distinct clients seen rather than with any fixed dimension.
INSERT INTO rollup_top_sources_1h
SELECT tenant_id, toStartOfHour(event_time) AS bucket, client_ip, client_country,
       client_asn, uniqCombinedState(12)(event_id),
       uniqCombinedStateIf(12)(event_id, verdict IN ('blocked', 'rate_limited'))
FROM normalized_events GROUP BY tenant_id, bucket, client_ip, client_country, client_asn
SETTINGS max_bytes_before_external_group_by = 1000000000, max_memory_usage = 3000000000;

INSERT INTO rollup_disagreement_5m
SELECT tenant_id, toStartOfFiveMinute(window_start) AS bucket, disagreement_kind,
       uniqCombinedStateIf(12)(toString(correlation_id), has_disagreement),
       uniqCombinedState(12)(toString(correlation_id))
FROM correlated_requests GROUP BY tenant_id, bucket, disagreement_kind
SETTINGS max_bytes_before_external_group_by = 1000000000, max_memory_usage = 3000000000;
