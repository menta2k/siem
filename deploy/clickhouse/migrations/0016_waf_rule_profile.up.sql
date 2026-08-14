-- Per-rule WAF profile, for tuning rulesets.
--
-- NO BACKFILL. Both views read waf_attack_score and waf_action, which migration 0015
-- added and which fill forward only -- every row written before it reads 0 and empty, so
-- a backfill would insert a large block of rows saying nothing. The rollups start from
-- the point the columns became real.
--
-- Every comment in this file sits BEFORE a statement. The migration runner splits on
-- the semicolon, so a comment trailing the final one becomes a chunk containing no
-- statement at all, and ClickHouse rejects it as an empty query.
--
-- rollup_top_rules_1h answers "which rules fire most" and nothing else -- no host, no
-- action, no score. None of those are optional for tuning: a rule is adjusted per site,
-- the decision turns on whether it is enforced or merely logged, and whether a hit is a
-- true positive is a question only the attack score can answer.
--
-- THE SCORE BANDS ARE PRE-AGGREGATED rather than stored as an average, because an
-- average is the one summary that hides the answer. A rule that fires on ten real
-- attacks and ninety clean requests averages to "clean" and reads as harmless, when in
-- fact it is doing its job ten times and crying wolf ninety. The split is the finding.
--
-- Bands follow how scores actually fall here: detections land at 1-4, noisy rules at
-- 85-89, and untouched traffic scores 100. Remember the scale is INVERTED -- 1 is
-- certainly an attack, 100 certainly clean.
CREATE TABLE IF NOT EXISTS rollup_waf_rules_1h
(
    tenant_id         UUID,
    bucket            DateTime('UTC'),
    rule_id           String,
    request_host      String,
    -- The vendor's own verb, not the verdict it collapses into. `log` is the state
    -- tuning acts on and `skip` is the one that silently disables everything downstream,
    -- and both read as "allowed" once collapsed.
    waf_action        LowCardinality(String),
    -- firewallManaged or firewallCustom decides HOW a rule is tuned: an override and an
    -- exception against an edit.
    waf_source        LowCardinality(String),

    -- uniqCombined over event_id rather than count(), because normalized_events is a
    -- ReplacingMergeTree and this view sees the inserted block: a redelivered event
    -- would be counted twice.
    events            AggregateFunction(uniqCombined(12), String),

    -- The score split. SimpleAggregateFunction(sum) rather than a state, because these
    -- are plain addition and need no merge function.
    attack_events     SimpleAggregateFunction(sum, UInt64),
    suspicious_events SimpleAggregateFunction(sum, UInt64),
    clean_events      SimpleAggregateFunction(sum, UInt64),
    -- Kept alongside the bands so a mean can still be shown, never instead of them.
    score_sum         SimpleAggregateFunction(sum, UInt64),
    score_count       SimpleAggregateFunction(sum, UInt64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toDate(bucket)
ORDER BY (tenant_id, bucket, rule_id, request_host, waf_action, waf_source)
TTL bucket + INTERVAL 400 DAY DELETE
SETTINGS index_granularity = 8192;

-- Hourly, and with host in the key, which is the cardinality decision. rule_id alone is
-- already high cardinality -- that is why rollup_top_rules_1h is hourly rather than
-- 5-minute -- and multiplying it by host makes a finer grain expensive for a view whose
-- questions are all asked over hours or days. Paths are deliberately NOT in the key:
-- they are effectively unbounded, and the path drill-down is a live query against the
-- events for one rule instead.
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_waf_rules_1h
TO rollup_waf_rules_1h
AS SELECT
    tenant_id,
    toStartOfHour(event_time)       AS bucket,
    rule_id,
    request_host,
    waf_action,
    waf_source,
    uniqCombinedState(12)(event_id) AS events,
    countIf(waf_attack_score BETWEEN 1 AND 20)  AS attack_events,
    countIf(waf_attack_score BETWEEN 21 AND 50) AS suspicious_events,
    countIf(waf_attack_score > 50)              AS clean_events,
    sum(waf_attack_score)                       AS score_sum,
    countIf(waf_attack_score > 0)               AS score_count
FROM normalized_events
-- Cloudflare only: it is the sole vendor reporting a WAF rule engine and an attack
-- score, and including the others would add rows whose score columns are all zero.
-- Events that triggered no rule are excluded for the same reason the top-rules rollup
-- excludes them -- they are the overwhelming majority and would form one vast bucket.
WHERE rule_id != '' AND vendor = 'cloudflare'
GROUP BY tenant_id, bucket, rule_id, request_host, waf_action, waf_source;

-- Coverage gaps: what the WAF scored as an attack and no rule matched.
--
-- The mirror image of a false positive, and the reason it needs its own table is that
-- it is keyed on the ABSENCE of a rule. On this deployment 15 of 33 requests scoring
-- 1-20 in an hour matched nothing at all, which is a hole in the ruleset rather than
-- noise in it.
CREATE TABLE IF NOT EXISTS rollup_waf_gaps_1h
(
    tenant_id         UUID,
    bucket            DateTime('UTC'),
    request_host      String,
    events            AggregateFunction(uniqCombined(12), String),
    attack_events     SimpleAggregateFunction(sum, UInt64),
    suspicious_events SimpleAggregateFunction(sum, UInt64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toDate(bucket)
ORDER BY (tenant_id, bucket, request_host)
TTL bucket + INTERVAL 400 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_waf_gaps_1h
TO rollup_waf_gaps_1h
AS SELECT
    tenant_id,
    toStartOfHour(event_time)       AS bucket,
    request_host,
    uniqCombinedState(12)(event_id) AS events,
    countIf(waf_attack_score BETWEEN 1 AND 20)  AS attack_events,
    countIf(waf_attack_score BETWEEN 21 AND 50) AS suspicious_events
FROM normalized_events
-- Scored as an attack or as suspicious, and matched by nothing. The score bound also
-- keeps the row count small: the overwhelming majority of traffic scores above 50.
WHERE vendor = 'cloudflare' AND rule_id = '' AND waf_attack_score BETWEEN 1 AND 50
GROUP BY tenant_id, bucket, request_host;
