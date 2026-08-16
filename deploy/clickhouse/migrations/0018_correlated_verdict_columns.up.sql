-- The per-vendor verdicts as real columns, because an index on a Map cannot be used.
--
-- 0017 added set indexes on verdicts['f5'] and verdicts['cloudflare'] and ClickHouse
-- 24.8 never used them -- EXPLAIN indexes=1 does not even list them, and
-- force_data_skipping_indices reports INDEX_NOT_USED. A skip index defined on Map element
-- access is not matched against a `verdicts['f5'] = ...` predicate, so those two indexes
-- were dead weight. They are dropped here rather than left to confuse the next reader.
--
-- The fix is to stop asking the question of a Map at all. Reading one LowCardinality
-- column across a seven-day range costs 0.5s where decompressing the Map to answer the
-- same question costs 1.9s, and unlike the Map a plain column can carry a skip index that
-- the server will actually use.
--
-- MATERIALIZED, not DEFAULT: the value is derived from a column already on the row, and
-- nothing should ever be able to insert a verdict that disagrees with the map it came
-- from. It is also excluded from SELECT * and from an implicit INSERT column list, so no
-- writer changes -- and correlated.go names its columns explicitly in any case.
ALTER TABLE correlated_requests
    ADD COLUMN IF NOT EXISTS f5_verdict LowCardinality(String) MATERIALIZED verdicts['f5'];

ALTER TABLE correlated_requests
    ADD COLUMN IF NOT EXISTS cf_verdict LowCardinality(String) MATERIALIZED verdicts['cloudflare'];

-- ADD COLUMN alone leaves the value computed on read for existing parts, which is the
-- Map read this migration exists to avoid. MATERIALIZE writes it down, per part, in the
-- background.
ALTER TABLE correlated_requests MATERIALIZE COLUMN f5_verdict;

ALTER TABLE correlated_requests MATERIALIZE COLUMN cf_verdict;

-- Now the indexes can do their job. The rows these panels look for CLUSTER -- of 2,156
-- index blocks, only 189 hold a Cloudflare `monitored` row and 293 an F5 `blocked` one,
-- because a scan or a probing campaign arrives as a burst and lands in adjacent parts.
--
-- set(8) holds the whole domain of verdicts exactly, so equality is answered without
-- false positives. A set that overflows its cap degrades to "always read", which is the
-- behaviour before this migration rather than a wrong answer.
ALTER TABLE correlated_requests DROP INDEX IF EXISTS idx_corr_f5_verdict;

ALTER TABLE correlated_requests DROP INDEX IF EXISTS idx_corr_cf_verdict;

ALTER TABLE correlated_requests
    ADD INDEX IF NOT EXISTS idx_corr_f5_verdict f5_verdict TYPE set(8) GRANULARITY 4;

ALTER TABLE correlated_requests
    ADD INDEX IF NOT EXISTS idx_corr_cf_verdict cf_verdict TYPE set(8) GRANULARITY 4;

ALTER TABLE correlated_requests MATERIALIZE INDEX idx_corr_f5_verdict;

ALTER TABLE correlated_requests MATERIALIZE INDEX idx_corr_cf_verdict
