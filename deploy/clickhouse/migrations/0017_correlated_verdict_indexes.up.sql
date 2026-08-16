-- Skip indexes on the per-vendor verdicts, for the WAF migration views.
--
-- Those views ask for the RARE cross-vendor cases in a table dominated by the boring
-- ones: what F5 blocked and Cloudflare allowed, what Cloudflare logged and F5 blocked.
-- Measured here over seven days, that is 2,472 and 434 rows respectively out of 66.5
-- million, and finding them cost 6.5 seconds -- against a 10 second query limit, with
-- the joins still to come. The panel timed out at its own default range.
--
-- The cost is not the comparison, it is reading the column: counting every row in the
-- range takes 0.34s and adding one `verdicts['f5'] = ...` predicate takes 6.55s, because
-- the Map has to be decompressed for all 66.5 million rows to find two thousand.
--
-- These rows CLUSTER, which is what makes an index worth adding rather than a rewrite.
-- Of 2,156 index blocks in the table, only 189 contain a Cloudflare `monitored` row and
-- 293 contain an F5 `blocked` one -- so 86-91% of the table can be skipped without being
-- read at all. They cluster because a scan or a probing campaign arrives as a burst and
-- lands in adjacent parts, which is exactly the traffic these views exist to find.
--
-- `set(8)` rather than a bloom filter: the indexed expression has at most a handful of
-- distinct values (allowed, blocked, challenged, monitored, rate_limited, unknown, and
-- the empty string for a vendor absent from the record), so a set holds the whole domain
-- exactly and answers equality without false positives. Eight leaves headroom for a
-- verdict added later, and a set that overflows its cap degrades to "always read" --
-- the behaviour before this migration rather than a wrong answer.
--
-- GRANULARITY 4 matches every other index on this table: one index entry per four
-- granules, 32,768 rows.
ALTER TABLE correlated_requests
    ADD INDEX IF NOT EXISTS idx_corr_f5_verdict verdicts['f5'] TYPE set(8) GRANULARITY 4;

ALTER TABLE correlated_requests
    ADD INDEX IF NOT EXISTS idx_corr_cf_verdict verdicts['cloudflare'] TYPE set(8) GRANULARITY 4;

-- ADD INDEX only affects parts written AFTERWARDS. Without this the seven days of
-- history the migration views are read over -- which is the whole point of them -- would
-- still be scanned in full, and the panel would still time out on everything already
-- stored.
--
-- MATERIALIZE runs as a background mutation. It is safe to run against a live table:
-- queries continue against the existing parts and pick the index up per part as each one
-- finishes. Progress is visible in system.mutations.
ALTER TABLE correlated_requests MATERIALIZE INDEX idx_corr_f5_verdict;

ALTER TABLE correlated_requests MATERIALIZE INDEX idx_corr_cf_verdict
