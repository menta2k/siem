-- Cloudflare WAF scoring and the security action that produced a verdict.
--
-- These arrive on every Cloudflare record and were mapped nowhere. They were declared
-- known so they would not read as schema drift, and there they stopped: migration 0006
-- dropped raw_extra, so the only surviving copy is inside raw_events.payload, reachable
-- one event at a time by re-parsing it on the detail view. Nothing could aggregate them,
-- which is the difference between having the data and being able to act on it.
--
-- THE SCALE IS INVERTED and this is the single most important thing to know about these
-- columns. Cloudflare scores 1 to 100 where 1 means "certainly an attack" and 100 means
-- "certainly clean" -- 1-100 despite the documentation describing 1-99, because 100 is
-- what it actually sends for a clean request and that is the most common value there is.
--
-- F5's violation_rating, carried in the shared `score` column, runs
-- the other way: higher is worse. That is why these are their own columns rather than
-- more values in `score` -- mixing the two directions in one column would silently
-- corrupt every threat comparison, the score-conflict disagreement detector and any
-- alert rule keyed on score, and would do it quietly.
--
-- 0 means NOT SCORED rather than "scored zero", which the 1-100 range leaves free.
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS waf_attack_score UInt8 DEFAULT 0;
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS waf_sqli_score UInt8 DEFAULT 0;
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS waf_xss_score UInt8 DEFAULT 0;
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS waf_rce_score UInt8 DEFAULT 0;

-- The action Cloudflare actually took, kept verbatim beside the verdict it maps to.
--
-- The verdict deliberately collapses vocabulary: log, skip, allow and bypass all mean
-- the request was served. For tuning, the difference between them is the entire subject
-- -- "a managed rule matched but was not enforced" is what you act on, and it is not
-- recoverable from `allowed`. LowCardinality because the set is small and closed.
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS waf_action LowCardinality(String) DEFAULT '';

-- Which engine matched: firewallManaged, firewallCustom, ip, bic.
--
-- It decides HOW a rule is tuned, not just whether. A managed rule is adjusted with an
-- exception or an override, a custom rule is edited directly, and an IP or Browser
-- Integrity Check match is neither.
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS waf_source LowCardinality(String) DEFAULT '';

-- minmax rather than bloom_filter, because the query this exists for is a RANGE:
-- "show me the requests scoring as attacks". In an hour of this deployment's traffic
-- 1.98M of 2.03M requests score 81-99, so nearly every granule is entirely clean and
-- minmax skips it on the min alone. A bloom filter answers equality and would read
-- everything for a range.
ALTER TABLE normalized_events ADD INDEX IF NOT EXISTS idx_waf_score waf_attack_score TYPE minmax GRANULARITY 4;
