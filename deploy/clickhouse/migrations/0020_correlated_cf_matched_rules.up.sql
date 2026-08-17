-- The Cloudflare rule list as its own column, with an index.
--
-- 0019 put every matched rule on the record as Map(vendor -> array), which is the right
-- shape for the data and the wrong shape to read 40 million times. Measured over seven
-- days -- the range the migration pages default to -- the predicates alone cost 0.75s and
-- adding matched_rule_ids['cloudflare'] took it to 4.0s, with the full stage at 10.1s
-- against a 10 second limit. Reading one key of a Map means reading its keys and its
-- values, where a plain array column is read directly.
--
-- The index is what actually pays. Candidate rules are the ones a customer has put in log
-- mode -- a handful out of thousands -- so most granules contain none of them and can be
-- skipped without being read at all. This is the same shape of fix as 0018, for the same
-- reason, and it works here for the same reason it worked there: these matches arrive in
-- bursts and land in adjacent parts.
--
-- bloom_filter rather than set: the domain is every rule id a tenant has, which is
-- thousands, so a set would overflow its cap and degrade to "always read". A bloom filter
-- answers hasAny() with a false-positive rate instead of a size limit, and a false positive
-- only costs one granule read.
ALTER TABLE correlated_requests
    ADD COLUMN IF NOT EXISTS cf_matched_rules Array(String)
    MATERIALIZED matched_rule_ids['cloudflare'];

-- ADD COLUMN alone leaves it computed on read from the Map, which is the cost being
-- avoided. MATERIALIZE writes it down per part, in the background.
ALTER TABLE correlated_requests MATERIALIZE COLUMN cf_matched_rules;

ALTER TABLE correlated_requests
    ADD INDEX IF NOT EXISTS idx_corr_cf_matched_rules cf_matched_rules
    TYPE bloom_filter(0.01) GRANULARITY 4;

ALTER TABLE correlated_requests MATERIALIZE INDEX idx_corr_cf_matched_rules
