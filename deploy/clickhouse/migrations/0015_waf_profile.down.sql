-- Dropping these loses every score already captured, and they cannot be recovered from
-- SQL -- the values live inside raw_events.payload and getting them out means re-parsing
-- each payload through the vendor adapter. Re-applying the migration starts from empty
-- and fills again only as new events arrive.
ALTER TABLE normalized_events DROP INDEX IF EXISTS idx_waf_score;
ALTER TABLE normalized_events DROP COLUMN IF EXISTS waf_source;
ALTER TABLE normalized_events DROP COLUMN IF EXISTS waf_action;
ALTER TABLE normalized_events DROP COLUMN IF EXISTS waf_rce_score;
ALTER TABLE normalized_events DROP COLUMN IF EXISTS waf_xss_score;
ALTER TABLE normalized_events DROP COLUMN IF EXISTS waf_sqli_score;
ALTER TABLE normalized_events DROP COLUMN IF EXISTS waf_attack_score;
