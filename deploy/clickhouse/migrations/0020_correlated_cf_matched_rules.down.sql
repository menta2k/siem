-- The index goes first because it is defined on the column. Both are derived from
-- matched_rule_ids, which is untouched, so nothing is lost beyond the speed they bought.
ALTER TABLE correlated_requests DROP INDEX IF EXISTS idx_corr_cf_matched_rules;

ALTER TABLE correlated_requests DROP COLUMN IF EXISTS cf_matched_rules
