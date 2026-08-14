-- The views go first. Dropping a target table while its materialized view still points
-- at it leaves every insert into normalized_events failing on a missing destination.
DROP VIEW IF EXISTS mv_waf_gaps_1h;
DROP VIEW IF EXISTS mv_waf_rules_1h;
DROP TABLE IF EXISTS rollup_waf_gaps_1h;
DROP TABLE IF EXISTS rollup_waf_rules_1h;
