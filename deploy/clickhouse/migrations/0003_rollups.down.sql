-- Views are dropped before their targets: a materialized view whose destination table
-- has gone still fires on every insert and fails it, which would take ingestion down
-- rather than merely removing a dashboard.
DROP VIEW IF EXISTS mv_disagreement_5m;
DROP VIEW IF EXISTS mv_top_sources_1h;
DROP VIEW IF EXISTS mv_top_rules_1h;
DROP VIEW IF EXISTS mv_verdict_mix_5m;
DROP VIEW IF EXISTS mv_vendor_volume_5m;

DROP TABLE IF EXISTS rollup_disagreement_5m;
DROP TABLE IF EXISTS rollup_top_sources_1h;
DROP TABLE IF EXISTS rollup_top_rules_1h;
DROP TABLE IF EXISTS rollup_verdict_mix_5m;
DROP TABLE IF EXISTS rollup_vendor_volume_5m;
