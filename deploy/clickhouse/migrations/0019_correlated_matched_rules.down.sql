-- Dropping the column loses the per-vendor rule lists and nothing else. The deciding rule
-- in rule_ids is untouched, so every panel that reads that keeps working, and the
-- migration stages fall back to counting only decisions -- which is what they did before
-- 0019 and why it exists.
ALTER TABLE correlated_requests DROP COLUMN IF EXISTS matched_rule_ids
