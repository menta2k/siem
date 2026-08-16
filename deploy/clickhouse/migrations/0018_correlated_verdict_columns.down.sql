-- Back to reading the Map. The indexes go first because they are defined on the columns
-- below, and the data itself is untouched -- both columns are derived from verdicts,
-- which stays exactly as it was.
--
-- The indexes 0017 added are NOT restored. They were never usable, which is the whole
-- reason 0018 exists, and rolling back to a broken index helps no one.
ALTER TABLE correlated_requests DROP INDEX IF EXISTS idx_corr_f5_verdict;

ALTER TABLE correlated_requests DROP INDEX IF EXISTS idx_corr_cf_verdict;

ALTER TABLE correlated_requests DROP COLUMN IF EXISTS f5_verdict;

ALTER TABLE correlated_requests DROP COLUMN IF EXISTS cf_verdict
