-- Dropping an index drops its files; the data is untouched and the queries that used it
-- go back to reading the Map column in full, which is what they did before 0017.
ALTER TABLE correlated_requests DROP INDEX IF EXISTS idx_corr_f5_verdict;

ALTER TABLE correlated_requests DROP INDEX IF EXISTS idx_corr_cf_verdict
