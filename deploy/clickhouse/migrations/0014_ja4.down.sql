-- Dropping this loses the fingerprints already extracted, and they cannot be recovered
-- from SQL — re-applying the migration starts from empty and only fills again as new
-- events arrive.
ALTER TABLE normalized_events DROP INDEX IF EXISTS idx_ja4;
ALTER TABLE normalized_events DROP COLUMN IF EXISTS ja4;
