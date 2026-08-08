-- Dropping the index first: an index over a column that no longer exists is not a
-- state ClickHouse should be asked to hold, however briefly.
ALTER TABLE normalized_events DROP INDEX IF EXISTS idx_vendor_event_id;
ALTER TABLE normalized_events DROP COLUMN IF EXISTS vendor_event_id;
