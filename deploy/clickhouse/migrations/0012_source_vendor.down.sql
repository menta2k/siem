-- Dropping it returns every read path to inferring the delivering vendor, or to the full
-- scan of raw_events that inference could not avoid.
ALTER TABLE normalized_events DROP COLUMN IF EXISTS source_vendor
