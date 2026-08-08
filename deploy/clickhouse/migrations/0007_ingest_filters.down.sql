-- Removes the ingest filter column.
--
-- Rolling back means every event is ingested again, including whatever the filters were
-- excluding. That is the safe direction to fail in -- nothing is lost, only stored -- but
-- it can be a large and sudden volume increase on a tenant that was filtering heavily, so
-- it is worth knowing before rather than after.

ALTER TABLE tenants DROP COLUMN IF EXISTS ingest_filters;

ALTER TABLE feed_health DROP COLUMN IF EXISTS events_filtered;
