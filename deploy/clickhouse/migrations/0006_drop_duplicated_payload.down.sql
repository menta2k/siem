-- Restores the raw_extra and unknown_fields columns.
--
-- The columns come back EMPTY. There is no backfill because there is nowhere to backfill
-- from in SQL: both were produced by the vendor adapters in Go, and reconstructing them
-- means re-parsing every payload through that code -- which is exactly what the read path
-- now does on demand.
--
-- That makes this rollback structural rather than restorative: it returns the schema so a
-- previous build can start and write into it again, and rows written before the rollback
-- keep empty values in both columns. Any consumer wanting those fields for older rows
-- should read them from EventDetail, which rebuilds them from raw_events.payload
-- regardless of which schema version wrote the row.

ALTER TABLE normalized_events
    ADD COLUMN IF NOT EXISTS raw_extra Map(String, String);

ALTER TABLE normalized_events
    ADD COLUMN IF NOT EXISTS unknown_fields Array(String);
