-- Finding the correlated record one event belongs to.
--
-- An event does not carry a correlation id: records store event ids, and writing the
-- reverse would mean rewriting every event after the join. So the console searches
-- has(event_ids, ...) instead, and without an index that reads the event_ids column of
-- every row in the window -- arrays of 64-character hex strings, the widest column on the
-- table. Measured on production, a seven-day range took 24.5 seconds over 69 million rows,
-- which is not a slow answer but a cancelled one.
--
-- The service already bounds the search to the minutes around the event, which brought the
-- same lookup to 2.8 seconds over half a million rows. This is what takes it the rest of
-- the way: an event id appears in exactly one record, so nearly every granule can be
-- skipped without being read.
--
-- bloom_filter rather than set, for the reason 0020 gives: the domain is every event id a
-- tenant has, which is hundreds of millions, and a set would overflow its cap and degrade
-- to "always read". GRANULARITY 1 rather than 4 because the filter is being asked about a
-- single value that lives in a single granule -- a coarser index would keep four times as
-- many granules alive for nothing.
ALTER TABLE correlated_requests
    ADD INDEX IF NOT EXISTS idx_corr_event_ids event_ids
    TYPE bloom_filter(0.01) GRANULARITY 1;

-- NOT materialized, deliberately. This table holds 90 days at roughly ten million rows a
-- day, and rewriting all of it to backfill an index would compete with ingestion for hours
-- to speed up lookups against records nobody is looking at any more. Parts written from
-- here on carry the index, and older parts are read exactly as they are today, so the
-- worst case is the speed we already have.
--
-- To backfill anyway, one day at a time and watching ingestion lag:
--   ALTER TABLE correlated_requests MATERIALIZE INDEX idx_corr_event_ids IN PARTITION '2026-08-17'
