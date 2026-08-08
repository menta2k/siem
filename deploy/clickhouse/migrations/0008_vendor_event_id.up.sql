-- The vendor's OWN reference for its record of a request, as opposed to
-- vendor_request_id, which is the identifier shared BETWEEN vendors.
--
-- For BIG-IP ASM that is support_id, the value an operator quotes to F5 support and
-- searches for in the ASM event log. It used to survive in raw_extra, which migration
-- 0006 dropped as duplicated storage: correct for fields the common model already
-- holds, wrong for this one, which had no column of its own. Since then support_id has
-- been reachable only by scanning raw_events.payload, which is not a search.
--
-- It cannot share vendor_request_id. That column carries the CF-Ray on ~99% of ASM
-- events precisely so the tier-1 exact join fires, and support_id is only its fallback
-- -- storing both in one column would either break the join or lose the reference.
--
-- Empty for Cloudflare by design: its RayID already serves both roles and is in
-- vendor_request_id. An empty String under ZSTD costs effectively nothing per row.
ALTER TABLE normalized_events
    ADD COLUMN IF NOT EXISTS vendor_event_id String DEFAULT '' AFTER vendor_request_id;

-- Same index shape as idx_vendor_request_id: an exact-match lookup of a
-- high-cardinality identifier, which is what a bloom filter is for.
ALTER TABLE normalized_events
    ADD INDEX IF NOT EXISTS idx_vendor_event_id vendor_event_id TYPE bloom_filter(0.01) GRANULARITY 4;
