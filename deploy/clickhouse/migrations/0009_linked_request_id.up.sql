-- A SECOND identifier the same request is known by.
--
-- Cloudflare logs one row per hop of a Worker-protected request, each with its own
-- ray: the client-facing request, the Worker's call to DataDome, and the fetch to the
-- origin. Measured on production, F5 receives the ORIGIN FETCH's ray in its CF-Ray
-- header -- 100% of sampled F5 events -- while the DataDome verdict is only reachable
-- through the client-facing ray. No single identifier reaches all three vendors, which
-- is why a request that passed Cloudflare, DataDome and F5 produced two disjoint
-- correlated records and never three verdicts.
--
-- Every subrequest carries its parent's ray, and that is the bridge. Recording it lets
-- one event be known by two identifiers, so the origin fetch joins F5 through its own
-- ray and DataDome through its parent's.
--
-- Empty for events with only one identifier, which is most of them.
ALTER TABLE normalized_events
    ADD COLUMN IF NOT EXISTS linked_request_id String DEFAULT '' AFTER vendor_event_id;

-- Same shape as the other identifier indexes: exact-match lookup of a
-- high-cardinality value.
ALTER TABLE normalized_events
    ADD INDEX IF NOT EXISTS idx_linked_request_id linked_request_id TYPE bloom_filter(0.01) GRANULARITY 4;
