-- Who an AS number belongs to.
--
-- An ASN identifies a network but does not name it, and a bare "AS8866" tells an analyst
-- nothing about whether the traffic came from a residential ISP, a hosting provider, or a
-- corporate VPN — which is the first thing they need to know when a network shows up in
-- the top-networks panel with a 24% block rate.
--
-- NOT TENANT-SCOPED, deliberately, and the only table here that is not. Ownership of
-- AS8866 is a fact about the internet rather than about anyone's traffic: partitioning it
-- per tenant would store the same 90,000 rows once per customer and let two tenants
-- disagree about who a network belongs to. Nothing here derives from any tenant's events,
-- so there is no data to leak between them.
--
-- Sourced from iptoasn.com, which publishes under PDDL v1.0 (public domain) and rebuilds
-- hourly. The refresh worker downloads the combined file and reduces it to one row per
-- AS number. The address ranges themselves are not stored, because the events already
-- carry the ASN and this table only has to name it.
--
-- NOTE: no semicolon may appear inside these comments. The migration runner splits the
-- file on it, and a comment containing one produces an empty statement and a failed
-- migration.
CREATE TABLE IF NOT EXISTS asn_owners
(
    asn        UInt32,
    -- The AS description as the registry publishes it, e.g. "VIVACOM-AS". Kept verbatim
    -- rather than prettified: an analyst who searches for what they see here must find
    -- the same string in a registry lookup.
    name       LowCardinality(String),
    -- The registry's country for the AS itself. This is where the NETWORK is registered,
    -- which is NOT where its traffic comes from — the panels report the observed country
    -- separately, and conflating the two would mislabel every multinational carrier.
    country    LowCardinality(String),
    -- When this row was last refreshed, and the ReplacingMergeTree version. A re-import
    -- of an unchanged AS collapses to one row, and a renamed AS keeps the newest name.
    updated_at DateTime('UTC')
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY asn
-- No TTL. The table is a snapshot that is wholly replaced on each refresh, not a log
-- that accumulates: expiring rows by age would empty it the moment a refresh failed for
-- long enough, which is exactly when the last good copy matters most.
SETTINGS index_granularity = 8192;
