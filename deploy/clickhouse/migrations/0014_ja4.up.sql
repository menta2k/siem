-- TLS client fingerprint, promoted to a first-class searchable column.
--
-- JA4 identifies the CLIENT STACK rather than the client: the same fingerprint across a
-- thousand addresses is one tool run from a thousand hosts, which is the pivot an analyst
-- reaches for when an attacker rotates IPs and user agents but not their TLS library. A
-- filter is only useful if it is indexed, and it can only be indexed if it is a column.
--
-- FORWARD-LOOKING BY NECESSITY. It cannot be backfilled with SQL: migration 0006 dropped
-- raw_extra, so the only surviving copy of the fingerprint is inside raw_events.payload,
-- and getting it out means re-parsing every payload through its vendor adapter rather than
-- reading a column. Events ingested before this migration therefore have an empty ja4 and
-- do not match a fingerprint filter. That is a gap in history, not a wrong answer, and it
-- ages out with the 30-day retention.
--
-- DEFAULT '' rather than Nullable: "no fingerprint" and "not fingerprinted" are the same
-- thing to a search, and a Nullable column would cost a second mark per granule to express
-- a distinction nothing acts on.
ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS ja4 String DEFAULT '';

-- A bloom filter, matching the other exact-match identifiers, because the query is always
-- ja4 = 'value' and never a substring. tokenbf_v1 is for the columns that get token
-- matched -- user_agent, request_path -- and a fingerprint is one opaque token.
--
-- Skip indexes are built as parts are written, so this covers new data only. Old parts are
-- scanned, which costs nothing in practice: their ja4 is empty and they cannot match.
ALTER TABLE normalized_events ADD INDEX IF NOT EXISTS idx_ja4 ja4 TYPE bloom_filter(0.01) GRANULARITY 4;
