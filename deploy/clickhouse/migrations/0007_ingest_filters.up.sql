-- Per-tenant ingest filters.
--
-- Events matching a filter are never ingested: no raw payload, no normalized row, no
-- rejection. Static assets and health checks can be a large share of a WAF's log volume
-- while carrying no security signal, and the cheapest event is the one never written.
--
-- Stored as a JSON array of rules rather than a typed column set, because a rule is three
-- parts -- field, operator, values -- and the alternatives are worse. Three parallel
-- Array columns can fall out of step with each other, and a delimited string breaks the first
-- time a value contains the delimiter. The application validates on write, so what lands
-- here has already been rejected if it names an unknown field or operator.
--
-- DEFAULTS TO NO FILTERING, and every failure path in the reader agrees: an unreadable
-- tenant row, undecodable JSON, or rules that no longer compile all yield an empty set.
-- That direction is deliberate. Ingesting an event that should have been filtered wastes
-- storage and can be corrected later, while dropping one that should have been kept destroys it
-- with no copy anywhere to recover from.

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS ingest_filters String DEFAULT '[]';

-- The filtered counter has nowhere else to live.
--
-- A filtered event leaves no payload, no row and no rejection, so this column is the only
-- evidence that a rule is working -- and the only warning when it is working far too well.
-- Without it a filtered event is indistinguishable from a lost one, which is precisely the
-- confusion this feature must not create.
ALTER TABLE feed_health
    ADD COLUMN IF NOT EXISTS events_filtered UInt64 DEFAULT 0;
