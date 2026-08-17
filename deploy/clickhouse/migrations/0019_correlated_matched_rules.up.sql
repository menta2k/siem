-- EVERY rule each vendor matched, not just the one that decided the outcome.
--
-- rule_ids on this table holds one rule per vendor: the deciding one. That is the right
-- answer to "why was this request blocked" and the wrong answer to the question the WAF
-- migration asks, which is "which rules matched, and what did the other vendor make of
-- the same requests".
--
-- The two differ whenever more than one rule matches, and on this deployment they differ
-- constantly. A Cloudflare rule running in log mode does not terminate evaluation, so a
-- `skip` rule further down becomes the deciding action and the log-mode match vanishes
-- from this table: 13,619 such events in seven days. Those are precisely the rules being
-- migrated, so the stage built to measure them was blind to most of its own subject --
-- a rule could match thousands of requests and still show as "not enough evidence".
--
-- Map(vendor -> array), matching the shape of verdicts and rule_ids beside it, because
-- the point of a correlated record is that an analyst can see WHICH vendor said what.
-- It serves F5 as readily as Cloudflare: F5's rule list is its violation set, so the
-- uncovered stage can eventually group by violation without joining normalized_events
-- for it.
--
-- NO BACKFILL. The value is copied from the events as records are written, so it fills
-- forward and history reads as an empty array. A backfill is possible -- the record keeps
-- the event ids it was built from, and re-emitting at a higher version is how amendments
-- already work -- and is deliberately left as a separate, reviewable step rather than
-- bundled into a schema change. Until then the migration stages measure from here on.
ALTER TABLE correlated_requests
    ADD COLUMN IF NOT EXISTS matched_rule_ids Map(LowCardinality(String), Array(String))
    AFTER rule_ids
