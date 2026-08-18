-- Per-minute correlation pipeline health, so a stalled closer is VISIBLE.
--
-- Correlation has now stopped twice on production without anything saying so. Once
-- because a column was added to the insert and not to the scan, so every close pass
-- failed. Once because the closer fell behind the rate windows were being filed, and
-- past the window TTL every window it closed was empty. Both times the console went on
-- serving the records written before the fall and looked entirely healthy — the API
-- reads stored records, and stored records do not know that no new ones are arriving.
--
-- The failures had one shape in common: events go in, correlated records do not come
-- out. That relationship is what this table records, minute by minute, so the next
-- fault — whatever its cause — is a state the console can show rather than something
-- an operator has to notice by missing data.
--
-- Modelled on feed_health, deliberately: SummingMergeTree over per-minute counters,
-- written by an aggregator that flushes once a minute, read as an hour's aggregate.
-- Silence is detected FROM this table rather than from the absence of correlated
-- records, for the same reason feed silence is: an absence cannot distinguish a dead
-- pipeline from a quiet one.
--
-- events_filed is the denominator that makes the rest mean anything. Zero records
-- emitted is healthy when nothing was filed, and an outage when thousands were.
--
-- windows_due and max_claim_lag_ms are the two readings of "how far behind". The count
-- is the steady one. The lag is noisier, because a feed delivering hours-old events
-- schedules windows whose deadline is already in the past through no fault of the
-- closer, and those sit at the head of the schedule. Neither is the alarm — that is
-- windows_dropped_empty, which is exact — but they are what moves first.
--
-- max_claim_lag_ms is how far behind the closer's claims are — measured against the
-- schedule, not against event time, so a feed delivering hours-old events does not
-- read as a stalled closer. It is a property of the shared schedule rather than of one
-- tenant, and is recorded on every tenant's row because a shared closer that is behind
-- is behind for all of them.
--
-- window_ttl_ms travels with it so the reader can judge the lag without knowing the
-- tenant's settings: past that, window state has expired and the windows being closed
-- are empty. That is the difference between "behind" and "losing data", and it is the
-- line the console needs to draw.
-- NO SEMICOLONS IN A COMMENT, here or anywhere in this directory -- not even inside
-- quotes, which is why this paragraph does not contain the character it is about. The
-- runner splits the file textually on it, so one in prose ends the statement early and
-- hands ClickHouse a fragment that is nothing but a comment: an empty query, code 62.
-- This file failed that way twice while being written, first for a semicolon in the
-- paragraph above and then for one in this warning.
CREATE TABLE IF NOT EXISTS correlation_health
(
    tenant_id             UUID,
    minute                DateTime('UTC'),
    events_filed          UInt64,
    windows_closed        UInt64,
    records_emitted       UInt64,
    windows_dropped_empty UInt64,
    close_failures        UInt64,
    windows_due           SimpleAggregateFunction(max, UInt64),
    max_claim_lag_ms      SimpleAggregateFunction(max, UInt64),
    window_ttl_ms         SimpleAggregateFunction(max, UInt64)
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(minute)
ORDER BY (tenant_id, minute)
TTL minute + INTERVAL 30 DAY DELETE
