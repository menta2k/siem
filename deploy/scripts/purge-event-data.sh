#!/usr/bin/env bash
# Removes ingested event data and everything derived from it, keeping the deployment's
# identity and configuration.
#
#   sudo /srv/siem/purge-event-data.sh
#
# DELETED:  ClickHouse  raw_events, normalized_events, correlated_requests,
#                       rejected_events, alerts, feed_health, every rollup_* table
#           Redpanda    the event topics, and the consumer offsets with them
#           Redis       dedup:* and correlate:*
# KEPT:     ClickHouse  tenants, users, feeds, alert_rules, audit_entries,
#                       schema_migrations
#           Redis       secret:* and quota:*
#
# ALL THREE STORES, because clearing one leaves a deployment that is not fresh but
# inconsistent:
#
#   Redpanda holds events already accepted but not yet consumed. Truncating ClickHouse
#   alone leaves them to be replayed into the empty tables, so the "wipe" refills itself
#   — and after an unclean shutdown the committed offsets can point past what the broker
#   still has, which stalls the consumers permanently. Dropping the topics takes the
#   backlog and those offsets together.
#
#   Redis holds the ingest dedup window. An event id seen before the wipe is suppressed
#   after it, so a vendor retrying the deliveries that spanned the outage would have
#   them silently dropped — exactly the events a fresh start most needs. It also holds
#   correlation window state that refers to events no longer in ClickHouse.
#
# The rollup_* tables are separate storage fed by materialized views, not views over
# normalized_events. Clearing the events alone leaves them populated, and the dashboards
# then show traffic with no events behind it.
#
# secret:* is NEVER touched. Those are the feed credentials, stored as references that
# cannot be read back — deleting them does not "reset" the feeds, it permanently breaks
# every vendor delivery until each token is rotated and reconfigured at the vendor end.
# That is why this script names the patterns it deletes and never uses FLUSHALL.
#
# The audit trail is kept too. It is a compliance record of who did what, it is
# hash-chained, and deleting entries from the middle of a chain is indistinguishable
# from tampering with it.

set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-/srv/siem/docker-compose.prod.yml}"
ENV_FILE="${ENV_FILE:-/srv/siem/.env}"

cd "$(dirname "$COMPOSE_FILE")"
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

compose() { docker compose -f "$COMPOSE_FILE" "$@"; }

ch() {
    compose exec -T clickhouse \
        clickhouse-client --user "$CLICKHOUSE_USERNAME" --password "$CLICKHOUSE_PASSWORD" -q "$1"
}

redis() { compose exec -T redis redis-cli "$@"; }

# Counts keys without loading them all: SCAN is incremental, where KEYS blocks the
# server for the whole sweep and this runs against a live deployment.
redis_count() { redis --scan --pattern "$1" | wc -l; }

rpk() { compose exec -T redpanda rpk "$@"; }

TABLES=(
    raw_events
    normalized_events
    correlated_requests
    rejected_events
    alerts
    feed_health
    rollup_vendor_volume_5m
    rollup_verdict_mix_5m
    rollup_disagreement_5m
    rollup_top_rules_1h
    rollup_top_sources_1h
)

# Named individually rather than discovered, so a topic added later is a deliberate
# edit here instead of something this quietly starts deleting.
TOPICS=(
    siem.events.raw
    siem.events.normalized
    siem.events.dlq
)

# Deleted key patterns, also named individually. secret:* and quota:* are absent from
# this list on purpose.
REDIS_PATTERNS=(
    'dedup:*'
    'correlate:*'
)

echo "About to delete from ClickHouse (${CLICKHOUSE_DATABASE:-siem}):"
for t in "${TABLES[@]}"; do
    printf '  %-28s %s rows\n' "$t" "$(ch "SELECT count() FROM ${CLICKHOUSE_DATABASE:-siem}.$t")"
done

echo
echo "About to delete from Redpanda:"
for t in "${TOPICS[@]}"; do
    printf '  %-28s\n' "$t"
done

echo
echo "About to delete from Redis:"
for p in "${REDIS_PATTERNS[@]}"; do
    printf '  %-28s %s keys\n' "$p" "$(redis_count "$p")"
done

echo
echo "Kept:"
for t in tenants users feeds alert_rules audit_entries; do
    printf '  %-28s %s rows\n' "$t" "$(ch "SELECT count() FROM ${CLICKHOUSE_DATABASE:-siem}.$t")"
done
printf '  %-28s %s keys  (feed credentials)\n' 'secret:*' "$(redis_count 'secret:*')"
printf '  %-28s %s keys\n' 'quota:*' "$(redis_count 'quota:*')"

echo
read -r -p "Type 'purge' to delete the event data: " answer
if [ "$answer" != "purge" ]; then
    echo "aborted; nothing was deleted"
    exit 1
fi

# Recorded before anything is deleted so the check at the end compares against the
# state this script was actually given, not against an assumption about it.
SECRETS_BEFORE="$(redis_count 'secret:*')"

# ClickHouse first. Dropping the topics first would have ingest recreate them
# immediately and start publishing, and those events would land in tables about to be
# truncated — visible in the vendor's delivery log as accepted, and absent here.
#
# TRUNCATE rather than DELETE: a lightweight DELETE is an asynchronous mutation that
# leaves the rows readable until it materialises, so a "cleaned" table keeps serving the
# data it was supposed to have dropped.
echo
for t in "${TABLES[@]}"; do
    ch "TRUNCATE TABLE ${CLICKHOUSE_DATABASE:-siem}.$t"
    echo "  truncated $t"
done

# Redpanda next. Deleting a topic takes its consumer offsets with it, which is the
# point: after an unclean shutdown those offsets can point past what the broker still
# holds, and the consumers then fail every fetch with "lost records" and never recover
# on their own.
echo
for t in "${TOPICS[@]}"; do
    rpk topic delete "$t" >/dev/null 2>&1 && echo "  deleted topic $t" \
        || echo "  topic $t absent, nothing to delete"
done

# Redis last, by explicit pattern. xargs batches the deletes so a large dedup window
# does not become one enormous command line.
echo
for p in "${REDIS_PATTERNS[@]}"; do
    before="$(redis_count "$p")"
    if [ "$before" -gt 0 ]; then
        # The whole pipeline runs INSIDE one exec. Piping the key list out and batching
        # it through xargs out here spawns a container attach per batch — 123,007 keys
        # at 500 a time is 246 of them, several minutes of Docker overhead for work
        # Redis finishes in seconds, and it reads as a hung script.
        compose exec -T redis sh -c \
            "redis-cli --scan --pattern '$p' | xargs -r -n 500 redis-cli del" >/dev/null
    fi
    echo "  cleared $p ($before keys)"
done

# The credentials are the one thing here that cannot be recovered or recreated, so their
# survival is asserted rather than assumed. A mismatch means a pattern above matched
# something it should not have.
SECRETS_AFTER="$(redis_count 'secret:*')"
if [ "$SECRETS_BEFORE" != "$SECRETS_AFTER" ]; then
    echo
    echo "FAILED: feed credentials went from $SECRETS_BEFORE to $SECRETS_AFTER keys."
    echo "Every vendor delivery will now be rejected until each token is rotated."
    exit 1
fi

echo
echo "Remaining event rows:"
for t in "${TABLES[@]}"; do
    printf '  %-28s %s\n' "$t" "$(ch "SELECT count() FROM ${CLICKHOUSE_DATABASE:-siem}.$t")"
done
printf '  %-28s %s keys  (unchanged)\n' 'secret:*' "$SECRETS_AFTER"

# The consumers hold a client for topics that no longer exist, and ingest recreates them
# on startup. Restarting is part of the purge rather than a step to remember afterwards.
echo
echo "Restarting ingest and processor so the topics are recreated..."
compose up -d --force-recreate siem-ingest siem-processor >/dev/null
echo "done"
