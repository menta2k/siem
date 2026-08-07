#!/usr/bin/env bash
# Removes ingested event data and everything derived from it, keeping the deployment's
# identity and configuration.
#
#   sudo /srv/siem/purge-event-data.sh
#
# DELETED:  raw_events, normalized_events, correlated_requests, rejected_events,
#           alerts, feed_health, and every rollup_* table
# KEPT:     tenants, users, feeds, alert_rules, audit_entries, schema_migrations
#
# The rollup_* tables are separate storage fed by materialized views, not views over
# normalized_events. Clearing the events alone leaves them populated, and the dashboards
# then show traffic with no events behind it.
#
# Redis is deliberately NOT touched. It holds the feed credentials as
# `secret:feed-credential/*`, and those are stored as references that cannot be read
# back — flushing them does not "reset" the feeds, it permanently breaks every vendor
# delivery until each token is rotated and reconfigured at the vendor end.
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

ch() {
    docker compose -f "$COMPOSE_FILE" exec -T clickhouse \
        clickhouse-client --user "$CLICKHOUSE_USERNAME" --password "$CLICKHOUSE_PASSWORD" -q "$1"
}

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

echo "About to delete from ${CLICKHOUSE_DATABASE:-siem}:"
for t in "${TABLES[@]}"; do
    printf '  %-28s %s rows\n' "$t" "$(ch "SELECT count() FROM ${CLICKHOUSE_DATABASE:-siem}.$t")"
done

echo
echo "Kept:"
for t in tenants users feeds alert_rules audit_entries; do
    printf '  %-28s %s rows\n' "$t" "$(ch "SELECT count() FROM ${CLICKHOUSE_DATABASE:-siem}.$t")"
done

echo
read -r -p "Type 'purge' to delete the event data: " answer
if [ "$answer" != "purge" ]; then
    echo "aborted; nothing was deleted"
    exit 1
fi

# TRUNCATE rather than DELETE: a lightweight DELETE is an asynchronous mutation that
# leaves the rows readable until it materialises, so a "cleaned" table keeps serving the
# data it was supposed to have dropped.
for t in "${TABLES[@]}"; do
    ch "TRUNCATE TABLE ${CLICKHOUSE_DATABASE:-siem}.$t"
    echo "  truncated $t"
done

echo
echo "Remaining event rows:"
for t in "${TABLES[@]}"; do
    printf '  %-28s %s\n' "$t" "$(ch "SELECT count() FROM ${CLICKHOUSE_DATABASE:-siem}.$t")"
done
