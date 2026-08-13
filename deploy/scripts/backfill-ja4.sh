#!/usr/bin/env bash
#
# Backfills normalized_events.ja4 from the raw payloads that still hold it.
#
# WHY THIS EXISTS. Migration 0014 added the column, but it could not populate it:
# migration 0006 dropped raw_extra, so on rows written before the fingerprint was mapped
# the only surviving copy is inside raw_events.payload. Getting it out is a join, and a
# ClickHouse mutation cannot join. This does the join.
#
# HOW IT WRITES. normalized_events is a ReplacingMergeTree(ingest_version), so a row is
# "updated" by inserting the same sort key with a higher version and letting the merge
# collapse the pair. Every column is carried across unchanged except ja4 and the version
# — the sort key is (tenant_id, event_date, vendor, event_id) and event_date is
# MATERIALIZED from event_time, so preserving event_time preserves the key.
#
# Reads stay correct THROUGHOUT, before any merge has run: search uses FINAL and the
# detail lookup takes the highest ingest_version, so both already resolve a duplicated
# key to the newest row. There is no window where an analyst sees the old value.
#
# HOURLY CHUNKS, deliberately. A whole day is 32M raw rows on the join's right side and a
# multi-gigabyte hash table competing with live ingestion for the same memory. An hour is
# ~1.3M, small enough to be unnoticeable, and it makes the job resumable: each chunk is
# independent and re-running one is a no-op because the WHERE clause only selects rows
# whose ja4 is still empty.
#
# The raw-side window is padded FORWARD because received_at trails event_time by 12s to
# 402s in this deployment (p99.9 is 154s). The pad is an order of magnitude beyond the
# observed maximum; a backward pad of 10 minutes covers clock variance that has not been
# observed at all. Too small a window would silently under-fill rather than fail, which is
# why the summary at the end reports what is left rather than declaring success.
#
# Usage:
#   ./backfill-ja4.sh --from 2026-08-09 --to 2026-08-14           # run it
#   ./backfill-ja4.sh --from 2026-08-09 --to 2026-08-14 --dry-run # count only
#
# --to is EXCLUSIVE. Ranges are UTC, matching the stored timestamps.
set -euo pipefail

COMPOSE=${COMPOSE:-/srv/siem/docker-compose.prod.yml}
VENDOR=cloudflare
DRY_RUN=0
FROM_DAY=""
TO_DAY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from) FROM_DAY="$2"; shift 2 ;;
    --to) TO_DAY="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$FROM_DAY" || -z "$TO_DAY" ]]; then
  echo "usage: $0 --from YYYY-MM-DD --to YYYY-MM-DD [--dry-run]" >&2
  exit 2
fi

# The password never appears in an argument list: it is read from the container's own
# environment inside the shell that uses it, so it stays out of `ps` and out of history.
ch() {
  docker compose -f "$COMPOSE" exec -T clickhouse sh -c \
    'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
       --database "$CLICKHOUSE_DB" --multiquery'
}

# The columns carried across verbatim. Listed rather than SELECT *-ed so that a schema
# change fails loudly here instead of shifting values silently into the wrong columns —
# which is exactly what migration 0006 did to the normalizer in production.
CARRIED="tenant_id, event_id, event_time, event_time_original, received_at,
  vendor, source_vendor, feed_id, vendor_account, vendor_request_id, vendor_event_id,
  linked_request_id, client_ip, client_ip_shared, client_asn, client_country,
  request_host, request_path, request_query, request_method, user_agent, http_status,
  verdict, verdict_reason, rule_id, rule_ids, score, score_kind, ingest_version"

# The fingerprint, pulled out with a regex rather than a JSON parser. JSONExtractString
# over these payloads hits CANNOT_ALLOCATE_MEMORY at this row count, and a JA4 is
# alphanumeric with underscores — it contains nothing JSON would have escaped, so the
# extraction is exact rather than merely close.
JA4_EXPR="extract(payload, '\"JA4\":\"([^\"]+)\"')"

total_written=0
start_epoch=$(date -u -d "$FROM_DAY" +%s)
end_epoch=$(date -u -d "$TO_DAY" +%s)

# Normalised back to timestamps so the summary matches the loop exactly. Both arguments
# accept an hour ("2026-08-12 04:00:00") as readily as a day, which is what makes it
# possible to prove one chunk correct before turning the job loose on five days.
RANGE_FROM=$(date -u -d "@$start_epoch" +'%Y-%m-%d %H:%M:%S')
RANGE_TO=$(date -u -d "@$end_epoch" +'%Y-%m-%d %H:%M:%S')

echo "backfilling ja4 for $VENDOR events in [$RANGE_FROM, $RANGE_TO) UTC"
[[ $DRY_RUN -eq 1 ]] && echo "DRY RUN: counting only, nothing is written"

cursor=$start_epoch
while [[ $cursor -lt $end_epoch ]]; do
  window_from=$(date -u -d "@$cursor" +'%Y-%m-%d %H:%M:%S')
  window_to=$(date -u -d "@$((cursor + 3600))" +'%Y-%m-%d %H:%M:%S')

  # Deduplicated on the raw side: a re-delivered payload appears more than once per
  # (tenant, event), and without the GROUP BY the join would multiply the left row.
  raw_side="(
      SELECT tenant_id, event_id, any($JA4_EXPR) AS ja4
      FROM raw_events
      WHERE vendor = '$VENDOR'
        AND received_at >= toDateTime('$window_from', 'UTC') - INTERVAL 10 MINUTE
        AND received_at <  toDateTime('$window_to', 'UTC') + INTERVAL 30 MINUTE
      GROUP BY tenant_id, event_id
      HAVING ja4 != ''
    ) AS r"

  # FINAL on the left: without it an unmerged duplicate could be read at an older
  # version, and re-inserting that at version+1 would promote stale field values over
  # the current ones.
  left_side="(
      SELECT $CARRIED
      FROM normalized_events FINAL
      WHERE vendor = '$VENDOR' AND ja4 = ''
        AND event_time >= toDateTime('$window_from', 'UTC')
        AND event_time <  toDateTime('$window_to', 'UTC')
    ) AS n"

  if [[ $DRY_RUN -eq 1 ]]; then
    count=$(echo "SELECT count() FROM $left_side INNER JOIN $raw_side USING (tenant_id, event_id)
                  SETTINGS max_memory_usage = 6000000000;" | ch)
    printf '%s  would fill %s\n' "$window_from" "$count"
    total_written=$((total_written + count))
  else
    # Prefixed with the target column list so the insert is bound by NAME. A positional
    # insert would silently shift every value after a future schema change.
    echo "INSERT INTO normalized_events
            ($CARRIED, ja4)
          SELECT
            n.tenant_id, n.event_id, n.event_time, n.event_time_original, n.received_at,
            n.vendor, n.source_vendor, n.feed_id, n.vendor_account, n.vendor_request_id,
            n.vendor_event_id, n.linked_request_id, n.client_ip, n.client_ip_shared,
            n.client_asn, n.client_country, n.request_host, n.request_path,
            n.request_query, n.request_method, n.user_agent, n.http_status,
            n.verdict, n.verdict_reason, n.rule_id, n.rule_ids, n.score, n.score_kind,
            n.ingest_version + 1,
            r.ja4
          FROM $left_side
          INNER JOIN $raw_side USING (tenant_id, event_id)
          SETTINGS max_memory_usage = 6000000000, max_execution_time = 900;" | ch

    written=$(echo "SELECT count() FROM normalized_events FINAL
                    WHERE vendor = '$VENDOR' AND ja4 != ''
                      AND event_time >= toDateTime('$window_from', 'UTC')
                      AND event_time <  toDateTime('$window_to', 'UTC');" | ch)
    printf '%s  filled, hour now has %s with a fingerprint\n' "$window_from" "$written"
    total_written=$((total_written + written))
  fi

  cursor=$((cursor + 3600))
done

echo
echo "---- coverage after the run ----"
# Reported per day rather than as a single "done". An hour whose raw payloads had already
# aged out of their own 30-day TTL cannot be filled, and the honest output is the number
# still empty, not a success message that hides it.
echo "SELECT toDate(event_time) AS day, count() AS events,
              countIf(ja4 != '') AS with_ja4,
              countIf(ja4 = '') AS still_empty,
              round(100 * countIf(ja4 != '') / count(), 1) AS pct
       FROM normalized_events FINAL
       WHERE vendor = '$VENDOR'
         AND event_time >= toDateTime('$RANGE_FROM', 'UTC')
         AND event_time <  toDateTime('$RANGE_TO', 'UTC')
       GROUP BY day ORDER BY day FORMAT PrettyCompactMonoBlock;" | ch
