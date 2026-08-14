#!/usr/bin/env bash
#
# Adds ResponseHeaders to the Cloudflare Logpush job feeding the SIEM.
#
# Logging a header needs TWO configurations, and each fails silently in its own way:
#   - the zone custom-fields ruleset says WHICH headers  -> without it: "RequestHeaders":{}
#   - this job's field_names says WHETHER the field ships -> without it: the key is absent
#
# ResponseHeaders is what tells a DataDome Device Check apart from a hard block: both
# answer 403, and only X-DataDome-Traffic-Rule-Response distinguishes them. The REQUEST
# header cannot -- enrichment adds headers before a request reaches the backend, and a
# challenged request never reaches it, so that capture only ever reads `authorize`.
#
# Needs Zone -> Logs -> Write. Less than that returns "request is not authorized", which
# reads like a credential problem and is a permission one.
#
#   CF_API_TOKEN=... ZONE_ID=... ./logpush-fields.sh --list   # find the job id
#   CF_API_TOKEN=... ZONE_ID=... JOB_ID=1826689 ./logpush-fields.sh
set -euo pipefail

: "${CF_API_TOKEN:?set CF_API_TOKEN}"
: "${ZONE_ID:?set ZONE_ID}"
API="https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/logpush/jobs"

if [[ "${1:-}" == "--list" ]]; then
  curl -sS "$API" -H "Authorization: Bearer ${CF_API_TOKEN}" |
    jq '.result[] | {id, name, dataset, fields: .output_options.field_names}'
  exit 0
fi

: "${JOB_ID:?set JOB_ID (use --list)}"

# Logpush REPLACES the whole set on update, so this list is the source of truth: a field
# omitted here is a field switched off. ParentRayID looks like noise and is not -- it is
# the only thing joining a DataDome verdict back to the request it describes.
curl -sS -X PUT "${API}/${JOB_ID}" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{
    "output_options": {
      "field_names": [
        "ClientIP","ClientRequestHost","ClientRequestMethod","ClientRequestURI",
        "EdgeEndTimestamp","EdgeResponseBytes","EdgeResponseStatus","EdgeStartTimestamp",
        "BotDetectionIDs","BotScore","BotScoreSrc","BotTags",
        "ContentScanObjResults","ContentScanObjTypes","EdgePathingSrc","EdgePathingStatus",
        "JA3Hash","SecurityAction","SecurityActions","SecurityRuleDescription",
        "SecurityRuleID","SecurityRuleIDs","SecuritySources",
        "WAFAttackScore","WAFFlags","WAFMatchedVar","WAFRCEAttackScore",
        "WAFSQLiAttackScore","WAFXSSAttackScore","WorkerStatus",
        "EdgeCFConnectingO2O","EdgeColoCode","EdgeColoID","EdgeServerIP",
        "SmartRouteColoID","UpperTierColoID","ParentRayID","RayID",
        "JA4","JA4Signals","ClientCity","ClientLatitude","ClientLongitude",
        "BotDetectionTags","JSDetectionPassed","MatchedRules","ZoneName",
        "ClientASN","ClientCountry","RequestHeaders","ResponseHeaders"
      ],
      "timestamp_format": "rfc3339",
      "output_type": "ndjson"
    }
  }' | jq '{success, errors}'

# destination_conf is deliberately NOT sent: it carries the SIEM ingest token in its query
# string, and resending it on every edit is how it eventually gets overwritten with a
# stale copy. Cloudflare leaves it untouched when it is absent.
