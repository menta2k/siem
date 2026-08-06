# Phase 1 Data Model: Multi-Vendor WAF & Bot-Defense Log Correlation

**Feature**: `001-waf-bot-log-correlation` | **Date**: 2026-08-06 | **Store**: ClickHouse

All tables are tenant-scoped. `tenant_id` is the leading sort-key column on every table, so tenant
isolation is a physical property of the data layout, not a filter the application remembers to add.
Types below are ClickHouse types. Engine choices and the reasoning behind sort-key ordering are in
[research.md](./research.md) R3.

---

## 1. Event pipeline tables

### 1.1 `raw_events`

The vendor payload exactly as received. Immutable, append-only, never updated.

| Column | Type | Notes |
|--------|------|-------|
| `tenant_id` | `UUID` | isolation boundary |
| `feed_id` | `UUID` | which configured feed delivered it |
| `vendor` | `LowCardinality(String)` | `cloudflare` \| `f5` \| `datadome` |
| `event_id` | `String` | stable identity — see [Event identity](#event-identity) |
| `received_at` | `DateTime64(3, 'UTC')` | platform receipt time |
| `payload` | `String CODEC(ZSTD(3))` | byte-exact vendor payload |
| `payload_format` | `LowCardinality(String)` | `json` \| `ndjson` \| `cef` \| `syslog` |
| `batch_id` | `UUID` | delivery batch, for replay and troubleshooting |

```
ENGINE = MergeTree
PARTITION BY toDate(received_at)
ORDER BY (tenant_id, vendor, received_at, event_id)
TTL received_at + INTERVAL {raw_retention_days} DAY DELETE
```

**Rules**: FR-005 — this row is written before any parsing is attempted, so a parse failure can
never cost the original data. Deletion happens only by TTL partition expiry or an audited purge.

---

### 1.2 `normalized_events`

The common event model (FR-009). One row per raw event that parsed successfully.

| Column | Type | Notes |
|--------|------|-------|
| `tenant_id` | `UUID` | |
| `event_id` | `String` | same identity as the raw event |
| `event_date` | `Date MATERIALIZED toDate(event_time)` | partition/sort helper |
| `event_time` | `DateTime64(3, 'UTC')` | vendor's time of the request |
| `event_time_original` | `String` | vendor's raw time value, preserved (FR-011) |
| `received_at` | `DateTime64(3, 'UTC')` | |
| `vendor` | `LowCardinality(String)` | |
| `feed_id` | `UUID` | |
| `vendor_account` | `String` | zone / partition / account within the vendor |
| `vendor_request_id` | `String` | Cloudflare `RayID`, F5 `support_id`, DataDome request id |
| `client_ip` | `IPv6` | IPv4 stored as mapped |
| `client_ip_shared` | `Bool` | NAT/proxy/carrier heuristic — downgrades join confidence |
| `client_asn` | `UInt32` | |
| `client_country` | `LowCardinality(String)` | ISO-3166 alpha-2 |
| `request_host` | `String` | |
| `request_path` | `String` | |
| `request_query` | `String` | subject to redaction policy |
| `request_method` | `LowCardinality(String)` | |
| `user_agent` | `String` | |
| `http_status` | `UInt16` | 0 when the vendor did not report one |
| `verdict` | `LowCardinality(String)` | `allowed` \| `blocked` \| `challenged` \| `rate_limited` \| `monitored` \| `unknown` |
| `verdict_reason` | `String` | vendor's human-readable reason |
| `rule_id` | `String` | rule / policy / violation identifier |
| `rule_ids` | `Array(String)` | when the vendor reports several |
| `score` | `Nullable(Float32)` | bot or threat score, vendor-native scale |
| `score_kind` | `LowCardinality(String)` | `bot` \| `threat` \| `none` |
| `raw_extra` | `Map(String, String)` | vendor fields with no common-model home (FR-010) |
| `unknown_fields` | `Array(String)` | drives schema-drift warnings (FR-012) |
| `ingest_version` | `UInt64` | version for ReplacingMergeTree |

```
ENGINE = ReplacingMergeTree(ingest_version)
PARTITION BY toDate(event_time)
ORDER BY (tenant_id, event_date, vendor, event_id)
TTL event_time + INTERVAL {raw_retention_days} DAY DELETE
```

**Skip indexes**: bloom filter on `client_ip`, `request_host`, `rule_id`, `vendor_request_id`;
token bloom filter on `user_agent`.

**Validation rules**:
- `event_time` must be within `[now - 90d, now + 5m]`; outside that range the event is rejected as
  `TIMESTAMP_OUT_OF_RANGE` rather than silently clamped.
- `verdict` must map to one of the enumerated values; an unmappable vendor action becomes `unknown`
  and adds the original string to `raw_extra`.
- Fields listed in the tenant's redaction policy are masked before this row is written (FR-037).

---

### 1.3 `rejected_events`

Dead-letter store. FR-006 — nothing is dropped silently.

| Column | Type | Notes |
|--------|------|-------|
| `tenant_id` | `UUID` | |
| `feed_id` | `UUID` | |
| `vendor` | `LowCardinality(String)` | |
| `rejected_at` | `DateTime64(3, 'UTC')` | |
| `reason_code` | `LowCardinality(String)` | `PARSE_ERROR` \| `SCHEMA_UNKNOWN` \| `QUOTA_EXCEEDED` \| `TIMESTAMP_OUT_OF_RANGE` \| `TENANT_UNKNOWN` \| `PAYLOAD_TOO_LARGE` |
| `reason_detail` | `String` | parser message, no secrets |
| `payload` | `String CODEC(ZSTD(3))` | the offending payload |
| `batch_id` | `UUID` | |

```
ENGINE = MergeTree
PARTITION BY toDate(rejected_at)
ORDER BY (tenant_id, feed_id, rejected_at)
TTL rejected_at + INTERVAL 14 DAY DELETE
```

---

### 1.4 `correlated_requests`

One client request as seen by one or more vendors (FR-013 – FR-018).

| Column | Type | Notes |
|--------|------|-------|
| `tenant_id` | `UUID` | |
| `correlation_id` | `UUID` | deterministic from the join key, so re-emission is idempotent |
| `window_start` | `DateTime64(3, 'UTC')` | start of the correlation window |
| `first_event_time` | `DateTime64(3, 'UTC')` | earliest contributing event |
| `last_event_time` | `DateTime64(3, 'UTC')` | latest contributing event |
| `vendors` | `Array(LowCardinality(String))` | participating vendors, sorted |
| `vendor_count` | `UInt8` | 1 for single-vendor records (FR-016) |
| `event_ids` | `Array(String)` | contributing normalized events |
| `client_ip` | `IPv6` | |
| `client_asn` | `UInt32` | |
| `client_country` | `LowCardinality(String)` | |
| `request_host` | `String` | |
| `request_path` | `String` | |
| `request_method` | `LowCardinality(String)` | |
| `verdicts` | `Map(LowCardinality(String), LowCardinality(String))` | vendor → verdict |
| `rule_ids` | `Map(LowCardinality(String), String)` | vendor → rule that fired |
| `scores` | `Map(LowCardinality(String), Float32)` | vendor → score |
| `combined_outcome` | `LowCardinality(String)` | most restrictive verdict across vendors |
| `has_disagreement` | `Bool` | FR-017 — indexed, searchable as a category |
| `disagreement_kind` | `LowCardinality(String)` | `none` \| `allow_vs_block` \| `allow_vs_challenge` \| `score_conflict` |
| `join_signals` | `Array(LowCardinality(String))` | `vendor_request_id` \| `ip_host_path_method` \| `time_window` |
| `join_tier` | `UInt8` | 1 = exact, 2 = heuristic |
| `confidence` | `LowCardinality(String)` | `high` \| `medium` \| `low` (FR-015) |
| `candidate_count` | `UInt8` | >1 means the window was ambiguous → confidence downgraded |
| `version` | `UInt64` | bumped on late-arrival amendment (FR-018) |
| `amended` | `Bool` | true when a late event changed this record |

```
ENGINE = ReplacingMergeTree(version)
PARTITION BY toDate(window_start)
ORDER BY (tenant_id, toDate(window_start), correlation_id)
TTL window_start + INTERVAL {correlated_retention_days} DAY DELETE
```

**Read rule**: every query against this table uses `FINAL` or `argMax(..., version)`. Reading
without one is a review-blocking defect — eventual dedup means a naive read can return both the
pre- and post-amendment row.

**State transitions**:

```
open window ──(window closes)──> emitted (version = 1)
emitted ──(late event within lateness bound)──> amended (version += 1, amended = true)
emitted ──(late event beyond lateness bound)──> new single-vendor record + late_arrival_dropped metric
```

---

## 2. Control-plane tables

All use `ReplacingMergeTree(version)` and are read with `FINAL`. Uniqueness is enforced in the
single `siem-api` write path under a per-entity Redis lock — see [research.md](./research.md) R6 for
the accepted risk.

### 2.1 `tenants`

`tenant_id UUID`, `name String`, `status LowCardinality(String)` (`active` | `suspended`),
`raw_retention_days UInt16` (default 30), `correlated_retention_days UInt16` (default 90),
`alert_retention_days UInt16` (default 365), `redacted_fields Array(String)`,
`correlation_window_ms UInt32` (default 5000), `lateness_bound_ms UInt32` (default 900000),
`created_at`, `updated_at`, `version UInt64`.
`ORDER BY (tenant_id)`.

### 2.2 `users`

`tenant_id`, `user_id UUID`, `email String`, `password_hash String` (argon2id), `mfa_secret String`
(encrypted), `mfa_enabled Bool`, `role LowCardinality(String)` (`admin` | `analyst` | `auditor` |
`ingest_only`), `status LowCardinality(String)`, `last_login_at`, `created_at`, `version UInt64`.
`ORDER BY (tenant_id, user_id)`. Uniqueness on `(tenant_id, lower(email))` is application-enforced.

### 2.3 `feeds`

`tenant_id`, `feed_id UUID`, `vendor LowCardinality(String)`, `name String`,
`delivery_mode LowCardinality(String)` (`push` | `pull`), `enabled Bool`,
`credential_ref String` (pointer into the secret manager — **never the secret itself**),
`pull_config String` (JSON: endpoint, bucket, prefix, interval), `quota_events_per_sec UInt32`,
`quota_bytes_per_day UInt64`, `created_at`, `version UInt64`.
`ORDER BY (tenant_id, feed_id)`.

### 2.4 `feed_health`

Rolling per-minute health (FR-008). `ENGINE = SummingMergeTree`.

`tenant_id`, `feed_id`, `minute DateTime`, `events_received UInt64`, `events_rejected UInt64`,
`duplicates_suppressed UInt64`, `bytes_received UInt64`, `max_ingest_lag_ms UInt32`,
`credential_valid Bool`.
`ORDER BY (tenant_id, feed_id, minute)`, `TTL minute + INTERVAL 30 DAY`.

Feed-silence detection (edge case: a vendor stops sending) is a query over this table, not an
absence of rows elsewhere.

### 2.5 `alert_rules`

`tenant_id`, `rule_id UUID`, `name String`, `enabled Bool`, `severity LowCardinality(String)`
(`low` | `medium` | `high` | `critical`), `condition String` (JSON: filters, aggregate, threshold,
comparator), `window_seconds UInt32`, `group_by Array(String)`, `cooldown_seconds UInt32`,
`webhook_url String`, `webhook_secret_ref String`, `created_by UUID`, `created_at`,
`version UInt64`.
`ORDER BY (tenant_id, rule_id)`.

### 2.6 `alerts`

`tenant_id`, `alert_id UUID`, `rule_id UUID`, `fired_at DateTime64(3,'UTC')`, `severity`,
`state LowCardinality(String)` (`new` | `acknowledged` | `resolved`), `group_values Map(String,String)`,
`observed_value Float64`, `threshold Float64`, `evidence_correlation_ids Array(UUID)`,
`acknowledged_by Nullable(UUID)`, `acknowledged_at`, `resolved_by`, `resolved_at`,
`notify_status LowCardinality(String)` (`pending` | `delivered` | `failed`), `notify_attempts UInt8`,
`version UInt64`.
`PARTITION BY toDate(fired_at)`, `ORDER BY (tenant_id, alert_id)`,
`TTL fired_at + INTERVAL {alert_retention_days} DAY`.

### 2.7 `audit_entries`

Append-only. Plain `MergeTree` — there is no version column and no application update or delete
path (FR-035).

`tenant_id`, `entry_id UUID`, `occurred_at DateTime64(3,'UTC')`, `actor_user_id Nullable(UUID)`,
`actor_email String`, `source_ip IPv6`, `action LowCardinality(String)`
(`login` | `login_failed` | `role_change` | `feed_create` | `feed_update` | `feed_delete` |
`correlation_settings_change` | `rule_create` | `rule_update` | `rule_delete` | `alert_state_change` |
`export` | `purge` | `retention_change`), `target_type LowCardinality(String)`, `target_id String`,
`before_value String`, `after_value String`, `result LowCardinality(String)` (`success` | `denied`),
`detail String`.
`PARTITION BY toDate(occurred_at)`, `ORDER BY (tenant_id, occurred_at, entry_id)`,
`TTL occurred_at + INTERVAL 365 DAY`.

Tamper-evidence: each entry stores `prev_hash String` and `entry_hash String`, chaining entries per
tenant per day so a deletion or edit is detectable by a chain walk.

---

## 3. Dashboard rollups

Materialized views feeding `AggregatingMergeTree` tables, so dashboard panels (FR-025) do not scan
raw events.

| View | Grain | Aggregates |
|------|-------|-----------|
| `mv_vendor_volume_5m` | tenant, vendor, 5-minute bucket | event count, bytes |
| `mv_verdict_mix_5m` | tenant, vendor, verdict, 5-minute bucket | count |
| `mv_top_rules_1h` | tenant, vendor, rule_id, hour | count |
| `mv_top_sources_1h` | tenant, client_ip, country, asn, hour | count, blocked count |
| `mv_disagreement_5m` | tenant, disagreement_kind, 5-minute bucket | count, total correlated |

---

## Event identity

`event_id = hex(sha256(feed_id ‖ vendor_request_id))` when the vendor supplies a request
identifier; otherwise `hex(sha256(feed_id ‖ vendor_raw_line_bytes))`. This makes a vendor retry
produce a byte-identical id, which is what lets ReplacingMergeTree dedup (FR-004) and what lets a
replayed batch be safely re-ingested.

`correlation_id = uuid_from(sha256(tenant_id ‖ join_key ‖ window_start))` — deterministic, so a
late-arrival amendment targets the same row rather than creating a second one.

---

## Entity relationships

```
Tenant 1───* Feed 1───* RawEvent 1───1 NormalizedEvent *───1 CorrelatedRequest
   │            │
   │            └───* FeedHealth (per minute)
   ├───* User
   ├───* AlertRule 1───* Alert *───* CorrelatedRequest (evidence)
   └───* AuditEntry

RawEvent ──(parse failure)──> RejectedEvent
```

Out of scope for this release, per spec assumptions: an `Entity` aggregate (client IP / ASN /
fingerprint activity over time). `normalized_events` deliberately carries `client_asn`,
`client_ip_shared`, and vendor fingerprint values in `raw_extra` so that table can be added later
without reshaping stored data.
