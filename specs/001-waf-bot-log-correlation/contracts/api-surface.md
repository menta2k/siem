# Frontend API Surface (`/api/v1`)

Generated into `backend/api/openapi.yaml` from annotated protos. This document states the shape and,
more importantly, the invariants every operation must satisfy.

## Global invariants

Applied by Kratos middleware, so they hold for every operation including ones added later.

1. **Authentication** — Bearer JWT on everything except `POST /api/v1/auth/login`,
   `POST /api/v1/auth/mfa`, and `POST /api/v1/auth/refresh`.
2. **Tenant scoping** — `tenant_id` is read from the verified token claim and injected into the
   request context. It never appears as a request parameter, path segment, or body field. Repository
   methods take it from context only.
3. **Authorization** — Casbin `enforce(user, tenant, object, action)` runs before the handler.
   Default is deny; an operation with no policy entry is unreachable.
4. **Validation** — bodies and query parameters are validated against the generated schema at the
   boundary; violations return `400` with a field-level error list.
5. **Bounded queries** — every read of event data requires `from` and `to`; missing or inverted
   range returns `400 TIME_RANGE_REQUIRED`. `limit` is capped at 1000. Server-side execution timeout
   is 10s; exceeding it returns `408 QUERY_TIMEOUT`. Paging is cursor-based, never offset.
6. **Error envelope** — `{"code":"STABLE_CODE","message":"human readable","details":[...],
   "trace_id":"..."}`. Codes are stable and enumerated; messages never leak internals. Every non-2xx
   is logged server-side with full context.
7. **Rate limiting** — per-tenant and per-credential; `429` carries `Retry-After`.
8. **Audit** — any operation marked **[audited]** writes an `audit_entries` row before returning.

## Operations

### Auth

| Method | Path | Roles | Notes |
|--------|------|-------|-------|
| `POST` | `/auth/login` | — | email + password → MFA challenge token. **[audited]** (success and failure) |
| `POST` | `/auth/mfa` | — | TOTP → access + refresh token. **[audited]** |
| `POST` | `/auth/refresh` | any | rotates refresh token; revoked tokens rejected |
| `POST` | `/auth/logout` | any | revokes refresh token |
| `GET` | `/auth/me` | any | current user, role, tenant |

### Feeds

| Method | Path | Roles | Notes |
|--------|------|-------|-------|
| `GET` | `/feeds` | admin, analyst, auditor | list with current health |
| `POST` | `/feeds` | admin | credential passed once, stored as a secret-manager reference. **[audited]** |
| `GET` | `/feeds/{feed_id}` | admin, analyst, auditor | never returns the credential |
| `PATCH` | `/feeds/{feed_id}` | admin | **[audited]** |
| `DELETE` | `/feeds/{feed_id}` | admin | soft-disable; ingested data is untouched. **[audited]** |
| `POST` | `/feeds/{feed_id}/test` | admin | validates credentials and reachability |
| `GET` | `/feeds/{feed_id}/health` | admin, analyst, auditor | last event, rate, lag, rejects, credential validity (FR-008) |
| `GET` | `/feeds/{feed_id}/rejected` | admin, analyst | dead-letter browse with `reason_code` filter (FR-006) |

### Search

| Method | Path | Roles | Notes |
|--------|------|-------|-------|
| `POST` | `/search/events` | analyst, admin, auditor | normalized events across vendors. Filters: `client_ip`, `request_host`, `request_path`, `vendor`, `verdict`, `rule_id`, `min_score`/`max_score`, `country`, `asn`, `user_agent`, `q`. Requires time range. Returns `{items, next_cursor, total_is_estimate}` |
| `POST` | `/search/correlated` | analyst, admin, auditor | same plus `vendor_count`, `has_disagreement`, `disagreement_kind`, `confidence`, `combined_outcome` |
| `GET` | `/events/{event_id}` | analyst, admin, auditor | normalized fields **and** the raw vendor payload (FR-005) |
| `GET` | `/correlated/{correlation_id}` | analyst, admin, auditor | each vendor's contribution, `join_signals`, `join_tier`, `confidence`, `candidate_count`, and links to contributing events (FR-024) |
| `POST` | `/search/export` | analyst, admin | NDJSON or CSV, row-capped, streamed. **[audited]** with the query and row count (FR-026) |

`total_is_estimate` is deliberate: exact counts over hundreds of millions of rows cannot meet the 3s
p95 budget, so the API states when a count is approximate rather than implying precision it does not
have.

### Dashboards

| Method | Path | Roles | Notes |
|--------|------|-------|-------|
| `GET` | `/dashboards/overview` | analyst, admin, auditor | volume by vendor, verdict mix, block/challenge rates |
| `GET` | `/dashboards/rules` | analyst, admin, auditor | top triggering rules per vendor |
| `GET` | `/dashboards/sources` | analyst, admin, auditor | top source IPs, countries, ASNs |
| `GET` | `/dashboards/disagreements` | analyst, admin, auditor | disagreement rate and breakdown by kind |
| `GET` | `/dashboards/feed-health` | analyst, admin, auditor | per-feed health tiles including silence warnings |

All accept the same `from`/`to`/`interval`, so a range change updates every panel consistently
(FR-025). All are served from the rollup tables in [data-model.md](../data-model.md) §3.

### Alert rules and alerts

| Method | Path | Roles | Notes |
|--------|------|-------|-------|
| `GET` | `/alert-rules` | analyst, admin, auditor | |
| `POST` | `/alert-rules` | admin | condition validated and dry-run against recent data before saving. **[audited]** |
| `PATCH` | `/alert-rules/{rule_id}` | admin | **[audited]** with before/after (FR-029 §3) |
| `DELETE` | `/alert-rules/{rule_id}` | admin | **[audited]** |
| `POST` | `/alert-rules/{rule_id}/preview` | admin, analyst | how often this rule would have fired over a past range |
| `GET` | `/alerts` | analyst, admin, auditor | filter by state, severity, rule, time |
| `GET` | `/alerts/{alert_id}` | analyst, admin, auditor | includes `evidence_correlation_ids` |
| `POST` | `/alerts/{alert_id}/acknowledge` | analyst, admin | **[audited]** |
| `POST` | `/alerts/{alert_id}/resolve` | analyst, admin | **[audited]** |

### Administration

| Method | Path | Roles | Notes |
|--------|------|-------|-------|
| `GET`/`POST`/`PATCH`/`DELETE` | `/admin/users` | admin | role changes **[audited]** |
| `GET`/`PATCH` | `/admin/tenant` | admin | retention days, redacted fields **[audited]** (FR-036, FR-037) |
| `GET`/`PATCH` | `/admin/correlation-settings` | admin | correlation window, lateness bound, signal ranking **[audited]** (FR-020) |
| `POST` | `/admin/purge` | admin | explicit purge, requires typed confirmation **[audited]** |
| `GET` | `/audit` | auditor, admin | append-only; no write, update, or delete operation exists |

### Operational

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| `GET` | `/healthz` | none | liveness |
| `GET` | `/readyz` | none | ClickHouse, Redpanda, Redis reachability |
| `GET` | `/metrics` | internal only | Prometheus exposition |

## Error codes

`UNAUTHENTICATED`, `MFA_REQUIRED`, `PERMISSION_DENIED`, `TENANT_SUSPENDED`, `VALIDATION_FAILED`,
`TIME_RANGE_REQUIRED`, `TIME_RANGE_TOO_LARGE`, `RESULT_LIMIT_EXCEEDED`, `QUERY_TIMEOUT`,
`CURSOR_INVALID`, `NOT_FOUND`, `CONFLICT`, `RATE_LIMITED`, `FEED_CREDENTIAL_INVALID`,
`RULE_CONDITION_INVALID`, `EXPORT_TOO_LARGE`, `INTERNAL`.
