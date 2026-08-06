# ClickHouse migrations

Applied with [golang-migrate](https://github.com/golang-migrate/migrate) via `make migrate`
(rollback: `make migrate-down`).

## Conventions

- Files are named `NNNN_description.up.sql` / `NNNN_description.down.sql`. **Both directions are
  required** — the constitution mandates that every schema change ships a rollback path.
- One logical concern per migration; never edit a migration that has been applied anywhere.
- Statements are separated by `;`. The connection string sets `x-multi-statement=true`, so a single
  file may contain several statements.
- Retention is expressed as `TTL` clauses in the table definitions, not as scheduled deletes, so
  expiry becomes a cheap partition drop rather than a row-level mutation.

## Order

| File | Creates |
|------|---------|
| `0001_control_plane` | `tenants`, `users`, `feeds`, `feed_health`, `audit_entries` |
| `0002_events` | `raw_events`, `normalized_events`, `rejected_events`, `correlated_requests` |
| `0003_rollups` | dashboard materialized views and their `AggregatingMergeTree` targets |
| `0004_alerting` | `alert_rules`, `alerts` |

## Testing

Integration tests apply these exact files against a throwaway ClickHouse container
(`backend/test/support/containers.go`) — the schema under test is never a hand-maintained copy.
