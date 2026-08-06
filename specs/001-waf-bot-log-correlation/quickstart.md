# Quickstart & Validation Guide

**Feature**: `001-waf-bot-log-correlation` | **Date**: 2026-08-06

How to bring the stack up and prove the feature works end to end. Every scenario below maps to a
success criterion in [spec.md](./spec.md).

## Prerequisites

| Tool | Version | Why |
|------|---------|-----|
| Go | 1.24+ | backend |
| Node | 22 LTS | frontend |
| Docker + Compose v2 | current | ClickHouse, Redpanda, Redis, services |
| `buf` | 1.x | proto lint / breaking checks |
| `protoc-gen-go`, `protoc-gen-go-http`, `protoc-gen-openapi` | current | contract generation |
| `golangci-lint` | 1.6x | lint gate |

`make init` installs the Go plugin binaries and frontend dependencies. Docker needs roughly 8 GB of
memory available — ClickHouse and Redpanda together will not run comfortably below that.

## First run

```bash
cp .env.example .env      # then set the required secrets; startup fails fast if any are missing
make init                 # install toolchain + deps
make api                  # generate protos -> Go stubs + backend/api/openapi.yaml + TS client
make up                   # docker compose up: clickhouse, redpanda, redis, 3 services, frontend
make migrate              # apply ClickHouse migrations
make seed                 # demo tenant, admin user, one feed per vendor
```

Console at `http://localhost:5173`, API at `http://localhost:8000/api/v1`, OpenAPI document at
`http://localhost:8000/q/openapi.yaml`.

`make down` stops everything; `make down-v` also drops volumes.

## Make targets

| Target | Does |
|--------|------|
| `make init` | install toolchain and dependencies |
| `make api` | regenerate protos, `openapi.yaml`, and the frontend TS client |
| `make api-check` | fail if generated output differs from what is committed (CI drift gate) |
| `make build` | build all three Go binaries and the frontend bundle |
| `make lint` | `golangci-lint`, `buf lint`, `buf breaking`, ESLint |
| `make test` | unit + integration + contract tests, enforces the 80% coverage floor |
| `make test-unit` / `make test-integration` / `make test-contract` | individual suites |
| `make replay` | run the labelled corpus and report join accuracy and false-join rate |
| `make loadtest` | sustained 5k EPS with a 15k peak, reports ingest lag and loss |
| `make e2e` | Playwright suite against the Compose stack |
| `make up` / `make down` / `make down-v` | Compose lifecycle |
| `make migrate` / `make seed` | schema and demo data |

## Validation scenarios

### V1 — Ingest with nothing lost (SC-001, FR-003/004/005/006)

```bash
make seed
go run ./backend/test/tools/sendfixtures --vendor=cloudflare --count=10000 --feed=$CF_FEED_ID
go run ./backend/test/tools/sendfixtures --vendor=f5         --count=10000 --feed=$F5_FEED_ID
go run ./backend/test/tools/sendfixtures --vendor=datadome   --count=10000 --feed=$DD_FEED_ID
```

Expected: each call returns `202` with `accepted` matching the sent count. Within 60s,
`GET /api/v1/feeds/{id}/health` reports 10,000 received and 0 rejected per feed, and a count over
`normalized_events` equals 30,000. Replaying the same batch returns `202` with
`duplicates_suppressed` equal to the batch size and leaves the event count unchanged.

Negative check: send a fixture batch containing 5 malformed lines. Expect `207`, five entries in
`GET /api/v1/feeds/{id}/rejected` with `reason_code: PARSE_ERROR`, and the other events ingested
normally — a malformed line must not fail its batch.

Durability check: `docker compose stop clickhouse`, send a batch, expect `202` (Redpanda still
holds it), restart ClickHouse, confirm the batch appears. Then `docker compose stop redpanda`, send
a batch, and expect `503` — never a `2xx` the system cannot honor.

### V2 — Cross-vendor correlation (SC-004, FR-013–FR-018)

```bash
make replay      # replays backend/test/corpus with known ground-truth join labels
```

Expected: join rate ≥95% for requests seen by two or more vendors, false-join rate <1%. The command
prints a per-tier breakdown; tier-1 (`vendor_request_id`) joins must be 100% correct — any tier-1
false join is a defect, not a tuning issue.

Manual check: open any correlated record in the console and confirm it shows each vendor's verdict,
`join_signals`, `join_tier`, `confidence`, and links to the contributing raw events.

Disagreement check: replay the `disagreement` fixture set, then filter search on
`has_disagreement = true`. Every request where one vendor allowed and another blocked must appear,
and no agreeing request may.

Late arrival: send an event with `event_time` 3 minutes in the past belonging to an
already-emitted window. Expect the existing `correlation_id` to gain the vendor, `version` to
increment, and `amended` to become true — no second record. Send one 30 minutes late (beyond the
default bound) and expect a new single-vendor record plus an incremented
`late_arrival_dropped` metric.

Ambiguity: replay the `nat` fixture set (many clients behind one IP). Expect joins to carry
`confidence: low` and `candidate_count > 1` rather than being asserted at medium confidence.

### V3 — Search and dashboards (SC-003, SC-005, FR-022–FR-027)

Search by client IP over 24h and confirm results from all three vendors, newest first, first page
under 3s. Submit a search with no time range and expect `400 TIME_RANGE_REQUIRED`. Page through a
5,000-row result and confirm no event is skipped or repeated. Change the dashboard range and
confirm every panel moves together.

XSS check: ingest the `xss` fixture, whose user-agent field contains
`<img src=x onerror=alert(1)>`. Render it in the events table and confirm it displays as literal
text with no dialog and no CSP violation in the console. This is FR-027 and it is a release blocker.

### V4 — Alerting (FR-028–FR-032a)

Create a rule: `has_disagreement = true` grouped by `client_ip`, threshold 50 in 5 minutes, pointed
at a local webhook receiver (`go run ./backend/test/tools/webhookecho`). Replay traffic that
satisfies it and confirm one alert with a working evidence link, and that a second qualifying window
inside the cooldown does not re-fire. Stop the receiver, replay again, and confirm the alert is
still created with `notify_status: failed`, retries are attempted, and the failure is visible in the
console — a notification failure must never lose the alert.

### V5 — Tenancy, RBAC, retention, audit (SC-008, SC-009, SC-010)

```bash
make test-integration -- -run TestTenantIsolation
```

Expected: for every read endpoint, a token for tenant A returns zero rows belonging to tenant B —
`404`/empty, never a leak. An Analyst token receives `403 PERMISSION_DENIED` on every admin
endpoint. An Auditor token can read `/audit` and cannot write anywhere.

Audit: perform a login, a role change, a feed update, a rule change, and an export, then confirm
five `audit_entries` rows with correct actor, before/after values, and an intact hash chain.

Retention: seed events with `event_time` past the tenant's retention window, run the retention job,
and confirm they are gone within 24 simulated hours while in-window data is untouched.

### V6 — Load (SC-002)

```bash
make loadtest
```

Expected: 5,000 EPS sustained for 30 minutes with a 15,000 EPS peak for 5 minutes, zero rejected
valid events, ingest lag returning under 60s within 2 minutes of the peak ending, and p95 search
latency staying under 3s throughout.

## Definition of done

- [ ] `make lint`, `make test`, and `make api-check` pass
- [ ] Coverage ≥80% on both backend and frontend
- [ ] V1–V6 all pass on a clean `make down-v && make up`
- [ ] `make replay` meets the ≥95% join / <1% false-join bar
- [ ] No `v-html` anywhere in the frontend; CSP present and violation-free
- [ ] Prometheus alert rules in `deploy/prometheus/` fire in a fault-injection test
