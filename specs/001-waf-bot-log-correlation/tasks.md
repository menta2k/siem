---

description: "Task list for Multi-Vendor WAF & Bot-Defense Log Correlation"
---

# Tasks: Multi-Vendor WAF & Bot-Defense Log Correlation

**Input**: Design documents from `/specs/001-waf-bot-log-correlation/`

**Prerequisites**: [plan.md](./plan.md), [spec.md](./spec.md), [research.md](./research.md), [data-model.md](./data-model.md), [contracts/](./contracts/)

**Tests**: Test tasks ARE included. Constitution Principle III makes TDD non-negotiable — every
test task must be written and observed FAILING before the implementation tasks that follow it.

**Organization**: Tasks are grouped by user story so each story is independently implementable,
testable, and demoable.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: US1–US4, mapping to the user stories in spec.md
- Exact file paths are given in every task

## Path Conventions

Web application layout from plan.md: `backend/` (Go + go-kratos, three binaries) and `frontend/`
(Vue 3 + Vuetify), with `deploy/` for migrations and observability config and a root `Makefile`.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Repository skeleton, toolchain, and local orchestration

- [X] T001 Create the repository tree from plan.md (`backend/`, `frontend/`, `deploy/`, `specs/` already present) and initialize the Go module in `backend/go.mod` as `github.com/<org>/siem` targeting Go 1.24
- [X] T002 [P] Create `.env.example` listing every required variable (ClickHouse DSN, Redpanda brokers, Redis URL, JWT signing key, secret-manager endpoint, per-service ports) with no real values
- [X] T003 [P] Configure `backend/.golangci.yml` enabling `govet`, `errcheck`, `staticcheck`, `revive`, `funlen` (50 lines), `gocognit`, `lll` (100 cols), `gosec`, `bodyclose`, `noctx`
- [X] T004 [P] Configure `backend/buf.yaml` and `backend/buf.gen.yaml` for `protoc-gen-go`, `protoc-gen-go-http`, and `protoc-gen-openapi`, outputting to `backend/api/gen/` and `backend/api/openapi.yaml`
- [X] T005 [P] Scaffold the frontend in `frontend/` with Vite + Vue 3 + TypeScript + Vuetify 3 + Pinia + vue-router (`frontend/package.json`, `frontend/vite.config.ts`, `frontend/src/main.ts`)
- [X] T006 [P] Configure `frontend/.eslintrc.cjs` with `vue/no-v-html` set to `error` (FR-027 is enforced by lint, not by review discipline) plus Prettier
- [X] T007 Author `docker-compose.yml` at the repo root with ClickHouse, Redpanda, Redis, `siem-ingest`, `siem-processor`, `siem-api`, and the frontend dev server, each with health checks and `depends_on` conditions
- [X] T008 Author the root `Makefile` with targets `init`, `api`, `api-check`, `build`, `lint`, `test`, `test-unit`, `test-integration`, `test-contract`, `replay`, `loadtest`, `e2e`, `up`, `down`, `down-v`, `migrate`, `seed`, delegating to `backend/Makefile` and `frontend` npm scripts
- [X] T009 [P] Configure `deploy/clickhouse/migrations/` with golang-migrate and wire `make migrate` to apply it against the Compose ClickHouse
- [X] T010 [P] Create the testcontainers helper in `backend/test/support/containers.go` starting ClickHouse, Redis, and Redpanda for integration tests
- [X] T011 [P] Add the CI workflow in `.github/workflows/ci.yml` running the blocking chain: `make lint` → `make api-check` → `make test` (coverage ≥80%) → dependency and secret scan → `make build`
- [X] T012 [P] Add `deploy/prometheus/prometheus.yml`, `deploy/prometheus/alerts.yml`, and `deploy/grafana/dashboards/` placeholders for ingest lag, query latency, and join-rate panels

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: The contract pipeline, storage layer, tenancy, authn/authz, audit, and observability that every user story depends on

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

### Contract pipeline

- [X] T013 Define the shared types in `backend/api/protos/siem/v1/common.proto`: `TimeRange`, `Cursor`, `PageRequest`, `PageResponse`, `Error` envelope, `Verdict` enum, `Confidence` enum, `Vendor` enum
- [X] T014 Implement `make api` in `backend/Makefile` to run `buf generate`, producing `backend/api/gen/**` and `backend/api/openapi.yaml`, then generate `frontend/src/api/schema.d.ts` via `openapi-typescript`
- [X] T015 Implement `make api-check` to regenerate into a temp dir and fail on any diff against committed output, and wire `buf lint` + `buf breaking` into `make lint`

### Configuration and data layer

- [X] T016 Implement config structs and loading in `backend/internal/conf/conf.go`, with `Validate()` failing startup when any required secret or DSN is absent (Constitution: secrets validated at startup)
- [X] T017 [P] Implement the ClickHouse client and base repository in `backend/internal/data/clickhouse/client.go`, with connection pooling, `max_execution_time`, and query-level context timeouts
- [X] T018 [P] Implement the Redis client and key-namespace helpers in `backend/internal/data/redis/client.go`
- [X] T019 [P] Implement the Redpanda producer/consumer wrappers in `backend/internal/data/stream/stream.go` using franz-go, with `acks=all` on the producer and a dead-letter topic helper
- [X] T020 Write migration `deploy/clickhouse/migrations/0001_control_plane.up.sql` creating `tenants`, `users`, `feeds`, `feed_health`, and `audit_entries` per data-model.md §2
- [X] T021 Write migration `deploy/clickhouse/migrations/0002_events.up.sql` creating `raw_events`, `normalized_events`, `rejected_events`, and `correlated_requests` with the sort keys, codecs, skip indexes, and TTL clauses in data-model.md §1

### Tenancy, authorization, audit

- [X] T022 [P] Write the failing test `backend/test/integration/tenancy_test.go` asserting that a repository call cannot be made without a tenant in context and that tenant A's token returns zero of tenant B's rows
- [X] T023 Implement tenant context injection and the repository guard in `backend/internal/tenancy/context.go`, exposing `FromContext(ctx)` and panicking on a missing tenant — repository methods take no tenant parameter (SC-009)
- [X] T024 [P] Write the failing test `backend/test/integration/rbac_test.go` covering deny-by-default plus the Admin/Analyst/Auditor/Ingest-Only matrix across a representative endpoint per role
- [X] T025 Implement the Casbin RBAC-with-domains model and policy in `backend/internal/auth/casbin/model.conf` and `backend/internal/auth/casbin/policy.csv`, with the tenant as the domain
- [X] T026 Implement the Kratos authorization middleware in `backend/internal/auth/middleware/authz.go` applying `enforce(subject, tenant, object, action)` to every route by default
- [X] T027 [P] Write the failing test `backend/test/unit/auth/password_test.go` for argon2id hashing, verification, and timing-safe comparison
- [X] T028 Implement credentials, TOTP MFA, and JWT issuance/refresh in `backend/internal/auth/credentials.go`, `backend/internal/auth/mfa.go`, and `backend/internal/auth/tokens.go`, with refresh-token revocation held in Redis
- [X] T029 [P] Write the failing test `backend/test/integration/audit_test.go` asserting an audit row per privileged action, correct before/after values, and an intact per-tenant hash chain
- [X] T030 Implement the append-only audit writer with `prev_hash`/`entry_hash` chaining in `backend/internal/audit/writer.go`, exposing no update or delete method

### Service skeletons and cross-cutting middleware

- [X] T031 Define `backend/api/protos/siem/v1/auth.proto` (login, MFA, refresh, logout, me) and `backend/api/protos/siem/v1/admin.proto` (users, tenant settings, correlation settings, purge) per contracts/api-surface.md
- [X] T032 Implement the `siem-api` Kratos application in `backend/cmd/siem-api/main.go` and `backend/cmd/siem-api/wire.go`, mounting HTTP transport, middleware chain, and `/healthz`, `/readyz`, `/metrics`
- [X] T033 [P] Implement the `siem-ingest` Kratos application skeleton in `backend/cmd/siem-ingest/main.go` with its own middleware chain (feed-token auth, not user JWT)
- [X] T034 [P] Implement the `siem-processor` worker host in `backend/cmd/siem-processor/main.go` with a pluggable worker registry and graceful shutdown
- [X] T035 [P] Implement structured JSON logging middleware with trace-id propagation and secret redaction in `backend/internal/middleware/logging.go`
- [X] T036 [P] Implement Prometheus metrics middleware and the metric registry in `backend/internal/middleware/metrics.go` (request latency, error rate, plus registration points for ingest and query metrics)
- [X] T037 [P] Implement the stable error-code envelope and panic recovery in `backend/internal/middleware/errors.go`, mapping internal errors to the codes listed in contracts/api-surface.md
- [X] T038 [P] Implement per-tenant and per-credential rate limiting backed by Redis in `backend/internal/middleware/ratelimit.go`, returning `429` with `Retry-After`
- [X] T039 Implement the auth and admin services in `backend/internal/service/auth.go` and `backend/internal/service/admin.go` against the protos from T031, wiring audit writes for every privileged action
- [X] T040 Build the frontend shell in `frontend/src/`: generated API client wrapper (`src/api/client.ts`), Pinia auth store, router with role guards, Vuetify app layout, login + MFA pages, and a strict CSP meta/header

**Checkpoint**: ✅ COMPLETE. A user can log in with MFA, roles are enforced deny-by-default,
every action is audited on a verified hash chain, and the contract pipeline is drift-gated.
Integration tests pass against real ClickHouse, Redis, and Redpanda containers. User story work
can begin.

> **Three bugs the integration tests caught, worth remembering:**
>
> 1. `Client.Query` deferred its context cancel, killing lazily-fetched ClickHouse rows before the
>    caller could iterate them. Every read failed with `context canceled`. The cancel is now tied
>    to the rows' `Close`.
> 2. Casbin's `keyMatch` treats `/api/v1/admin/*` as matching every future admin route, so
>    deny-by-default was not actually holding. Switched to `keyMatch2` with an explicit line per
>    route.
> 3. The audit hash covered a nanosecond timestamp that ClickHouse rounds to milliseconds on write,
>    so every entry failed verification after a round trip — the trail reported tampering where none
>    had occurred. The hash now covers the value as stored.

---

## Phase 3: User Story 1 - Receive and normalize logs from all three vendors (Priority: P1) 🎯 MVP

**Goal**: Cloudflare, F5, and DataDome feeds can be configured; their events are durably accepted, deduplicated, preserved raw, normalized onto the common model, and browsable — with rejects visible and nothing silently lost.

**Independent Test**: Configure one feed per vendor, send fixture batches including malformed lines and a duplicate replay, then confirm every event is retrievable, raw payloads are byte-identical, normalized fields are correct for all three vendors, duplicates are reported, and malformed lines land in the dead-letter view with reasons. Quickstart scenario V1.

### Tests for User Story 1 ⚠️ Write first, observe failing

- [X] T041 [P] [US1] Build the Cloudflare fixture corpus in `backend/test/fixtures/cloudflare/` — valid NDJSON batch, gzip batch, missing-optional-field record, malformed record, unknown-field record, and an XSS-payload user agent
- [X] T042 [P] [US1] Build the F5 fixture corpus in `backend/test/fixtures/f5/` covering JSON, CEF, and delimited-syslog variants plus malformed and unknown-field records
- [X] T043 [P] [US1] Build the DataDome fixture corpus in `backend/test/fixtures/datadome/` covering JSON array and NDJSON variants plus malformed and unknown-field records
- [X] T044 [P] [US1] Write the failing adapter test `backend/internal/vendor/cloudflare/adapter_test.go` asserting the field mapping and verdict table in contracts/events-common-model.md
- [X] T045 [P] [US1] Write the failing adapter test `backend/internal/vendor/f5/adapter_test.go` including the CEF and syslog paths
- [X] T046 [P] [US1] Write the failing adapter test `backend/internal/vendor/datadome/adapter_test.go`
- [X] T047 [P] [US1] Write the failing fuzz test `backend/test/unit/vendor/fuzz_parse_test.go` asserting no adapter panics on arbitrary bytes
- [X] T048 [P] [US1] Write the failing contract test `backend/test/contract/ingest_test.go` asserting the `/ingest/v1/{vendor}/{feed_id}` request/response shapes, status codes, and the `207` per-event reject body against `openapi.yaml`
- [X] T049 [P] [US1] Write the failing integration test `backend/test/integration/ingest_durability_test.go` covering: `202` only after broker ack, `503` when the broker is down, replay produces `duplicates_suppressed` with no event-count change, and a ClickHouse outage does not lose acknowledged events
- [X] T050 [P] [US1] Write the failing integration test `backend/test/integration/ingest_rejects_test.go` asserting malformed lines yield `207`, land in `rejected_events` with the right `reason_code`, and do not fail their batch

### Implementation for User Story 1

- [X] T051 [P] [US1] Define the common event model Go types and the `VendorAdapter` interface in `backend/internal/vendor/adapter.go` per contracts/ingest-contracts.md
- [X] T052 [P] [US1] Implement the Cloudflare adapter in `backend/internal/vendor/cloudflare/adapter.go` (NDJSON + gzip, `RayID`, `EdgeStartTimestamp`, `SecurityAction` mapping)
- [X] T053 [P] [US1] Implement the F5 adapter in `backend/internal/vendor/f5/adapter.go` with JSON, CEF, and syslog detection and `support_id` extraction
- [X] T054 [P] [US1] Implement the DataDome adapter in `backend/internal/vendor/datadome/adapter.go` with `botscore` and request-id extraction
- [X] T055 [US1] Implement verdict normalization and the restrictiveness ordering in `backend/internal/normalize/verdict.go` per the mapping table in contracts/events-common-model.md
- [X] T056 [US1] Implement common-model normalization, timestamp handling, `raw_extra` preservation, and unknown-field reporting in `backend/internal/normalize/normalize.go`
- [X] T057 [US1] Implement event-identity hashing (`event_id`) in `backend/internal/normalize/identity.go` per data-model.md
- [X] T058 [P] [US1] Define `backend/api/protos/siem/ingest/v1/ingest.proto` and `backend/api/protos/siem/v1/feeds.proto`, then regenerate via `make api`
- [X] T059 [US1] Implement the feed repository in `backend/internal/data/clickhouse/feeds.go` (ReplacingMergeTree reads with `FINAL`, per-entity Redis lock on write, credential stored as a secret-manager reference only)
- [X] T060 [US1] Implement feed CRUD, credential test, and health endpoints in `backend/internal/service/feeds.go` with audit writes on every mutation
- [X] T061 [US1] Implement the vendor push receivers in `backend/internal/ingest/receiver/receiver.go` — feed-token auth bound to the path `feed_id`, optional HMAC signature verification, 32 MiB / 50k-event limits
- [X] T062 [US1] Implement the Redis short-window dedup set and duplicate accounting in `backend/internal/ingest/dedup/dedup.go` (source of FR-004's reported count)
- [X] T063 [US1] Implement durable publish with `acks=all` and the `202`/`207`/`503` response logic in `backend/internal/ingest/publisher.go` — never return `2xx` on a failed broker write
- [X] T064 [US1] Implement per-feed quota enforcement and the `429` + `Retry-After` backpressure path in `backend/internal/ingest/quota.go`
- [X] T065 [US1] Implement the pull workers in `backend/internal/ingest/puller/` for Cloudflare object storage, F5 Distributed Cloud, and DataDome export, each with a per-feed watermark and at-least-once semantics
- [X] T066 [US1] Implement the normalization worker in `backend/internal/normalize/worker.go`: consume raw topic → write `raw_events` before parsing → write `normalized_events` or `rejected_events` → publish to the normalized topic
- [X] T067 [US1] Implement schema-drift detection and the feed-health warning in `backend/internal/normalize/drift.go` (>1% unknown fields over 10 minutes)
- [X] T068 [US1] Implement the feed-health aggregator in `backend/internal/ingest/health.go` writing `feed_health` per minute, including silence detection and credential validity
- [X] T069 [US1] Implement the event read repository and detail endpoint in `backend/internal/data/clickhouse/events.go` and `backend/internal/service/events.go`, returning normalized fields alongside the raw payload
- [X] T070 [US1] Build the Feeds pages in `frontend/src/pages/Feeds/` — list with health tiles, create/edit dialog, credential test, and the rejected-events browser with `reason_code` filter
- [X] T071 [US1] Build the event detail view in `frontend/src/pages/EventDetail.vue` showing normalized fields and the raw payload side by side, all rendered as inert text
- [X] T072 [US1] Register ingest metrics (received, rejected, duplicates, bytes, lag) in `backend/internal/ingest/metrics.go` and add the corresponding Prometheus alert rules to `deploy/prometheus/alerts.yml`

**Checkpoint**: US1 is fully functional — three feeds ingest, normalize, dedup, dead-letter, and are browsable. This alone replaces three vendor consoles with one searchable store. Quickstart V1 passes.

---

## Phase 4: User Story 2 - Correlate one request across vendors (Priority: P2)

**Goal**: Events describing the same client request are joined into one correlated record carrying each vendor's verdict, the signals used, a confidence level, and a disagreement flag — with late arrivals amending rather than duplicating.

**Independent Test**: Replay the labelled corpus and confirm ≥95% join rate with <1% false joins, tier-1 joins 100% correct, disagreements correctly flagged, NAT traffic degraded to `low` confidence, and a late event amending its existing record. Quickstart scenario V2.

### Tests for User Story 2 ⚠️ Write first, observe failing

- [X] T073 [P] [US2] Build the labelled replay corpus in `backend/test/corpus/` with ground-truth join labels: multi-vendor same-request sets, shared-`vendor_request_id` sets, a NAT set with many clients per IP, a disagreement set, and a late-arrival set
- [X] T074 [P] [US2] Write the failing test `backend/internal/correlate/keys/keys_test.go` for tier-1 exact keying, tier-2 heuristic keying, and path normalization (case, trailing slash, query strip, repeated slashes)
- [X] T075 [P] [US2] Write the failing test `backend/internal/correlate/confidence/confidence_test.go` asserting `high` for tier 1, `medium` for clean tier 2, and `low` when `client_ip_shared` or `candidate_count > 1`
- [X] T076 [P] [US2] Write the failing test `backend/internal/normalize/disagreement_test.go` covering every `disagreement_kind` and asserting `vendor_count = 1` is never a disagreement
- [X] T077 [P] [US2] Write the failing integration test `backend/test/integration/correlate_late_arrival_test.go` asserting an in-bound late event increments `version` and sets `amended` on the same `correlation_id`, while an out-of-bound one creates a new single-vendor record and increments the drop metric
- [X] T078 [P] [US2] Write the failing accuracy harness `backend/test/corpus/replay_test.go` (driven by `make replay`) reporting join rate, false-join rate, and a per-tier breakdown against SC-004's thresholds
- [X] T079 [P] [US2] Write the failing contract test `backend/test/contract/correlated_test.go` for `GET /api/v1/correlated/{correlation_id}` against `openapi.yaml`

### Implementation for User Story 2

- [X] T080 [P] [US2] Implement join-key derivation in `backend/internal/correlate/keys/keys.go` — tier-1 shared `vendor_request_id`, tier-2 normalized `tenant|ip|host|path|method`, with path normalization
- [X] T081 [P] [US2] Implement shared/NAT client-IP detection in `backend/internal/correlate/keys/shared_ip.go` setting `client_ip_shared`
- [X] T082 [US2] Implement confidence scoring and signal recording in `backend/internal/correlate/confidence/confidence.go`
- [X] T083 [US2] Implement Redis-backed overlapping window state with TTL = correlation window + lateness bound in `backend/internal/correlate/window/window.go`
- [X] T084 [US2] Implement deterministic `correlation_id` derivation in `backend/internal/correlate/keys/id.go` (moved from `window/` — the id is derived from the join key, so it belongs beside key derivation) so amendment targets the same row
- [X] T085 [US2] Implement disagreement classification and `combined_outcome` in `backend/internal/normalize/disagreement.go`
- [X] T086 [US2] Implement the correlation worker in `backend/internal/correlate/worker.go`: consume normalized topic → window → emit `correlated_requests` on close → merge and re-emit with incremented `version` on in-bound late arrivals
- [X] T087 [US2] Implement the correlated-request repository in `backend/internal/data/clickhouse/correlated.go`, with every read using `FINAL` or `argMax(..., version)`
- [X] T088 [US2] Define `backend/api/protos/siem/v1/correlation.proto` and implement `backend/internal/service/correlation.go` for the correlated-record detail endpoint, then regenerate via `make api`
- [X] T089 [US2] Make correlation settings (window, lateness bound, signal ranking) tenant-configurable and hot-reloadable in `backend/internal/correlate/settings.go`, with audit writes on change (FR-020)
- [X] T090 [US2] Build the correlated-record view in `frontend/src/pages/CorrelatedRequest.vue` showing each vendor's verdict, join signals, tier, confidence, `candidate_count`, and links to contributing events
- [X] T091 [P] [US2] Build the reusable `frontend/src/components/VendorVerdictBadge.vue` and `frontend/src/components/ConfidenceChip.vue` with an explicit visual treatment for disagreement
- [X] T092 [US2] Register correlation metrics (join rate by tier, single-vendor rate, amendment rate, late-arrival drops, window size) in `backend/internal/correlate/metrics.go` and add Grafana panels in `deploy/grafana/dashboards/correlation.json`

**Checkpoint**: US1 and US2 both work independently. `make replay` meets the SC-004 accuracy bar. Quickstart V2 passes.

---

## Phase 5: User Story 3 - Search, investigate, and dashboard (Priority: P2)

**Goal**: Analysts search across all vendors at once with bounded, fast, correctly paginated queries, and dashboards summarize volume, verdicts, rules, sources, disagreements, and feed health over a shared time range.

**Independent Test**: With a loaded dataset, run representative searches and confirm correct cross-vendor results under 3s p95, that a query without a time range is rejected, that paging never skips or repeats, that dashboard panels reconcile with event counts and move together, and that an XSS fixture renders inert. Quickstart scenario V3.

### Tests for User Story 3 ⚠️ Write first, observe failing

- [X] T093 [P] [US3] Write the failing contract test `backend/test/contract/search_test.go` for `/search/events`, `/search/correlated`, and `/search/export` against `openapi.yaml`
- [X] T094 [P] [US3] Write the failing test `backend/internal/query/bounds_test.go` asserting `TIME_RANGE_REQUIRED` on a missing range, `TIME_RANGE_TOO_LARGE` past the cap, `limit` capped at 1000, and `QUERY_TIMEOUT` on overrun
- [X] T095 [P] [US3] Write the failing test `backend/internal/query/cursor_test.go` asserting cursor stability — no skipped or repeated rows across pages, including when new events arrive mid-page
- [X] T096 [P] [US3] Write the failing integration test `backend/test/integration/search_test.go` covering cross-vendor filters (IP, host, path, verdict, rule, score, country, ASN, user agent, free text) against a seeded dataset
- [X] T097 [P] [US3] Write the failing integration test `backend/test/integration/dashboards_test.go` asserting rollup figures reconcile with direct event counts for the same range
- [X] T098 [P] [US3] Write the failing E2E test `frontend/tests/e2e/xss.spec.ts` asserting the XSS fixture's user agent renders as literal text with no dialog and no CSP violation (FR-027, release blocker)
- [X] T099 [P] [US3] Write the failing E2E test `frontend/tests/e2e/search.spec.ts` covering search → paginate → open correlated record → export

### Implementation for User Story 3

- [X] T100 [US3] Implement bounded-query enforcement (mandatory range, range cap, result cap, `max_execution_time`) in `backend/internal/query/bounds.go`
- [X] T101 [US3] Implement opaque cursor encoding/decoding over the sort key in `backend/internal/query/cursor.go`
- [X] T102 [US3] Implement the safe query builder in `backend/internal/query/builder.go` — parameterized only, with an allowlist of filterable fields so no caller-supplied string reaches SQL
- [X] T103 [US3] Implement the event and correlated search repositories in `backend/internal/data/clickhouse/search.go`, exploiting the sort key and bloom skip indexes
- [X] T104 [P] [US3] Write migration `deploy/clickhouse/migrations/0003_rollups.up.sql` creating the five materialized views and `AggregatingMergeTree` targets in data-model.md §3
- [X] T105 [US3] Implement the dashboard repository in `backend/internal/data/clickhouse/dashboards.go` reading exclusively from the rollup tables
- [X] T106 [US3] Define `backend/api/protos/siem/v1/search.proto` and `backend/api/protos/siem/v1/dashboards.proto`, then regenerate via `make api`
- [X] T107 [US3] Implement `backend/internal/service/search.go` and `backend/internal/service/dashboards.go` with `total_is_estimate` semantics
- [X] T108 [US3] Implement streamed, row-capped NDJSON and CSV export in `backend/internal/query/export.go` with an audit write recording actor, query, and row count
- [X] T109 [US3] Build the search page in `frontend/src/pages/Search.vue` with a required, pre-filled time-range control so an unbounded query is not expressible in the UI
- [X] T110 [P] [US3] Build the virtualized results table in `frontend/src/components/EventTable.vue` with server-side cursor paging and text-only rendering of log content
- [X] T111 [P] [US3] Build the filter panel in `frontend/src/components/SearchFilters.vue` covering every filter in contracts/api-surface.md, including the disagreement and confidence facets
- [X] T112 [US3] Build the dashboard pages in `frontend/src/pages/Dashboards/` (overview, rules, sources, disagreements, feed health) sharing one range control across all panels
- [X] T113 [P] [US3] Implement the Pinia search store with URL-synced query state in `frontend/src/stores/search.ts` so an investigation is shareable by link
- [X] T114 [US3] Register query metrics (latency by endpoint, rows scanned, timeout rate) in `backend/internal/query/metrics.go` and add the query-latency Grafana panel

**Checkpoint**: US1–US3 all work independently. Analysts can investigate end to end. Quickstart V3 passes.

---

## Phase 6: User Story 4 - Alert on correlated conditions (Priority: P3)

**Goal**: Engineers define rules over correlated data, alerts fire once per cooldown with links to evidence, delivery goes to a webhook with retry, and triage state is tracked and audited.

**Independent Test**: Define a disagreement-threshold rule, replay matching and non-matching traffic, and confirm exactly one alert with a working evidence link, cooldown suppression on the second window, and — with the receiver stopped — the alert still created with `notify_status: failed`, retries attempted, and the failure visible in the console. Quickstart scenario V4.

### Tests for User Story 4 ⚠️ Write first, observe failing

- [X] T115 [P] [US4] Write the failing test `backend/internal/alerting/rule/condition_test.go` for condition parsing and validation, rejecting malformed conditions with `RULE_CONDITION_INVALID`
- [X] T116 [P] [US4] Write the failing test `backend/internal/alerting/evaluator_test.go` asserting fire-on-threshold, no-fire below threshold, and correct group-by splitting
- [X] T117 [P] [US4] Write the failing test `backend/internal/alerting/cooldown_test.go` asserting a second qualifying window inside the cooldown does not re-fire and the first window after it does
- [X] T118 [P] [US4] Write the failing integration test `backend/test/integration/alert_delivery_test.go` asserting webhook retry with backoff and that a permanently failing webhook still leaves a persisted alert with `notify_status: failed`
- [X] T119 [P] [US4] Write the failing contract test `backend/test/contract/alerts_test.go` for the alert-rule and alert endpoints against `openapi.yaml`

### Implementation for User Story 4

- [X] T120 [P] [US4] Implement the rule condition model, JSON schema, and validator in `backend/internal/alerting/rule/condition.go`
- [X] T121 [P] [US4] Write migration `deploy/clickhouse/migrations/0004_alerting.up.sql` creating `alert_rules` and `alerts` per data-model.md §2.5–2.6
- [X] T122 [US4] Implement the alert-rule and alert repositories in `backend/internal/data/clickhouse/alerting.go` with `FINAL` reads and versioned state writes
- [X] T123 [US4] Implement the windowed rule evaluator in `backend/internal/alerting/evaluator.go`, running over `correlated_requests` with group-by support
- [X] T124 [US4] Implement cooldown suppression keyed by rule plus group values in `backend/internal/alerting/cooldown.go`
- [X] T125 [US4] Implement webhook delivery with HMAC signing, exponential backoff retry, and `notify_status` tracking in `backend/internal/alerting/webhook.go`
- [X] T126 [US4] Implement the alerting worker in `backend/cmd/siem-processor` wiring evaluator → cooldown → persist → deliver, registered in the worker registry
- [X] T127 [US4] Define `backend/api/protos/siem/v1/alerts.proto` and implement `backend/internal/service/alerts.go` including rule preview/dry-run and acknowledge/resolve with audit writes, then regenerate via `make api`
- [X] T128 [US4] Build the alert-rule editor in `frontend/src/pages/AlertRules.vue` with condition builder, dry-run preview, and webhook configuration
- [X] T129 [US4] Build the alert triage page in `frontend/src/pages/Alerts.vue` with state filters, evidence links reaching the correlated records in ≤3 interactions (SC-006), and visible delivery-failure state
- [X] T130 [P] [US4] Build the webhook echo tool in `backend/test/tools/webhookecho/main.go` for local validation
- [X] T131 [US4] Register alerting metrics (rules evaluated, alerts fired, suppressed, delivery failures) in `backend/internal/alerting/metrics.go` and add Prometheus alert rules for delivery failure

**Checkpoint**: All four user stories are independently functional. Quickstart V4 passes.

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: Retention, hardening, performance validation, and the release gates that span every story

- [X] T132 Implement TTL-driven retention plus the audited explicit purge path in `backend/internal/retention/retention.go`, registered as a processor worker (FR-036)
- [X] T133 Implement ingest-time field redaction driven by the tenant policy in `backend/internal/normalize/redact.go` so masked fields are never stored readable (FR-037)
- [X] T134 [P] Write the failing-then-passing integration test `backend/test/integration/retention_test.go` asserting expired data is gone within the SC-010 window and in-window data is untouched
- [X] T135 [P] Implement the nightly control-plane consistency check in `backend/internal/data/clickhouse/consistency.go` reporting duplicate-key violations (the accepted risk in research.md R6)
- [X] T136 Build the audit browser in `frontend/src/pages/Audit.vue` — read-only, with hash-chain verification status shown
- [X] T137 Build the admin pages in `frontend/src/pages/Admin/` for users, tenant retention and redaction settings, and correlation settings
- [X] T138 [P] Implement the load-test harness in `backend/test/load/` and wire `make loadtest` to assert SC-002 (5k EPS sustained, 15k peak) and SC-003 (60s p95 searchability)
- [X] T139 [P] Implement the fixture sender tool in `backend/test/tools/sendfixtures/main.go` used throughout quickstart.md
- [X] T140 [P] Implement `make seed` in `backend/cmd/seed/main.go` creating the demo tenant, admin user, and one feed per vendor
- [X] T141 [P] Add fault-injection tests in `backend/test/integration/faults_test.go` proving the Prometheus alert rules fire on feed silence, ingest lag, and elevated error rate
- [X] T142 [P] Write `README.md` and `docs/quickstart.md` linking to the constitution and the specs (closes the ⚠ pending item in the constitution's Sync Impact Report)
- [X] T143 Run a full security review: dependency and secret scan, verify CSP headers, confirm no `v-html` anywhere, confirm no secret reaches a log, and confirm every ingest and API endpoint is rate-limited
- [ ] T144 Verify coverage ≥80% on backend and frontend, and refactor any file over 800 lines or function over 50 lines flagged by `golangci-lint`
- [ ] T145 Execute the full quickstart.md validation (V1–V6) against a clean `make down-v && make up` and record results in the feature directory — V1–V4 pass and the throughput defect they found is fixed (see validation-results.md); V5 and V6 still to run

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: no dependencies — start immediately
- **Foundational (Phase 2)**: depends on Setup — **blocks every user story**
- **US1 (Phase 3)**: depends on Foundational only
- **US2 (Phase 4)**: depends on Foundational; consumes the normalized topic US1 produces
- **US3 (Phase 5)**: depends on Foundational; searches events from US1 and correlated records from US2
- **US4 (Phase 6)**: depends on Foundational; evaluates the correlated records US2 produces
- **Polish (Phase 7)**: depends on all delivered stories

### User Story Dependencies

Unlike a typical CRUD feature, these stories sit on a pipeline, so they are *demoable* independently
but not *deployable* out of order:

- **US1 (P1)**: fully independent. This is the MVP.
- **US2 (P2)**: needs US1's normalized events to correlate. Can be developed in parallel against the
  fixture corpus and the normalized-topic schema, then integrated.
- **US3 (P2)**: search over normalized events needs only US1; the correlated search and disagreement
  facets need US2. Split the phase accordingly if running in parallel — T093–T096 and T100–T103,
  T109–T111 are US1-only; T105, T112 depend on US2.
- **US4 (P3)**: needs US2's correlated records. Rule evaluation can be built and tested against
  seeded `correlated_requests` rows without waiting for the live correlator.

### Within Each Story

- Tests are written and observed FAILING before the implementation tasks below them
- Fixtures and corpora before adapters; adapters before workers
- Migrations before repositories; repositories before services; services before UI
- Contract (proto) changes before the handlers and clients that depend on them — always via `make api`

### Parallel Opportunities

- Phase 1: T002–T006 and T009–T012 run in parallel
- Phase 2: T017–T019 in parallel; T022/T024/T027/T029 (tests) in parallel; T033–T038 in parallel
- Phase 3: all three fixture corpora (T041–T043) in parallel; all three adapter tests (T044–T046) in
  parallel; all three adapters (T052–T054) in parallel — this is the largest parallel block in the
  project and maps naturally onto three developers
- Phase 4: T074–T079 in parallel; T080–T081 in parallel
- Phase 5: T093–T099 in parallel; T110–T111 and T113 in parallel
- Phase 6: T115–T119 in parallel; T120–T121 in parallel
- Phase 7: T134, T135, T138–T142 in parallel

---

## Parallel Example: User Story 1

```bash
# Fixtures first — three corpora, three files, no shared state:
Task: "Build the Cloudflare fixture corpus in backend/test/fixtures/cloudflare/"
Task: "Build the F5 fixture corpus in backend/test/fixtures/f5/"
Task: "Build the DataDome fixture corpus in backend/test/fixtures/datadome/"

# Then the failing adapter tests, still fully parallel:
Task: "Write the failing adapter test backend/internal/vendor/cloudflare/adapter_test.go"
Task: "Write the failing adapter test backend/internal/vendor/f5/adapter_test.go"
Task: "Write the failing adapter test backend/internal/vendor/datadome/adapter_test.go"

# Then the three adapters, one per developer:
Task: "Implement the Cloudflare adapter in backend/internal/vendor/cloudflare/adapter.go"
Task: "Implement the F5 adapter in backend/internal/vendor/f5/adapter.go"
Task: "Implement the DataDome adapter in backend/internal/vendor/datadome/adapter.go"
```

---

## Implementation Strategy

### MVP First (User Story 1 only)

1. Phase 1: Setup
2. Phase 2: Foundational — blocks everything, do not shortcut it
3. Phase 3: User Story 1
4. **STOP and VALIDATE**: run quickstart V1, including the durability and dedup checks
5. Demo: three vendor feeds ingesting into one searchable, audited, tenant-isolated store

### Incremental Delivery

1. Setup + Foundational → login, RBAC, audit, contract pipeline
2. + US1 → **MVP**: unified, trustworthy ingest (V1)
3. + US2 → cross-vendor correlation with confidence and disagreement flagging (V2)
4. + US3 → search and dashboards analysts actually use (V3)
5. + US4 → alerting on correlated conditions (V4)
6. + Polish → retention, redaction, load validation, security review (V5, V6)

### Parallel Team Strategy

After Phase 2 completes, with three developers:

- **Dev A**: US1 ingest path (receivers, publisher, dedup, quota, pull workers)
- **Dev B**: US1 vendor adapters and normalization, then US2 correlation
- **Dev C**: US3 query layer and frontend, working against seeded data until US1 lands

The three vendor adapters (T052–T054) are the cleanest three-way split in the project — identical
interface, independent files, independent fixtures.

---

## Notes

- **The riskiest task in this list is T080–T082 plus T078.** Tier-2 heuristic joining is where
  SC-004's <1% false-join target is won or lost. Build the labelled corpus (T073) before writing the
  join logic — without it, the accuracy target is unmeasurable and tuning is guesswork.
- Every read of `correlated_requests` and every control-plane table must use `FINAL` or
  `argMax(..., version)`. A naive read returns pre- and post-amendment rows and is a review-blocking
  defect.
- `make api` is the only way protos, `openapi.yaml`, and the frontend client change. Hand-editing any
  generated file will be caught by `make api-check`.
- Constitution gates apply per task: no silently swallowed errors, no hardcoded values, no mutation
  of inputs, files under 800 lines, functions under 50.
- Commit after each task or logical group; stop at any checkpoint to validate a story independently.
