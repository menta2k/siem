# Phase 0 Research: Multi-Vendor WAF & Bot-Defense Log Correlation

**Feature**: `001-waf-bot-log-correlation` | **Date**: 2026-08-06

This document resolves every unknown in the plan's Technical Context. The stack itself
(Go + go-kratos, OpenAPI, Vue + Vuetify, Makefile, Docker Compose, ClickHouse) was mandated by the
user; research below covers *how* to use it well, not whether to use it.

---

## R1. Contract generation: how does Kratos produce OpenAPI?

**Decision**: Protobuf files under `backend/api/` are the authoring source; `protoc-gen-openapi`
(gnostic) emits `backend/api/openapi.yaml` (OpenAPI v3), which is the committed, published contract
the frontend consumes. Kratos generates HTTP handlers from `google.api.http` annotations, so the
REST surface and the OpenAPI document are generated from the same annotations and cannot drift.

**Rationale**: The requirement is that the frontend-facing API *be* OpenAPI. Kratos's native
workflow is proto-first with `make api` running `protoc` with `protoc-gen-go`,
`protoc-gen-go-http`, and `protoc-gen-openapi`. Hand-writing OpenAPI alongside Kratos would mean
maintaining two descriptions of one API — exactly the drift Constitution Principle I forbids.
Generating both from one annotated proto gives a single source of truth while still delivering a
real OpenAPI v3 document.

**Consequences**:
- `openapi.yaml` is committed and CI fails if regenerating produces a diff (drift gate).
- The frontend generates its TypeScript client from `openapi.yaml`, never from proto.
- gRPC is *not* exposed publicly in this release; it stays available for internal service calls.

**Alternatives considered**:
- *Hand-written OpenAPI + oapi-codegen server stubs*: idiomatic OpenAPI-first, but abandons the
  Kratos code-generation toolchain the user mandated and leaves two artifacts to reconcile.
- *grpc-gateway `protoc-gen-openapiv2`*: emits Swagger 2.0, not OpenAPI 3; worse tooling on the
  Vue/TypeScript side.

---

## R2. Durable intake: how is "acknowledge only after durable" satisfied at 15k EPS?

**Decision**: Vendor deliveries land in Redpanda (Kafka API) on a per-vendor raw topic. The ingest
service acknowledges the vendor only after the broker confirms the write (`acks=all`). A separate
processor consumes from Redpanda and writes to ClickHouse.

**Rationale**: Constitution Principle II requires acknowledgement only after durable commit, and
FR-007 requires explicit backpressure rather than unbounded buffering. Writing synchronously to
ClickHouse per request would either force tiny inserts (ClickHouse's worst pattern — one part per
insert, merge storms) or force in-memory batching, which loses acknowledged events on crash. A
durable log decouples the two and additionally provides replay for late-arrival correlation
(FR-018), a natural dead-letter topic (FR-006), and consumer-lag as the backpressure signal
(FR-008).

**Consequences**: Redpanda is a required infrastructure component in Docker Compose. This is
tracked as justified complexity in the plan's Complexity Tracking table.

**Alternatives considered**:
- *Direct ClickHouse `async_insert` with `wait_for_async_insert=1`*: genuinely durable and removes
  a component, but gives no replay, no dead-letter, and no lag metric; a ClickHouse outage becomes
  an immediate ingest outage with nowhere to buffer.
- *Kafka*: same semantics; Redpanda chosen for a single binary, no ZooKeeper/KRaft ceremony, and a
  much lighter Docker Compose footprint for local development.
- *NATS JetStream*: lighter still, but weaker replay/compaction ergonomics and a smaller Go
  ecosystem for consumer-group semantics at this scale.

---

## R3. ClickHouse schema for high-volume events with idempotent retry

**Decision**:
- `raw_events` — `MergeTree`, `PARTITION BY toDate(received_at)`, `ORDER BY (tenant_id, vendor,
  received_at, event_id)`, raw payload in a `String` column with ZSTD codec.
- `normalized_events` — `ReplacingMergeTree(ingest_version)`, `PARTITION BY toDate(event_time)`,
  `ORDER BY (tenant_id, event_date, vendor, event_id)`.
- `correlated_requests` — `ReplacingMergeTree(version)`, `PARTITION BY toDate(window_start)`,
  `ORDER BY (tenant_id, correlation_id)`; late arrivals bump `version` and re-insert the whole
  record rather than mutating.
- TTL clauses drive retention (FR-036); no `ALTER DELETE` mutations in the hot path.
- Bloom-filter skip indexes on `client_ip`, `request_host`, and `rule_id`; `LowCardinality(String)`
  for `vendor`, `verdict`, `country`, `method`.

**Rationale**: Research confirms ReplacingMergeTree is the standard upsert/dedup mechanism, and
that dedup only works when the identity is in the sorting key — hence `event_id` as the final sort
column. It also warns against high-cardinality leading sort columns, so `event_id` is placed *last*,
behind low-cardinality tenant/date/vendor prefixes that carry the actual query filters. Partitioning
by day keeps TTL-based deletion a cheap partition drop instead of a row-level mutation.

**Consequences**:
- ReplacingMergeTree dedup is *eventual*. Queries that must not double-count use `FINAL` or
  aggregate with `argMax(...)` on the version column. This is documented per-query, not left to
  chance.
- Because dedup is eventual, FR-004's *reported* duplicate count comes from a short-window Redis
  seen-set at ingest, not from ClickHouse.

**Alternatives considered**:
- *Plain MergeTree with dedup entirely in Redis*: unbounded Redis memory for a 15-minute-plus
  lateness bound at 15k EPS, and no protection against replayed historical batches.
- *`OPTIMIZE ... FINAL` on a schedule*: expensive at this volume and still not a correctness
  guarantee at read time.
- *CollapsingMergeTree*: requires the writer to know the prior state to emit a cancel row; the
  ingest path does not.

---

## R4. Correlation algorithm and state

**Decision**: A windowed streaming join in Go inside `siem-processor`. Two-tier keying, matching
FR-014's ranked signals:

1. **Tier 1 (exact)** — a shared request identifier where two vendors both expose one (e.g. a
   Cloudflare `RayID` propagated into an F5 or DataDome field, or a customer-injected trace header).
   Joins at confidence `high`.
2. **Tier 2 (heuristic)** — normalized key of `tenant_id + client_ip + request_host + path +
   method`, bucketed into overlapping time windows of the configured correlation width (default 5s).
   Joins at confidence `medium`, downgraded to `low` when the source IP is flagged as shared/NAT or
   when more than one candidate matched within the window.

Window state lives in Redis (hash per correlation key, TTL = correlation window + lateness bound),
so processor instances are horizontally scalable and stateless across restarts. A closed window
emits a `correlated_requests` row; a late event within the lateness bound re-reads the key, merges,
and re-emits with an incremented version.

**Rationale**: SC-004 demands ≥95% join rate with <1% false joins. Tier 1 is exact and carries no
false-join risk; the entire risk sits in Tier 2, which is why ambiguity is expressed as reduced
confidence (FR-015) rather than as a silent guess. Doing the join in Go rather than in a ClickHouse
materialized view keeps the ranking logic testable with fixture replays (Constitution Principle III)
and keeps late-arrival merging explicit.

**Consequences**: Redis is required. A labelled replay corpus is a first-class test asset, not an
afterthought — SC-004 is unverifiable without it.

**Alternatives considered**:
- *ClickHouse materialized view / `ASOF JOIN` at query time*: elegant for ad-hoc analysis, but
  recomputing joins per query cannot meet the p95 3s search budget, and confidence scoring in SQL is
  unmaintainable.
- *Flink / Kafka Streams*: proven for exactly this shape, but adds a JVM runtime to a Go+Compose
  stack for a join this simple.
- *IP + time only*: fails the <1% false-join bar outright on NAT and mobile-carrier traffic.

---

## R5. Vendor feed formats and delivery modes

**Decision**: One adapter per vendor behind a common `VendorAdapter` interface (`Detect`, `Parse`,
`Normalize`), each with its own fixture corpus.

| Vendor | Delivery | Format | Key fields for normalization |
|--------|----------|--------|------------------------------|
| Cloudflare | Logpush to HTTP endpoint or S3-compatible object store (pull) | newline-delimited JSON, gzip | `RayID` (→ vendor request id), `EdgeStartTimestamp`, `ClientIP`, `ClientRequestHost`, `ClientRequestURI`, `ClientRequestMethod`, `EdgeResponseStatus`, `SecurityAction`, `SecurityRuleID`, `SecuritySources` |
| F5 | BIG-IP remote logging (syslog/HSL) or F5 Distributed Cloud event export | JSON preferred; CEF/syslog fallback | `support_id` (→ vendor request id), `ip_client`, `method`, `uri`, `policy_name`, `violations`, `request_status`, `response_code` |
| DataDome | Logs Enrichment / webhook export | JSON | `X-DataDome-requestid` (→ vendor request id), `botscore`, `X-DataDome-isbot`, `botname`, `family`, action/verdict, client IP, user agent |

**Rationale**: All three publish a stable per-request identifier, which is what makes Tier-1
correlation viable at all. F5 is the awkward one: BIG-IP ASM commonly emits CEF or delimited syslog
rather than JSON, so the F5 adapter must accept both and normalize to the same shape.

**Consequences**:
- FR-012 schema-drift detection is per-adapter: unknown keys are preserved into a `raw_extra` map
  and counted, never dropped.
- Timestamps arrive in three different formats (RFC3339, epoch nanos, syslog) — normalization to
  UTC is adapter-local and fixture-tested.

**Alternatives considered**:
- *A generic grok/regex pipeline*: flexible, but untestable against SC-004 and prone to silent
  mis-parses; three known vendors do not justify a rules engine.
- *OpenTelemetry Collector as the intake tier*: strong prior art, but pushes normalization into
  YAML config outside the Go test suite and complicates per-tenant quota enforcement.

---

## R6. Control-plane storage under a ClickHouse-only mandate

**Decision**: ClickHouse is the only persistent store of record, as mandated. Mutable control-plane
entities (tenants, users, feeds, alert rules, alert state) live in `ReplacingMergeTree` tables keyed
by entity id with a monotonically increasing `version`; reads use `FINAL`. `audit_entries` is a
plain append-only `MergeTree` — a natural fit. Redis holds only ephemeral state (sessions, ingest
dedup window, rate-limit counters, correlation windows) and is never the system of record.

**Concern, stated once**: ClickHouse has no unique constraints, no transactions, and only eventual
dedup, so uniqueness (one active user per email, one feed per vendor per tenant) must be enforced in
application code and is racy under concurrent writes. This is a real, accepted weakness for
control-plane data. The mitigations are: all control-plane writes funnel through a single
`siem-api` write path that takes a short Redis lock per entity key, reads use `FINAL`, and a
nightly consistency check reports any duplicate-key violations it finds.

**Escape hatch**: the control-plane repository interfaces are defined independently of ClickHouse,
so swapping in PostgreSQL later is a data-layer change, not an application change. Recommended if
tenant/user counts grow or uniqueness violations show up in the consistency report.

**Alternatives considered**:
- *PostgreSQL for the control plane + ClickHouse for events*: the conventional split and materially
  safer for uniqueness and transactions — rejected because the user directed ClickHouse as the
  storage. Documented here so the decision can be revisited deliberately.

---

## R7. AuthN / AuthZ

**Decision**: Password + TOTP MFA, argon2id hashing (`golang.org/x/crypto/argon2`), short-lived JWT
access tokens with refresh tokens held in Redis for revocation. Authorization via Casbin with an
RBAC-with-domains model, where the domain is the tenant — every enforcement call is
`enforce(subject, tenant, object, action)`, making tenant scoping structural rather than incidental.

**Rationale**: Constitution Principle IV requires deny-by-default, server-side, per-request
authorization and tenant scoping that does not depend on a caller-supplied filter. Casbin's domain
model encodes exactly that, and it is battle-tested — preferable to a hand-rolled permission matrix
per the constitution's research-and-reuse rule. Kratos middleware applies the check uniformly across
every endpoint, so a new endpoint is protected by default.

**Additional control**: tenant id is taken from the verified token claim and injected into every
repository call through the request context. Repository methods have no parameter for "which
tenant" that a handler could pass wrongly.

**Alternatives considered**: OIDC/enterprise SSO (deferred per spec assumptions); Ory Keto
(another service to run for a permission model Casbin covers in-process); hand-rolled middleware
(rejected by the reuse rule).

---

## R8. Frontend architecture

**Decision**: Vue 3 `<script setup>` + TypeScript, Vuetify 3, Vite, Pinia for state, vue-router.
API client generated from `openapi.yaml` via `openapi-typescript` + `openapi-fetch`; the generated
client is committed and CI fails on drift. Testing: Vitest + Vue Test Utils for units, Playwright
for the critical E2E flows.

**Rationale**: Matches the mandated stack, and generating the client from the same `openapi.yaml`
the backend publishes closes the loop on Principle I. Vuetify's data table with server-side
pagination maps directly onto FR-023's cursor pagination.

**Key constraints carried into the design**:
- FR-027 (log content is attacker-controlled): `v-html` is banned by an ESLint rule; all log-derived
  values render through text interpolation. A strict CSP is served with the SPA.
- FR-023 (bounded queries): the search UI cannot submit without a time range — the control is
  required and pre-filled with a default range, so an unbounded query is not expressible in the UI.
- Large result rendering uses Vuetify's virtualized table to keep a 1,000-row page responsive.

**Alternatives considered**: Nuxt (SSR adds no value for an authenticated internal console);
hand-written API client (drift risk); Element Plus / PrimeVue (Vuetify mandated).

---

## R9. Build, run, and test tooling

**Decision**:
- `Makefile` at the repo root is the single entry point: `make init`, `make api`, `make build`,
  `make test`, `make lint`, `make up`, `make down`, `make migrate`, `make seed`, `make e2e`.
  Backend and frontend sub-makefiles are invoked from it.
- `docker compose` brings up ClickHouse, Redpanda, Redis, the three Go services, and the frontend
  dev server, with health checks and dependency ordering.
- Migrations: `golang-migrate` with a ClickHouse driver, plain `.sql` files under
  `deploy/clickhouse/migrations/`, applied by `make migrate`.
- Testing: `go test` with table-driven tests, `testcontainers-go` for ClickHouse/Redis/Redpanda
  integration tests, fixture-replay tests for adapters and correlation, `go-fuzz`-style fuzzing on
  the three parsers, `golangci-lint` and `buf lint`/`buf breaking` on protos.

**Rationale**: Directly satisfies the mandated build and orchestration requirements plus the
constitution's blocking CI chain and 80% coverage floor. Testcontainers keeps integration tests
honest against real ClickHouse behavior — ReplacingMergeTree's eventual dedup in particular cannot
be verified against a mock.

**Alternatives considered**: Taskfile/just (Makefile mandated); `goose` (golang-migrate has
better ClickHouse support); mocked stores for integration tests (rejected — would hide exactly the
merge/dedup semantics the correctness of this system rests on).

---

## Sources

- [Kratos OpenAPI / Swagger guide](https://go-kratos.dev/docs/guide/openapi/) and [go-kratos/swagger-api](https://github.com/go-kratos/swagger-api)
- [ClickHouse ReplacingMergeTree best practices (Tinybird)](https://www.tinybird.co/blog/clickhouse-replacingmergetree-example)
- [ClickHouse query optimization guide](https://clickhouse.com/resources/engineering/clickhouse-query-optimisation-definitive-guide)
- [ClickHouse deduplication patterns](https://oneuptime.com/blog/post/2026-01-21-clickhouse-deduplication/view)
- [Cloudflare Logpush HTTP requests dataset fields](https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/zone/http_requests/)
- [F5 BIG-IP ASM application security event logging](https://techdocs.f5.com/kb/en-us/products/big-ip_asm/manuals/product/asm-implementations-13-1-0/14.html)
- [DataDome Logs Enrichment integration](https://docs.datadome.co/docs/logs-integration)
