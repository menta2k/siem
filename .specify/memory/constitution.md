<!--
Sync Impact Report
==================
Version change: (uninitialized template) → 1.0.0
Bump rationale: Initial ratification of the project constitution. All placeholder
tokens replaced with concrete, testable rules for the log management platform.

Modified principles:
  - [PRINCIPLE_1_NAME] → I. Contract-First Backend & Frontend Separation
  - [PRINCIPLE_2_NAME] → II. Ingestion Integrity (NON-NEGOTIABLE)
  - [PRINCIPLE_3_NAME] → III. Test-First (NON-NEGOTIABLE)
  - [PRINCIPLE_4_NAME] → IV. Tenant Isolation & Least Privilege
  - [PRINCIPLE_5_NAME] → V. Observability & Bounded Performance

Added sections:
  - Security, Compliance & Data Retention Requirements (was [SECTION_2_NAME])
  - Development Workflow & Quality Gates (was [SECTION_3_NAME])

Removed sections: none

Templates requiring updates:
  ✅ .specify/templates/plan-template.md — Constitution Check gate is generic and
     resolves against this file; no edits required.
  ✅ .specify/templates/spec-template.md — scope/requirements sections already
     cover the mandatory constraints introduced here.
  ✅ .specify/templates/tasks-template.md — task categories (contract tests,
     integration tests, observability, security) align with Principles I–V.
  ✅ README.md / docs/quickstart.md — written, and both link back to this
     constitution and the feature specs.

Deferred TODOs: none
-->

# SIEM Log Management Platform Constitution

## Core Principles

### I. Contract-First Backend & Frontend Separation

The system MUST be built as two independently deployable tiers: a backend that owns all
ingestion, storage, query, and policy logic, and a frontend that is a pure consumer of the
backend's published API.

- Every backend capability MUST be exposed through a versioned, machine-readable API
  contract (OpenAPI or Protobuf) checked into the repository before implementation begins.
- The frontend MUST NOT contain business rules, retention logic, authorization decisions,
  or direct data-store access; it renders state and issues API calls only.
- Breaking API changes MUST ship a new major API version; the previous version MUST remain
  served for at least one release cycle.
- Generated clients MUST be derived from the contract; hand-written duplicates of contract
  types are prohibited.

Rationale: A single authoritative contract lets the two tiers evolve and scale on separate
schedules, and keeps security decisions on the trusted side of the boundary.

### II. Ingestion Integrity (NON-NEGOTIABLE)

Accepted log data MUST NOT be silently lost, silently altered, or silently duplicated.

- Ingestion endpoints MUST acknowledge an event only after it is durably persisted or
  committed to a durable queue.
- Every ingested event MUST carry: tenant id, source identity, ingest timestamp, original
  event timestamp, and a stable event id enabling idempotent retry.
- Malformed or over-quota events MUST be routed to a dead-letter store with the rejection
  reason and MUST be counted in an exposed metric; they MUST NEVER be dropped silently.
- Parsing and enrichment MUST preserve the raw original payload; normalization writes new
  fields and MUST NOT overwrite raw content.
- Backpressure MUST be explicit: the API returns a retryable status with a retry hint rather
  than degrading into unbounded buffering.

Rationale: A log platform is evidence infrastructure. Data that may have been lost is data
that cannot be relied on in an investigation or an audit.

### III. Test-First (NON-NEGOTIABLE)

TDD is mandatory across backend and frontend.

- Order is strict: write the test → confirm it fails (RED) → implement the minimum to pass
  (GREEN) → refactor.
- Every API contract MUST have contract tests that fail when the implementation drifts from
  the published schema.
- Every ingestion parser and every detection/alert rule MUST have fixture-based tests using
  real sample log lines, including malformed input cases.
- Minimum line coverage is 80% per package/module; merges that lower coverage MUST be
  rejected.
- Bug fixes MUST begin with a regression test that reproduces the defect.

Rationale: Query correctness and rule correctness are not visually verifiable; only
executable tests keep them honest as the schema and rule set grow.

### IV. Tenant Isolation & Least Privilege

Authorization is enforced server-side, on every request, without exception.

- Every query, aggregation, dashboard, alert, and export MUST be scoped by tenant id at the
  data-access layer; tenant scoping MUST NOT depend on a caller-supplied filter alone.
- Access control MUST be role-based with, at minimum, the roles: Admin, Analyst, Auditor,
  and Ingest-Only. Permissions are deny-by-default.
- All user and API inputs MUST be validated against a schema at the system boundary before
  processing; queries MUST be parameterized or built through a safe query builder.
- Every privileged action (login, role change, retention change, rule change, export, data
  deletion) MUST write an append-only audit record that the application itself cannot edit
  or delete.
- Secrets MUST come from environment variables or a secret manager, MUST be validated as
  present at startup, and MUST NEVER be committed or written to logs.

Rationale: A log platform aggregates the most sensitive data in an organization; a single
cross-tenant leak or unaudited change is an unrecoverable trust failure.

### V. Observability & Bounded Performance

The platform MUST be able to explain its own behavior and MUST have declared limits.

- Backend logs MUST be structured (JSON), MUST carry a request/trace id propagated from the
  frontend, and MUST NEVER contain secrets or raw personal data.
- Ingest rate, ingest lag, query latency, error rate, dead-letter count, and storage usage
  MUST be exported as metrics and MUST be covered by alerts.
- Every query path MUST be bounded: a mandatory time range, a result-size cap, a server-side
  timeout, and cursor-based pagination. Unbounded scans MUST be rejected, not queued.
- Every user-facing error MUST return a stable machine-readable error code plus a
  human-readable message that leaks no internal detail; the full context is logged
  server-side. Errors MUST NEVER be silently swallowed.
- Performance targets are part of the definition of done and MUST be asserted by tests or
  load checks, not assumed.

Rationale: Operators debug this system while under incident pressure; unbounded queries and
unexplained failures turn a monitoring tool into an outage.

## Security, Compliance & Data Retention Requirements

- **Transport & storage**: All traffic MUST use TLS. Log data at rest MUST be encrypted, and
  credentials MUST be hashed with a modern memory-hard algorithm.
- **Retention**: Every tenant MUST have an explicit retention policy per data class. Deletion
  MUST be automated, idempotent, and audited. Data MUST NEVER outlive its configured
  retention window, and retention changes MUST be audit-logged with the actor.
- **Immutability**: Persisted log events are append-only. There is no update path and no
  user-facing delete path other than the retention pipeline and an explicitly audited
  administrative purge.
- **Rate limiting**: All API endpoints, including ingestion, MUST enforce per-tenant and
  per-credential rate limits with quota accounting.
- **Frontend hardening**: The UI MUST apply output escaping/sanitization for all rendered log
  content (log fields are untrusted input), MUST set a restrictive Content Security Policy,
  and MUST enable CSRF protection for cookie-authenticated routes.
- **Dependencies**: Dependency and secret scanning MUST run in CI; CRITICAL and HIGH findings
  block the merge.
- **Configuration**: No hardcoded values — endpoints, limits, retention defaults, and
  thresholds come from configuration or named constants.

## Development Workflow & Quality Gates

- **Research before build**: Before implementing new subsystems, search for proven
  libraries and existing implementations; prefer adopting a battle-tested solution over
  hand-rolled code, and record the decision in the plan.
- **Spec-driven flow**: Feature work follows specify → clarify → plan → tasks → implement.
  Code MUST NOT be written before the feature's plan passes the Constitution Check.
- **Immutability in code**: Data transformations MUST return new values rather than mutating
  inputs, in both backend and frontend state handling.
- **File hygiene**: Modules stay focused — typically 200–400 lines, 800 maximum; functions
  stay under 50 lines; nesting stays under 4 levels. Organize by feature/domain, not by type.
- **Review**: Every change MUST pass automated review gates plus a code review that
  explicitly checks the affected principles. CRITICAL and HIGH findings block the merge;
  MEDIUM findings are fixed or ticketed with a named owner.
- **CI gates (all blocking)**: lint → type check → unit tests → integration tests → contract
  tests → coverage ≥80% → security scan → build.
- **Migrations**: Schema changes MUST ship forward and rollback paths and MUST be verified
  against a dataset representative of production volume.
- **Commits**: Conventional commit format (`feat:`, `fix:`, `refactor:`, `docs:`, `test:`,
  `chore:`, `perf:`, `ci:`).

## Governance

This constitution supersedes all other development practices, conventions, and habits. Where
another document conflicts with it, this document wins.

- **Amendments** MUST be proposed as a pull request that modifies this file, states the
  motivation, and describes the migration path for any code or specs that become
  non-compliant. Amendments take effect only when merged.
- **Versioning** follows semantic versioning of governance intent:
  - MAJOR — a principle is removed, or redefined in a backward-incompatible way.
  - MINOR — a principle or mandatory section is added, or guidance is materially expanded.
  - PATCH — clarifications, wording, and non-semantic refinements.
- **Compliance review**: Every plan MUST complete the Constitution Check gate before tasks
  are generated, and every pull request MUST confirm compliance. Any deviation MUST be
  recorded in the plan's Complexity Tracking section with the simpler alternative that was
  rejected and why. Undocumented complexity is grounds for rejection.
- **Runtime guidance**: Day-to-day development guidance lives in the repository's agent
  guidance files and `.specify/templates/`; those files MUST be updated whenever an
  amendment changes what they assert.

**Version**: 1.0.0 | **Ratified**: 2026-08-06 | **Last Amended**: 2026-08-06
