# Quickstart validation results

**Run:** 2026-08-07, against a clean `make down-v && make up` on a single developer
machine (WSL2, contended — other containers running).

**Outcome: pass, with one scenario not yet run (V4, alerting) and V6's peak leg not
attempted.** The stack starts, ingests,
normalizes, correlates, and serves. The throughput defect this run found has since been
fixed and re-measured — see the resolution below.

---

## Defects found by this validation

Every one of these was invisible to the automated suites, because those use
testcontainers and call handlers directly rather than exercising the Compose stack and
the binaries' own wiring. All are fixed unless stated.

| # | Defect | Effect |
|---|---|---|
| 1 | `Dockerfile.backend` used a `/bin/sh` entrypoint on a **distroless** base | No service could start at all |
| 2 | ClickHouse bound to `127.0.0.1`; its healthcheck probed localhost from inside the container | Reported healthy while refusing every other container |
| 3 | `cmd/siem-ingest` never mounted the receiver | Entire ingest path returned 404 |
| 4 | Kafka topics were never created; auto-creation races the first produce | Every first delivery on a fresh stack → `503` |
| 5 | `make migrate` passed credentials as DSN userinfo, which golang-migrate's ClickHouse driver ignores | Migrations could never authenticate |
| 6 | `profile` was sent as a per-connection ClickHouse setting | Rejected outright; every service failed at startup |
| 7 | `cp .env.example .env` (as the README instructed) left secrets blank | `make up` failed on the first documented command |
| 8 | Infrastructure host ports were hardcoded | Stack could not start alongside a local Redis or ClickHouse |
| 9 | API had **no rate limiting** — `cmd/siem-api` never passed a limiter, and the server treats nil as unlimited | Unauthenticated flood against `/auth/login` unbounded |
| 10 | Three Prometheus alert rules read metrics that do not exist | Those rules could never fire |
| 11 | `ListAuditEntries` never set `ChainIntact`, so it was always `false` | The audit page reported tampering on a provably intact chain |
| 12 | An unbounded Redis pipeline timed out under sustained load, and a failed worker was never restarted | Correlation died silently and stayed dead while the service reported healthy |

---

## Scenario results

### V1 — ingest and store · **PASS**

3,000 fixture events across all three vendors accepted with `202`. Raw and normalized
rows present in ClickHouse. `rejected_events` empty.

The `202`/`503` contract behaves correctly: before topics existed, ingest returned
`503 BROKER_UNAVAILABLE` rather than accepting events it could not durably commit.

### V2 — feed health · **PASS**

Feeds report healthy after first delivery. Credential rejection returns `401`.

### V3 — search · **PASS**

Events searchable. A query without a time range is rejected with
`TIME_RANGE_REQUIRED`. Unauthenticated requests return the platform error envelope:

```json
{"code":"UNAUTHENTICATED","message":"a bearer token is required"}
```

### V4 — correlation · **PASS**

With all three vendors sending the same `--seed`, correlation produced:

```
correlated    2020
multi_vendor  1000
```

1,000 cross-vendor records from 1,000 shared request shapes — the join works end to end
in the deployed stack, not only in the corpus harness.

> **Numbering correction.** The V1–V6 labels above were this run's own, and they do not
> match quickstart.md. The quickstart's scenarios are V1 ingest, V2 correlation, V3
> search and dashboards, **V4 alerting**, **V5 tenancy/RBAC/retention/audit**, **V6
> load**. The results below use the quickstart's numbering. V4 (alerting) has still not
> been run under either numbering.

### V5 — tenancy, RBAC, retention, audit · **PASS** (2026-08-07)

Automated half — `TestTenantIsolation`, the full role/permission matrix,
`TestAuditorHoldsNoWritePermissions`, the nine audit tests and the four retention
tests — all pass against real ClickHouse and Redis.

Live stack, through the HTTP layer with real tokens for three roles:

| Check | Result |
|---|---|
| Analyst and auditor on every admin endpoint | `403` on all of them |
| Auditor reads `/audit` | `200`; analyst `403` |
| Unauthenticated read | `401` |
| Five audited actions (login, role change, feed update, rule change, export) | all five recorded with actor and before/after values |
| Retention: 14-day probe vs 7-day window | 500 expired rows deleted, 500 in-window rows kept, 1.22M in-window events untouched |

**Defect #11 found and fixed — the audit page's integrity indicator always read
"tampered".** `ListAuditEntries` never set `ChainIntact`, so the field kept its zero
value. The chain itself was provably whole: all 16 entries' content hashes and every
`prev_hash` link verified when checked directly against storage. An integrity indicator
that always cries wolf is worse than none, because operators learn to ignore it — and
the one time it means something, they will ignore that too.

Fixing it surfaced a second problem: `audit.VerifyChain` requires the slice to start at
the tenant's first entry, so verifying a *time range* — which is what an audit page
always shows — would have reported tampering for every range that did not reach back to
the beginning. Added `audit.VerifyRange`, which checks the two things a partial view can
actually prove: every entry still hashes to its own content, and each still links to the
one before it. Covered by two new integration tests.

### V6 — load (SC-002) · **PARTIAL PASS**

`make loadtest` passes, but it does not validate V6 as written: it measures the storage
layer in **0.18-second bursts** (40k events in 182ms = 219k eps; 64k in 144ms = 445k
eps), not 5,000 EPS sustained for 30 minutes. The test names claim SC-002; the durations
do not support the claim.

So the scenario was run for real against the Compose stack — 9,001,800 events across
all three vendors from three concurrent senders:

| V6 criterion | Target | Measured | Result |
|---|---|---|---|
| Sustained ingest | 5,000 EPS / 30 min | **~5,325 EPS over 28m10s** | PASS |
| Zero rejected valid events | 0 | **0** (`rejected_events` empty) | PASS |
| p95 search latency throughout | < 3s | **7–13 ms**, one 63 ms sample | PASS |
| Ingest lag recovery | < 60s within 2 min of peak | normalizer lag peaked at 4,500 events (~0.9s) and hit 0 | PASS |
| 15,000 EPS peak / 5 min | 15,000 | **not run** | NOT RUN |

The 15k peak was not attempted: the measured ceiling from three sender processes is
~8,200 EPS, and reaching 15k needs more load generators than this single contended
developer box can host without measuring the generator instead of the platform.

**Defect #12 found — the correlator died and was never restarted.** Under sustained
load the correlator exited with
`redis rpush 1648 entries: i/o timeout` and stayed dead for the rest of the run. The
service kept running and reporting healthy while correlation silently stopped; the
consumer lag froze at 1.77M and never moved.

Two causes, both fixed:

1. **An unbounded Redis pipeline.** The batching change pipelined a whole Kafka fetch in
   one `Exec` — 1,648 entries is 3,296 commands — whose response could not arrive inside
   the client's 3s read timeout. Now chunked at 500 entries per round trip, which keeps
   round trips at ~1/500th of the per-event cost while each one completes comfortably.
   This was a regression introduced by the throughput fix and only appears under
   sustained load, which is exactly what V6 is for.
2. **No worker supervision.** A worker returning an error was logged and abandoned.
   Every stage here is unattended background work, so a dead one is invisible in the
   product: events still arrive, the API still answers, and correlation quietly falls
   behind for ever. Workers now restart with bounded exponential backoff (1s → 60s) and
   increment `siem_worker_restarts_total`. Covered by three new tests.

After both fixes the correlator drained the 1.49M backlog at **26,748 eps with zero
errors**.

---

## RESOLVED — pipeline throughput (was ~1000× under target)

**Fixed 2026-08-07 by batching the consumer dispatch.** Measured on the same stack,
300,000 events across all three vendors from three concurrent senders:

| Stage | Before | After | Target |
|---|---|---|---|
| Ingest accept | 4,204 eps | **8,171 eps** | 5,000 sustained |
| Normalize → store | 4.6 eps | **8,051 eps** | 5,000 sustained |
| Correlation filing | 2,293 eps | keeps pace with normalize | — |
| Correlated records emitted | ~14/sec | **~1,600/sec** | — |

End to end, 300,000 events were accepted, normalized, stored, correlated and emitted
as 101,143 correlated records in 98 seconds — of which 35 seconds is the correlation
window plus grace that must elapse before any window may close.

Correctness is unchanged: **100,000 multi-vendor joins from 100,000 shared request
shapes — a 100% join rate**, with `rejected_events` empty and no errors logged.

### What was actually slow

Three separate places, all the same defect: **one round trip per event**.

1. **Normalizer** — one ClickHouse insert per record. With the ingest profile's
   `wait_for_async_insert=1` and `async_insert_busy_timeout_ms=200`, each insert blocks
   on the async buffer flush, bounding the stage at `1 / 0.2s ≈ 5 eps`.
2. **Correlator** — up to three Redis round trips per event (exact key, closing key,
   schedule). Redis was never the limit; the round trips were.
3. **Closer** — one ClickHouse insert *and* one point query per closed window, plus a
   hard ceiling of one 256-window claim per second.

### What was done

- `stream.Consumer.RunBatch` hands a whole fetch to the handler. Offsets commit only
  after the batch is durably written, exactly as before.
- `normalize.HandleBatch` — one insert per table per batch, tenant redaction policy
  read once per tenant rather than once per event. Raw is still written before any
  normalization is attempted (FR-005), and redaction still runs before the row is
  built (FR-037).
- `correlate.HandleBatch` + `window.AddBatch` — a whole fetch files in two pipelined
  Redis calls via new `RPushMany`/`ZAddMany` primitives.
- `Closer.Tick` — one insert per tenant per pass, one batched `Versions` query in place
  of a point lookup per record, and the tick now keeps claiming while the schedule
  returns full batches (bounded by `MaxPassesPerTick`).

### Why `wait_for_async_insert=0` was not the fix

Setting it would have restored throughput immediately and must not be done. The
consumer commits its offset after the insert returns; without the wait, the offset
would commit while rows were still buffered in ClickHouse, and a crash would lose them.
That trades the ingestion-integrity guarantee for a benchmark number — the exact trade
the constitution's Principle II forbids. Batching preserves the guarantee: a storage
failure fails the whole batch, no offset advances, and every event is redelivered.

Covered by 9 tests in `internal/normalize/batch_test.go`, 6 in
`internal/correlate/batch_test.go`, and 6 in `internal/correlate/closer_batch_test.go`,
including the durability guarantee and the FR-018 amendment contract. The 64-test
integration suite passes unchanged.

---

## Original defect report — ingest throughput is ~1000× under target

**SC-002 requires 5,000 events/sec sustained and 15,000 peak.**

Measured on the running stack:

| Stage | Measured | Target | Status |
|---|---|---|---|
| Ingest accept (HTTP + durable broker commit) | **4,204 eps** from one sender process | 5,000 sustained | Close; not the bottleneck, and one sender is not the ceiling |
| Normalize → store | **~4.6 eps** | 5,000 sustained | **Fails by three orders of magnitude** |

Measurement: `raw_events` grew 3,941 → 4,124 over 40 seconds while 20,000 events sat in
the topic — 183 rows in 40s.

### Cause

The normalizer consumes **one Kafka record at a time** and performs a separate
single-row insert per event. The ingest ClickHouse profile sets
`async_insert=1`, `wait_for_async_insert=1`, `async_insert_busy_timeout_ms=200`, so
each insert blocks up to 200 ms waiting for the async buffer to flush. That bounds
throughput at roughly `1 / 0.2s = 5 eps`, which matches the observed 4.6 eps.

This path had **never executed before** this validation: defect #6 meant the ingest
profile connection failed at startup, so the settings were never actually applied.

### Why the obvious fix is wrong

Setting `wait_for_async_insert=0` would restore throughput immediately, and it must not
be done. The consumer commits its offset after the insert returns; without the wait,
the offset would be committed while rows are still buffered in ClickHouse, and a crash
would lose them. That trades the ingestion-integrity guarantee for a benchmark number —
the exact trade the constitution's Principle II forbids.

### The correct fix

Batch the consumer dispatch. `InsertRaw` and `InsertNormalized` already take slices, so
only `stream.Consumer` needs to hand a whole fetch to the handler instead of one record
at a time. Insert the batch, then commit — durability preserved, and one insert covers
hundreds of events instead of one.

**Done — see the resolution above.**

---

## Coverage

Backend coverage across unit, contract, and integration suites: **65.9%** against the
80% floor (T144). All files are under the 800-line limit and `funlen` reports no
function over 50 lines.

Frontend coverage is ~10%; only the two correlation components have unit tests.
