# SIEM — multi-vendor WAF & bot-defence correlation

Receives logs from **Cloudflare**, **F5**, and **DataDome**, joins the events that
describe the same HTTP request, and shows where the vendors disagreed.

The disagreement is the product. Any one vendor's console already shows you what that
vendor did; what none of them can show you is that Cloudflare allowed a request F5
blocked, which is where both a missed attack and a false positive look the same until
someone correlates them.

---

## What it does

| | |
|---|---|
| **Ingest** | Push (webhook) and pull (poll) per feed. A delivery is acknowledged only after a durable broker commit — a `202` means the events are safe, a `503` means retry. |
| **Normalize** | Each vendor's format is mapped to one common model. Vendor-native fields with no home are preserved, never discarded. |
| **Correlate** | Two tiers: an exact shared request id, or a heuristic over client, host, path, method, and time. Every record says which evidence produced it and how far to trust it. |
| **Search** | Cross-vendor, bounded, cursor-paginated. A query without a time range is rejected rather than queued. |
| **Alert** | Rules over correlated data, dry-run before saving, delivered to a signed webhook with retry. A delivery failure is visible on the alert, not just in a log. |

## Quick start

```bash
make up            # generates local secrets, then starts everything
make seed          # demo tenant, admin user, one feed per vendor — prints credentials
```

`make up` runs `make env` first, which writes a `.env` with freshly generated
development secrets. `.env.example` ships those blank on purpose, so copying it by hand
produces a stack that will not start.

Then send some traffic. Running all three vendors with the **same `--seed`** makes them
describe the same requests, which is what produces correlated records:

```bash
go run ./backend/test/tools/sendfixtures --vendor=cloudflare --feed=$CF_FEED --token=$CF_TOKEN --count=5000 --seed=1
go run ./backend/test/tools/sendfixtures --vendor=f5         --feed=$F5_FEED --token=$F5_TOKEN --count=5000 --seed=1
go run ./backend/test/tools/sendfixtures --vendor=datadome   --feed=$DD_FEED --token=$DD_TOKEN --count=5000 --seed=1
```

The console is on <http://localhost:5173>. Full walkthrough in
[docs/quickstart.md](docs/quickstart.md).

## Architecture

```
vendors ──> siem-ingest ──> Redpanda ──> siem-processor ──> ClickHouse <── siem-api <── console
                 │                            │
            durable ack                normalize → correlate → alert → retention
```

Three binaries, deliberately separate:

- **`siem-ingest`** — the only latency-critical path. Accepts, deduplicates, and
  publishes. Holds no query state.
- **`siem-processor`** — normalization, correlation, alerting, retention. Falls behind
  without ever applying backpressure to ingestion.
- **`siem-api`** — the console's OpenAPI surface. Read-heavy, holds no pipeline state.

**ClickHouse is the only store of record.** Redis holds nothing that cannot be lost:
dedup windows, rate limits, locks, correlation windows, secrets. Redpanda is the
durability boundary between accepting an event and processing it.

## Development

```bash
make api          # protos -> Go stubs + openapi.yaml + the frontend's TS client
make lint         # golangci-lint, buf lint, eslint, vue-tsc
make test         # unit + contract, with the coverage gate
make test-integration   # against real containers (testcontainers)
make loadtest     # SC-002 / SC-003 assertions; slow, own build tag
```

The API is **contract-first**. `backend/api/protos/**` is the source; the Go server,
the OpenAPI document, and the frontend's types are all generated from it. `make
api-check` fails the build when the committed output has drifted.

### Tests

| Suite | Tag | What it is for |
|---|---|---|
| unit | — | Pure logic. Fast, no containers. |
| contract | `contract` | Real handlers against the **generated** `openapi.yaml`. |
| integration | `integration` | Real ClickHouse, Redis, and Redpanda. One shared stack per package. |
| corpus | `corpus` | The SC-004 accuracy gate: join rate and false-join rate against a labelled corpus. |
| e2e | Playwright | The console, including the XSS containment release blocker. |
| load | `load` | SC-002 throughput and SC-003 latency, asserted rather than reported. |

The corpus suite is worth knowing about: it is the only place SC-004 becomes a number
rather than an aspiration, and it contains deliberate near-miss traps so a correlator
cannot pass by joining everything.

## Releases

Tagging `v*` builds and publishes everything a deployment needs; pushes to `main`
publish images only, tagged by branch and commit.

| Artefact | Where |
|---|---|
| `ghcr.io/<owner>/siem/siem-api`, `-ingest`, `-processor` | GHCR, `linux/amd64` and `linux/arm64` |
| `ghcr.io/<owner>/siem/siem-frontend` | GHCR — nginx serving the built SPA |
| `siem_<version>_<arch>.deb` / `.rpm` | attached to the GitHub release, with checksums |

One package carries all three services and their systemd units. They share a module, a
wire contract and a version, so they are always upgraded together; a host installs the
package and enables only the units it should run:

```bash
sudo dpkg -i siem_1.0.0_amd64.deb
sudo vi /etc/siem/env                      # template: /usr/share/siem/env.example
sudo systemctl enable --now siem-ingest    # …and/or siem-api, siem-processor
```

Nothing is enabled or started on install: every service exits without a configured
ClickHouse, broker and signing key, so auto-starting would hand the operator three
crash-looping units before they had a chance to configure anything.

Build the same artefacts locally:

```bash
make package VERSION=1.0.0   # .deb + .rpm into dist/ (needs nfpm)
make images  VERSION=1.0.0   # the four container images
```

Every binary reports its own build — `GET /version` on the operational port, and the
first line of its log:

```json
{"version":"1.0.0","commit":"a1b2c3d","build_date":"2026-08-07T09:12:00Z","go_version":"go1.25.4","platform":"linux/amd64"}
```

## Documentation

- [Constitution](.specify/memory/constitution.md) — the five principles every change is
  reviewed against
- [Feature specification](specs/001-waf-bot-log-correlation/spec.md) — requirements and
  success criteria
- [Implementation plan](specs/001-waf-bot-log-correlation/plan.md) — technical choices
  and their rationale
- [Data model](specs/001-waf-bot-log-correlation/data-model.md) — every table and why
  its sort key is what it is
- [Contracts](specs/001-waf-bot-log-correlation/contracts/) — API surface, ingest
  contracts, the common event model
- [Connecting vendors](docs/connecting-vendors.md) — step-by-step for Cloudflare, F5,
  and DataDome
- [Quickstart](docs/quickstart.md) — validation scenarios V1–V6
- [Validation results](specs/001-waf-bot-log-correlation/validation-results.md) — what
  passed on a clean stack, and the twelve defects the runs found

## Security

- Tokens live in **memory only** in the browser. A console that renders attacker-
  controlled log content must not keep credentials anywhere a script can reach.
- All log-derived values render as **text**; `v-html` is an eslint error, and an E2E
  test drives real payloads through the UI to prove it.
- CSV exports neutralize **formula injection** — a user agent beginning `=` executes
  when the file opens in a spreadsheet.
- Webhook targets are checked for **SSRF** before delivery, and redirects are not
  followed.
- Every privileged action is written to a **hash-chained** audit trail, and the console
  verifies the linkage rather than asserting it.
