# Common Event Model — Vendor Field Mapping

The contract that makes correlation possible: three vendor vocabularies onto one set of names.
Column types are in [data-model.md](../data-model.md) §1.2. Field names are indicative of each
vendor's documented output and are pinned by the fixture corpus in `backend/test/fixtures/`.

| Common field | Cloudflare (Logpush `http_requests`) | F5 (BIG-IP ASM / Distributed Cloud) | DataDome (Logs Enrichment) |
|---|---|---|---|
| `event_time` | `EdgeStartTimestamp` | `date_time` / event timestamp | request timestamp |
| `vendor_request_id` | `RayID` | `support_id` | `X-DataDome-requestid` |
| `client_ip` | `ClientIP` | `ip_client` (falling back to `x_forwarded_for_header_value`) | client IP |
| `client_asn` | `ClientASN` | — (enriched by the platform) | — (enriched by the platform) |
| `client_country` | `ClientCountry` | `geo_location` | country |
| `request_host` | `ClientRequestHost` | `host` / `virtual_server` | host |
| `request_path` | `ClientRequestURI` (path part) | `uri` | request path |
| `request_query` | `ClientRequestURI` (query part) | `query_string` | query string |
| `request_method` | `ClientRequestMethod` | `method` | method |
| `user_agent` | `ClientRequestUserAgent` | `user_agent` header item | user agent |
| `http_status` | `EdgeResponseStatus` | `response_code` | response status |
| `verdict` | derived from `SecurityAction` | derived from `request_status` + `severity` | derived from action / `X-DataDome-isbot` |
| `verdict_reason` | `SecurityRuleDescription` | `attack_type` / `violation_details` | `botname` + `family` |
| `rule_id` | `SecurityRuleID` | `policy_name` + violation id | detection rule id |
| `rule_ids` | `SecurityRuleIDs` | `violations` (split) | — |
| `score` | — | `violation_rating` | `botscore` |
| `score_kind` | `none` | `threat` | `bot` |
| `vendor_account` | zone id / name | partition / namespace | client-side account id |

Fields with no common-model home go to `raw_extra` verbatim (FR-010) — Cloudflare's cache and
performance fields, F5's `unit_hostname` / `management_ip_address`, DataDome's device signals.

## Verdict normalization

The single most correctness-sensitive mapping in the system: correlation's disagreement detection is
only as good as this table. Every row is covered by a fixture test.

| Common `verdict` | Cloudflare `SecurityAction` | F5 `request_status` | DataDome action |
|---|---|---|---|
| `blocked` | `block`, `drop` | `blocked` | `BLOCK`, `HARDBLOCK` |
| `challenged` | `challenge`, `jschallenge`, `managed_challenge` | — | `CAPTCHA`, `DEVICE_CHECK` |
| `rate_limited` | `connectionClose`, rate-limit action | `blocked` with a rate-limit violation | rate-limit action |
| `allowed` | `allow`, `log`, `skip`, `unknown` (no action taken) | `passed` | `ALLOW` |
| `monitored` | `simulate` | `alerted` (transparent/staging policy) | monitoring mode |
| `unknown` | anything unmapped | anything unmapped | anything unmapped |

`monitored` is kept distinct from `allowed` on purpose: a vendor in monitoring mode did *not* choose
to allow the request, and treating it as an allow would manufacture false disagreements against a
vendor that genuinely blocked.

## Disagreement classification (FR-017)

Restrictiveness ordering: `blocked` > `rate_limited` > `challenged` > `monitored` > `allowed`.
`combined_outcome` is the most restrictive verdict present.

| `disagreement_kind` | Condition |
|---|---|
| `allow_vs_block` | one vendor `allowed`, another `blocked` or `rate_limited` |
| `allow_vs_challenge` | one vendor `allowed`, another `challenged` |
| `score_conflict` | all vendors `allowed`, but a bot/threat score exceeds the tenant's conflict threshold (default 0.8 normalized) |
| `none` | all participating vendors agree, or only one vendor participated |

Records with `vendor_count = 1` are never disagreements — a single vendor cannot disagree with
itself, and marking them as such would swamp the disagreement rate on single-vendor hostnames.

## Correlation join keys (FR-014)

**Tier 1 — exact, confidence `high`**: two events share a `vendor_request_id` value, which happens
when a customer propagates one vendor's id into another's logs (typically Cloudflare's `RayID`
forwarded to F5 or DataDome). Checked first; when it matches, no heuristic is attempted.

**Tier 2 — heuristic, confidence `medium`**: normalized key
`tenant_id ‖ client_ip ‖ request_host ‖ lower(request_path) ‖ request_method`, within the tenant's
correlation window (default 5s), using overlapping buckets so an event near a boundary is not
missed.

**Confidence downgrades to `low`** when `client_ip_shared` is true (NAT, proxy chain, or carrier
range) or when `candidate_count > 1`, meaning more than one plausible counterpart sat in the window.
This is the mechanism behind FR-015 and the reason SC-004's <1% false-join target is reachable: an
ambiguous join is published as ambiguous rather than asserted as fact.

**Path normalization** before keying: lowercase, strip the trailing slash, drop the query string,
and collapse repeated slashes — F5 and Cloudflare differ in how they report the same URI.
