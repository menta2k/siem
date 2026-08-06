# Vendor Ingest Contracts (`/ingest/v1`)

Served by `siem-ingest`, separately from the frontend API. Credentials here are Ingest-Only and
grant no console access.

## Push endpoints

| Method | Path | Vendor mechanism | Body |
|--------|------|------------------|------|
| `POST` | `/ingest/v1/cloudflare/{feed_id}` | Logpush HTTP destination | gzip NDJSON |
| `POST` | `/ingest/v1/f5/{feed_id}` | BIG-IP HSL / iRule HTTP, or F5 Distributed Cloud export | JSON array, NDJSON, or raw syslog/CEF lines |
| `POST` | `/ingest/v1/datadome/{feed_id}` | Logs Enrichment webhook | JSON array or NDJSON |

**Authentication**: `Authorization: Bearer <feed_token>`. The token is bound to the `feed_id` in the
path; a mismatch returns `403 FEED_TOKEN_MISMATCH` and is audited. Where a vendor supports request
signing (HMAC over the body), the signature is verified and a bad signature returns `401` — a valid
token alone is not sufficient when signing is configured.

**Limits**: 32 MiB per request, 50,000 events per batch. Exceeding either returns `413
PAYLOAD_TOO_LARGE`.

### Responses

| Status | Meaning | Vendor should |
|--------|---------|---------------|
| `202 Accepted` | Every event in the batch is durably committed to Redpanda | not retry |
| `207 Multi-Status` | Batch committed; some events were dead-lettered. Body lists per-event `reason_code` | not retry |
| `400` | Batch envelope unparseable — nothing committed | fix, do not retry blindly |
| `401` / `403` | Bad token or signature | fix credentials |
| `413` | Too large | split the batch |
| `429` | Quota or rate limit exceeded, with `Retry-After` | retry after the stated delay |
| `503` | Broker unavailable, with `Retry-After` | retry |

**Acknowledgement rule (FR-003)**: `202` and `207` are returned only after `acks=all` from
Redpanda. If the broker write fails or times out, the response is `503` — never a `2xx`. The system
prefers a vendor retry (which dedup handles) over an acknowledgement it cannot honor.

**Response body**

```json
{
  "batch_id": "uuid",
  "accepted": 4998,
  "duplicates_suppressed": 1,
  "rejected": [
    { "index": 4711, "reason_code": "PARSE_ERROR", "reason_detail": "field EdgeStartTimestamp: invalid RFC3339" }
  ]
}
```

## Pull mode

For feeds configured `delivery_mode: pull`, `siem-ingest` polls on the configured interval:

- **Cloudflare** — S3-compatible or R2 bucket populated by Logpush. Objects processed in
  lexicographic order; a per-feed watermark records the last completed object key. Objects are never
  deleted by the platform.
- **F5** — F5 Distributed Cloud event export API, paged by cursor, watermark on the cursor.
- **DataDome** — log export API, paged by time range, watermark on the last completed range.

Pull rules: an object or page is marked complete only after every event in it is committed to
Redpanda; a crash mid-object replays the whole object and dedup absorbs it. Pull failures increment
`feed_health.credential_valid = false` where the failure is authentication, and surface through
`GET /feeds/{feed_id}/health`.

## Per-vendor parsing contract

Each adapter implements:

```go
type VendorAdapter interface {
    Vendor() string
    Detect(payload []byte) (Format, bool)          // json | ndjson | cef | syslog
    Parse(payload []byte, f Format) ([]RawRecord, error)
    Normalize(RawRecord) (NormalizedEvent, []string, error)  // returns unknown field names
}
```

Contract obligations, verified by fixture tests per adapter:

1. `Parse` never panics on arbitrary bytes — enforced by a fuzz test.
2. A record missing an optional field normalizes successfully with that field empty; it is not
   rejected (Acceptance Scenario 1.2).
3. Unknown incoming fields are preserved into `raw_extra` and returned in the unknown-field list;
   they never fail the batch (FR-012).
4. `Normalize` is pure and deterministic — same input, same output, no clock or network access. This
   is what makes replay-based correlation testing meaningful.
5. Every adapter maps its vendor's action vocabulary onto the six-value `verdict` enum, and any
   unmapped action becomes `unknown` with the original string kept in `raw_extra`.

## Schema drift

When an adapter reports unknown fields for more than 1% of a feed's events over a 10-minute window,
the platform raises a `SCHEMA_DRIFT` feed-health warning naming the fields. The feed keeps ingesting
— degrading to a warning rather than a failure is deliberate, since a vendor adding a field must not
take a customer's logging offline.
