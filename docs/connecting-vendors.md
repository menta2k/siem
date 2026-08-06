# Connecting Cloudflare, F5, and DataDome

Step-by-step for pointing each vendor at this platform.

Every feed follows the same shape:

1. Create the feed in the console (or via the API) — this mints a **feed id** and an
   **ingest token**.
2. Configure the vendor to deliver to
   `https://<your-ingest-host>/ingest/v1/<vendor>/<feed-id>` with
   `Authorization: Bearer <token>`.
3. Confirm the feed goes green on **Feeds**, then check events appear under **Search**.

> **The token is shown once.** It is stored as a reference into the secret manager, not
> as a value, so it cannot be recovered — only rotated. Put it straight into the
> vendor's configuration or your secret store.

---

## Before you start

Create the feed and capture its id and token:

```bash
curl -sS -X POST https://<api-host>/api/v1/feeds \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"vendor":"VENDOR_CLOUDFLARE","name":"prod cloudflare","deliveryMode":"DELIVERY_MODE_PUSH"}'
```

The response contains `feedId` and, once only, `credential`.

For a local stack, `make seed` creates one feed per vendor and prints all three.

### Which delivery mode

| Mode | Use when | How it behaves |
|---|---|---|
| **Push** | The vendor can POST to a URL (Cloudflare Logpush, DataDome webhooks) | The vendor calls us. Lowest latency; the vendor retries on `503`. |
| **Pull** | The vendor only exposes an API to poll (F5 in most deployments) | We poll on a schedule and track a watermark so a restart does not re-read or skip. |

---

## Cloudflare

Cloudflare delivers via **Logpush**, as newline-delimited JSON.

### 1. Create a Logpush job

Console: **Analytics & Logs → Logpush → Add Logpush job**, or via API:

```bash
curl -sS -X POST \
  "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/logpush/jobs" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "siem-http-requests",
    "dataset": "http_requests",
    "destination_conf": "https://<ingest-host>/ingest/v1/cloudflare/<feed-id>?header_Authorization=Bearer%20<token>",
    "output_options": {
      "field_names": [
        "RayID","EdgeStartTimestamp","ClientIP","ClientRequestHost",
        "ClientRequestPath","ClientRequestMethod","ClientRequestUserAgent",
        "EdgeResponseStatus","SecurityAction","SecurityRuleID","WAFRuleID",
        "BotScore","BotScoreSrc","ClientCountry","ClientASN"
      ],
      "timestamp_format": "rfc3339",
      "output_type": "ndjson"
    },
    "enabled": true
  }'
```

The `header_Authorization` query parameter is how Logpush sets a custom header — the
value must be URL-encoded, which is why the space after `Bearer` appears as `%20`.

### 2. Fields that matter

`RayID` is the important one. It is Cloudflare's per-request identifier, and when
another vendor reports the same id the platform joins them at **tier 1** — an exact
match with no false-join risk. Without it, correlation falls back to matching on
client, host, path, method, and time, which is less certain.

`BotScoreSrc` is worth including: it distinguishes a machine-learning score from a
heuristic one, which changes how much weight a disagreement deserves.

### 3. Verify

Cloudflare validates the destination when the job is created and pushes a test record.
The feed should go green within a few minutes. Logpush batches, so expect delivery
every ~30 seconds rather than per request.

---

## F5 (BIG-IP ASM / Advanced WAF)

F5 has two workable paths. **Pull is usually easier**, because remote logging on
BIG-IP is configured per-virtual-server and often already points somewhere else.

### Option A — pull (recommended)

Create the feed with `"deliveryMode":"DELIVERY_MODE_PULL"` and a `pullConfig`
describing the BIG-IP endpoint:

```json
{
  "vendor": "VENDOR_F5",
  "name": "prod bigip",
  "deliveryMode": "DELIVERY_MODE_PULL",
  "pullConfig": "{\"baseUrl\":\"https://bigip.internal\",\"partition\":\"Common\"}",
  "credential": "<bigip-api-token>"
}
```

The puller tracks a watermark per feed, so a restart resumes where it stopped rather
than re-reading the window or skipping it.

### Option B — push via a logging profile

If you can send from BIG-IP directly, configure a **Logging Profile** with an HTTP
destination:

1. **Security → Event Logs → Logging Profiles → Create**
2. Enable **Application Security**, set **Request Type** to *All requests* (or
   *Illegal requests only* if volume is a concern).
3. Under **Remote Storage**, choose *Remote* with **Protocol: HTTPS**, and set the URL
   to `https://<ingest-host>/ingest/v1/f5/<feed-id>`.
4. Add the header `Authorization: Bearer <token>`.
5. Attach the profile to the virtual servers you want covered.

### Fields that matter

Include **`host`** — the HTTP Host header. This one deserves emphasis: BIG-IP's
`virtual_server` field looks like a hostname (`/Common/vs_shop_https`) but is a
BIG-IP object path. If `host` is missing, F5 events cannot be joined with any other
vendor on hostname, and searching by hostname will silently miss all F5 traffic.

Also include:

- `support_id` — F5's per-request identifier
- `date_time`, `ip_client`, `uri`, `method`, `request_status`
- `policy_name`, `attack_type`, `violations` — what triggered
- `response_code`, `geo_location`

---

## DataDome

DataDome delivers via **webhook**.

### 1. Configure the webhook

In the DataDome dashboard: **Settings → Integrations → Webhooks → Add endpoint**

- **URL:** `https://<ingest-host>/ingest/v1/datadome/<feed-id>`
- **Method:** `POST`
- **Content type:** `application/json`
- **Custom header:** `Authorization: Bearer <token>`
- **Events:** all decisions, not only blocks

### 2. Send allowed traffic too

Sending only blocked requests is the most common mistake here, and it quietly breaks
the product's main purpose. The disagreement worth seeing is *"DataDome allowed this
and F5 blocked it"* — and that comparison is impossible if DataDome only ever reports
its blocks.

### 3. Fields that matter

- `requestid` — DataDome's per-request identifier
- `timestamp`, `ip`, `host`, `uri`, `method`
- `action` (`ALLOW` / `BLOCK` / `CHALLENGE`) and `score`
- `useragent`, `country`

The `score` is a **bot** score, which the platform treats differently from a WAF threat
score: a high bot score on an allowed request raises a *score conflict*, whereas a WAF
threat rating on an allowed request is only a severity hint.

---

## Confirming it works

### The feed is healthy

**Feeds** shows a chip per feed. What each state means:

| Chip | Meaning |
|---|---|
| **Healthy** | Events arriving |
| **Awaiting first event** | Configured, nothing received yet |
| **Silent** | Nothing for 15 minutes. A silent feed looks identical to clean traffic on a dashboard, which is why it alerts. |
| **Credential rejected** | The token did not authenticate — rotate it and update the vendor |
| **Schema drift** | The vendor is sending fields we do not recognise. Ingestion continues and the new fields are preserved. |

### Events are searchable

**Search** with a time range covering the last hour. Events are searchable within 60
seconds of acceptance.

### Correlation is working

**Dashboards** shows vendors per record. If every record has exactly one vendor,
nothing is joining. The usual causes, in order of likelihood:

1. **Clock skew.** The vendors' timestamps disagree by more than the correlation
   window (5s by default). Check **Admin → Correlation** and widen it, or fix NTP.
2. **A missing host.** Most often F5 — see above.
3. **Different traffic.** The feeds genuinely cover different hostnames or zones.
4. **One feed only sends blocks.** Most often DataDome — see above.

---

## Rotating a token

```bash
curl -sS -X PATCH https://<api-host>/api/v1/feeds/<feed-id> \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"credential":"<new-token>"}'
```

The new token takes effect immediately, so update the vendor first or accept a short
window of rejected deliveries. Rejected deliveries are **not** lost data: the platform
returns a non-2xx and every vendor retries.

---

## What the responses mean

| Status | Meaning | What the vendor should do |
|---|---|---|
| `202` | Accepted and durably committed | Nothing — the events are safe |
| `400` | Malformed payload | Fix the format; retrying will not help |
| `401` | Bad or missing token | Fix the credential |
| `413` | Batch too large | Send smaller batches |
| `429` | Quota exceeded | Back off; `Retry-After` says how long |
| `503` | The platform cannot durably accept right now | **Retry.** The events were not stored. |

The `202`/`503` distinction is the core of the ingest contract. A `202` is only
returned after the events are committed to the broker — never before — so a `202` is a
promise and a `503` is an honest refusal. Any vendor integration that treats `503` as a
permanent failure will lose data that the platform deliberately did not accept.
