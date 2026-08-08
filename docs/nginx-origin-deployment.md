# Connecting the nginx origin

Shipping nginx access logs from the origin server so a correlated request shows its
**whole** path, end to end.

```
Client ──> Cloudflare ──> DataDome (CF Worker) ──> F5 BIG-IP ──> nginx ──> app
```

The first three decide whether a request may proceed. nginx is what it proceeds *to*,
and that difference shapes everything below: nginx is not a fourth opinion about whether
the request should have been allowed, it is the evidence that it cleared every gate and
what the application actually returned.

---

## What this gets you

Without the origin feed, a correlated record ends at F5. You can see that Cloudflare
allowed a request, DataDome device-checked it and F5 passed it — and then nothing. You
cannot tell whether it reached the application at all, how long the origin took, or what
it answered.

With it, one record carries all four hops, and three questions become answerable:

| Question | Answered by |
|---|---|
| Did this request actually reach the app, or die between F5 and the origin? | presence of the nginx event |
| Was a slow request slow at the edge or at the origin? | `request_time`, `upstream_response_time` |
| Did the app return an error for a request every WAF allowed? | `status`, `upstream_status` |

---

## How the join works, and the one thing it depends on

Cloudflare stamps `CF-Ray` on the request it sends to the origin. F5 passes that header
through, so **nginx sees exactly the identifier F5 keys on** — the origin fetch's ray.
The nginx event therefore lands in the group F5 is already in, and reaches Cloudflare
and DataDome through the bridge the origin-fetch row provides. No new correlation
machinery, no time window, no heuristic.

**Everything below depends on `CF-Ray` surviving the BIG-IP.** If your Logging Profile,
an iRule, or a request-header policy strips or rewrites it, `$http_cf_ray` will be empty
and nginx events will only join by the heuristic IP/host/path/time match — the tier that
carries all of the false-join risk.

Verify before you trust it — see [Confirming the join](#confirming-the-join).

---

## Before you start

Create the feed and capture its id and token. The token is shown **once** — it is stored
as a reference into the secret manager, not as a value, so it can only be rotated, never
recovered.

```bash
curl -sS -X POST https://<api-host>/api/v1/feeds \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"vendor":"VENDOR_NGINX","name":"origin nginx","deliveryMode":"DELIVERY_MODE_PUSH"}'
```

Or **Administration → Feeds → New feed**, vendor **nginx (origin)**.

You will need:

- `SIEM_INGEST_URL` — `https://<ingest-host>/ingest/v1/nginx/<feed-id>`
- `SIEM_FEED_TOKEN` — the token from feed creation

---

## Step 1 — the nginx log format

The default `combined` format is not usable here, and no amount of parsing fixes it. The
two fields correlation depends on are simply absent:

| Field | Why it cannot be omitted |
|---|---|
| `$http_cf_ray` | the join key. Without it there is no exact join. |
| `$http_cf_connecting_ip` | the real client. `$remote_addr` is the **BIG-IP** on every single request. |

Copy [`deploy/nginx-origin/log_format.conf`](../deploy/nginx-origin/log_format.conf) to
the origin and include it from the `http` block:

```nginx
http {
    include /etc/nginx/conf.d/siem_log_format.conf;
    ...
}
```

Then add the log to each server you want correlated:

```nginx
server {
    server_name www.jobs.bg;

    access_log /var/log/nginx/access.log combined;   # keep whatever you already had
    access_log /var/log/nginx/siem.log    siem;      # additional, for the SIEM
    ...
}
```

This is an **additional** log, not a replacement. Anything else consuming your existing
access log keeps working.

### Two details that are not cosmetic

**`escape=json` is mandatory.** A user agent or URI containing a quote or a backslash
would otherwise produce a line that is not valid JSON — and an attacker controls both.
The adapter refuses a line it cannot parse, so a missing `escape=json` shows up as a
steady trickle of dead-lettered events.

**JSON rather than a text layout, deliberately.** The adapter rejects a plain-text
access line rather than guessing at field positions. A visible dead-letter is a
misconfiguration you can find and fix; a guessed layout silently produces events with
the wrong values in the wrong fields.

Apply it:

```bash
nginx -t && systemctl reload nginx
head -1 /var/log/nginx/siem.log | jq .   # must print an object, not an error
```

If `jq` fails here, stop and fix it — nothing downstream will work.

---

## Step 2 — ship the log

### Why not Filebeat

Filebeat's outputs are Elasticsearch, Logstash, Kafka, Redis, file and console. There is
**no generic HTTP output**, and the ingest endpoint is a plain authenticated POST. So
Filebeat cannot deliver here on its own; it needs Logstash in between, which is a second
JVM service to run, tune and monitor for a job one static binary already does.

If Filebeat is required for fleet-management reasons, the bridge is
`Filebeat → Logstash → http output` pointed at the same URL with the same bearer token.

### Vector

[Vector](https://vector.dev) is a single static Rust binary with no runtime
dependencies, and it is already what the BIG-IP feed uses — same shipper, same auth
model, same disk-buffer behaviour, one less thing to reason about at three in the
morning.

Copy [`deploy/nginx-origin/vector.yaml`](../deploy/nginx-origin/vector.yaml) to the
origin host.

**Native package** (recommended on the origin — no container, no Docker socket):

```bash
curl --proto '=https' --tlsv1.2 -sSfL https://sh.vector.dev | bash
sudo install -m 0644 vector.yaml /etc/vector/vector.yaml
```

Credentials go in the unit environment, not the config file:

```bash
sudo systemctl edit vector
```

```ini
[Service]
Environment="SIEM_INGEST_URL=https://<ingest-host>/ingest/v1/nginx/<feed-id>"
Environment="SIEM_FEED_TOKEN=<token>"
```

```bash
sudo usermod -aG adm vector          # so it can read /var/log/nginx
sudo systemctl enable --now vector
sudo systemctl status vector
```

**Docker alternative**, if you would rather not install on the host:

```yaml
name: siem-nginx-collector
services:
  vector:
    image: timberio/vector:0.44.0-alpine
    restart: unless-stopped
    environment:
      SIEM_INGEST_URL: ${SIEM_INGEST_URL:?set SIEM_INGEST_URL in .env}
      SIEM_FEED_TOKEN: ${SIEM_FEED_TOKEN:?set SIEM_FEED_TOKEN in .env}
    volumes:
      - ./vector.yaml:/etc/vector/vector.yaml:ro
      - /var/log/nginx:/var/log/nginx:ro
      - vector-data:/var/lib/vector
volumes:
  vector-data:
```

### What the config does, and why

| Setting | Reason |
|---|---|
| `ignore_older_secs: 600` | On first start, read only recent lines. Replaying a rotated week would flood the correlator with events whose partners expired from window state long ago — they would all land as single-vendor records. |
| `fingerprint.strategy: checksum` | nginx rewrites the inode on rotation; Vector follows the file by content, not by inode. |
| `buffer.type: disk` | A SIEM restart or a network blip must not lose evidence, and the buffer has to survive Vector restarting too. |
| `when_full: block` | Back-pressure, not discard. Dropping the newest events silently loses the ones most likely to matter. |
| `retry_attempts: 10` | The platform answers `202` only once events are durably committed to the broker, and `503` when it cannot. Retrying a `503` is the platform explicitly asking to be asked again — lossless by design. |

---

## Step 3 — log rotation

Vector follows rotation by checksum, so `copytruncate` is **not** required and is worth
avoiding: it can truncate a file mid-line and produce a partial JSON record.

```
/var/log/nginx/siem.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        [ -f /var/run/nginx.pid ] && kill -USR1 $(cat /var/run/nginx.pid)
    endscript
}
```

`delaycompress` matters: compressing a file Vector has not finished reading loses the
tail of it.

---

## Confirming it works

### 1. Vector is delivering

```bash
journalctl -u vector -n 50 --no-pager
vector top --url http://127.0.0.1:8686/graphql   # if the API is enabled
```

A healthy sink shows events out and no errors. `401` means the token is wrong; `404`
means the feed id in the URL is wrong.

### 2. The feed is green

**Administration → Feeds** — the nginx feed should show recent activity and a rising
event count.

### 3. Events are searchable

**Search**, filter **Vendor = nginx (origin)**. You should see requests with the real
client address, not the BIG-IP's.

### Confirming the join

This is the check that actually matters. Run it against ClickHouse:

```sql
SELECT
  count()                                AS nginx_events,
  countIf(vendor_request_id = '')        AS missing_ray,
  round(100 * countIf(vendor_request_id = '') / count(), 1) AS pct_missing
FROM normalized_events
WHERE vendor = 'nginx' AND event_time >= now() - INTERVAL 15 MINUTE;
```

- **`pct_missing` near 0** — `CF-Ray` is arriving. Correlation will work.
- **`pct_missing` high** — the header is not reaching nginx. **The fix is on the BIG-IP,
  not here.** Check that no iRule or HTTP header policy strips or rewrites `CF-Ray` on
  the way to the pool. Until it is fixed, nginx events join only by the heuristic
  IP/host/path/time match, which is the tier carrying all the false-join risk.

Then confirm four-vendor records are forming:

```sql
SELECT arrayStringConcat(vendors, '+') AS v, count() AS n
FROM correlated_requests FINAL
WHERE window_start >= now() - INTERVAL 15 MINUTE
GROUP BY v ORDER BY n DESC LIMIT 10;
```

`cloudflare+datadome+f5+nginx` should appear within a few minutes.

---

## How nginx events are interpreted

### The verdict is always `allowed`

An nginx event only *exists* for a request every gate let through — Cloudflare, DataDome
and F5 each terminate a request they refuse, so it never reaches the origin and no line
is written. **The presence of the event is itself the evidence the request was allowed
all the way through.**

The response status is deliberately **not** mapped to a verdict. An application `403` is
an authorization decision about a user, a `404` is a missing page, a `429` may be
application rate limiting — none of them is a security vendor's judgement on the
request, and treating them as one would manufacture disagreements against vendors that
correctly allowed it. The status is recorded on its own field, where it means what it
says.

So: **nginx never appears in a disagreement.** If you want to find requests every WAF
allowed but the app rejected, filter on the status field, not on verdicts.

### The client address

`$remote_addr` is the BIG-IP on every request and is **never** used as the client.
Resolution order, mirroring the F5 adapter so the two agree about who the client is:

1. `CF-Connecting-IP` — Cloudflare *overwrites* this rather than appending, so it is
   unspoofable behind Cloudflare and matches Cloudflare's own logs by construction.
2. The `X-Forwarded-For` chain walked from the **right**, stopping at the first routable
   public address that is not the peer. The header is append-only, so its leftmost entry
   is attacker-controlled — on live F5 traffic 27.7% of events carried a forged address
   in reserved `240.0.0.0/4`.
3. **Nothing.** Unlike F5 there is no peer fallback: there the peer may genuinely be the
   client, here it is always the load balancer, and recording it would be worse than
   recording no address at all.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Events dead-lettered as unparseable | `escape=json` missing, or the text `combined` format is being shipped | fix `log_format`, reload nginx |
| `vendor_request_id` empty on most events | `CF-Ray` not surviving the BIG-IP | fix on the BIG-IP; see [Confirming the join](#confirming-the-join) |
| Client IP empty on most events | neither `CF-Connecting-IP` nor a usable `X-Forwarded-For` reaching the origin | confirm Cloudflare is in front and F5 forwards both headers |
| All events show one client address | `$remote_addr` is being logged into `cf_connecting_ip` | check the `log_format` field mapping |
| Vector reads nothing | permissions | `usermod -aG adm vector`, then restart |
| Flood of old events after install | `ignore_older_secs` removed or raised | restore it; the correlator cannot pair events whose partners have expired |
| `401` from the ingest endpoint | wrong or rotated token | rotate in **Feeds → Rotate token** and update the unit environment |
| nginx events never join | verdict/host mismatch, or events arriving outside the lateness bound | check `pct_missing` above first — it is nearly always the ray |

---

## Scope

- Only servers with `access_log ... siem;` are shipped. Add the directive per `server`
  block as you want each host correlated.
- Hosts DataDome does not protect will produce `cloudflare+f5+nginx` records rather than
  four-vendor ones. That is correct, not a fault.
- Requests Cloudflare serves from cache, redirects, or refuses never reach the origin, so
  they have no nginx event by definition.
