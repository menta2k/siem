# Grafana dashboards

Provisioned into the Compose stack under the `observability` profile:

```bash
docker compose --profile observability up -d
```

| File | Panels | Added by |
|------|--------|----------|
| `ingest.json` | events/sec by vendor, ingest lag, reject rate, duplicates suppressed, feed silence | _not yet written_ — T072 delivered `internal/ingest/metrics.go` and the Prometheus alert rules, not a dashboard |
| `correlation.json` | join tier mix, single-vendor share, confidence mix, vendors per record, amendment rate, late-arrival drops, window size, close failures | T092 |
| `query.json` | search p50/p95/p99, rows scanned, timeout rate, export volume | T114 |
| `alerting.json` | rules evaluated, alerts fired vs suppressed, webhook delivery failures | T131 |

Metric names are defined alongside the code that emits them; see
`backend/internal/*/metrics.go`. Alert rules for the same signals live in
`deploy/prometheus/alerts.yml`.
