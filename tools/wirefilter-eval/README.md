# wirefilter-eval

Evaluates candidate Cloudflare rule expressions against captured requests, using
Cloudflare's own expression engine.

Stage 1 of the WAF migration asks an operator to write a Cloudflare rule that would catch
the requests F5 blocked. Until this existed, the only way to find out whether it does was to
deploy it in log mode and wait — and a mistake cost a day: one production rule differed from
a working one by a single backslash (`\\.` reaching the regex engine as a literal backslash)
and matched nothing while looking correct.

## API

`POST /evaluate`

```json
{
  "expression": "http.request.uri.path eq \"/js_file.php\" and http.request.method eq \"POST\"",
  "requests": [
    {
      "id": "event-id",
      "fields": { "http.request.uri.path": "/js_file.php", "http.request.method": "POST" },
      "fields_base64": { "http.request.body.raw": "..." },
      "body_truncated": true
    }
  ]
}
```

```json
{ "valid": true, "results": [ { "id": "event-id", "matched": true } ] }
```

A broken expression is an ANSWER, not a transport error: the reply is `200` with
`valid: false` and the parser's own message, because the caller asked whether the expression
works and that is what it found out.

`GET /healthz` reports liveness and the fields an expression may use.

## What it will not answer

- **Fields the platform cannot reconstruct.** Bot scores, JA4 signals, threat scores and the
  rest are computed at Cloudflare's edge and are not in a stored request. An expression using
  one is refused **by name** rather than answered — a confident "no match" would be a lie an
  operator would act on.
- **Truncated bodies.** F5 logs a bounded prefix of the request, so a body expression that
  misses may be missing on the evidence rather than on the request. Those misses carry a
  caveat; matches do not, because a match found in the prefix is a match at the edge.

## Engine version

Pinned to a wirefilter **commit**, not a branch, and not to the published `0.6.1` crate —
that release cannot parse raw strings, so it would reject `matches r"\.(swf|htm|gz)$"`, a
form real rules are written in. A tester that reports "parse error" for a rule running in
production is worse than no tester.
