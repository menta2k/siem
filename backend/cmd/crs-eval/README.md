# crs-eval — what OWASP rule actually matched

Cloudflare's OWASP managed ruleset reports the decision and not the reasoning. A blocked
request comes back as

    949110: Inbound Anomaly Score Exceeded

which says a score crossed a threshold, and never says which rules built the score. That is
the one thing you need in order to decide whether the block was right, whether to raise the
threshold, or which single rule to exclude.

`949110` is CRS's own rule number, because Cloudflare's OWASP ruleset *is* the OWASP Core
Rule Set. So the contributors can be recovered by running the same rule set locally against
the request the platform already stored. That is all this is: real CRS, via
[Coraza](https://github.com/corazawaf/coraza), against the request as F5 logged it.

    $ crs-eval -threshold 40 < payload.log
    POST /js_file.php?subm=1&ajax=1
    paranoia level 1, threshold 40, 12 headers, 169 of 90000 body bytes captured

    score 20 of 40 — would NOT be blocked

    +5  942100  attack-sqli      SQL Injection Attack Detected via libinjection
    +5  942190  attack-sqli      Detects MSSQL code execution and information gathering
    +5  942270  attack-sqli      Looking for basic sql injection
    +5  942360  attack-sqli      Detects concatenated basic SQL injection and SQLLFI
        949110                   Inbound Anomaly Score Exceeded (Total Score: 20)

    note: only 169 of the 90000 body bytes the request declared were captured, so the body
    rules were barely evaluated — the edge saw the rest

Input is an F5 syslog payload (the same bytes `raw_events.payload` holds), or the HTTP
request on its own with `-raw`.

## Matching your Cloudflare settings

Two knobs decide what CRS says, and Cloudflare exposes both:

| Cloudflare setting | flag | note |
| --- | --- | --- |
| Paranoia level PL1–PL4 | `-pl` | higher levels add rules and false positives |
| Score threshold Low / Medium / High | `-threshold 60 / 40 / 25` | CRS's own default is 5 |

The **rule identities transfer exactly** — a 942100 here is a 942100 there. The **numbers do
not, quite**: Cloudflare assigns its own per-rule scores, which is why their thresholds are
in the tens while CRS's default is 5. Read the rule list as the answer and the score as an
indication of how close the decision was.

## What it cannot tell you, and why that matters here

F5 logs a bounded prefix of the request — roughly 2 KB on this deployment. For a multipart
upload declaring 130 KB, the transcript holds the form fields and the first fragment of the
file, and nothing else.

That is not a footnote for this traffic; it is the main event. Every correlated request where
Cloudflare's OWASP ruleset fired on this deployment is a POST to an upload endpoint, and
running those through this tool scores **0 out of 40 with no rule matched** — while
Cloudflare, which saw all 130 KB, scored them over the line. The rules that decided are in
the bytes F5 did not keep, and the most likely explanation is that CRS is scoring the binary
content of ordinary JPEG uploads: a very well known source of OWASP false positives.

So:

- **URI, headers, cookies, and form fields**: answered properly.
- **File uploads**: answered only for the surviving prefix. A clean result is not a clean
  request, which is why every result prints how many of the declared body bytes it actually
  had.

The tool never hides this. A miss on a truncated body is reported as unanswered, not as a
pass.

## Details worth knowing

- The engine runs in **detection mode** even though the question is about blocking. In
  blocking mode the first disruptive rule ends the transaction and every later phase is
  skipped, so you would be shown one rule out of the several that matched. "Would block" is
  derived from the score instead.
- Rules 200002–200004 fire because of how the request was *captured* (a body cut off
  mid-multipart), not because of the request. They are marked as artifacts.
- Loading CRS parses several thousand rules and takes about a second; `crs.Engine` is built
  once and is safe to share across goroutines.

## If this graduates

The obvious next step is wiring `internal/crs` into the WAF migration pages: for any
correlated request where Cloudflare reported 949110, show the contributing rules inline —
the same way the wirefilter tester answers "would this expression catch these". The
F5-escaping decode is duplicated from `internal/wirefilter` on purpose so the PoC could not
break the working path; that is the first thing to share.
