# Feature Specification: Multi-Vendor WAF & Bot-Defense Log Correlation

**Feature Branch**: `001-waf-bot-log-correlation`

**Created**: 2026-08-06

**Status**: Draft

**Input**: User description: "I am building a app that should be able to receive logs from Cloudflare, F5 and DataDome and to make a correlation between them"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Receive and normalize logs from all three vendors (Priority: P1)

A platform operator connects the organization's Cloudflare, F5, and DataDome log feeds to the
platform. Each vendor sends events in its own format and on its own schedule. Within minutes of
connecting a feed, the operator sees a live count of events arriving from that vendor, can open
any single event, and sees both the vendor's original payload and a normalized view where the
same concept (client IP, request URL, HTTP method, verdict, rule/policy that fired, timestamp)
appears under the same field name regardless of which vendor sent it.

**Why this priority**: Nothing else in the product is possible without trustworthy, normalized
intake. On its own it already replaces three separate vendor consoles with one searchable place,
so it is a viable standalone MVP.

**Independent Test**: Connect one feed per vendor with sample traffic, confirm every event that
was sent is retrievable, that its raw payload is byte-identical to what the vendor sent, and that
the normalized fields are populated correctly for all three vendors.

**Acceptance Scenarios**:

1. **Given** a configured Cloudflare feed, **When** the vendor delivers a batch of events,
   **Then** every event is stored, retrievable by its event id, and counted in the feed's
   received-events metric.
2. **Given** a configured F5 feed, **When** an event arrives that omits an optional field,
   **Then** the event is still stored with the missing normalized field left empty, and it is not
   rejected.
3. **Given** a configured DataDome feed, **When** the same event is delivered twice due to a
   vendor retry, **Then** the platform stores it once and reports one duplicate suppressed.
4. **Given** an event that cannot be parsed, **When** it is received, **Then** it is preserved in
   a rejected-events area with a machine-readable reason and is never silently discarded.
5. **Given** any stored event from any vendor, **When** an operator opens it, **Then** both the
   original vendor payload and the normalized fields are shown side by side.

---

### User Story 2 - Correlate one request across vendors (Priority: P2)

A security analyst investigating suspicious traffic opens a single request and sees what every
vendor in the path concluded about it: Cloudflare's WAF verdict, F5's policy decision, and
DataDome's bot score — presented as one correlated timeline instead of three disconnected logs.
The analyst can immediately tell whether the vendors agreed, and where they disagreed.

**Why this priority**: This is the core differentiating value — the reason the three feeds are in
one system. It depends on Story 1 but is independently demonstrable once intake exists.

**Independent Test**: Replay a known traffic sample through all three vendor feeds and confirm
that events belonging to the same original client request are grouped into a single correlated
record, with a stated confidence, and that unrelated events are not grouped.

**Acceptance Scenarios**:

1. **Given** events from two or more vendors describing the same client request, **When**
   correlation runs, **Then** they are joined into one correlated request record listing each
   vendor's verdict.
2. **Given** vendors that observed the same request at slightly different times, **When**
   correlation runs, **Then** they are still joined provided the timestamps fall inside the
   configured correlation window.
3. **Given** two vendors that reached opposite verdicts on the same request (one allowed, one
   blocked), **When** the analyst views the correlated record, **Then** the record is explicitly
   flagged as a disagreement.
4. **Given** an event that matches no event from any other vendor, **When** correlation runs,
   **Then** it forms a single-vendor correlated record rather than being dropped.
5. **Given** a correlated record, **When** the analyst inspects it, **Then** the platform shows
   which signals were used to join the events and a confidence level for the join.

---

### User Story 3 - Search, investigate, and dashboard (Priority: P2)

An analyst searches across all vendors at once — by client IP, URL, verdict, rule or policy
identifier, bot score, country, or time range — and gets results fast enough to iterate during a
live incident. A dashboard shows traffic volume by vendor, block and challenge rates, top
triggering rules, top offending source IPs, and the current vendor-disagreement rate.

**Why this priority**: Correlation is only useful if analysts can reach it. Ranks alongside
Story 2 because either one alone is demonstrable, but the pair is what analysts actually use.

**Independent Test**: With a loaded dataset, run a set of representative searches and confirm
correct, complete, and time-bounded results, plus dashboard figures that reconcile with the
underlying event counts.

**Acceptance Scenarios**:

1. **Given** a populated dataset, **When** the analyst searches by client IP over a time range,
   **Then** matching events from all three vendors are returned together, newest first.
2. **Given** a search that would match an unbounded number of events, **When** it is submitted
   without a time range, **Then** the platform requires a time range instead of running the query.
3. **Given** a result set larger than one page, **When** the analyst pages through it, **Then**
   no event is skipped or repeated across pages.
4. **Given** a dashboard time range, **When** the analyst changes it, **Then** every panel
   updates consistently to that same range.
5. **Given** a search result, **When** the analyst exports it, **Then** the export is recorded in
   the audit trail with the actor, the query, and the row count.

---

### User Story 4 - Alert on correlated conditions (Priority: P3)

A security engineer defines rules that fire on cross-vendor conditions — for example "DataDome
scored this as a bot but Cloudflare allowed it, more than 50 times in 5 minutes from one source"
— and receives a notification with a direct link to the matching evidence.

**Why this priority**: High operational value, but it presupposes reliable correlation. Deferring
it keeps the earlier slices shippable.

**Independent Test**: Define a rule, replay traffic that satisfies it and traffic that does not,
and confirm the alert fires exactly once for the matching condition and not at all otherwise.

**Acceptance Scenarios**:

1. **Given** an enabled rule, **When** matching correlated activity occurs, **Then** an alert is
   raised with a link to the correlated records that triggered it.
2. **Given** a condition that persists, **When** the rule keeps matching, **Then** repeat alerts
   are suppressed for the configured cooldown rather than re-firing continuously.
3. **Given** a rule change, **When** it is saved, **Then** the change is written to the audit
   trail with the actor and the previous rule content.
4. **Given** an alert, **When** an analyst acknowledges or resolves it, **Then** the state change
   and the actor are recorded.

---

### Edge Cases

- A vendor stops sending (feed goes silent) — the platform must detect the gap and warn, rather
  than showing a quiet dashboard that looks like clean traffic.
- A vendor sends a burst far above normal rate — intake must apply backpressure and shed to
  retry, never drop accepted events or exhaust storage without warning.
- Vendor clocks disagree, or an event arrives out of order or hours late — correlation must
  handle late arrivals up to a stated lateness bound and state what happens beyond it.
- A vendor changes its log schema without notice — unknown fields must be preserved, and a schema
  drift warning raised, rather than the whole feed failing.
- The client IP is shared (NAT, proxy chain, mobile carrier), making IP-based correlation
  ambiguous — the join must express reduced confidence rather than assert a false match.
- Only one vendor sits in front of a given hostname — records with a single vendor must be normal,
  not treated as errors.
- Log payloads contain attacker-controlled strings — rendering them in the UI must never execute
  them.
- Personal data appears in a log field (headers, query strings) — retention and redaction rules
  must apply.
- A feed's credentials expire — the failure must surface as an actionable feed-health error.

## Requirements *(mandatory)*

### Functional Requirements

**Ingestion**

- **FR-001**: System MUST accept log events from Cloudflare, F5, and DataDome, each configured as
  an independently enabled, independently credentialed feed.
- **FR-002**: System MUST support both vendor-push delivery and platform-initiated pull for each
  feed, so that a vendor that cannot push can still be onboarded.
- **FR-003**: System MUST acknowledge an event only after it is durably stored; an acknowledged
  event MUST NOT be lost.
- **FR-004**: System MUST deduplicate re-delivered events using a stable per-vendor event
  identity, and MUST report the count of suppressed duplicates per feed.
- **FR-005**: System MUST preserve every event's original vendor payload unmodified alongside its
  normalized form.
- **FR-006**: System MUST route unparseable or over-quota events to a rejected-events store with a
  machine-readable reason, and MUST expose the rejected count per feed.
- **FR-007**: System MUST enforce per-feed rate limits and quotas, and MUST respond to excess
  volume with an explicit retryable signal rather than unbounded buffering.
- **FR-008**: System MUST report per-feed health: last event received, current rate, ingest lag,
  rejection rate, and credential validity.

**Normalization**

- **FR-009**: System MUST map every vendor's events onto one common event model covering at
  minimum: event time, receipt time, vendor, account/zone/tenant, client IP, client geo, request
  host, path, method, user agent, HTTP status, vendor verdict (allowed / blocked / challenged /
  rate-limited / monitored), verdict reason or rule identifier, bot or threat score, and any
  vendor-supplied request or trace identifier.
- **FR-010**: System MUST preserve vendor-specific fields that have no common-model equivalent,
  without discarding them.
- **FR-011**: System MUST record all event times in a single normalized time zone while retaining
  the vendor's original time value.
- **FR-012**: System MUST detect unrecognized incoming fields and raise a schema-drift warning
  without failing the feed.

**Correlation**

- **FR-013**: System MUST join events from different vendors that describe the same client
  request into one correlated request record.
- **FR-014**: System MUST perform joins using a ranked set of signals — an exact shared request or
  trace identifier where any vendor provides one, otherwise the combination of client IP, request
  host, path, method, and closeness in time within a configurable correlation window (default 5
  seconds).
- **FR-015**: System MUST attach a confidence level to every join and MUST record which signals
  produced it.
- **FR-016**: System MUST create a valid single-vendor correlated record when no counterpart
  exists, rather than discarding the event.
- **FR-017**: System MUST flag a correlated record as a disagreement when the participating
  vendors reached conflicting verdicts, and MUST make disagreements searchable as a category.
- **FR-018**: System MUST handle late-arriving events up to a configurable lateness bound (default
  15 minutes) by amending the existing correlated record instead of creating a duplicate.
- **FR-019**: System MUST make correlated records available for search within 60 seconds of the
  last contributing event being ingested, under normal load.
- **FR-020**: System MUST allow an operator to view, and an administrator to tune, the correlation
  window, the lateness bound, and the signal ranking.
- **FR-021**: System MUST limit correlation to the per-request level in this release. Entity-level
  behavioral correlation (aggregating a client IP, ASN, or device/bot fingerprint's activity over
  time) is explicitly out of scope; the common event model MUST nonetheless carry the identifiers
  such correlation would need, so it can be added later without reshaping stored data.

**Search, dashboards, and UI**

- **FR-022**: Users MUST be able to search across all vendors simultaneously by client IP, host,
  path, verdict, rule/policy identifier, score threshold, country, ASN, user agent, and free text.
- **FR-023**: System MUST require an explicit time range on every query, MUST cap result size,
  MUST apply a server-side timeout, and MUST paginate results without gaps or repeats.
- **FR-024**: Users MUST be able to open any correlated record and see each vendor's contribution,
  the join signals, the join confidence, and the raw payloads.
- **FR-025**: System MUST provide dashboards showing per-vendor volume, verdict mix, block and
  challenge rates, top rules, top source IPs and countries, vendor-disagreement rate, and feed
  health, all filtered by a shared time range.
- **FR-026**: Users MUST be able to export a result set in a machine-readable format, subject to a
  row cap and permission check.
- **FR-027**: System MUST render all log-derived content as inert text so that attacker-supplied
  strings cannot execute in the browser.

**Alerting**

- **FR-028**: Users MUST be able to define alert rules over correlated data, including thresholds,
  time windows, group-by dimensions, and vendor-disagreement conditions.
- **FR-029**: System MUST evaluate rules continuously and raise alerts that link back to the
  triggering evidence.
- **FR-030**: System MUST suppress repeat alerts for an ongoing condition for a configurable
  cooldown period.
- **FR-031**: Users MUST be able to acknowledge and resolve alerts, and the system MUST record the
  actor and time of each state change.
- **FR-032**: System MUST deliver alert notifications to a customer-configured generic outbound
  webhook, sending a structured payload that contains the rule, severity, trigger time, grouping
  values, and a link to the triggering evidence. Email, chat, and ticketing integrations are out of
  scope for this release.
- **FR-032a**: System MUST retry failed webhook deliveries with backoff, MUST surface per-rule
  delivery failures in the console, and MUST NOT drop an alert because its notification failed.

**Access control, tenancy, retention, and audit**

- **FR-033**: System MUST scope every event, correlated record, dashboard, search, alert, and
  export to a tenant, and MUST prevent any cross-tenant access.
- **FR-034**: System MUST enforce deny-by-default roles: Administrator (full configuration),
  Analyst (search, dashboards, alert triage), Auditor (read-only including audit trail), and
  Ingest-Only (feed delivery credentials, no console access).
- **FR-035**: System MUST record an append-only, tamper-evident audit entry for every login, role
  change, feed change, correlation-setting change, alert-rule change, export, and data purge.
- **FR-036**: System MUST apply a configurable per-tenant retention period to raw events,
  correlated records, and alerts independently, and MUST delete data automatically once the period
  expires.
- **FR-037**: System MUST allow designated sensitive fields to be redacted or masked at ingest so
  they are never stored in readable form.

### Key Entities

- **Feed**: A configured connection to one vendor for one tenant. Holds delivery mode,
  credentials, enabled state, quota, and current health.
- **Raw Event**: The vendor's payload exactly as received, plus receipt time, feed reference,
  tenant, and a stable event id. Immutable and append-only.
- **Normalized Event**: The common-model projection of a raw event. Links back to its raw event
  and forward to its correlated record.
- **Correlated Request**: One client request as observed by one or more vendors. Holds the
  participating normalized events, the join signals used, a confidence level, a combined outcome,
  and a disagreement flag.
- **Alert Rule**: A named, tenant-scoped condition over correlated data, with threshold, window,
  grouping, cooldown, and webhook destination.
- **Alert**: A firing of a rule, with triggering evidence, severity, state (new / acknowledged /
  resolved), and state history.
- **Audit Entry**: An immutable record of a privileged action: actor, action, target, before and
  after values, time, and source address.
- **Tenant**: The isolation boundary owning all of the above, with its own retention and redaction
  policy.
- **User & Role**: An authenticated principal and its deny-by-default permission set within a
  tenant.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of events acknowledged by the platform are retrievable afterwards; zero
  acknowledged-then-lost events across a sustained 24-hour load test.
- **SC-002**: The platform sustains 5,000 events per second of combined vendor traffic, with peaks
  of 15,000 events per second for 5 minutes, without rejecting valid events.
- **SC-003**: A newly ingested event is searchable within 60 seconds of receipt, at the 95th
  percentile, under sustained load.
- **SC-004**: For traffic passing through two or more vendors, at least 95% of requests are
  correctly joined into a single correlated record, with a false-join rate below 1%, measured
  against a labelled replay dataset.
- **SC-005**: 95% of analyst searches over a 24-hour range return their first page of results in
  under 3 seconds.
- **SC-006**: An analyst can go from an alert notification to the underlying cross-vendor evidence
  in 3 interactions or fewer.
- **SC-007**: An operator can connect a new vendor feed and confirm events arriving in under 15
  minutes without engineering assistance.
- **SC-008**: 100% of privileged actions appear in the audit trail, verified by a quarterly
  sampling review.
- **SC-009**: Zero cross-tenant data exposures, verified by automated isolation tests on every
  release.
- **SC-010**: 100% of data past its retention period is deleted within 24 hours of expiry.
- **SC-011**: Time to identify which vendor blocked or missed a given request drops from consulting
  three separate consoles to one search, cutting investigation time by at least 60% against a
  measured baseline.

## Assumptions

- **Vendor roles**: Cloudflare and F5 act as WAF/CDN/edge enforcement; DataDome acts as bot
  detection. All three may observe the same request, and any subset may be deployed for a given
  hostname.
- **Vendor delivery**: Each vendor can deliver logs by push to a receiving endpoint or by making
  them retrievable from an object store or API. Vendor-side configuration is the customer's
  responsibility; the platform documents what to configure.
- **Analysis, not enforcement**: The first release observes and correlates only. It does not push
  blocks, rules, or feedback back to Cloudflare, F5, or DataDome. Vendor-side enforcement remains
  configured in the vendor consoles.
- **Not a replacement for vendor consoles**: Vendor-native configuration and policy authoring stay
  in the vendor products.
- **Per-request correlation only**: This release joins events describing the same client request.
  Behavioral or entity-level correlation over time is a planned follow-up, not part of v1.
- **Webhook-only notifications**: Alert delivery is a generic outbound webhook. Customers bridge it
  to email, chat, or ticketing on their side; native integrations come later.
- **Volume and retention**: Default retention is 30 days for raw events, 90 days for correlated
  records, and 1 year for alerts and audit entries — all tenant-configurable.
- **Time**: Vendors deliver reasonably accurate timestamps; clock skew up to a few seconds is
  expected and absorbed by the correlation window.
- **Deployment**: A hosted, multi-tenant web application with a browser-based console; no mobile
  app in the first release.
- **Users**: Security analysts, security engineers, and platform operators — technical users
  familiar with WAF and bot-management concepts.
- **Identity**: Standard username/password with multi-factor authentication, with enterprise SSO
  as a later addition.
- **Additional vendors**: Only Cloudflare, F5, and DataDome are in scope, but normalization is
  designed so a fourth vendor can be added without reworking the common model.
