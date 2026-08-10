-- What a Cloudflare rule id MEANS.
--
-- Logpush reports the rule that matched as an opaque identifier -- a bare uuid with no
-- name, no category and no description. An analyst reading a blocked request therefore
-- learns that "a rule" fired, which is the one thing they could already tell from the
-- verdict. The names live in Cloudflare's ruleset API, and this table is where the
-- refresh worker puts them so the console can say "SQLi - Body detection" instead.
--
-- TENANT-SCOPED, unlike asn_owners. Who owns AS8866 is a fact about the internet. Which
-- WAF rules exist and what they are called is the CUSTOMER'S configuration, read with
-- their API token, and it must never be visible to another tenant.
--
-- NOTE: no semicolon may appear in these comments. The migration runner splits the file
-- on it, and a comment containing one produces an empty statement and a failed migration.
--
-- Keyed by zone as well as rule, because a rule id is only unique within its ruleset and
-- the same managed rule is deployed to many zones. The events carry ZoneName, which is
-- what the lookup joins on.
CREATE TABLE IF NOT EXISTS cloudflare_rules
(
    tenant_id    UUID,
    -- The zone's name as it appears in the events, e.g. "example.com". Matched against
    -- vendor_account, which is where the Cloudflare adapter stores ZoneName.
    zone_name    LowCardinality(String),
    zone_id      String,
    rule_id      String,
    -- The ruleset the rule belongs to, kept so an analyst can tell a managed WAF hit
    -- from a custom rule of their own without leaving the page.
    ruleset_id   String,
    ruleset_name String,
    ruleset_kind LowCardinality(String),
    -- The human-readable name. This is the entire point of the table.
    description  String,
    -- What the rule does when it matches. Recorded because a rule can be changed from
    -- log to block without changing its id, and an old event should not be re-labelled
    -- by a description fetched today -- see the note on staleness in the resolver.
    action       LowCardinality(String),
    -- Cloudflare's own reference for a managed rule, and its categories. Both are absent
    -- on custom rules, which have only what the customer typed.
    ref          String DEFAULT '',
    categories   Array(String) DEFAULT [],
    updated_at   DateTime('UTC')
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (tenant_id, zone_name, rule_id)
-- No TTL. The table is a snapshot wholly replaced on each refresh, not a log that
-- accumulates. Expiring rows by age would empty it exactly when a refresh has been
-- failing for a while, which is when the last good copy matters most.
SETTINGS index_granularity = 8192;

-- The API token the refresh worker reads rules with, held BY REFERENCE.
--
-- The token itself never reaches this table, or any other. It goes to the secret store
-- and only the reference is persisted, exactly as feed credentials are: a database
-- backup, a query log or a support export must not be able to leak a credential that
-- can read a customer's WAF configuration.
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS cloudflare_token_ref String DEFAULT '' AFTER redacted_fields;
