-- A durable home for feed credentials, so a cache restart cannot take the platform down.
--
-- What happened: Redis holds the feed credentials, and Redis is deliberately configured
-- with no persistence -- documented as safe because "nothing here is a store of record".
-- That was true of everything except these. One restart wiped all four feeds' credentials,
-- every delivery failed authentication, and ingestion stopped dead for two hours.
--
-- The package rule that kept them out of here is a good rule: a credential written to the
-- analytical store would sit beside the customer's logs, share their retention, and be
-- readable from every query path. What is written here is CIPHERTEXT, sealed with
-- AES-256-GCM under a key held in the service environment, which ClickHouse cannot read.
-- None of the three harms survive that, and the alternative -- the only copy living in a
-- cache that is designed to be thrown away -- has now been measured against production.
--
-- Redis stays as the read path. This is the copy it is refilled from.
--
-- NO TTL, deliberately, where every other table here has one. A credential is not
-- observability data: it must outlive the logs it authenticates, and a feed that delivers
-- once a quarter must still be able to.
CREATE TABLE IF NOT EXISTS feed_secrets
(
    -- The opaque reference the feeds table stores. It encodes a purpose and a random id
    -- and nothing about the tenant or the feed, so this table cannot be used to map out
    -- who owns what.
    ref         String,
    -- Base64 of nonce + AES-256-GCM ciphertext. Useless without the key.
    sealed      String,
    purpose     LowCardinality(String),
    updated_at  DateTime64(3, 'UTC') DEFAULT now64(3),
    -- A tombstone rather than a delete: mutations are expensive and asynchronous, and a
    -- rotated credential has to stop resolving at a predictable moment.
    deleted     Bool DEFAULT false,
    -- Monotonic, so a rotation always wins over the value it replaces regardless of the
    -- order two replicas' parts merge in.
    version     UInt64
)
ENGINE = ReplacingMergeTree(version)
ORDER BY ref
