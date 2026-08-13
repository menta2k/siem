-- One-time account setup invitations.
--
-- A user created by an admin has no usable password: the admin never learns one, so
-- the audit trail can always tell the two of them apart. The invite is what turns that
-- unusable account into a usable one, exactly once.
--
-- ORDER BY (tenant_id, user_id) with ReplacingMergeTree gives the property the flow
-- needs for free: a user has AT MOST ONE live invite, and re-issuing supersedes the
-- previous row rather than leaving two valid tokens in circulation. Redemption writes
-- a further version with redeemed_at set, which is what makes the token one-time.
CREATE TABLE IF NOT EXISTS user_invites
(
    tenant_id   UUID,
    user_id     UUID,

    -- Hex SHA-256 of the token's secret half. The token itself is NEVER stored: it is
    -- returned once, at issuance, and is unrecoverable afterwards. SHA-256 rather than
    -- argon2id because the secret is 256 bits of CSPRNG output — there is no dictionary
    -- to mount against it, and the hash must be deterministic to be comparable.
    token_hash  String,

    -- Denormalised so the pre-login redemption path can name the account being set up
    -- without a second read against a table it has no tenant context for.
    email       String,

    -- The admin who issued it. Nullable because an invite may be issued by the seed
    -- path, which has no authenticated actor.
    issued_by   Nullable(UUID),
    issued_at   DateTime64(3, 'UTC') DEFAULT now64(3),
    expires_at  DateTime64(3, 'UTC'),

    -- Set when the token is spent. A non-null value makes every later presentation of
    -- the same token a replay, and it is checked BEFORE the password is written.
    redeemed_at Nullable(DateTime64(3, 'UTC')),

    version     UInt64
)
ENGINE = ReplacingMergeTree(version)
ORDER BY (tenant_id, user_id);
