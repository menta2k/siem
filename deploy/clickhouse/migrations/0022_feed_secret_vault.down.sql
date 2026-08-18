-- Dropping this leaves the credentials in Redis alone, which is where they are read from.
-- It also restores the failure this table exists to prevent.
DROP TABLE IF EXISTS feed_secrets
