-- Dropping this strands every account still in the `invited` state: their setup tokens
-- become unredeemable and an admin has to set a password for them directly.
DROP TABLE IF EXISTS user_invites
