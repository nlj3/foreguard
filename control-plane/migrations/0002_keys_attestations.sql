-- Per-instance API keys: each reporting instance authenticates with its own key,
-- so a leak is scoped to one instance and can be revoked without disturbing the rest.
-- We store only the SHA-256 of the key; the key itself is shown once at issue time.
CREATE TABLE IF NOT EXISTS instance_keys (
  key_hash TEXT PRIMARY KEY,   -- sha-256 hex of the API key
  instance TEXT    NOT NULL,
  created  INTEGER NOT NULL,
  revoked  INTEGER             -- NULL = active; timestamp = revoked
);

CREATE INDEX IF NOT EXISTS idx_keys_instance ON instance_keys (instance);

-- Signed head attestations: an instance signs its current ledger head with an
-- Ed25519 key it holds, so the audit trail is non-repudiable and a control-plane-side
-- rewrite is detectable (the operator can't forge a valid signature). The public key
-- is pinned on first sight (trust-on-first-use); `seq` must never roll back.
CREATE TABLE IF NOT EXISTS attestations (
  instance TEXT PRIMARY KEY,
  pubkey   TEXT    NOT NULL,   -- base64 Ed25519 public key (pinned)
  seq      INTEGER NOT NULL,   -- the attested head sequence
  hash     TEXT    NOT NULL,   -- the attested head hash
  sig      TEXT    NOT NULL,   -- base64 Ed25519 signature over the canonical head
  at       INTEGER NOT NULL
);
