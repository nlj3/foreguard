-- Foreguard control plane schema.

-- One row per reporting Foreguard instance (a proxy/gateway deployment). Carries
-- the running head of its hash chain (last_seq / last_hash) so an ingest batch can
-- be linkage-verified against what we've already accepted, plus rolled-up counters
-- and the latest reported spend for the fleet view.
CREATE TABLE IF NOT EXISTS instances (
  id            TEXT PRIMARY KEY,
  last_seq      INTEGER NOT NULL DEFAULT -1,
  last_hash     TEXT    NOT NULL DEFAULT 'genesis',
  spent_cents   INTEGER NOT NULL DEFAULT 0,
  first_seen    INTEGER NOT NULL,
  last_seen     INTEGER NOT NULL,
  total         INTEGER NOT NULL DEFAULT 0,
  executed      INTEGER NOT NULL DEFAULT 0,
  dry_run       INTEGER NOT NULL DEFAULT 0,
  denied        INTEGER NOT NULL DEFAULT 0,
  policy_denied INTEGER NOT NULL DEFAULT 0,
  forwarded     INTEGER NOT NULL DEFAULT 0
);

-- Every ingested ledger entry, keyed by (instance, seq). Stores the integrity
-- envelope (hash/prev) alongside the queryable decision fields.
CREATE TABLE IF NOT EXISTS entries (
  instance TEXT    NOT NULL,
  seq      INTEGER NOT NULL,
  ts       INTEGER NOT NULL,
  tool     TEXT,
  kind     TEXT,
  risk     TEXT,
  decision TEXT,
  policy   TEXT,
  taint    TEXT,
  hash     TEXT    NOT NULL,
  prev     TEXT    NOT NULL,
  PRIMARY KEY (instance, seq)
);

CREATE INDEX IF NOT EXISTS idx_entries_instance_seq ON entries (instance, seq DESC);

-- The single central Cedar policy pushed to the fleet (id is pinned to 1).
CREATE TABLE IF NOT EXISTS policy (
  id      INTEGER PRIMARY KEY CHECK (id = 1),
  cedar   TEXT    NOT NULL,
  updated INTEGER NOT NULL
);
