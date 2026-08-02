/** Runtime bindings. `wrangler types` generates the authoritative version; this
 * mirrors it for a project with one D1 database and two secrets. */
export interface Env {
  DB: D1Database;
  /** Bearer token instances present to ingest and to pull the policy. */
  INGEST_TOKEN: string;
  /** Bearer token required to push policy and read the fleet/audit APIs. */
  ADMIN_TOKEN: string;
}

/** One row of the `instances` table — a reporting Foreguard deployment. */
export interface InstanceRow {
  id: string;
  last_seq: number;
  last_hash: string;
  spent_cents: number;
  first_seen: number;
  last_seen: number;
  total: number;
  executed: number;
  dry_run: number;
  denied: number;
  policy_denied: number;
  forwarded: number;
}

/** A stored ledger entry (the queryable fields plus its integrity envelope). */
export interface StoredEntry {
  instance: string;
  seq: number;
  ts: number;
  tool: string | null;
  kind: string | null;
  risk: string | null;
  decision: string | null;
  policy: string | null;
  taint: string | null;
  hash: string;
  prev: string;
}

/** The central Cedar policy row. */
export interface PolicyRow {
  cedar: string;
  updated: number;
}

/** A resolved API key: which instance it authenticates, and whether it's revoked. */
export interface KeyRow {
  instance: string;
  revoked: number | null;
}

/** A signed head attestation: the instance's pinned pubkey and its latest signed head. */
export interface AttestationRow {
  instance: string;
  pubkey: string;
  seq: number;
  hash: string;
  sig: string;
  at: number;
}
