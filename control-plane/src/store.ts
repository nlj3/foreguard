import type { InstanceRow, StoredEntry, PolicyRow, KeyRow, AttestationRow } from "./types.js";

/**
 * Persistence for the control plane, behind a narrow interface so the request
 * handler can be tested against an in-memory store (see `test/mem-store.ts`) while
 * production uses D1. Keeping the surface this small is what makes the whole handler
 * exercisable offline.
 */
export interface Store {
  getInstance(id: string): Promise<InstanceRow | null>;
  /** Atomically upsert the instance head/counters and append its new entries. */
  commitIngest(row: InstanceRow, entries: StoredEntry[]): Promise<void>;
  recentEntries(instance: string, limit: number): Promise<StoredEntry[]>;
  fleet(): Promise<InstanceRow[]>;
  getPolicy(): Promise<PolicyRow | null>;
  setPolicy(cedar: string, updated: number): Promise<void>;

  /** Register a new API key (stored by hash) for an instance. */
  createKey(instance: string, keyHash: string, now: number): Promise<void>;
  /** Resolve a key hash to its instance + revocation status, or null if unknown. */
  resolveKey(keyHash: string): Promise<KeyRow | null>;
  /** Revoke every active key for an instance; returns how many were revoked. */
  revokeInstance(instance: string, now: number): Promise<number>;

  getAttestation(instance: string): Promise<AttestationRow | null>;
  setAttestation(a: AttestationRow): Promise<void>;
}

/** D1-backed store for production. */
export class D1Store implements Store {
  constructor(private readonly db: D1Database) {}

  async getInstance(id: string): Promise<InstanceRow | null> {
    return await this.db
      .prepare(
        `SELECT id, last_seq, last_hash, spent_cents, first_seen, last_seen,
                total, executed, dry_run, denied, policy_denied, forwarded
         FROM instances WHERE id = ?`,
      )
      .bind(id)
      .first<InstanceRow>();
  }

  async commitIngest(row: InstanceRow, entries: StoredEntry[]): Promise<void> {
    const upsert = this.db
      .prepare(
        `INSERT OR REPLACE INTO instances
           (id, last_seq, last_hash, spent_cents, first_seen, last_seen,
            total, executed, dry_run, denied, policy_denied, forwarded)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        row.id,
        row.last_seq,
        row.last_hash,
        row.spent_cents,
        row.first_seen,
        row.last_seen,
        row.total,
        row.executed,
        row.dry_run,
        row.denied,
        row.policy_denied,
        row.forwarded,
      );

    const inserts = entries.map((e) =>
      this.db
        .prepare(
          `INSERT OR IGNORE INTO entries
             (instance, seq, ts, tool, kind, risk, decision, policy, taint, hash, prev)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          e.instance,
          e.seq,
          e.ts,
          e.tool,
          e.kind,
          e.risk,
          e.decision,
          e.policy,
          e.taint,
          e.hash,
          e.prev,
        ),
    );

    // A D1 batch runs as one transaction, so the head and its entries commit together.
    await this.db.batch([upsert, ...inserts]);
  }

  async recentEntries(instance: string, limit: number): Promise<StoredEntry[]> {
    const res = await this.db
      .prepare(
        `SELECT instance, seq, ts, tool, kind, risk, decision, policy, taint, hash, prev
         FROM entries WHERE instance = ? ORDER BY seq DESC LIMIT ?`,
      )
      .bind(instance, limit)
      .all<StoredEntry>();
    return res.results;
  }

  async fleet(): Promise<InstanceRow[]> {
    const res = await this.db
      .prepare(
        `SELECT id, last_seq, last_hash, spent_cents, first_seen, last_seen,
                total, executed, dry_run, denied, policy_denied, forwarded
         FROM instances ORDER BY last_seen DESC`,
      )
      .all<InstanceRow>();
    return res.results;
  }

  async getPolicy(): Promise<PolicyRow | null> {
    return await this.db
      .prepare(`SELECT cedar, updated FROM policy WHERE id = 1`)
      .first<PolicyRow>();
  }

  async setPolicy(cedar: string, updated: number): Promise<void> {
    await this.db
      .prepare(
        `INSERT OR REPLACE INTO policy (id, cedar, updated) VALUES (1, ?, ?)`,
      )
      .bind(cedar, updated)
      .run();
  }

  async createKey(instance: string, keyHash: string, now: number): Promise<void> {
    await this.db
      .prepare(`INSERT INTO instance_keys (key_hash, instance, created, revoked) VALUES (?, ?, ?, NULL)`)
      .bind(keyHash, instance, now)
      .run();
  }

  async resolveKey(keyHash: string): Promise<KeyRow | null> {
    return await this.db
      .prepare(`SELECT instance, revoked FROM instance_keys WHERE key_hash = ?`)
      .bind(keyHash)
      .first<KeyRow>();
  }

  async revokeInstance(instance: string, now: number): Promise<number> {
    const res = await this.db
      .prepare(`UPDATE instance_keys SET revoked = ? WHERE instance = ? AND revoked IS NULL`)
      .bind(now, instance)
      .run();
    return res.meta.changes ?? 0;
  }

  async getAttestation(instance: string): Promise<AttestationRow | null> {
    return await this.db
      .prepare(`SELECT instance, pubkey, seq, hash, sig, at FROM attestations WHERE instance = ?`)
      .bind(instance)
      .first<AttestationRow>();
  }

  async setAttestation(a: AttestationRow): Promise<void> {
    await this.db
      .prepare(
        `INSERT OR REPLACE INTO attestations (instance, pubkey, seq, hash, sig, at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .bind(a.instance, a.pubkey, a.seq, a.hash, a.sig, a.at)
      .run();
  }
}
