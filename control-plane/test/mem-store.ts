import type { Store } from "../src/store.js";
import type { InstanceRow, StoredEntry, PolicyRow, KeyRow, AttestationRow } from "../src/types.js";

/** An in-memory {@link Store} so the whole handler is testable without D1/workerd. */
export class MemStore implements Store {
  instances = new Map<string, InstanceRow>();
  entries: StoredEntry[] = [];
  policy: PolicyRow | null = null;
  keys = new Map<string, { instance: string; revoked: number | null }>();
  attestations = new Map<string, AttestationRow>();

  async getInstance(id: string): Promise<InstanceRow | null> {
    const r = this.instances.get(id);
    return r ? { ...r } : null;
  }

  async commitIngest(row: InstanceRow, entries: StoredEntry[]): Promise<void> {
    this.instances.set(row.id, { ...row });
    for (const e of entries) {
      const dup = this.entries.some((x) => x.instance === e.instance && x.seq === e.seq);
      if (!dup) this.entries.push({ ...e });
    }
  }

  async recentEntries(instance: string, limit: number): Promise<StoredEntry[]> {
    return this.entries
      .filter((e) => e.instance === instance)
      .sort((a, b) => b.seq - a.seq)
      .slice(0, limit)
      .map((e) => ({ ...e }));
  }

  async fleet(): Promise<InstanceRow[]> {
    return [...this.instances.values()].map((r) => ({ ...r })).sort((a, b) => b.last_seen - a.last_seen);
  }

  async getPolicy(): Promise<PolicyRow | null> {
    return this.policy ? { ...this.policy } : null;
  }

  async setPolicy(cedar: string, updated: number): Promise<void> {
    this.policy = { cedar, updated };
  }

  async createKey(instance: string, keyHash: string, now: number): Promise<void> {
    this.keys.set(keyHash, { instance, revoked: null });
    void now;
  }

  async resolveKey(keyHash: string): Promise<KeyRow | null> {
    const k = this.keys.get(keyHash);
    return k ? { ...k } : null;
  }

  async revokeInstance(instance: string, now: number): Promise<number> {
    let n = 0;
    for (const k of this.keys.values()) {
      if (k.instance === instance && k.revoked === null) {
        k.revoked = now;
        n++;
      }
    }
    return n;
  }

  async getAttestation(instance: string): Promise<AttestationRow | null> {
    const a = this.attestations.get(instance);
    return a ? { ...a } : null;
  }

  async setAttestation(a: AttestationRow): Promise<void> {
    this.attestations.set(a.instance, { ...a });
  }
}
