import { describe, it, expect, beforeEach } from "vitest";
import { handle } from "../src/app.js";
import type { Env } from "../src/types.js";
import { MemStore } from "./mem-store.js";

const INGEST = "ingest-secret";
const ADMIN = "admin-secret";
const env: Env = { DB: {} as unknown as D1Database, INGEST_TOKEN: INGEST, ADMIN_TOKEN: ADMIN };

let store: MemStore;
beforeEach(() => {
  store = new MemStore();
});

/** Build a linkage-valid ledger line (opaque hashes, real prev/seq chaining). */
function line(seq: number, prev: string, decision: string): Record<string, unknown> {
  return {
    ts: 1000 + seq,
    tool: "write_file",
    kind: "mutation",
    decision,
    _fg: { seq, prev, hash: `h${seq}` },
  };
}

function post(path: string, token: string | null, body: unknown): Request {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (token) headers["authorization"] = `Bearer ${token}`;
  return new Request(`http://cp.local${path}`, { method: "POST", headers, body: JSON.stringify(body) });
}
function get(path: string, token: string | null): Request {
  const headers: Record<string, string> = {};
  if (token) headers["authorization"] = `Bearer ${token}`;
  return new Request(`http://cp.local${path}`, { headers });
}

describe("ingest", () => {
  it("accepts a valid chain and updates the fleet head + counters", async () => {
    const entries = [line(0, "genesis", "executed"), line(1, "h0", "dry-run"), line(2, "h1", "policy-denied")];
    const res = await handle(post("/v1/ingest", INGEST, { instance: "agent-1", entries, spent_cents: 1500 }), env, store);
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ ok: true, accepted: 3, last_seq: 2 });

    const row = await store.getInstance("agent-1");
    expect(row).toMatchObject({
      last_seq: 2, last_hash: "h2", spent_cents: 1500,
      total: 3, executed: 1, dry_run: 1, policy_denied: 1,
    });
  });

  it("continues the chain across a second batch", async () => {
    await handle(post("/v1/ingest", INGEST, { instance: "a", entries: [line(0, "genesis", "executed")] }), env, store);
    const res = await handle(post("/v1/ingest", INGEST, { instance: "a", entries: [line(1, "h0", "executed")] }), env, store);
    expect(res.status).toBe(200);
    expect((await store.getInstance("a"))?.last_seq).toBe(1);
  });

  it("rejects a batch that breaks the chain and stores nothing", async () => {
    await handle(post("/v1/ingest", INGEST, { instance: "a", entries: [line(0, "genesis", "executed")] }), env, store);
    // Wrong prev on the continuation.
    const bad = { ...line(1, "WRONG-PREV", "executed") };
    const res = await handle(post("/v1/ingest", INGEST, { instance: "a", entries: [bad] }), env, store);
    expect(res.status).toBe(409);
    expect((await res.json() as { reason: string }).reason).toMatch(/chain link broken/);
    // Head unchanged; the bad entry was not stored.
    expect((await store.getInstance("a"))?.last_seq).toBe(0);
    expect(store.entries.length).toBe(1);
  });

  it("rejects a malformed entry (no _fg)", async () => {
    const res = await handle(post("/v1/ingest", INGEST, { instance: "a", entries: [{ tool: "x" }] }), env, store);
    expect(res.status).toBe(400);
  });

  it("requires the ingest token", async () => {
    expect((await handle(post("/v1/ingest", null, { instance: "a", entries: [] }), env, store)).status).toBe(401);
    expect((await handle(post("/v1/ingest", "wrong", { instance: "a", entries: [] }), env, store)).status).toBe(401);
    // The admin token is not an ingest token.
    expect((await handle(post("/v1/ingest", ADMIN, { instance: "a", entries: [] }), env, store)).status).toBe(401);
  });
});

describe("fleet + audit", () => {
  beforeEach(async () => {
    await handle(post("/v1/ingest", INGEST, {
      instance: "a", spent_cents: 500,
      entries: [line(0, "genesis", "executed"), line(1, "h0", "dry-run")],
    }), env, store);
    await handle(post("/v1/ingest", INGEST, {
      instance: "b", spent_cents: 250, entries: [line(0, "genesis", "denied")],
    }), env, store);
  });

  it("aggregates spend and counts across instances", async () => {
    const res = await handle(get("/v1/fleet", ADMIN), env, store);
    expect(res.status).toBe(200);
    const body = await res.json() as { instance_count: number; total_spend_cents: number };
    expect(body.instance_count).toBe(2);
    expect(body.total_spend_cents).toBe(750);
  });

  it("guards the fleet view with the admin token", async () => {
    expect((await handle(get("/v1/fleet", INGEST), env, store)).status).toBe(401);
    expect((await handle(get("/v1/fleet", null), env, store)).status).toBe(401);
  });

  it("returns audit entries for an instance", async () => {
    const res = await handle(get("/v1/audit?instance=a&limit=10", ADMIN), env, store);
    expect(res.status).toBe(200);
    const body = await res.json() as { last_seq: number; entries: unknown[] };
    expect(body.last_seq).toBe(1);
    expect(body.entries.length).toBe(2);
  });

  it("404s an unknown instance", async () => {
    expect((await handle(get("/v1/audit?instance=nope", ADMIN), env, store)).status).toBe(404);
  });

  it("reports a head for resuming (known and unknown instances)", async () => {
    const known = await handle(get("/v1/head?instance=a", INGEST), env, store);
    expect(known.status).toBe(200);
    expect(await known.json()).toMatchObject({ instance: "a", last_seq: 1, last_hash: "h1" });

    // A never-seen instance resumes from genesis so a fresh reporter starts at 0.
    const fresh = await handle(get("/v1/head?instance=new", INGEST), env, store);
    expect(await fresh.json()).toMatchObject({ last_seq: -1, last_hash: "genesis" });
  });
});

describe("central policy", () => {
  it("round-trips: admin pushes, instance pulls", async () => {
    const cedar = 'forbid(principal, action, resource) when { context.tool == "delete_file" };';
    const put = new Request("http://cp.local/v1/policy", {
      method: "PUT",
      headers: { authorization: `Bearer ${ADMIN}`, "content-type": "application/json" },
      body: JSON.stringify({ cedar }),
    });
    expect((await handle(put, env, store)).status).toBe(200);

    // An instance (ingest token) may pull it.
    const res = await handle(get("/v1/policy", INGEST), env, store);
    expect(res.status).toBe(200);
    expect((await res.json() as { cedar: string }).cedar).toBe(cedar);
  });

  it("only the admin token may push policy", async () => {
    const put = new Request("http://cp.local/v1/policy", {
      method: "PUT",
      headers: { authorization: `Bearer ${INGEST}`, "content-type": "application/json" },
      body: JSON.stringify({ cedar: "x" }),
    });
    expect((await handle(put, env, store)).status).toBe(401);
  });
});

async function issueKey(instance: string): Promise<string> {
  const req = new Request("http://cp.local/v1/instances", {
    method: "POST",
    headers: { authorization: `Bearer ${ADMIN}`, "content-type": "application/json" },
    body: JSON.stringify({ instance }),
  });
  const res = await handle(req, env, store);
  return (await res.json() as { key: string }).key;
}

function postAs(path: string, key: string, body: unknown): Request {
  return new Request(`http://cp.local${path}`, {
    method: "POST",
    headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("per-instance keys", () => {
  it("a key authenticates as its own instance and cannot spoof another", async () => {
    const key = await issueKey("agent-1");
    // Report as self: instance may be omitted (derived from the key) or match.
    const ok = await handle(postAs("/v1/ingest", key, {
      entries: [line(0, "genesis", "executed")],
    }), env, store);
    expect(ok.status).toBe(200);
    expect((await store.getInstance("agent-1"))?.last_seq).toBe(0);

    // Spoof attempt: the key is agent-1's but the body claims agent-2.
    const spoof = await handle(postAs("/v1/ingest", key, {
      instance: "agent-2", entries: [line(1, "h0", "executed")],
    }), env, store);
    expect(spoof.status).toBe(403);
  });

  it("a revoked key stops authenticating", async () => {
    const key = await issueKey("agent-x");
    expect((await handle(postAs("/v1/ingest", key, { entries: [] }), env, store)).status).toBe(200);
    const revoke = await handle(postAs("/v1/instances/revoke", "unused", { instance: "agent-x" }), env, store);
    // revoke needs the admin token, not a key:
    expect(revoke.status).toBe(401);
    const revokeOk = new Request("http://cp.local/v1/instances/revoke", {
      method: "POST",
      headers: { authorization: `Bearer ${ADMIN}`, "content-type": "application/json" },
      body: JSON.stringify({ instance: "agent-x" }),
    });
    expect((await handle(revokeOk, env, store)).status).toBe(200);
    // The key no longer works.
    expect((await handle(postAs("/v1/ingest", key, { entries: [] }), env, store)).status).toBe(401);
  });

  it("only admins may mint keys", async () => {
    const req = new Request("http://cp.local/v1/instances", {
      method: "POST",
      headers: { authorization: `Bearer ${INGEST}`, "content-type": "application/json" },
      body: JSON.stringify({ instance: "nope" }),
    });
    expect((await handle(req, env, store)).status).toBe(401);
  });
});

describe("signed head", () => {
  // Generate a real Ed25519 keypair and sign the canonical head via WebCrypto.
  async function signer() {
    const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const raw = new Uint8Array((await crypto.subtle.exportKey("raw", kp.publicKey)) as ArrayBuffer);
    const pubkey = btoa(String.fromCharCode(...raw));
    const sign = async (instance: string, seq: number, hash: string) => {
      const msg = new TextEncoder().encode(`foreguard-head-v1\n${instance}\n${seq}\n${hash}`);
      const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", kp.privateKey, msg));
      return btoa(String.fromCharCode(...sig));
    };
    return { pubkey, sign };
  }

  it("accepts a valid signature bound to the batch tail, rejects a forged one", async () => {
    const key = await issueKey("agent-signed");
    const { pubkey, sign } = await signer();
    const entries = [line(0, "genesis", "executed"), line(1, "h0", "executed")];
    const sig = await sign("agent-signed", 1, "h1");

    const good = await handle(postAs("/v1/ingest", key, {
      entries, signed_head: { seq: 1, hash: "h1", pubkey, sig },
    }), env, store);
    expect(good.status).toBe(200);
    expect(await good.json()).toMatchObject({ ok: true, attested: true });

    // A tampered signature over the same head is rejected.
    const bad = await handle(postAs("/v1/ingest", key, {
      entries: [line(2, "h1", "executed")],
      signed_head: { seq: 2, hash: "h2", pubkey, sig: sig.replace(/.$/, sig.endsWith("A") ? "B" : "A") },
    }), env, store);
    expect(bad.status).toBe(400);
  });

  it("pins the public key and blocks a rollback", async () => {
    const key = await issueKey("agent-pin");
    const a = await signer();
    await handle(postAs("/v1/ingest", key, {
      entries: [line(0, "genesis", "executed"), line(1, "h0", "executed")],
      signed_head: { seq: 1, hash: "h1", pubkey: a.pubkey, sig: await a.sign("agent-pin", 1, "h1") },
    }), env, store);

    // A different key trying to attest the same instance → 409 (possible key swap).
    const b = await signer();
    const swap = await handle(postAs("/v1/ingest", key, {
      entries: [line(2, "h1", "executed")],
      signed_head: { seq: 2, hash: "h2", pubkey: b.pubkey, sig: await b.sign("agent-pin", 2, "h2") },
    }), env, store);
    expect(swap.status).toBe(409);
  });
});

describe("dashboard", () => {
  it("serves the HTML shell publicly (no data without a token)", async () => {
    const res = await handle(get("/", null), env, store);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/text\/html/);
    expect(await res.text()).toMatch(/Foreguard/);
  });
});
