import type { Env, InstanceRow, StoredEntry, AttestationRow } from "./types.js";
import type { Store } from "./store.js";
import { parseEntry, verifyBatch, type ParsedEntry } from "./integrity.js";
import { sha256hex, randomKey, verifyEd25519, headMessage } from "./crypto.js";
import { dashboardHtml } from "./dashboard.js";

const MAX_BATCH = 5000;
const MAX_ID_LEN = 200;

/** Constant-time string comparison, preferring the runtime's primitive when present
 * (Workers), falling back to a portable XOR-accumulate so tests run under Node too. */
function safeEqual(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const ab = enc.encode(a);
  const bb = enc.encode(b);
  if (ab.length !== bb.length) return false;
  const subtle = crypto.subtle as unknown as {
    timingSafeEqual?: (x: ArrayBufferView, y: ArrayBufferView) => boolean;
  };
  if (typeof subtle.timingSafeEqual === "function") {
    return subtle.timingSafeEqual(ab, bb);
  }
  let diff = 0;
  for (let i = 0; i < ab.length; i++) diff |= (ab[i] as number) ^ (bb[i] as number);
  return diff === 0;
}

/** The Bearer token on a request, or null. */
function bearer(request: Request): string | null {
  const h = request.headers.get("authorization");
  if (!h) return null;
  const m = /^Bearer\s+(.+)$/i.exec(h.trim());
  return m ? (m[1] as string) : null;
}

/** True when the request presents a Bearer token matching any of `expected`. Empty
 * or missing expected secrets never match, so a misconfigured deploy fails closed. */
function authorized(request: Request, ...expected: (string | undefined)[]): boolean {
  const token = bearer(request);
  if (!token) return false;
  return expected.some((e) => typeof e === "string" && e.length > 0 && safeEqual(token, e));
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function str(record: Record<string, unknown>, key: string): string | null {
  const v = record[key];
  return typeof v === "string" ? v : null;
}

/** Turn a parsed entry into the row we store, keyed to its instance. */
function toStored(instance: string, e: ParsedEntry, fallbackTs: number): StoredEntry {
  const tsVal = e.record["ts"];
  return {
    instance,
    seq: e.fg.seq,
    ts: typeof tsVal === "number" ? tsVal : fallbackTs,
    tool: str(e.record, "tool"),
    kind: str(e.record, "kind"),
    risk: str(e.record, "risk"),
    decision: str(e.record, "decision"),
    policy: str(e.record, "policy"),
    taint: str(e.record, "taint"),
    hash: e.fg.hash,
    prev: e.fg.prev,
  };
}

/** A fresh instance head for a never-before-seen reporter. */
function newInstance(id: string, now: number): InstanceRow {
  return {
    id,
    last_seq: -1,
    last_hash: "genesis",
    spent_cents: 0,
    first_seen: now,
    last_seen: now,
    total: 0,
    executed: 0,
    dry_run: 0,
    denied: 0,
    policy_denied: 0,
    forwarded: 0,
  };
}

/** Fold one batch's decisions into the running instance counters. */
function tally(row: InstanceRow, entries: StoredEntry[]): void {
  for (const e of entries) {
    row.total += 1;
    switch (e.decision) {
      case "executed": row.executed += 1; break;
      case "dry-run": row.dry_run += 1; break;
      case "denied": row.denied += 1; break;
      case "policy-denied": row.policy_denied += 1; break;
      case "forwarded": row.forwarded += 1; break;
      default: break;
    }
  }
}

/** Who is this reporting request? A per-instance API key resolves the instance
 * itself (the caller can only report as itself). A shared master `INGEST_TOKEN`
 * still works but leaves the instance to be declared in the request (less secure —
 * spoofable). Returns null when neither authenticates. */
async function resolveIngestIdentity(
  request: Request,
  env: Env,
  store: Store,
): Promise<{ instance: string | null } | null> {
  const token = bearer(request);
  if (!token) return null;
  const key = await store.resolveKey(await sha256hex(token));
  if (key) {
    if (key.revoked !== null) return null; // a revoked key never authenticates again
    return { instance: key.instance };
  }
  if (typeof env.INGEST_TOKEN === "string" && env.INGEST_TOKEN.length > 0 && safeEqual(token, env.INGEST_TOKEN)) {
    return { instance: null };
  }
  return null;
}

type SignedHeadCheck =
  | { ok: true; att: AttestationRow | null }
  | { ok: false; status: number; error: string };

/** Validate an optional `signed_head`: it must describe this batch's tail, carry a
 * valid Ed25519 signature over the canonical head, use the pinned public key
 * (trust-on-first-use), and never roll the sequence backward. */
async function checkSignedHead(
  store: Store,
  instance: string,
  sh: unknown,
  parsed: ParsedEntry[],
): Promise<SignedHeadCheck> {
  if (sh === undefined) return { ok: true, att: null };
  if (typeof sh !== "object" || sh === null) return { ok: false, status: 400, error: "signed_head must be an object" };
  const s = sh as Record<string, unknown>;
  const { seq, hash, pubkey, sig } = s;
  if (
    typeof seq !== "number" || !Number.isInteger(seq) ||
    typeof hash !== "string" || typeof pubkey !== "string" || typeof sig !== "string"
  ) {
    return { ok: false, status: 400, error: "signed_head is malformed" };
  }
  // Bind the signature to the data: it must attest the last entry of this batch.
  const tail = parsed[parsed.length - 1];
  if (tail && (tail.fg.seq !== seq || tail.fg.hash !== hash)) {
    return { ok: false, status: 400, error: "signed_head does not match the batch tail" };
  }
  if (!(await verifyEd25519(pubkey, sig, headMessage(instance, seq, hash)))) {
    return { ok: false, status: 400, error: "invalid head signature" };
  }
  const prev = await store.getAttestation(instance);
  if (prev) {
    if (prev.pubkey !== pubkey) return { ok: false, status: 409, error: "attestation public key changed (possible key swap)" };
    if (seq < prev.seq) return { ok: false, status: 409, error: "attestation rolled back to an older head" };
  }
  return { ok: true, att: { instance, pubkey, seq, hash, sig, at: Date.now() } };
}

async function handleIngest(request: Request, env: Env, store: Store): Promise<Response> {
  const identity = await resolveIngestIdentity(request, env, store);
  if (!identity) return json(401, { error: "unauthorized" });

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return json(400, { error: "body must be JSON" });
  }
  if (typeof body !== "object" || body === null) return json(400, { error: "body must be an object" });
  const b = body as Record<string, unknown>;

  const bodyInstance = typeof b["instance"] === "string" ? (b["instance"] as string) : null;
  let instance: string;
  if (identity.instance !== null) {
    // Per-instance key: identity is fixed by the key; a mismatched body id is a spoof.
    instance = identity.instance;
    if (bodyInstance !== null && bodyInstance !== instance) {
      return json(403, { error: "instance does not match the presented key" });
    }
  } else {
    if (!bodyInstance || bodyInstance.length === 0 || bodyInstance.length > MAX_ID_LEN) {
      return json(400, { error: "`instance` must be a non-empty string" });
    }
    instance = bodyInstance;
  }
  const rawEntries = Array.isArray(b["entries"]) ? (b["entries"] as unknown[]) : [];
  if (rawEntries.length > MAX_BATCH) {
    return json(413, { error: `at most ${MAX_BATCH} entries per batch` });
  }

  const parsed: ParsedEntry[] = [];
  for (let i = 0; i < rawEntries.length; i++) {
    const p = parseEntry(rawEntries[i]);
    if (!p) return json(400, { error: `entry ${i} is missing a valid _fg envelope` });
    parsed.push(p);
  }

  const existing = await store.getInstance(instance);
  const now = Date.now();
  const row = existing ?? newInstance(instance, now);

  const verdict = verifyBatch(row.last_seq, row.last_hash, parsed);
  if (!verdict.ok) {
    // Reject the whole batch; nothing is stored, and the instance head is unchanged.
    return json(409, {
      ok: false,
      error: "integrity check failed",
      index: verdict.index,
      reason: verdict.reason,
    });
  }

  // Verify an optional signed head *before* committing, so a bad attestation
  // rejects the whole batch rather than storing unattested data.
  const headCheck = await checkSignedHead(store, instance, b["signed_head"], parsed);
  if (!headCheck.ok) {
    return json(headCheck.status, { ok: false, error: headCheck.error });
  }

  const stored = parsed.map((e) => toStored(instance, e, now));
  tally(row, stored);
  row.last_seq = verdict.lastSeq;
  row.last_hash = verdict.lastHash;
  row.last_seen = now;
  const spent = b["spent_cents"];
  if (typeof spent === "number" && Number.isFinite(spent) && spent >= 0) {
    row.spent_cents = Math.round(spent);
  }

  await store.commitIngest(row, stored);
  if (headCheck.att) await store.setAttestation(headCheck.att);
  return json(200, {
    ok: true,
    accepted: stored.length,
    last_seq: row.last_seq,
    attested: headCheck.att !== null,
  });
}

async function handleFleet(request: Request, env: Env, store: Store): Promise<Response> {
  if (!authorized(request, env.ADMIN_TOKEN)) return json(401, { error: "unauthorized" });
  const rows = await store.fleet();
  const totalSpend = rows.reduce((s, r) => s + r.spent_cents, 0);
  return json(200, {
    instances: rows,
    total_spend_cents: totalSpend,
    instance_count: rows.length,
  });
}

async function handleAudit(request: Request, env: Env, store: Store, url: URL): Promise<Response> {
  if (!authorized(request, env.ADMIN_TOKEN)) return json(401, { error: "unauthorized" });
  const instance = url.searchParams.get("instance");
  if (!instance) return json(400, { error: "?instance= is required" });
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") ?? 100), 1), 1000);
  const head = await store.getInstance(instance);
  if (!head) return json(404, { error: "unknown instance" });
  const entries = await store.recentEntries(instance, limit);
  return json(200, {
    instance,
    last_seq: head.last_seq,
    last_hash: head.last_hash,
    entries,
  });
}

async function handleHead(request: Request, env: Env, store: Store, url: URL): Promise<Response> {
  const identity = await resolveIngestIdentity(request, env, store);
  const isAdmin = authorized(request, env.ADMIN_TOKEN);
  if (!identity && !isAdmin) return json(401, { error: "unauthorized" });
  const q = url.searchParams.get("instance");
  // A keyed instance reads its own head; an admin or master token names one.
  const instance = identity?.instance ?? q;
  if (!instance) return json(400, { error: "?instance= is required" });
  if (identity?.instance && q && q !== identity.instance) {
    return json(403, { error: "instance does not match the presented key" });
  }
  const head = await store.getInstance(instance);
  const att = await store.getAttestation(instance);
  // Unknown instance resumes from genesis, so a fresh reporter sends from seq 0.
  return json(200, {
    instance,
    last_seq: head?.last_seq ?? -1,
    last_hash: head?.last_hash ?? "genesis",
    attested_seq: att?.seq ?? -1,
  });
}

async function handleGetPolicy(request: Request, env: Env, store: Store): Promise<Response> {
  // Any valid instance (to enforce it) or an admin may pull the policy.
  const identity = await resolveIngestIdentity(request, env, store);
  if (!identity && !authorized(request, env.ADMIN_TOKEN)) {
    return json(401, { error: "unauthorized" });
  }
  const p = await store.getPolicy();
  if (!p) return json(200, { cedar: "", updated: 0 });
  return json(200, p);
}

/** Admin: mint a per-instance API key. Returned once; only its hash is stored. */
async function handleCreateInstance(request: Request, env: Env, store: Store): Promise<Response> {
  if (!authorized(request, env.ADMIN_TOKEN)) return json(401, { error: "unauthorized" });
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return json(400, { error: "body must be JSON" });
  }
  const instance = (body as Record<string, unknown>)?.["instance"];
  if (typeof instance !== "string" || instance.length === 0 || instance.length > MAX_ID_LEN) {
    return json(400, { error: "`instance` must be a non-empty string" });
  }
  const key = randomKey();
  await store.createKey(instance, await sha256hex(key), Date.now());
  return json(201, {
    instance,
    key,
    note: "store this key now — it is shown only once",
  });
}

/** Admin: revoke every active key for an instance. */
async function handleRevokeInstance(request: Request, env: Env, store: Store): Promise<Response> {
  if (!authorized(request, env.ADMIN_TOKEN)) return json(401, { error: "unauthorized" });
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return json(400, { error: "body must be JSON" });
  }
  const instance = (body as Record<string, unknown>)?.["instance"];
  if (typeof instance !== "string" || instance.length === 0) {
    return json(400, { error: "`instance` is required" });
  }
  const revoked = await store.revokeInstance(instance, Date.now());
  return json(200, { ok: true, revoked });
}

async function handlePutPolicy(request: Request, env: Env, store: Store): Promise<Response> {
  if (!authorized(request, env.ADMIN_TOKEN)) return json(401, { error: "unauthorized" });
  const ct = request.headers.get("content-type") ?? "";
  let cedar: string;
  if (ct.includes("application/json")) {
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return json(400, { error: "body must be JSON" });
    }
    const c = (body as Record<string, unknown>)?.["cedar"];
    if (typeof c !== "string") return json(400, { error: "`cedar` must be a string" });
    cedar = c;
  } else {
    cedar = await request.text();
  }
  await store.setPolicy(cedar, Date.now());
  return json(200, { ok: true, bytes: cedar.length });
}

/** The whole control plane as one function of (request, env, store) — so it can be
 * driven by tests against an in-memory store, and by `index.ts` against D1. */
export async function handle(request: Request, env: Env, store: Store): Promise<Response> {
  const url = new URL(request.url);
  const { pathname } = url;
  const method = request.method.toUpperCase();

  try {
    if (method === "GET" && pathname === "/") {
      return new Response(dashboardHtml(), {
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }
    if (method === "POST" && pathname === "/v1/ingest") return await handleIngest(request, env, store);
    if (method === "POST" && pathname === "/v1/instances") return await handleCreateInstance(request, env, store);
    if (method === "POST" && pathname === "/v1/instances/revoke") return await handleRevokeInstance(request, env, store);
    if (method === "GET" && pathname === "/v1/fleet") return await handleFleet(request, env, store);
    if (method === "GET" && pathname === "/v1/head") return await handleHead(request, env, store, url);
    if (method === "GET" && pathname === "/v1/audit") return await handleAudit(request, env, store, url);
    if (pathname === "/v1/policy") {
      if (method === "GET") return await handleGetPolicy(request, env, store);
      if (method === "PUT") return await handlePutPolicy(request, env, store);
    }
    return json(404, { error: "not found" });
  } catch (err) {
    // Explicit structured error — never passThroughOnException.
    console.error("control-plane error", { pathname, method, err: String(err) });
    return json(500, { error: "internal error" });
  }
}
