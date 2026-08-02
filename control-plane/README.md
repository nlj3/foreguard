# Foreguard Control Plane

The commercial layer Foreguard instances report to — a TypeScript **Cloudflare
Worker + D1**. It gives a fleet of proxies/gateways a shared view and one place to
manage them:

- **Fleet dashboard** (`GET /`) — instances, aggregated spend, decision counts,
  policy-blocked totals. Self-contained HTML; holds no secret (you paste an admin
  token, sent as a Bearer header to the API).
- **Ingest** (`POST /v1/ingest`) — instances push their hash-chained ledger entries
  and current spend. The chain's **linkage is verified on ingest** (a dropped,
  reordered, or injected entry is rejected with `409`, and nothing is stored).
- **Central Cedar policy** (`GET`/`PUT /v1/policy`) — push one policy, have the whole
  fleet pull and enforce it (`foreguard proxy --policy-url …`).
- **Per-instance API keys** — each instance authenticates with its own key, so a key
  can only report as *itself* (spoofing another instance is a `403`) and a leak is
  scoped and revocable.
- **Signed-head verification** — an instance signs its ledger head (Ed25519); the
  control plane verifies it (WebCrypto), pins the public key trust-on-first-use, and
  rejects rollbacks. The audit trail becomes non-repudiable.

## Endpoints

| Method & path | Auth | Purpose |
|---|---|---|
| `GET /` | none (data needs a token) | Fleet dashboard |
| `POST /v1/ingest` | instance key **or** master token | Report ledger entries + spend (+ optional signed head) |
| `GET /v1/head?instance=` | instance key or admin | Where to resume reporting |
| `GET /v1/fleet` | admin | Aggregated fleet view |
| `GET /v1/audit?instance=` | admin | Recent entries for an instance |
| `GET`/`PUT /v1/policy` | pull: any instance/admin · push: admin | Central Cedar policy |
| `POST /v1/instances` | admin | Mint a per-instance key (returned once) |
| `POST /v1/instances/revoke` | admin | Revoke an instance's keys |

Two secrets, set with `wrangler secret put` (never committed):
`ADMIN_TOKEN` (fleet/audit/policy-push/key-management) and `INGEST_TOKEN` (an
optional shared "master" token; prefer per-instance keys).

## Develop

```sh
npm install
npm test                 # 25 tests — full handler exercised against an in-memory store
npm run typecheck        # tsc --noEmit

# local run (create .dev.vars with INGEST_TOKEN / ADMIN_TOKEN first)
npm run migrate:local
npm run dev              # http://localhost:8787
```

## Deploy

```sh
npx wrangler d1 create foreguard_cp        # paste the id into wrangler.jsonc
npm run migrate:remote
npx wrangler secret put ADMIN_TOKEN
npx wrangler secret put INGEST_TOKEN
npm run deploy
```

## Design notes

- **Repository pattern** (`Store` interface + `D1Store` + an in-memory store for
  tests) so the whole request handler is testable offline — no workerd, no D1.
- **Timing-safe** token comparison, structured errors (no `passThroughOnException`),
  observability on, Web Crypto only.
- **Honest scope:** ingest verifies chain *linkage* (truncation/reorder/injection);
  re-deriving the SHA content hash server-side — matching Rust's canonical JSON
  byte-for-byte — is a deliberate follow-up. Signed heads already close the
  operator-forgery gap.

Source-available under [BUSL-1.1](../LICENSE), like the rest of Foreguard.
