# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project aims to follow [Semantic Versioning](https://semver.org) from 1.0.0.

## [Unreleased]

## [0.2.0] — 2026-07-24

### Added

- **Context Foresight — dynamic taint tracking** (`foreguard proxy --taint -- <server…>`).
  The proxy now tracks *provenance*: it marks the distinctive strings returned by
  untrusted-source tools (web `fetch`, inbox reads, scrapers, RAG retrieval) and,
  when any of that data reappears inside a **mutating** call, flags a **Rule-of-Two
  violation** and forces the human-approval gate for that call — even without
  `--approve`. This is a best-effort prompt-injection defense (OWASP LLM01): it
  catches the common untrusted→mutation flow and fails safe (a tainted mutation with
  no terminal attached is denied, i.e. dry-run), but — seeing only tool I/O, not the
  model's reasoning — it does not claim to stop every injection. Implements Meta's
  Agents "Rule of Two": untrusted input + a state-changing action requires a human.
- **Promote-to-live** (`foreguard proxy --approve -- <server…>`) — the proxy now has
  an interactive approval mode that closes the trust loop: each mutation *pauses*,
  shows its concrete effect, and asks `[y/N]` on the controlling terminal. Approve
  and the **exact** call you previewed is forwarded to execute for real; deny — or
  run with no terminal attached — and it stays a dry-run. Fail-safe: only an explicit
  `y`/`yes` executes; a bare Enter, EOF, or missing `/dev/tty` all mean "no". Without
  `--approve`, every mutation is dry-run as before.
- **Effect-rich Mutation Plan** — the preview now describes the *concrete effect* of
  each mutation, extracted from its arguments: `deletes <path>`, `METHOD <url>`,
  `writes N bytes to <path>` (with a content snippet), `SQL: <stmt>`, `runs: <cmd>`,
  `sends to <recipient>`, with a compact-args fallback. Shown in both the `plan`
  output and the proxy's intercept log.
- **Transparent MCP dry-run proxy** (`foreguard proxy -- <server…>`) — launches an
  MCP tool server and proxies stdio JSON-RPC to/from the host, forwarding
  everything **except** mutating `tools/call`s, which are intercepted and answered
  with a synthetic dry-run success (nothing executes). Point Claude Code / Cursor /
  Cline at it instead of the server — no agent changes. Two-task architecture
  drains in-flight responses cleanly on shutdown.
- **Argument-aware classification** — the preview now inspects a tool's
  *arguments*, not just its name, and **upgrades** the verdict when they reveal a
  hidden mutation (fail-safe: arguments can only make a call more restricted).
  Catches the cases a name-only classifier misses:
  - a read-looking `fetch`/`request` with a writing HTTP `method` (POST/PUT/PATCH/DELETE),
  - a `query`/`sql` whose leading keyword mutates (INSERT/UPDATE/DELETE/DROP/…),
  - an `operation`/`action` argument that names a mutating action,
  - a destructive program or write-redirect in a `command`/`cmd`/`script`.

  The Mutation Plan now shows *why* an argument-detected mutation was flagged.

### Changed

- Depend on the published `kedge-core = "0.2"` (hardened, deny-wins) instead of a
  git revision.

## [0.1.0] — 2026-07-24

### Added

- Initial release: `foreguard plan` produces a **Mutation Plan** from a JSON list
  of tool calls — classifying each as read-only (would run) or mutating
  (intercepted, previewed, not executed), with `--json` output.
- Classification engine reused from [kedge](https://github.com/nlj3/kedge)
  (`kedge-core`) — fail-safe and deny-wins.
- Pro hygiene: CI (fmt/clippy/test/audit on Linux + macOS), dependabot, pinned
  toolchain, BUSL-1.1 license.
