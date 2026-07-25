# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project aims to follow [Semantic Versioning](https://semver.org) from 1.0.0.

## [Unreleased]

### Fixed

- **Namespaced read-only tools are no longer flagged.** An ecosystem sweep of 10
  real MCP servers (80 tools), scored against the `readOnlyHint` each server
  publishes about itself, found zero false negatives and six false positives.
  Every one traced to `kedge_core::classify`, not to Foreguard.

  Read verbs were only recognised in head position, so a namespace prefix hid
  the verb: `get_file` passed while `github_get_file` was intercepted. That is
  why puppeteer scored 7 of 7 intercepted, including `puppeteer_screenshot`,
  which mutates nothing. Fixed in kedge-core 0.3.0, which Foreguard now depends
  on: a read verb counts at the head or directly behind one namespace prefix.

  It cannot weaken deny-wins, because the dangerous-token checks return earlier;
  `get_and_delete` never reaches that code. The window is two rather than
  unbounded so an unrecognised head stays honest: `frobnicate_and_get` still
  fails safe.

  Vocabulary also gained `screenshot`, `echo`, and `tree`. `open` and `convert`
  were deliberately left out as ambiguous, since `open_file` may create and
  `convert` may write its output; declared hints cover those without guessing.

  Measured on the same 80 tools: agreement **84.6% -> 89.7%** from the lexical
  change alone, and **97.4%** once declared annotations are also applied. False
  negatives remain **zero** throughout. The one remaining disagreement,
  `trigger-long-running-operation`, declares itself read-only while "trigger"
  reads as side-effecting; refusing that label is intended behaviour.

### Added

- **Capability-annotation awareness.** The proxy now learns the `readOnlyHint` and
  `destructiveHint` a server publishes in its `tools/list` reply and takes them
  into account when judging a later `tools/call`.

  Found by running against a real `@modelcontextprotocol/server-filesystem`
  rather than a fixture: `directory_tree` was being intercepted on every call
  even though the server declares it read-only. Directory exploration is
  constant, so that is the difference between a proxy people keep and one they
  uninstall on day one.

  Hints are honoured **asymmetrically**, which is the whole design:
  - Upgrades are always trusted (`destructiveHint: true`, `readOnlyHint: false`).
  - A downgrade from `readOnlyHint: true` applies **only** when our own lexical
    read already finds the name benign, and only when the arguments reveal
    nothing. A server declaring `readOnlyHint: true` on `delete_file` changes
    nothing.

  Distinguishing "unrecognised" from "recognised as dangerous" matters here,
  because `classify` returns the same verdict for both. Rather than re-listing
  kedge's vocabulary, which would drift, we ask kedge itself: prefix the name
  with a known read verb and see whether deny-wins still trips.

  Trade, stated rather than buried: for a name we do not recognise we now take
  the server's word. A hostile server could pair an innocuous name with
  `readOnlyHint: true` and be forwarded where fail-safe would have intercepted.
  It cannot do so for anything that reads as dangerous, and taint tracking still
  applies to whatever comes back.

  The registry is best-effort by construction: a hint only exists after
  `tools/list` has round-tripped, so a `tools/call` that beats it gets the
  fail-safe verdict.

### Testing

- The adversarial battery is now a committed regression suite. Every case was
  fired at the live filesystem server through the proxy and validated with a
  positive control (the same `write_file`, with Foreguard removed, really does
  overwrite the target). 15 name-obfuscation variants, 4 argument-hidden
  mutations, plus the real server's 9 read-only and 4 destructive tools.

## [0.5.0] — 2026-07-25

### Added

- **Stateless MCP (`2026-07-28`) support.** That revision removes the
  `initialize` / `initialized` handshake (SEP-2575) and the `Mcp-Session-Id`
  header (SEP-2567); what the handshake established once now travels in `_meta`
  on every request, and `server/discover` replaces `initialize` for capability
  lookup.
  - `promote` negotiates: it probes `server/discover` first and, if the server
    rejects it as an unknown method, falls back to the legacy handshake. Against
    a stateless server it attaches `io.modelcontextprotocol/clientInfo` to every
    `tools/call`; against a legacy one it does not.
  - **Client-identity monitoring.** Because identity is now re-asserted per
    message rather than pinned once, anything able to influence a request body
    can claim to be a different client. The proxy records the first claim and
    warns when a later message contradicts it, which is the observable signature
    of a spoof or a server mix-up. Reported, not enforced: a host legitimately
    multiplexing two clients over one pipe looks identical.
  - **`_meta` is scanned for taint** alongside `arguments`, since a tainted
    value can now ride there just as easily.

  Scope, stated plainly: Foreguard proxies stdio, not Streamable HTTP, so it
  never sees the new `Mcp-Method` / `Mcp-Name` routing headers and makes no
  claim to validate them.

## [0.4.0] — 2026-07-24

### Added

- **Promote a recorded ledger** (`foreguard promote <ledger> -- <server…>`) — closes
  the record→review→execute loop. Record a session in dry-run with `proxy --ledger`
  (nothing executes), review the plan offline, then replay the exact recorded calls —
  same tool, same arguments — against a live server. Foreguard acts as a minimal MCP
  client (does the `initialize` handshake, then sends each `tools/call` verbatim and
  prints the real response). Mutations only by default (read-only calls already ran);
  `--all` includes reads. Each call is confirmed on the terminal unless `--yes`;
  fail-safe — no confirmation, or no terminal, means skip. "What you previewed is what
  runs," even hours later.
  - `--dry-run` — print the replay plan (tools, effects, prior verdicts) and exit,
    launching nothing.
  - The MCP client advertises protocol version `2025-06-18` and reports the version
    the server negotiates back; a rejected `initialize` fails with a clear error.

### Changed

- **Broader taint sources & bounded extraction** — the untrusted-source heuristic now
  covers more content-pulling tools (web search, RSS/feeds, Slack/Discord/Telegram/SMS,
  attachments, uploads, …), and token extraction from a result is bounded so a hostile
  page can't turn a single response into unbounded work.

## [0.3.0] — 2026-07-24

### Added

- **Recorded ledger** (`foreguard proxy --ledger <path>`) — append a JSON line per
  tool call to an audit trail: timestamp, tool, kind (read-only/mutation), risk,
  concrete effect, taint verdict, and the decision (`forwarded` / `dry-run` /
  `executed` / `denied`), plus the arguments. Flushed per line, so a crash still
  leaves every prior decision on disk. Answers "what did my agent actually try to do,
  and what did we let through?" — greppable with `jq`. Honest scope: an audit log,
  not a tamper-proof one.

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
