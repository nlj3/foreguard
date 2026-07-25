# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project aims to follow [Semantic Versioning](https://semver.org) from 1.0.0.

## [Unreleased]

## [0.6.0] — 2026-07-25

The theme is accuracy: making the preview show more, and making the verdict
behind it correct against real servers rather than against fixtures.

### Added

- **Diff previews for file mutations.** The preview used to say a file changes;
  now it shows *what* changes. Foreguard reads the target as it exists right now
  and diffs it against what the agent proposes, so you see the before and after
  of a change that has not happened yet:

  ```
  ⚠  intercepted `write_file` (medium risk) — NOT executed
      ┌─ config.toml
      │   3 - host = "localhost"
      │   3 + host = "0.0.0.0"
      └─ +1, -1
  ```

  Deletes show what would be lost; new files read as creations. The alignment is
  a line-based longest-common-subsequence written from scratch, so the dependency
  list stays at zero. It is read-only, capped at 512 KiB and 400 lines, honours
  `NO_COLOR`, and only ever reads a path the agent already named itself.

- **Capability-annotation awareness.** The proxy learns the `readOnlyHint` and
  `destructiveHint` a server publishes in `tools/list` and applies them
  **asymmetrically**: upgrades are always trusted, while a downgrade from
  `readOnlyHint: true` requires our own lexical read to find the name benign and
  the arguments to reveal nothing. A server declaring `readOnlyHint: true` on
  `delete_file` changes nothing.

  Trade, stated rather than buried: for an unrecognised name we now take the
  server's word. That grants a hostile server nothing it did not already have,
  since such a server can simply name a destructive tool `get_status`, which the
  lexical pass forwards regardless. The threat this addresses is an honest server
  with a hijacked agent, where declared hints are trustworthy input.

- **Namespace resolution from the catalogue.** Servers routinely namespace
  (`puppeteer_navigate`, `puppeteer_click`, …), which pushed the real verb out of
  head position and made whole families fail safe: puppeteer scored 7 of 7
  intercepted, including `puppeteer_screenshot`, which mutates nothing.

  A head token shared by at least three tools is empirically a namespace, so the
  tool is judged as its unprefixed equivalent. Verified against live puppeteer,
  which publishes **no annotations at all**.

  Three properties keep this from becoming a bypass: corroboration is required,
  so a lone `ns_` prefix earns nothing; a verb is never treated as a namespace,
  or three `write_*` tools would turn `write_query` into `query`; and stripping
  can only make a namespaced name behave like the unprefixed tool of that name
  already did.

### Security

- **Requires kedge-core 0.3.1.** 0.3.0 had briefly widened read-verb matching to
  a two-token window, which let a known-safe verb validate an unknown action:
  `ns_get_frobnicate` and `x_get_nuke` were forwarded on the lexical pass alone,
  where 0.2.0 intercepted them. That turns a fail-safe default into a blocklist.
  0.3.1 reverts it, and namespaces are now handled here instead, where the
  catalogue provides the missing evidence.

### Testing

- **Adversarial regression suite**, committed rather than run once. Every case
  was fired at a live `@modelcontextprotocol/server-filesystem` through the proxy
  and validated with a positive control: the same `write_file`, with Foreguard
  removed, really does overwrite the target. 15 name-obfuscation variants
  (case, separators, padding, compound names, a fullwidth homoglyph, a zero-width
  space), 4 argument-hidden mutations, and the real server's read-only and
  destructive catalogues.
- **The async proxy loops are now testable and tested.** `run_proxy` read stdin
  directly and asked the tty inline, so its pumping logic could not run without a
  real process and terminal. Extracted generic over `AsyncBufRead`/`AsyncWrite`
  with an injectable approver, and covered: read-only reaches the server while a
  mutation does not, an approved mutation is forwarded byte-identical, a denied
  one never arrives, untrusted data gates a mutation with `--approve` off, and
  server output passes through verbatim while recording taint.
- **Ecosystem validation.** 10 real MCP servers, 80 tools, scored against the
  hints each server publishes about itself: **zero false negatives**.

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
