# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project aims to follow [Semantic Versioning](https://semver.org) from 1.0.0.

## [Unreleased]

### Changed

- The control plane has moved out of this repository and now lives in its own, at
  https://github.com/nlj3/foreguard-control-plane.

## [0.8.0] - 2026-08-17

This release adds authorization and spend control, and lets many instances report to
one control plane. Foreguard started as a local dry-run tool and is now an open,
local enforcement point that works with any agent framework. The classifier already
decided whether a call is a mutation. Now a Cedar policy can decide whether the call
is allowed, and the meter whether there is budget left for it. The ledger can also
be verified instead of taken on trust.

Every part of this fails safe by construction. A policy can add restrictions, or let
a known-safe call run without a prompt, but it cannot lower the floor. The meter
refuses instead of alerting. A broken policy or a bad signature fails closed.

### Added

- Cedar policy authorization (`foreguard proxy --policy <file>`). Foreguard adopts
  [Cedar](https://www.cedarpolicy.com/), the language AWS built for agent tool-call
  control and donated to the CNCF, rather than a bespoke DSL. Cedar's semantics
  (default-deny, forbid-overrides-permit, deterministic) match Foreguard's deny-wins
  approach. A satisfied `forbid` hard-blocks a call, even under `--approve`. A
  satisfied `permit` pre-authorizes a mutation to run without prompting. Anything
  neither permitted nor forbidden keeps the existing dry-run behavior. Policies see
  the call as
  `context.{tool,risk,mutating,tainted,session_calls,session_cost,args.*}`, and
  numeric arguments are also exposed as Cedar decimals under `context.dec.*`, so
  money rules accurate to the cent
  (`context.dec.amount.lessThanOrEqual(decimal("50.00"))`) work. `session_calls`
  acts as a kill switch for runaway loops at the tool-call layer. This fails safe.
  Any policy that errors during evaluation downgrades an `Allow` to the dry-run
  gate, so a silently broken `forbid` can never fail open into execution. Taint
  (Rule-of-Two) always overrides a `permit`.
- Central policy pull (`foreguard proxy --policy-url <url>`). The proxy fetches the
  fleet's Cedar policy from a URL at startup (the control plane's `/v1/policy`, or
  any other endpoint), so many proxies can enforce one centrally managed policy.
- LLM spend metering (`foreguard meter`). It reads model-API responses as JSON lines
  and prices each one against a `--budget`. It understands the Anthropic and OpenAI
  usage shapes, including nested streaming usage and cache tokens. Once cumulative
  spend crosses the budget, it refuses every further request. This is enforcement,
  not alerting.
- Live spend gateway (`foreguard gateway --upstream <url> --budget <$>`). It is a
  loopback HTTP proxy in front of the model API. Point an agent's
  `ANTHROPIC_BASE_URL`/`OPENAI_BASE_URL` at it, and the budget kill switch refuses
  the next request before it is sent upstream. The caller's own auth header is
  passed through, and Foreguard stores no keys. Responses are buffered for now
  rather than streamed token by token, and streaming is the next step.
- Tamper-evident ledger and `foreguard verify`. The audit ledger is now a SHA-256
  hash chain. Each entry carries `_fg:{seq,prev,hash}`, so editing, deleting or
  reordering any entry breaks the chain, and `verify` points to the exact line. This
  detects tampering but does not prevent it. The signed head below provides the
  anchor.
- Signed ledger head (`foreguard keygen`, `foreguard report --key`). An instance
  signs its ledger head with an Ed25519 key it holds. The control plane verifies the
  signature, pins the public key the first time it sees it, and rejects rollbacks.
  That makes the audit trail non-repudiable, because even an operator of the control
  plane cannot forge a valid head.
- Fleet reporting (`foreguard report <ledger> --to <url> --instance <id>`). It sends
  the ledger's new entries and current spend to the control plane. Running it again
  is safe, because only entries past the head the server has already accepted are
  sent. The bearer token is read from `FOREGUARD_INGEST_TOKEN`, never from the
  command line.
- The control plane, a TypeScript Cloudflare Worker with D1 that receives signed
  ledger heads and spend from many instances and shows them in one place. It now
  lives in a separate repository at https://github.com/nlj3/foreguard-control-plane.

### Changed

- The `--ledger` line format gains a top-level `_fg` integrity envelope. Payload
  fields stay at the top level, so `jq`, `grep` and `promote` are unaffected.

### Changed

- Relicensed to `MIT OR Apache-2.0`. The previous licence was BUSL-1.1. Versions
  already published to crates.io under BUSL-1.1 keep that licence, and the change
  applies to releases from here on. `LICENSE-MIT` and `LICENSE-APACHE` are now both
  present, and `LICENSE` points at the pair.

## [0.7.0] - 2026-07-27

The theme is reachability: two things that already worked but that nobody could get
to.

### Added

- An approval UI (`foreguard proxy --approve --ui`). `--approve` was documented as
  "the trust loop, closed", and in the case Foreguard is built for it was closed in
  the wrong position. An MCP host spawns the proxy as a stdio child, and a GUI host
  (Claude Desktop, Cursor, VS Code) has no controlling terminal, so opening
  `/dev/tty` fails with ENXIO and the approver fails safe to "no". Every mutation
  was denied, permanently, with nothing to say why. Under a terminal host it is not
  much better. The host owns the TUI, and two processes reading the same tty is a
  fight, not a prompt.

  The decision now happens on a page on loopback, showing the tool, the risk, the
  concrete effect, and the Rule-of-Two reason when taint fired. Your browser opens
  on the first approval, not at launch.

  It is an approval authority, so it is built like one. It is loopback-only, and a
  non-loopback bind is refused rather than warned about. Every request must carry a
  256-bit token from `/dev/urandom`, compared without an early exit. `Host` is
  checked against loopback literals so DNS rebinding fails, no CORS headers are ever
  sent, and `POST /decide` requires `application/json`, so a cross-origin form post
  cannot approve anything. A timeout, a dropped socket, a closed tab and an
  unparseable body all resolve to *deny*. `FOREGUARD_NO_OPEN=1` stops it reaching
  for your browser.

- `foreguard ecosystem`, which scores the classifier against what real MCP servers
  declare about their own tools and prints the table.

### Changed

- The published accuracy figure is corrected, and it is lower. nlj.dev claimed
  "84.6% agreement, 80 tools, 10 servers" and pointed at a command that passes,
  prints nothing, and asserts 38 hand-listed names with no per-server grouping and
  no comparison against any declared hint. The figures came from a one-off that
  existed in no repository.

  Measured against ten real servers captured over stdio, the result is 81.0%
  agreement over 63 scoreable tools of 98, with 0 false negatives. The claim that
  mattered survives. The headline number was wrong. The 35 tools carrying no
  `readOnlyHint` are excluded from the denominator rather than assumed either way.

- The `[y/N]` prompt is suppressed under `--ui`, where it was telling the reader to
  press a key that did nothing.
- The stateless MCP spec (`2026-07-28`) is described as a release candidate, because
  on the date of this release it still is one.

### Fixed

- `.wrangler/cache/` was tracked and not ignored. It carried a Cloudflare account
  id, which does not belong in a public repository.

## [0.6.0] - 2026-07-25

The theme is accuracy: making the preview show more, and making the verdict behind
it correct against real servers rather than against fixtures.

### Added

- Diff previews for file mutations. The preview used to say that a file changes, and
  now it shows what changes. Foreguard reads the target as it exists right now and
  diffs it against what the agent proposes, so you see the before and after of a
  change that has not happened yet:

  ```
  ⚠  intercepted `write_file` (medium risk) — NOT executed
      ┌─ config.toml
      │   3 - host = "localhost"
      │   3 + host = "0.0.0.0"
      └─ +1, -1
  ```

  A delete shows what would be lost, and a new file reads as a creation. The
  alignment is a line-based longest-common-subsequence written from scratch, so the
  dependency list stays at zero. It is read-only, capped at 512 KiB and 400 lines,
  honours `NO_COLOR`, and only ever reads a path the agent already named itself.

- Capability-annotation awareness. The proxy learns the `readOnlyHint` and
  `destructiveHint` a server publishes in `tools/list` and applies them
  asymmetrically. Upgrades are always trusted. A downgrade from `readOnlyHint: true`
  requires our own lexical read to find the name benign and the arguments to reveal
  nothing. A server declaring `readOnlyHint: true` on `delete_file` changes nothing.

  The trade-off is that for an unrecognised name we now take the server's word. That
  grants a hostile server nothing it did not already have, since such a server can
  simply name a destructive tool `get_status`, which the lexical pass forwards
  regardless. The threat this addresses is an honest server with a hijacked agent,
  where declared hints are trustworthy input.

- Namespace resolution from the catalogue. Servers routinely namespace their tools
  (`puppeteer_navigate`, `puppeteer_click`, …), which pushed the real verb out of
  head position and made whole families fail safe. Puppeteer scored 7 of 7
  intercepted, including `puppeteer_screenshot`, which mutates nothing.

  A head token shared by at least three tools is empirically a namespace, so the
  tool is judged as its unprefixed equivalent. This was verified against live
  puppeteer, which publishes no annotations at all.

  Three properties keep this from becoming a bypass. Corroboration is required, so a
  lone `ns_` prefix earns nothing. A verb is never treated as a namespace, because
  otherwise three `write_*` tools would turn `write_query` into `query`. Stripping
  can only make a namespaced name behave the way the unprefixed tool of that name
  already did.

### Security

- Requires kedge-core 0.3.1. Version 0.3.0 had briefly widened read-verb matching to
  a two-token window, which let a known-safe verb validate an unknown action.
  `ns_get_frobnicate` and `x_get_nuke` were forwarded on the lexical pass alone,
  where 0.2.0 intercepted them. That turns a fail-safe default into a blocklist.
  0.3.1 reverts it, and namespaces are now handled here instead, where the catalogue
  provides the missing evidence.

### Testing

- An adversarial regression suite, committed rather than run once. Every case was
  fired at a live `@modelcontextprotocol/server-filesystem` through the proxy and
  validated with a positive control: the same `write_file`, with Foreguard removed,
  really does overwrite the target. It covers 15 name-obfuscation variants (case,
  separators, padding, compound names, a fullwidth homoglyph, a zero-width space), 4
  argument-hidden mutations, and the real server's read-only and destructive
  catalogues.
- The async proxy loops are now testable, and tested. `run_proxy` read stdin
  directly and asked the tty inline, so its pumping logic could not run without a
  real process and terminal. It is now generic over `AsyncBufRead`/`AsyncWrite` with
  an injectable approver. The tests cover a read-only call reaching the server while
  a mutation does not, an approved mutation forwarded byte-identical, a denied one
  that never arrives, untrusted data gating a mutation with `--approve` off, and
  server output passing through verbatim while taint is recorded.
- Ecosystem validation. Across 10 real MCP servers and 80 tools, scored against the
  hints each server publishes about itself, there were zero false negatives.

## [0.5.0] - 2026-07-25

### Added

- Support for stateless MCP (`2026-07-28`). That revision removes the `initialize` /
  `initialized` handshake (SEP-2575) and the `Mcp-Session-Id` header (SEP-2567).
  What the handshake established once now travels in `_meta` on every request, and
  `server/discover` replaces `initialize` for capability lookup.
  - `promote` negotiates. It probes `server/discover` first and, if the server
    rejects that as an unknown method, falls back to the legacy handshake. Against a
    stateless server it attaches `io.modelcontextprotocol/clientInfo` to every
    `tools/call`, and against a legacy one it does not.
  - Client-identity monitoring. Identity is now re-asserted in every message rather
    than pinned once, so anything able to influence a request body can claim to be a
    different client. The proxy records the first claim and warns when a later
    message contradicts it, which is the observable signature of a spoof or a server
    mix-up. This is reported, not enforced, because a host legitimately multiplexing
    two clients over one pipe looks identical.
  - `_meta` is scanned for taint alongside `arguments`, since a tainted value can
    now ride there just as easily.

  Foreguard proxies stdio, not Streamable HTTP, so it never sees the new
  `Mcp-Method` / `Mcp-Name` routing headers and makes no claim to validate them.

## [0.4.0] - 2026-07-24

### Added

- Promote a recorded ledger (`foreguard promote <ledger> -- <server…>`). Record a
  session in dry-run with `proxy --ledger` (nothing executes), review the plan
  offline, then replay the exact recorded calls, with the same tool and the same
  arguments, against a live server. Foreguard acts as a minimal MCP client: it does
  the `initialize` handshake, then sends each `tools/call` verbatim and prints the
  real response. By default only mutations are replayed, since read-only calls
  already ran, and `--all` includes reads. Each call is confirmed on the terminal
  unless you pass `--yes`. It fails safe, so no confirmation, or no terminal, means
  the call is skipped. What you previewed is what runs, even hours later.
  - `--dry-run` prints the replay plan (tools, effects, prior verdicts) and exits
    without launching anything.
  - The MCP client advertises protocol version `2025-06-18` and reports the version
    the server negotiates back. A rejected `initialize` fails with a clear error.

### Changed

- Broader taint sources and bounded extraction. The untrusted-source heuristic now
  covers more content-pulling tools (web search, RSS/feeds,
  Slack/Discord/Telegram/SMS, attachments, uploads, …), and token extraction from a
  result is bounded, so a hostile page can't turn a single response into unbounded
  work.

## [0.3.0] - 2026-07-24

### Added

- Recorded ledger (`foreguard proxy --ledger <path>`). The proxy appends a JSON line
  per tool call to an audit trail, holding the timestamp, tool, kind
  (read-only/mutation), risk, concrete effect, taint verdict, the decision
  (`forwarded` / `dry-run` / `executed` / `denied`) and the arguments. Each line is
  flushed as it is written, so a crash still leaves every earlier decision on disk.
  It records what your agent actually tried to do and what was let through, and you
  can search it with `jq`. It is an audit log, not a tamper-proof one.

## [0.2.0] - 2026-07-24

### Added

- Context Foresight, dynamic taint tracking
  (`foreguard proxy --taint -- <server…>`). The proxy now tracks provenance. It
  marks the distinctive strings returned by untrusted-source tools (web `fetch`,
  inbox reads, scrapers, RAG retrieval), and when any of that data reappears inside
  a mutating call, it flags a Rule-of-Two violation and forces the human-approval
  gate for that call, even without `--approve`. This is a best-effort
  prompt-injection defense (OWASP LLM01). It catches the common flow from untrusted
  input to a mutation and fails safe, so a tainted mutation with no terminal
  attached is denied and stays a dry-run. It sees only tool I/O, not the model's
  reasoning, so it does not claim to stop every injection. It implements Meta's
  Agents "Rule of Two": untrusted input combined with a state-changing action
  requires a human.
- Promote-to-live (`foreguard proxy --approve -- <server…>`). The proxy now has an
  interactive approval mode. Each mutation pauses, shows its concrete effect, and
  asks `[y/N]` on the controlling terminal. Approve it and the exact call you
  previewed is forwarded to execute for real. Deny it, or run with no terminal
  attached, and it stays a dry-run. Only an explicit `y`/`yes` executes. A bare
  Enter, EOF or a missing `/dev/tty` all mean "no". Without `--approve`, every
  mutation is dry-run as before.
- Effect-rich Mutation Plan. The preview now describes the concrete effect of each
  mutation, taken from its arguments: `deletes <path>`, `METHOD <url>`,
  `writes N bytes to <path>` (with a content snippet), `SQL: <stmt>`, `runs: <cmd>`,
  `sends to <recipient>`, with a compact view of the arguments as the fallback. It
  appears in both the `plan` output and the proxy's intercept log.
- Transparent MCP dry-run proxy (`foreguard proxy -- <server…>`). It launches an MCP
  tool server and proxies stdio JSON-RPC between it and the host. Everything is
  forwarded except mutating `tools/call`s, which are intercepted and answered with a
  synthetic dry-run success, so nothing executes. Point Claude Code, Cursor or Cline
  at it instead of the server, with no changes to the agent. The proxy runs as two
  tasks, which lets it drain in-flight responses cleanly on shutdown.
- Argument-aware classification. The preview now inspects a tool's arguments as well
  as its name, and upgrades the verdict when they reveal a hidden mutation. It is
  fail-safe, because arguments can only make a call more restricted. It catches the
  cases a name-only classifier misses:
  - a read-looking `fetch`/`request` with a writing HTTP `method`
    (POST/PUT/PATCH/DELETE)
  - a `query`/`sql` whose leading keyword mutates (INSERT/UPDATE/DELETE/DROP/…)
  - an `operation`/`action` argument that names a mutating action
  - a destructive program or write-redirect in a `command`/`cmd`/`script`

  The Mutation Plan now shows why an argument-detected mutation was flagged.

### Changed

- Depend on the published `kedge-core = "0.2"` (hardened, deny-wins) instead of a
  git revision.

## [0.1.0] - 2026-07-24

### Added

- Initial release. `foreguard plan` produces a Mutation Plan from a JSON list of
  tool calls, classifying each one as read-only (would run) or mutating
  (intercepted, previewed, not executed), with `--json` output.
- The classification engine is reused from [kedge](https://crates.io/crates/kedge)
  (`kedge-core`), and is fail-safe and deny-wins.
- CI (fmt/clippy/test/audit on Linux and macOS), dependabot, a pinned toolchain, and
  the BUSL-1.1 license.
