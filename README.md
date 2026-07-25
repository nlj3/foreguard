# Foreguard

[![CI](https://github.com/nlj3/foreguard/actions/workflows/ci.yml/badge.svg)](https://github.com/nlj3/foreguard/actions/workflows/ci.yml)
[![License: BUSL-1.1](https://img.shields.io/badge/license-BUSL--1.1-orange.svg)](LICENSE)

> **Preview what your AI agent is about to do — before it does it.**

Foreguard is a **dry-run trust layer for autonomous agents**. Point it at the tool
calls an agent wants to make and it produces a **Mutation Plan**: which calls are
read-only (safe to run) and which would *mutate* your files, APIs, or data —
flagged, previewed, and **not executed**. You review the plan, then run for real
when you're ready.

Autonomous agents are powerful and terrifying for the same reason: you can't see
what they're about to do until it's done. Foreguard is the missing surface between
"fully trust it" and "babysit every step" — **see it before it acts.**

```console
$ echo '[{"name":"read_file","arguments":{"path":"src/main.rs"}},
         {"name":"delete_file","arguments":{"path":"/etc/passwd"}},
         {"name":"get_and_delete","arguments":{"id":42}},
         {"name":"deploy_to_prod","arguments":{}}]' | foreguard plan

Foreguard — mutation preview

  ✔  read_file                  read-only — would run for real
  ⚠  delete_file                MUTATING (high) — intercepted, NOT executed
  ⚠  get_and_delete             MUTATING (high) — intercepted, NOT executed
  ⚠  deploy_to_prod             MUTATING (high) — intercepted, NOT executed

Plan: 3 mutation(s) would be intercepted · 1 read-only call would run.
Nothing was executed. Review the plan above, then run for real when you're ready.
```

Note `get_and_delete` — a name that *looks* read-only but mutates. Foreguard's
classifier is **deny-wins**: it scans every token, so a compound mutation can't
hide behind a read verb. And it's **fail-safe**: anything not clearly read-only is
treated as mutating.

## Why this is different

Guardrails tools scan *text*. MCP gateways *block or approve* calls. Observability
tools *record* calls after the fact. **None of them show you the plan of intended
side effects before execution.** That preview — a dry-run of what the agent *would*
do — is what Foreguard is for.

## Powered by kedge

Foreguard doesn't reinvent the engine — it **extracts** one: the fail-safe tool
classifier from [**kedge**](https://github.com/nlj3/kedge), a deterministic
AI-agent harness. Foreguard is the focused product; kedge is the substrate. (It's a
git dependency, not a fork — same code, one source of truth.)

## Install

```sh
cargo install --git https://github.com/nlj3/foreguard
```

## Usage

### As a live proxy for your agent (the main event)

Point any MCP host — **Claude Code, Cursor, Cline** — at Foreguard *instead of* the
tool server, and it previews every mutating call live. In your MCP config, wrap the
server command:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "foreguard",
      "args": ["proxy", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/path"]
    }
  }
}
```

Now read-only tools run for real, but the moment the agent tries to mutate
something, Foreguard **intercepts it, logs the preview, and returns a dry-run
success** — the agent keeps planning, nothing gets written or deleted:

```text
⚠  foreguard intercepted `delete_file` (high risk) — NOT executed
```

No change to your agent, no change to your prompts — just put `foreguard proxy --`
in front of the server.

**Promote-to-live** — add `--approve` and the proxy stops auto-dry-running: each
mutation pauses and asks you, showing exactly what it would do. Approve and the
*same* call executes for real; deny (or run headless) and it stays a dry-run.

```text
⚠  `delete_file` (high risk)  ·  deletes /etc/passwd
    Execute this for real? [y/N] ▊
```

Only an explicit `y`/`yes` runs it — a bare Enter, or no terminal at all, means no.
What you previewed is exactly what runs.

### One-shot: preview a batch of tool calls

```sh
foreguard plan tools.json          # from a file
cat tools.json | foreguard plan    # or stdin
foreguard plan tools.json --json   # machine-readable
```

Input is a JSON array of `{ "name": ..., "arguments": ... }` — the tool calls an
agent proposes.

## Status & roadmap

Early. The classifier and the Mutation Plan are real and tested; the surface around
them is being built.

**Shipped:**

- ✅ **Argument-aware classification** — the preview inspects a tool's *arguments*,
  not just its name, and upgrades the verdict when they reveal a hidden mutation (a
  `fetch` with `method:"DELETE"`, a mutating SQL verb, `rm` in a command). Fail-safe:
  arguments can only make a call more restricted. This is what makes the preview
  *trustworthy*, not just fast.
- ✅ **Transparent MCP proxy** (`foreguard proxy -- <server…>`) — sit between any
  MCP host and its tool server; read-only calls forward for real, mutating calls
  are intercepted and previewed. Works with Claude Code / Cursor / Cline with no
  agent changes.
- ✅ **Effect-rich Mutation Plan** — the preview shows *what* a mutation would do,
  not just that it mutates: `deletes /etc/passwd`, `DELETE https://api/…`, `writes
  N bytes to config.toml:` (with a content snippet), `sends to all@company.com`.
- ✅ **Promote-to-live** (`foreguard proxy --approve`) — the trust loop, closed: each
  mutation pauses for a `[y/N]` on your terminal, and approving forwards the *exact*
  call you saw to execute for real. Fail-safe — only an explicit `y` runs; no
  terminal means dry-run. What you previewed is what runs.

**Planned:**

- **Recorded ledger** — persist every previewed/approved/executed call to an
  append-only log, so a run is auditable and replayable after the fact.

## License

[Business Source License 1.1](LICENSE) — source-available; converts to Apache-2.0
on the Change Date. See the file for details.
