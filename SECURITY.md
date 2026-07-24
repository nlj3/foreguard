# Security Policy

Foreguard decides which of an AI agent's actions are safe to run and which to hold
back — so its security posture is part of the product.

## Reporting a vulnerability

Email **noeljacksonjs@gmail.com** with `[foreguard security]` in the subject, or
open a private security advisory. Please **do not** open a public issue for
anything exploitable.

## What Foreguard does and does not claim

**Does:**

- Classify tool calls **fail-safe**: anything not clearly read-only is treated as
  mutating, and a compound name (`get_and_delete`) is caught by a deny-wins scan
  over every token.
- Produce a **preview** (Mutation Plan) of intended side effects without executing
  the mutating ones.

**Does not (yet):**

- **See arguments.** Classification is currently name-based, so a generic tool like
  `fetch` that mutates via a `method` argument is classified read-only. Argument-
  aware classification is on the roadmap; until then, treat the plan as a strong
  default, not a proof.
- **Contain execution.** Foreguard is a preview/policy layer, not a sandbox. It
  does not stop code that a tool *does* run from doing whatever it wants.

The classification engine is `kedge_core`; see
[kedge's SECURITY.md](https://github.com/nlj3/kedge/blob/main/SECURITY.md) for the
underlying threat model.
