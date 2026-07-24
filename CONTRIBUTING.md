# Contributing to Foreguard

Thanks for your interest. Foreguard is a security-sensitive tool (it decides what
an AI agent is allowed to do), so changes are held to a high bar — but small,
well-tested contributions are very welcome.

## Prerequisites

- A recent stable Rust toolchain (see `rust-toolchain.toml`).
- `rustup component add rustfmt clippy`.

## Before you open a PR

CI runs all of these with warnings denied — run them locally first:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

## Expectations

- **Every behavior change ships with a test.** Classification changes ship with a
  regression test encoding the exact case.
- **Fail safe.** When in doubt, the default is the more restrictive one — an
  ambiguous tool is treated as *mutating*, never read-only.
- **Honest claims.** Don't describe a capability the code doesn't have.

## The engine lives in kedge

Foreguard's classifier is `kedge_core` from
[kedge](https://github.com/nlj3/kedge). Fixes to classification logic usually
belong upstream in kedge; Foreguard consumes it.

## Reporting a vulnerability

Please do not open a public issue for anything exploitable — see
[`SECURITY.md`](SECURITY.md).
