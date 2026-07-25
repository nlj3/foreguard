//! # Foreguard
//!
//! **Preview what an AI agent is about to do — before it does it.**
//!
//! Foreguard is a dry-run trust layer for autonomous agents. Give it the tool
//! calls an agent wants to make and it produces a **Mutation Plan**: which calls
//! are read-only (safe to run) and which would *mutate* your files, APIs, or data
//! — flagged, previewed, and **not executed**. You review the plan, then run for
//! real when you're ready.
//!
//! The classification engine is [`kedge_core`] — the same fail-safe, deny-wins
//! classifier that powers kedge's Shadow-Guard. Foreguard is the focused product
//! extracted from that primitive.
//!
//! ```text
//! $ echo '[{"name":"read_file","arguments":{"path":"x"}},
//!          {"name":"delete_file","arguments":{"path":"/etc/passwd"}}]' | foreguard plan
//! ```

use std::io::Read;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use kedge_core::ToolSafety;
use serde::{Deserialize, Serialize};

mod classify;
mod effect;
mod ledger;
mod mcp;
mod promote;
mod proxy;
mod taint;
use classify::classify_call;

#[derive(Parser)]
#[command(
    name = "foreguard",
    version,
    about = "Preview what your AI agent is about to do — before it does it.",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Produce a Mutation Plan from a list of tool calls.
    ///
    /// Input is a JSON array of `{ "name": ..., "arguments": ... }`, read from a
    /// file or from stdin (`-`). Every call is classified: read-only calls would
    /// run for real; mutating calls are flagged and would be intercepted.
    Plan {
        /// Path to a JSON file of tool calls, or `-` for stdin.
        #[arg(default_value = "-")]
        input: String,
        /// Emit the plan as JSON instead of the human-readable preview.
        #[arg(long)]
        json: bool,
    },
    /// Run as a transparent MCP dry-run proxy in front of a tool server.
    ///
    /// Point an MCP host (Claude Code, Cursor, …) at this instead of the server:
    /// `foreguard proxy -- npx -y @modelcontextprotocol/server-filesystem .`
    /// Read-only tools run for real; mutating tool calls are intercepted and
    /// previewed — nothing mutating executes.
    Proxy {
        /// Promote-to-live: pause on each mutation for an interactive y/N. Approve
        /// and the *exact* call you previewed executes for real; deny (or no
        /// terminal) and it stays a dry-run. Without this, all mutations are dry-run.
        #[arg(long)]
        approve: bool,
        /// Context Foresight: taint the output of untrusted-source tools (web
        /// fetches, inbox reads, …) and, when that data flows into a mutating call
        /// — the agent "Rule of Two" violation — force human approval for that call,
        /// even without `--approve`. Best-effort prompt-injection defense.
        #[arg(long)]
        taint: bool,
        /// Append a JSON-lines audit trail of every tool call and Foreguard
        /// decision (forwarded / dry-run / executed / denied, with taint verdicts)
        /// to this file.
        #[arg(long, value_name = "PATH")]
        ledger: Option<std::path::PathBuf>,
        /// The MCP server command to wrap, given after `--`.
        #[arg(last = true, required = true)]
        server: Vec<String>,
    },
    /// Promote a recorded ledger: replay its calls against a live server.
    ///
    /// Record a session with `proxy --ledger plan.jsonl` (dry-run, nothing
    /// executes), review it, then run the exact calls for real:
    /// `foreguard promote plan.jsonl -- npx -y @modelcontextprotocol/server-filesystem .`
    /// Mutations only by default; each is confirmed on the terminal unless `--yes`.
    Promote {
        /// Path to a ledger file written by `proxy --ledger`.
        ledger: std::path::PathBuf,
        /// Also replay read-only calls (they already ran in the original session).
        #[arg(long)]
        all: bool,
        /// Skip the per-call confirmation — you already reviewed the ledger.
        #[arg(long)]
        yes: bool,
        /// Print the replay plan and exit — launch nothing, execute nothing.
        #[arg(long)]
        dry_run: bool,
        /// The MCP server command to run against, given after `--` (not needed with
        /// `--dry-run`).
        #[arg(last = true)]
        server: Vec<String>,
    },
}

/// One tool call an agent wants to make.
#[derive(Debug, Deserialize)]
struct ToolCall {
    name: String,
    #[serde(default)]
    arguments: serde_json::Value,
}

/// One line of the Mutation Plan.
#[derive(Debug, Serialize)]
struct PlanEntry {
    tool: String,
    /// `"run"` (read-only, executes for real) or `"intercept"` (mutating, previewed).
    verdict: &'static str,
    mutating: bool,
    risk: Option<&'static str>,
    /// Present when the *arguments* (not the name) revealed the mutation.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    /// What the mutation would concretely do (e.g. "deletes /etc/passwd").
    #[serde(skip_serializing_if = "Option::is_none")]
    effect: Option<String>,
    arguments: serde_json::Value,
}

/// The full preview: what would run, what would be intercepted.
#[derive(Debug, Serialize)]
struct Plan {
    entries: Vec<PlanEntry>,
    read_only: usize,
    intercepted: usize,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Plan { input, json } => cmd_plan(&input, json),
        Command::Proxy {
            approve,
            taint,
            ledger,
            server,
        } => proxy::run_proxy(server, approve, taint, ledger).await,
        Command::Promote {
            ledger,
            all,
            yes,
            dry_run,
            server,
        } => promote::run_promote(ledger, server, all, yes, dry_run).await,
    }
}

fn cmd_plan(input: &str, json: bool) -> Result<()> {
    let raw = read_input(input)?;
    let calls: Vec<ToolCall> = serde_json::from_str(&raw)
        .context("parsing tool calls (expected a JSON array of {name, arguments})")?;
    let plan = build_plan(&calls);
    if json {
        println!("{}", serde_json::to_string_pretty(&plan)?);
    } else {
        print_plan(&plan);
    }
    Ok(())
}

fn read_input(input: &str) -> Result<String> {
    if input == "-" {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .context("reading stdin")?;
        Ok(s)
    } else {
        std::fs::read_to_string(input).with_context(|| format!("reading {input}"))
    }
}

/// Classify every call into the plan. This is the whole product in one function:
/// **fail-safe** (anything not clearly read-only is treated as mutating) and
/// **deny-wins** (a compound like `get_and_delete` is caught as mutating), courtesy
/// of `kedge_core::classify`.
fn build_plan(calls: &[ToolCall]) -> Plan {
    let mut entries = Vec::with_capacity(calls.len());
    let (mut read_only, mut intercepted) = (0usize, 0usize);
    for c in calls {
        let v = classify_call(&c.name, &c.arguments);
        let (verdict, mutating, risk) = match v.safety {
            ToolSafety::ReadOnly => {
                read_only += 1;
                ("run", false, None)
            }
            ToolSafety::Mutating { risk } => {
                intercepted += 1;
                ("intercept", true, Some(risk.as_str()))
            }
        };
        // Describe the concrete effect only for the calls we'd intercept.
        let effect = mutating
            .then(|| effect::describe(&c.name, &c.arguments))
            .flatten();
        entries.push(PlanEntry {
            tool: c.name.clone(),
            verdict,
            mutating,
            risk,
            reason: v.arg_reason,
            effect,
            arguments: c.arguments.clone(),
        });
    }
    Plan {
        entries,
        read_only,
        intercepted,
    }
}

fn print_plan(plan: &Plan) {
    println!("Foreguard — mutation preview\n");
    for e in &plan.entries {
        if e.mutating {
            let why = e
                .reason
                .as_deref()
                .map(|r| format!("  ← {r}"))
                .unwrap_or_default();
            println!(
                "  ⚠  {:<26} MUTATING ({}) — intercepted, NOT executed{}",
                e.tool,
                e.risk.unwrap_or("?"),
                why
            );
            if let Some(eff) = &e.effect {
                println!("       → {eff}");
            }
        } else {
            println!("  ✔  {:<26} read-only — would run for real", e.tool);
        }
    }
    println!(
        "\nPlan: {} mutation(s) would be intercepted · {} read-only call(s) would run.",
        plan.intercepted, plan.read_only
    );
    if plan.intercepted > 0 {
        println!(
            "Nothing was executed. Review the plan above, then run for real when you're ready."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(name: &str) -> ToolCall {
        ToolCall {
            name: name.into(),
            arguments: serde_json::json!({}),
        }
    }

    #[test]
    fn plan_separates_reads_from_mutations() {
        let calls = [call("read_file"), call("list_dir"), call("delete_file")];
        let plan = build_plan(&calls);
        assert_eq!(plan.read_only, 2);
        assert_eq!(plan.intercepted, 1);
        assert_eq!(plan.entries[0].verdict, "run");
        assert!(plan.entries[2].mutating);
        assert_eq!(plan.entries[2].risk, Some("high"));
    }

    #[test]
    fn deny_wins_catches_a_read_looking_mutation() {
        // The whole point of the engine: a name that *looks* read-only but mutates
        // must still be intercepted. `get_and_delete` starts with a read verb.
        let plan = build_plan(&[call("get_and_delete")]);
        assert_eq!(plan.intercepted, 1, "a compound mutation must be caught");
        assert!(plan.entries[0].mutating);
    }

    #[test]
    fn unknown_tool_fails_safe_to_mutating() {
        let plan = build_plan(&[call("frobnicate")]);
        assert_eq!(plan.intercepted, 1, "unknown tools are treated as mutating");
    }
}
