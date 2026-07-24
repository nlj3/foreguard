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
    arguments: serde_json::Value,
}

/// The full preview: what would run, what would be intercepted.
#[derive(Debug, Serialize)]
struct Plan {
    entries: Vec<PlanEntry>,
    read_only: usize,
    intercepted: usize,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Plan { input, json } => cmd_plan(&input, json),
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
        entries.push(PlanEntry {
            tool: c.name.clone(),
            verdict,
            mutating,
            risk,
            reason: v.arg_reason,
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
