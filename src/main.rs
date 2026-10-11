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
mod diff;
mod ecosystem;
mod effect;
mod gateway;
mod ledger;
mod mcp;
mod policy;
mod promote;
mod proxy;
mod report;
mod signing;
mod spend;
mod taint;
mod ui;
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
        /// Ask for approval on a local web page instead of the terminal.
        ///
        /// Use this whenever an MCP host spawns Foreguard for you (Claude
        /// Desktop, Cursor, VS Code): those have no controlling terminal, so the
        /// `/dev/tty` prompt cannot be shown and every mutation is denied by
        /// default. Loopback only, and the URL carries a secret token.
        #[arg(long, value_name = "ADDR", num_args = 0..=1, default_missing_value = "127.0.0.1:7878")]
        ui: Option<String>,
        /// Authorize each tool call against a **Cedar policy file**.
        ///
        /// A satisfied `forbid` hard-blocks the call (it never executes, even under
        /// `--approve`); a satisfied `permit` pre-authorizes a mutation to run
        /// without prompting; anything neither permitted nor forbidden keeps
        /// Foreguard's default behavior. Policies see the call as
        /// `context.{tool,risk,mutating,tainted,session_calls,session_cost,args.*}`.
        #[arg(long, value_name = "PATH")]
        policy: Option<std::path::PathBuf>,
        /// Pull the Cedar policy from a URL instead of a file (e.g. the control
        /// plane's `/v1/policy`), so a fleet enforces one centrally-managed policy.
        /// The bearer token is read from `FOREGUARD_INGEST_TOKEN`, never the CLI.
        #[arg(long, value_name = "URL", conflicts_with = "policy")]
        policy_url: Option<String>,
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

    /// Meter LLM spend against a budget, and **hard-stop** a runaway.
    ///
    /// Reads model-API responses as JSON lines on stdin (Anthropic or OpenAI usage
    /// shapes), prices each against `--budget`, and the moment cumulative spend
    /// crosses the budget it refuses every further request — the kill switch for the
    /// retry loop that would otherwise burn the budget many times over. This is the
    /// deterministic core; a live HTTP gateway is a thin front-end over it.
    Meter {
        /// Budget ceiling in dollars (e.g. `--budget 5` for $5.00). Omit to meter
        /// only, never blocking.
        #[arg(long, value_name = "DOLLARS")]
        budget: Option<f64>,
        /// Model to assume when a response omits its own `model` field.
        #[arg(long, value_name = "NAME")]
        model: Option<String>,
        /// Override a model's price: `name=INPUT:OUTPUT` in cents per million tokens
        /// (repeatable). The built-in prices are illustrative defaults.
        #[arg(long, value_name = "SPEC")]
        price: Vec<String>,
        /// Emit one JSON object per line instead of the human-readable report.
        #[arg(long)]
        json: bool,
    },

    /// Run a live **LLM spend gateway** in front of a model API.
    ///
    /// Point an agent's `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` at this loopback
    /// address; every model call is forwarded to `--upstream` and metered, and once
    /// cumulative spend crosses `--budget` the next request is refused before it is
    /// sent. The caller's own auth header is passed through — Foreguard stores no keys.
    Gateway {
        /// Upstream API base URL to forward to (e.g. `https://api.anthropic.com`).
        #[arg(long, value_name = "URL")]
        upstream: String,
        /// Loopback address to listen on.
        #[arg(long, value_name = "ADDR", default_value = "127.0.0.1:8787")]
        addr: String,
        /// Budget ceiling in dollars (e.g. `--budget 5`). Omit to meter only.
        #[arg(long, value_name = "DOLLARS")]
        budget: Option<f64>,
        /// Model to assume when a response omits its own `model` field.
        #[arg(long, value_name = "NAME")]
        model: Option<String>,
        /// Override a model's price: `name=INPUT:OUTPUT` in cents per million tokens
        /// (repeatable). The built-in prices are illustrative defaults.
        #[arg(long, value_name = "SPEC")]
        price: Vec<String>,
    },

    /// Report a local ledger to the control plane's `/v1/ingest`.
    ///
    /// Ships the ledger's *new* entries (those past the seq the server last
    /// accepted) plus the current spend, so the fleet dashboard reflects this
    /// instance. Re-run it on a schedule; only new entries are sent each time. The
    /// bearer token is read from `FOREGUARD_INGEST_TOKEN`, never the command line.
    Report {
        /// Path to a ledger written by `proxy --ledger`.
        ledger: std::path::PathBuf,
        /// Control-plane base URL (e.g. `https://cp.example.com`).
        #[arg(long, value_name = "URL")]
        to: String,
        /// This instance's id in the fleet.
        #[arg(long, value_name = "ID")]
        instance: String,
        /// Current cumulative spend in cents to report (from `foreguard meter`/gateway).
        #[arg(long, value_name = "CENTS")]
        spent_cents: Option<u64>,
        /// Sign the reported ledger head with this Ed25519 key (from `foreguard
        /// keygen`), so the control plane can prove the trail wasn't rewritten.
        #[arg(long, value_name = "PATH")]
        key: Option<std::path::PathBuf>,
    },

    /// Generate an Ed25519 signing key for `report --key`.
    ///
    /// Writes the private key (owner-only) and prints the public key. The control
    /// plane pins that public key on the first signed report; no separate
    /// registration step is needed.
    Keygen {
        /// Where to write the private signing key.
        #[arg(long, value_name = "PATH", default_value = "foreguard-signing.key")]
        out: std::path::PathBuf,
    },

    /// Verify the tamper-evidence of a recorded ledger's hash chain.
    ///
    /// Recomputes the chain written by `proxy --ledger` and reports whether it is
    /// intact, or the exact line where it was edited, truncated, or reordered. Exits
    /// non-zero when the ledger has been tampered with.
    Verify {
        /// Path to a ledger file written by `proxy --ledger`.
        ledger: std::path::PathBuf,
    },

    /// Score the classifier against what real MCP servers declare about their
    /// own tools, from the catalogues captured in `catalogues/`.
    ///
    /// Prints agreement, false negatives (a mutation judged read-only, the class
    /// that matters) and false positives, per server and in total. Offline and
    /// deterministic: the catalogues are embedded in the binary.
    Ecosystem,
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
            ui,
            policy,
            policy_url,
            server,
        } => {
            // Load the policy up front so a malformed file/URL fails before we spawn
            // the server, not mid-session. `--policy-url` pulls central policy; the
            // token (if the endpoint needs one) comes from the environment.
            let engine = match (policy_url, policy) {
                (Some(url), _) => {
                    let token = std::env::var("FOREGUARD_INGEST_TOKEN").ok();
                    let src = report::fetch_policy_source(&url, token.as_deref())
                        .await
                        .with_context(|| format!("pulling policy from {url}"))?;
                    Some(policy::PolicyEngine::parse(&src).context("parsing pulled policy")?)
                }
                (None, Some(path)) => Some(policy::PolicyEngine::from_file(&path)?),
                (None, None) => None,
            };
            proxy::run_proxy(server, approve, taint, ledger, ui, engine).await
        }
        Command::Promote {
            ledger,
            all,
            yes,
            dry_run,
            server,
        } => promote::run_promote(ledger, server, all, yes, dry_run).await,
        Command::Meter {
            budget,
            model,
            price,
            json,
        } => cmd_meter(budget, model, price, json),
        Command::Gateway {
            upstream,
            addr,
            budget,
            model,
            price,
        } => {
            if let Some(d) = budget {
                if !d.is_finite() || d < 0.0 {
                    anyhow::bail!("--budget must be a non-negative dollar amount (got {d})");
                }
            }
            let mut prices = spend::PriceTable::builtin();
            for spec in &price {
                let (name, p) =
                    parse_price_spec(spec).with_context(|| format!("parsing --price {spec:?}"))?;
                prices.set(&name, p);
            }
            gateway::run_gateway(addr, upstream, budget, model, prices).await
        }
        Command::Report {
            ledger,
            to,
            instance,
            spent_cents,
            key,
        } => {
            let token = std::env::var("FOREGUARD_INGEST_TOKEN").map_err(|_| {
                anyhow::anyhow!(
                    "set FOREGUARD_INGEST_TOKEN to the control-plane ingest token before reporting"
                )
            })?;
            report::run_report(ledger, to, instance, spent_cents, key, token).await
        }
        Command::Keygen { out } => {
            let seed = signing::generate_seed()?;
            signing::write_seed(&out, &seed)?;
            let kp = signing::KeyPair::from_seed(&seed);
            println!("wrote signing key to {}", out.display());
            println!(
                "public key (pinned by the control plane on first signed report):\n  {}",
                kp.public_base64()
            );
            Ok(())
        }
        Command::Verify { ledger } => cmd_verify(&ledger),
        Command::Ecosystem => {
            print!("{}", ecosystem::render(&ecosystem::score()));
            Ok(())
        }
    }
}

/// Format a cents amount as dollars, e.g. `450` → `$4.50`.
fn dollars(cents: u64) -> String {
    format!("${}.{:02}", cents / 100, cents % 100)
}

/// Verify a ledger's hash chain and report intact / tampered.
fn cmd_verify(path: &std::path::Path) -> Result<()> {
    let report =
        ledger::verify(path).with_context(|| format!("reading ledger {}", path.display()))?;
    if report.intact {
        println!(
            "✔  ledger intact — {} entr{} verified, hash chain unbroken.",
            report.entries,
            if report.entries == 1 { "y" } else { "ies" }
        );
        Ok(())
    } else {
        println!(
            "✗  ledger TAMPERED at line {} — {}",
            report.broken_line.unwrap_or(0),
            report.detail.as_deref().unwrap_or("chain broken")
        );
        println!(
            "   {} entr{} verified before the break.",
            report.entries,
            if report.entries == 1 { "y" } else { "ies" }
        );
        // Non-zero exit so a caller (CI, a compliance check) can react.
        std::process::exit(2);
    }
}

/// Parse a `--price name=INPUT:OUTPUT` spec (cents per million tokens).
fn parse_price_spec(spec: &str) -> Result<(String, spend::Price)> {
    let (name, rates) = spec.split_once('=').context("expected name=INPUT:OUTPUT")?;
    let (input, output) = rates.split_once(':').context("expected INPUT:OUTPUT")?;
    Ok((
        name.to_string(),
        spend::Price {
            input_per_mtok_cents: input.trim().parse().context("INPUT must be an integer")?,
            output_per_mtok_cents: output.trim().parse().context("OUTPUT must be an integer")?,
        },
    ))
}

/// Meter a stream of model-API responses (JSONL on stdin) against a budget, hard-
/// stopping the moment cumulative spend crosses it.
fn cmd_meter(
    budget: Option<f64>,
    model: Option<String>,
    price: Vec<String>,
    json: bool,
) -> Result<()> {
    use std::io::BufRead;

    // Reject nonsense up front: a negative or non-finite budget would otherwise
    // saturate to 0 cents and silently refuse *every* request — fail-safe, but
    // baffling to debug.
    if let Some(d) = budget {
        if !d.is_finite() || d < 0.0 {
            anyhow::bail!("--budget must be a non-negative dollar amount (got {d})");
        }
    }
    let budget_cents = budget.map(|d| (d * 100.0).round() as u64);
    let mut prices = spend::PriceTable::builtin();
    for spec in &price {
        let (name, p) =
            parse_price_spec(spec).with_context(|| format!("parsing --price {spec:?}"))?;
        prices.set(&name, p);
    }
    let mut meter = spend::SpendMeter::new(budget_cents, prices);
    let default_model = model.unwrap_or_else(|| "unknown".into());

    if let Some(b) = budget_cents {
        eprintln!(
            "foreguard meter: budget {} — requests are refused once cumulative spend crosses it.",
            dollars(b)
        );
    } else {
        eprintln!("foreguard meter: no budget set — metering only, nothing will be blocked.");
    }

    let (mut metered, mut refused, mut no_usage) = (0u64, 0u64, 0u64);
    let mut tripped = false;

    for l in std::io::stdin().lock().lines() {
        let l = l.context("reading stdin")?;
        let l = l.trim();
        if l.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(l) else {
            eprintln!("… skipped a line that isn't JSON");
            continue;
        };
        // The model is top-level for non-streaming/OpenAI, but nested under
        // `message` in Anthropic's streaming `message_start` — check both so a
        // streamed response isn't mispriced as the unknown-model default.
        let model_name = v
            .get("model")
            .or_else(|| v.get("message").and_then(|m| m.get("model")))
            .and_then(|x| x.as_str())
            .unwrap_or(&default_model)
            .to_string();
        let Some(usage) = spend::Usage::from_response(&v) else {
            no_usage += 1;
            continue;
        };

        // Pre-flight: a live gateway checks the budget *before* forwarding, so a
        // request over budget is never sent. Here that means it's refused without
        // being priced or added to the total.
        if !meter.allow_request() {
            refused += 1;
            let spent = meter.spent_cents();
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "blocked", "model": model_name,
                        "spent_cents": spent, "budget_cents": budget_cents
                    })
                );
            } else {
                println!(
                    "  ⛔  {model_name:<22} REFUSED — spend {} ≥ budget {}",
                    dollars(spent),
                    dollars(budget_cents.unwrap_or(0))
                );
            }
            continue;
        }

        match meter.charge(&model_name, &usage) {
            spend::Charge::Ok {
                cost_cents,
                spent_cents,
            } => {
                metered += 1;
                if json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "event": "metered", "model": model_name,
                            "cost_cents": cost_cents, "spent_cents": spent_cents
                        })
                    );
                } else {
                    println!(
                        "  ✔  {model_name:<22} +{} → {} spent",
                        dollars(cost_cents),
                        dollars(spent_cents)
                    );
                }
                if meter.is_blocked() && !tripped {
                    tripped = true;
                    if !json {
                        println!(
                            "  ⛔  BUDGET REACHED at {} — kill switch tripped; further requests \
                             will be refused.",
                            dollars(spent_cents)
                        );
                    }
                }
            }
            spend::Charge::Blocked {
                spent_cents,
                budget_cents,
            } => {
                refused += 1;
                if json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "event": "blocked", "model": model_name,
                            "spent_cents": spent_cents, "budget_cents": budget_cents
                        })
                    );
                } else {
                    println!(
                        "  ⛔  {model_name:<22} REFUSED — spend {} ≥ budget {}",
                        dollars(spent_cents),
                        dollars(budget_cents)
                    );
                }
            }
        }
    }

    eprintln!(
        "foreguard meter: {} metered, {} refused{} · total spend {}.",
        metered,
        refused,
        if no_usage > 0 {
            format!(", {no_usage} without usage")
        } else {
            String::new()
        },
        dollars(meter.spent_cents())
    );

    // A tripped kill switch is a non-zero exit, so a caller (or CI) can react.
    if meter.is_blocked() {
        std::process::exit(3);
    }
    Ok(())
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
