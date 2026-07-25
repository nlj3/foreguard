//! A transparent **MCP dry-run proxy**.
//!
//! This is what turns Foreguard from a CLI into a layer any agent can use. Point
//! an MCP host (Claude Code, Cursor, Cline) at `foreguard proxy -- <server…>`
//! instead of the tool server directly. Foreguard launches the real server, speaks
//! MCP to the host on one side and to the server on the other, and forwards
//! everything **except** mutating `tools/call`s — those it **intercepts and
//! previews**, returning a synthetic success so the agent keeps planning while
//! nothing is actually written, sent, or deleted.
//!
//! Transport is newline-delimited JSON-RPC 2.0 on stdio (the MCP stdio spec).
//! Stdout carries the protocol to the host — so every human-facing line goes to
//! **stderr**.

use std::process::Stdio;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::Mutex;

use crate::classify::classify_call;
use kedge_core::ToolSafety;

/// The outcome of inspecting one host→server message.
enum Inspection {
    /// Not a mutating tool call — forward it verbatim.
    Passthrough,
    /// A mutating tool call — the caller decides: dry-run it, or (with --approve)
    /// prompt the human and, if approved, forward the original call to execute.
    Mutation(Preview),
}

/// Everything needed to log, prompt for, or synthesize a response to a mutation.
struct Preview {
    /// The synthetic dry-run success to return when the call is NOT executed.
    synthetic: String,
    /// One-line stderr log (dry-run mode).
    log: String,
    /// Interactive approval prompt (approve mode).
    prompt: String,
}

/// Inspect one host→server JSON-RPC line. Pure and testable: anything that isn't a
/// mutating `tools/call` is `Passthrough`.
fn inspect(line: &str) -> Inspection {
    let Ok(msg) = serde_json::from_str::<Value>(line) else {
        return Inspection::Passthrough; // not JSON we understand — stay transparent
    };
    if msg.get("method").and_then(Value::as_str) != Some("tools/call") {
        return Inspection::Passthrough;
    }
    let params = msg.get("params");
    let name = params
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let args = params
        .and_then(|p| p.get("arguments"))
        .cloned()
        .unwrap_or(Value::Null);

    let verdict = classify_call(name, &args);
    let ToolSafety::Mutating { risk } = verdict.safety else {
        return Inspection::Passthrough;
    };
    let why = verdict
        .arg_reason
        .map(|r| format!(" ({r})"))
        .unwrap_or_default();
    let effect =
        crate::effect::describe(name, &args).map(|e| e.lines().next().unwrap_or("").to_string());
    let effect_sentence = effect
        .as_deref()
        .map(|e| format!(" Intended action: {e}."))
        .unwrap_or_default();
    let effect_tag = effect
        .as_deref()
        .map(|e| format!("  ·  {e}"))
        .unwrap_or_default();
    let text = format!(
        "[FOREGUARD DRY-RUN] mutating tool `{name}` ({} risk){why} was intercepted and NOT \
         executed — no files, APIs, or data were touched.{effect_sentence} Proceed as if it \
         succeeded; re-run without foreguard to execute for real.",
        risk.as_str()
    );
    let synthetic = json!({
        "jsonrpc": "2.0",
        "id": msg.get("id").cloned().unwrap_or(Value::Null),
        "result": { "content": [{ "type": "text", "text": text }], "isError": false }
    })
    .to_string();
    let log = format!(
        "⚠  foreguard intercepted `{name}` ({} risk){why} — NOT executed{effect_tag}",
        risk.as_str()
    );
    let prompt = format!(
        "⚠  `{name}` ({} risk){why}{effect_tag}\n    Execute this for real? [y/N] ",
        risk.as_str()
    );
    Inspection::Mutation(Preview {
        synthetic,
        log,
        prompt,
    })
}

/// Does this terminal answer mean "yes, execute"? Only an explicit y/yes counts —
/// everything else (including a bare Enter or garbage) is a no. Fail-safe by default.
fn is_affirmative(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Ask the human on the controlling terminal (`/dev/tty`) to approve. Fail-safe: if
/// there's no terminal, or anything goes wrong, the answer is "no" (dry-run).
async fn approved_on_tty() -> bool {
    let answer = tokio::task::spawn_blocking(|| {
        use std::io::BufRead;
        let tty = std::fs::File::open("/dev/tty").ok()?;
        let mut line = String::new();
        std::io::BufReader::new(tty).read_line(&mut line).ok()?;
        Some(line)
    })
    .await
    .ok()
    .flatten()
    .unwrap_or_default();
    is_affirmative(&answer)
}

/// Launch `server` (program + args) and proxy MCP stdio to/from it, previewing
/// mutating tool calls.
///
/// With `approve = false` (default), every mutation is dry-run: intercepted and
/// answered with a synthetic success. With `approve = true` (promote-to-live), each
/// mutation pauses for an interactive y/N on the terminal — approve and the *exact*
/// call you saw is forwarded to execute for real; deny (or no terminal) and it stays
/// a dry-run.
pub async fn run_proxy(server: Vec<String>, approve: bool) -> Result<()> {
    let (program, args) = server
        .split_first()
        .context("`foreguard proxy` needs a server command after `--`")?;

    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // stderr inherited: the wrapped server's own logs pass through untouched.
        .spawn()
        .with_context(|| format!("launching MCP server `{program}`"))?;

    let mut server_in = child.stdin.take().context("server stdin")?;
    let server_out = child.stdout.take().context("server stdout")?;

    // Both directions write to the host's stdout, so it's shared behind a mutex.
    let host_out = Arc::new(Mutex::new(tokio::io::stdout()));

    if approve {
        eprintln!(
            "foreguard: promote-to-live for `{program}` — read-only tools run for real; each \
             mutation pauses for your approval, and only what you approve executes."
        );
    } else {
        eprintln!(
            "foreguard: previewing mutating tool calls to `{program}` — read-only tools run for \
             real, mutations are intercepted and NOT executed."
        );
    }

    // host → foreguard → server (intercepting mutations). On host close, dropping
    // `server_in` closes the server's stdin so it can finish and flush.
    let host_out_a = host_out.clone();
    let host_to_server = async move {
        let mut host_in = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(l)) = host_in.next_line().await {
            match inspect(&l) {
                Inspection::Passthrough => {
                    if !forward_line(&mut server_in, &l).await {
                        break;
                    }
                }
                Inspection::Mutation(p) if approve => {
                    // Promote-to-live: show the exact effect, ask, and execute only
                    // if the human says yes. The agent is blocked awaiting this
                    // tool result, so pausing for approval is safe.
                    eprint!("{}", p.prompt);
                    if approved_on_tty().await {
                        eprintln!("✔  approved — executing for real");
                        if !forward_line(&mut server_in, &l).await {
                            break;
                        }
                    } else {
                        eprintln!("✗  denied — dry-run, nothing executed");
                        write_line(&host_out_a, &p.synthetic).await;
                    }
                }
                Inspection::Mutation(p) => {
                    eprintln!("{}", p.log);
                    write_line(&host_out_a, &p.synthetic).await;
                }
            }
        }
        drop(server_in);
    };

    // server → host (verbatim). Runs until the server closes its stdout.
    let host_out_b = host_out.clone();
    let server_to_host = async move {
        let mut server_lines = BufReader::new(server_out).lines();
        while let Ok(Some(l)) = server_lines.next_line().await {
            write_line(&host_out_b, &l).await;
        }
    };

    // Run both directions concurrently; finish when both ends are closed.
    tokio::join!(host_to_server, server_to_host);
    let _ = child.kill().await;
    Ok(())
}

/// Forward one raw line to the server's stdin, newline-terminated and flushed.
/// Returns `false` on any write error (the server closed its stdin — stop pumping).
async fn forward_line(server_in: &mut tokio::process::ChildStdin, line: &str) -> bool {
    server_in.write_all(line.as_bytes()).await.is_ok()
        && server_in.write_all(b"\n").await.is_ok()
        && server_in.flush().await.is_ok()
}

/// Write one newline-terminated line to the shared host stdout, flushing.
async fn write_line(out: &Arc<Mutex<tokio::io::Stdout>>, line: &str) {
    let mut o = out.lock().await;
    let _ = o.write_all(line.as_bytes()).await;
    let _ = o.write_all(b"\n").await;
    let _ = o.flush().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_intercepted(line: &str) -> bool {
        matches!(inspect(line), Inspection::Mutation(_))
    }

    #[test]
    fn read_only_tool_call_is_forwarded() {
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"x"}}}"#;
        assert!(!is_intercepted(line));
    }

    #[test]
    fn mutating_tool_call_is_intercepted_with_a_synthetic_success() {
        let line = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"delete_file","arguments":{"path":"/etc/passwd"}}}"#;
        match inspect(line) {
            Inspection::Mutation(p) => {
                assert!(p.log.contains("delete_file"));
                // The approval prompt shows the concrete effect and defaults to No.
                assert!(p.prompt.contains("deletes /etc/passwd"));
                assert!(p.prompt.contains("[y/N]"));
                let v: Value = serde_json::from_str(&p.synthetic).unwrap();
                assert_eq!(v["id"], 7); // echoes the request id
                assert_eq!(v["result"]["isError"], false); // synthetic success
                assert!(v["result"]["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .contains("DRY-RUN"));
            }
            Inspection::Passthrough => panic!("a mutating call must be intercepted"),
        }
    }

    #[test]
    fn argument_hidden_mutation_is_intercepted() {
        // `fetch` looks read-only; the DELETE method makes it a mutation.
        let line = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fetch","arguments":{"method":"DELETE"}}}"#;
        assert!(is_intercepted(line));
    }

    #[test]
    fn only_explicit_yes_promotes_to_live() {
        // Approve (execute for real).
        for yes in ["y", "Y", "yes", "YES", " y ", "yes\n", "\ty\r\n"] {
            assert!(is_affirmative(yes), "{yes:?} should approve");
        }
        // Everything else stays a dry-run — including a bare Enter (fail-safe default).
        for no in ["", "\n", "n", "no", "yeah", "yep", "sure", "1", "delete"] {
            assert!(!is_affirmative(no), "{no:?} must NOT approve");
        }
    }

    #[test]
    fn non_tool_traffic_is_forwarded_untouched() {
        // initialize, tools/list, notifications, and garbage all pass through.
        assert!(!is_intercepted(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#
        ));
        assert!(!is_intercepted(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#
        ));
        assert!(!is_intercepted("not json at all"));
    }
}
