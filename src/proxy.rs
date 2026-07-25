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

/// What to do with one message from the host.
enum Action {
    /// Not a mutating tool call — pass it straight through to the server.
    Forward,
    /// A mutating tool call — don't forward it; reply to the host directly and log.
    Intercept { response: String, log: String },
}

/// Decide, from a single host→server JSON-RPC line, whether to forward it or
/// intercept it as a dry-run. Pure and testable: anything that isn't a mutating
/// `tools/call` is forwarded verbatim (transparent).
fn decide(line: &str) -> Action {
    let Ok(msg) = serde_json::from_str::<Value>(line) else {
        return Action::Forward; // not JSON we understand — stay transparent
    };
    if msg.get("method").and_then(Value::as_str) != Some("tools/call") {
        return Action::Forward;
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
    match verdict.safety {
        ToolSafety::ReadOnly => Action::Forward,
        ToolSafety::Mutating { risk } => {
            let why = verdict
                .arg_reason
                .map(|r| format!(" ({r})"))
                .unwrap_or_default();
            // What it would concretely do — first line, for the log + agent message.
            let effect = crate::effect::describe(name, &args)
                .map(|e| e.lines().next().unwrap_or("").to_string());
            let effect_sentence = effect
                .as_deref()
                .map(|e| format!(" Intended action: {e}."))
                .unwrap_or_default();
            let effect_tag = effect
                .as_deref()
                .map(|e| format!("  ·  {e}"))
                .unwrap_or_default();
            let text = format!(
                "[FOREGUARD DRY-RUN] mutating tool `{name}` ({} risk){why} was intercepted and \
                 NOT executed — no files, APIs, or data were touched.{effect_sentence} Proceed as \
                 if it succeeded; re-run without foreguard to execute for real.",
                risk.as_str()
            );
            let response = json!({
                "jsonrpc": "2.0",
                "id": msg.get("id").cloned().unwrap_or(Value::Null),
                "result": { "content": [{ "type": "text", "text": text }], "isError": false }
            })
            .to_string();
            let log = format!(
                "⚠  foreguard intercepted `{name}` ({} risk){why} — NOT executed{effect_tag}",
                risk.as_str()
            );
            Action::Intercept { response, log }
        }
    }
}

/// Launch `server` (program + args) and proxy MCP stdio to/from it, previewing
/// mutating tool calls.
pub async fn run_proxy(server: Vec<String>) -> Result<()> {
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

    eprintln!(
        "foreguard: previewing mutating tool calls to `{program}` — read-only tools run for real, \
         mutations are intercepted and NOT executed."
    );

    // host → foreguard → server (intercepting mutations). On host close, dropping
    // `server_in` closes the server's stdin so it can finish and flush.
    let host_out_a = host_out.clone();
    let host_to_server = async move {
        let mut host_in = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(l)) = host_in.next_line().await {
            match decide(&l) {
                Action::Forward => {
                    if server_in.write_all(l.as_bytes()).await.is_err()
                        || server_in.write_all(b"\n").await.is_err()
                        || server_in.flush().await.is_err()
                    {
                        break;
                    }
                }
                Action::Intercept { response, log } => {
                    eprintln!("{log}");
                    write_line(&host_out_a, &response).await;
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
        matches!(decide(line), Action::Intercept { .. })
    }

    #[test]
    fn read_only_tool_call_is_forwarded() {
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"x"}}}"#;
        assert!(!is_intercepted(line));
    }

    #[test]
    fn mutating_tool_call_is_intercepted_with_a_synthetic_success() {
        let line = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"delete_file","arguments":{"path":"/etc/passwd"}}}"#;
        match decide(line) {
            Action::Intercept { response, log } => {
                assert!(log.contains("delete_file"));
                let v: Value = serde_json::from_str(&response).unwrap();
                assert_eq!(v["id"], 7); // echoes the request id
                assert_eq!(v["result"]["isError"], false); // synthetic success
                assert!(v["result"]["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .contains("DRY-RUN"));
            }
            Action::Forward => panic!("a mutating call must be intercepted"),
        }
    }

    #[test]
    fn argument_hidden_mutation_is_intercepted() {
        // `fetch` looks read-only; the DELETE method makes it a mutation.
        let line = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fetch","arguments":{"method":"DELETE"}}}"#;
        assert!(is_intercepted(line));
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
