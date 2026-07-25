//! `foreguard promote <ledger> -- <server…>` — replay a recorded plan for real.
//!
//! This closes the loop the ledger opened. Record a session with `--ledger` (in
//! dry-run, so nothing executes), review the plan offline on your own time, then
//! promote the exact calls you approve against a live server. Foreguard becomes a
//! minimal **MCP client** here: it performs the `initialize` handshake and then
//! sends each recorded `tools/call` *verbatim* — same tool, same arguments — and
//! prints the server's real response. What you previewed is what runs, even hours
//! later.
//!
//! By default it promotes only the *mutations* in the ledger (read-only calls
//! already ran during the original session) and confirms each on the terminal
//! before executing. Fail-safe: no confirmation (or no terminal) means skip.

use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader, Lines};
use tokio::process::{ChildStdin, ChildStdout, Command};

/// One recorded call selected for replay, plus context for the review display.
struct Call {
    tool: String,
    arguments: Value,
    effect: Option<String>,
    taint: Option<String>,
    prior: Option<String>,
}

/// Parse a ledger file, selecting the calls to promote. Mutations only, unless
/// `include_read_only` (read-only calls already ran in the original session).
fn select_calls(contents: &str, include_read_only: bool) -> Vec<Call> {
    contents
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter_map(|e| {
            let tool = e.get("tool")?.as_str()?.to_string();
            let kind = e.get("kind").and_then(Value::as_str).unwrap_or("");
            if kind != "mutation" && !include_read_only {
                return None;
            }
            Some(Call {
                tool,
                arguments: e.get("arguments").cloned().unwrap_or(Value::Null),
                effect: e.get("effect").and_then(Value::as_str).map(str::to_string),
                taint: e.get("taint").and_then(Value::as_str).map(str::to_string),
                prior: e
                    .get("decision")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            })
        })
        .collect()
}

/// Replay the selected calls from `ledger` against the live `server`.
pub async fn run_promote(ledger: PathBuf, server: Vec<String>, all: bool, yes: bool) -> Result<()> {
    let contents = std::fs::read_to_string(&ledger)
        .with_context(|| format!("reading ledger {}", ledger.display()))?;
    let calls = select_calls(&contents, all);
    if calls.is_empty() {
        eprintln!(
            "foreguard: nothing to promote in {} (no recorded {}).",
            ledger.display(),
            if all { "tool calls" } else { "mutations" }
        );
        return Ok(());
    }

    let (program, args) = server
        .split_first()
        .context("`foreguard promote` needs a server command after `--`")?;

    eprintln!(
        "foreguard: promoting {} recorded call(s) from {} against `{program}`.",
        calls.len(),
        ledger.display()
    );

    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("launching MCP server `{program}`"))?;
    let mut stdin = child.stdin.take().context("server stdin")?;
    let mut stdout = BufReader::new(child.stdout.take().context("server stdout")?).lines();

    initialize(&mut stdin, &mut stdout)
        .await
        .context("MCP initialize handshake")?;

    let (mut promoted, mut skipped) = (0usize, 0usize);
    let mut id = 1000i64;
    for c in &calls {
        let effect = c
            .effect
            .as_deref()
            .map(|e| format!(" — {e}"))
            .unwrap_or_default();
        let prior = c
            .prior
            .as_deref()
            .map(|d| format!("  [recorded: {d}]"))
            .unwrap_or_default();
        let taint = c
            .taint
            .as_deref()
            .map(|t| format!("  ⛔ tainted by {t}"))
            .unwrap_or_default();
        eprintln!("\n▶  {}{}{}{}", c.tool, effect, prior, taint);

        if !yes {
            eprint!("    Execute this for real now? [y/N] ");
            if !crate::proxy::approved_on_tty().await {
                eprintln!("    ✗ skipped");
                skipped += 1;
                continue;
            }
        }

        id += 1;
        let resp = call_tool(&mut stdin, &mut stdout, id, &c.tool, &c.arguments).await?;
        eprintln!("    ✔ executed");
        println!("{}", summarize(&resp));
        promoted += 1;
    }

    eprintln!("\nforeguard: promoted {promoted}, skipped {skipped}.");
    let _ = child.kill().await;
    Ok(())
}

/// MCP `initialize` handshake: request, await the result, then send the
/// `notifications/initialized` acknowledgement the spec requires before tool calls.
async fn initialize(
    stdin: &mut ChildStdin,
    stdout: &mut Lines<BufReader<ChildStdout>>,
) -> Result<()> {
    let init = json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "foreguard", "version": env!("CARGO_PKG_VERSION") }
        }
    });
    send(stdin, &init).await?;
    await_response(stdout, 1).await?;
    send(
        stdin,
        &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    )
    .await?;
    Ok(())
}

/// Send one recorded `tools/call` verbatim and return the matching response.
async fn call_tool(
    stdin: &mut ChildStdin,
    stdout: &mut Lines<BufReader<ChildStdout>>,
    id: i64,
    name: &str,
    arguments: &Value,
) -> Result<Value> {
    let req = json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": { "name": name, "arguments": arguments }
    });
    send(stdin, &req).await?;
    await_response(stdout, id).await
}

/// Write one newline-terminated JSON-RPC message, flushed.
async fn send<W: AsyncWrite + Unpin>(w: &mut W, msg: &Value) -> Result<()> {
    w.write_all(msg.to_string().as_bytes()).await?;
    w.write_all(b"\n").await?;
    w.flush().await?;
    Ok(())
}

/// Read lines until one is a JSON-RPC message with the given id; skip everything
/// else (server notifications, logs). Errors if the server closes first.
async fn await_response<R: AsyncBufRead + Unpin>(lines: &mut Lines<R>, id: i64) -> Result<Value> {
    while let Some(line) = lines.next_line().await? {
        if let Ok(msg) = serde_json::from_str::<Value>(&line) {
            if msg.get("id").and_then(Value::as_i64) == Some(id) {
                return Ok(msg);
            }
        }
    }
    bail!("server closed the connection before responding to request {id}")
}

/// Render a response for the user: text content, an error, or the raw result.
fn summarize(resp: &Value) -> String {
    if let Some(err) = resp.get("error") {
        return format!("ERROR: {err}");
    }
    let mut text = String::new();
    if let Some(content) = resp.pointer("/result/content").and_then(Value::as_array) {
        for item in content {
            if let Some(t) = item.get("text").and_then(Value::as_str) {
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(t);
            }
        }
    }
    if !text.is_empty() {
        text
    } else {
        resp.get("result")
            .map(|r| r.to_string())
            .unwrap_or_else(|| resp.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEDGER: &str = concat!(
        r#"{"ts":1,"tool":"fetch","kind":"read-only","decision":"forwarded","arguments":{"url":"u"}}"#,
        "\n",
        r#"{"ts":2,"tool":"write_file","kind":"mutation","risk":"medium","effect":"writes 3 bytes to a.txt","decision":"dry-run","arguments":{"path":"a.txt","content":"hi"}}"#,
        "\n",
        r#"{"ts":3,"tool":"send_email","kind":"mutation","risk":"high","taint":"evil@x.com","decision":"denied","arguments":{"to":"evil@x.com"}}"#,
        "\n",
        "not json at all",
    );

    #[test]
    fn selects_only_mutations_by_default() {
        let calls = select_calls(LEDGER, false);
        assert_eq!(calls.len(), 2, "read-only and garbage lines are excluded");
        assert_eq!(calls[0].tool, "write_file");
        assert_eq!(calls[0].arguments["content"], "hi"); // exact args preserved
        assert_eq!(calls[1].tool, "send_email");
        assert_eq!(calls[1].taint.as_deref(), Some("evil@x.com"));
        assert_eq!(calls[1].prior.as_deref(), Some("denied"));
    }

    #[test]
    fn all_flag_includes_read_only_calls() {
        let calls = select_calls(LEDGER, true);
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].tool, "fetch");
    }

    #[test]
    fn summarize_extracts_text_content_and_errors() {
        let ok = json!({"result":{"content":[{"type":"text","text":"done"}]}});
        assert_eq!(summarize(&ok), "done");
        let err = json!({"error":{"code":-32601,"message":"nope"}});
        assert!(summarize(&err).starts_with("ERROR:"));
    }
}
