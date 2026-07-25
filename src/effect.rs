//! Describe the *effect* of a mutating call — the difference between "it mutates"
//! and "it deletes /etc/passwd".
//!
//! Given a mutating tool's name and arguments, produce a concise, human-readable
//! summary of the concrete action it would take, so the Mutation Plan is
//! actionable, not just a verdict. Best-effort and defensive: an unrecognized
//! shape falls back to a compact view of the arguments.

use serde_json::{Map, Value};

/// A one-or-few-line description of what a mutating call would do.
pub fn describe(name: &str, args: &Value) -> Option<String> {
    let obj = args.as_object()?;
    http(obj)
        .or_else(|| sql(obj))
        .or_else(|| shell(obj))
        .or_else(|| file(name, obj))
        .or_else(|| send(obj))
        .or_else(|| generic(obj))
}

/// First of `keys` present as a string.
fn get<'a>(obj: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|k| obj.get(*k).and_then(Value::as_str))
}

fn http(obj: &Map<String, Value>) -> Option<String> {
    let url = get(obj, &["url", "uri", "endpoint", "href"])?;
    let method = get(obj, &["method", "http_method", "verb"])
        .map(|m| m.trim().to_ascii_uppercase())
        .unwrap_or_else(|| "GET".into());
    let mut s = format!("{method} {}", truncate(url, 100));
    if let Some(b) = obj
        .get("body")
        .or_else(|| obj.get("data"))
        .or_else(|| obj.get("json"))
    {
        s.push_str(&format!("  (body: {})", value_preview(b, 60)));
    }
    Some(s)
}

fn sql(obj: &Map<String, Value>) -> Option<String> {
    let q = get(obj, &["sql", "statement"])?;
    Some(format!("SQL: {}", truncate(q, 120)))
}

fn shell(obj: &Map<String, Value>) -> Option<String> {
    let c = get(obj, &["command", "cmd", "script"])?;
    Some(format!("runs: {}", truncate(c, 120)))
}

fn file(name: &str, obj: &Map<String, Value>) -> Option<String> {
    let low = name.to_ascii_lowercase();
    // move / rename
    if ["move", "rename", "mv"].iter().any(|k| low.contains(k)) {
        if let (Some(from), Some(to)) = (
            get(obj, &["from", "source", "src", "path"]),
            get(obj, &["to", "dest", "destination"]),
        ) {
            return Some(format!("moves {from} → {to}"));
        }
    }
    let path = get(
        obj,
        &["path", "file", "filename", "filepath", "target", "dest"],
    )?;
    if ["delet", "remove", "unlink", "rm", "wipe", "erase"]
        .iter()
        .any(|k| low.contains(k))
    {
        return Some(format!("deletes {path}"));
    }
    if let Some(content) = get(obj, &["content", "contents", "text", "data", "body"]) {
        return Some(format!(
            "writes {} bytes to {path}:\n{}",
            content.len(),
            snippet(content, 3, 100)
        ));
    }
    Some(format!("modifies {path}"))
}

fn send(obj: &Map<String, Value>) -> Option<String> {
    let to = get(
        obj,
        &["to", "recipient", "channel", "chat_id", "phone", "email"],
    )?;
    let subj = get(obj, &["subject", "title"])
        .map(|s| format!(" — “{}”", truncate(s, 60)))
        .unwrap_or_default();
    Some(format!("sends to {to}{subj}"))
}

fn generic(obj: &Map<String, Value>) -> Option<String> {
    if obj.is_empty() {
        return None;
    }
    Some(format!(
        "args: {}",
        value_preview(&Value::Object(obj.clone()), 100)
    ))
}

/// Trim + char-safe truncate with an ellipsis.
fn truncate(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.chars().count() <= max {
        return s.to_string();
    }
    let taken: String = s.chars().take(max).collect();
    format!("{taken}…")
}

fn value_preview(v: &Value, max: usize) -> String {
    truncate(&v.to_string(), max)
}

/// The first few lines of `content`, indented for display under the plan line.
fn snippet(content: &str, max_lines: usize, max_cols: usize) -> String {
    let mut out = String::new();
    for (i, line) in content.lines().take(max_lines).enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str("       ");
        out.push_str(&truncate(line, max_cols));
    }
    if content.lines().count() > max_lines {
        out.push_str("\n       …");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn d(name: &str, args: serde_json::Value) -> String {
        describe(name, &args).unwrap()
    }

    #[test]
    fn describes_a_delete() {
        assert_eq!(
            d("delete_file", json!({"path": "/etc/passwd"})),
            "deletes /etc/passwd"
        );
        assert_eq!(
            d("remove_key", json!({"target": "prod/secret"})),
            "deletes prod/secret"
        );
    }

    #[test]
    fn describes_an_http_call() {
        assert_eq!(
            d(
                "fetch",
                json!({"url": "https://api/users/42", "method": "delete"})
            ),
            "DELETE https://api/users/42"
        );
        assert!(d(
            "request",
            json!({"url": "https://x", "method": "POST", "body": {"a": 1}})
        )
        .contains("body:"));
    }

    #[test]
    fn describes_a_write_with_a_snippet() {
        let s = d(
            "write_file",
            json!({"path": "a.toml", "content": "port = 8080\nhost = x"}),
        );
        assert!(s.starts_with("writes 20 bytes to a.toml:"), "got: {s}");
        assert!(s.contains("port = 8080"));
    }

    #[test]
    fn describes_shell_sql_and_send() {
        assert_eq!(
            d("check", json!({"command": "rm -rf /tmp/x"})),
            "runs: rm -rf /tmp/x"
        );
        assert_eq!(
            d("query", json!({"sql": "DROP TABLE users"})),
            "SQL: DROP TABLE users"
        );
        assert_eq!(
            d("send_email", json!({"to": "a@b.c", "subject": "Hi"})),
            "sends to a@b.c — “Hi”"
        );
    }

    #[test]
    fn falls_back_to_compact_args() {
        let s = d("frobnicate", json!({"widget": "x"}));
        assert!(s.starts_with("args: "));
        assert!(s.contains("widget"));
    }
}
