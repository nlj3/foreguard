//! Argument-aware classification — the difference between a *fast* preview and a
//! *trustworthy* one.
//!
//! kedge's [`classify`] is name-based and fail-safe, which catches most mutations.
//! But a tool *named* for a read — `fetch`, `request`, `query` — can still mutate
//! through its **arguments**: `method: "DELETE"`, a `DELETE` SQL statement, an `rm`
//! in a command. A preview that misses those is worse than none: it gives false
//! confidence. This module inspects the arguments and **upgrades** a verdict when
//! they reveal a hidden mutation.
//!
//! Like the name classifier, arguments may only make a call *more* restricted,
//! never less — a mutating name stays mutating no matter how benign its args look.

use kedge_core::{classify, Risk, ToolSafety};
use serde_json::Value;

/// The result of classifying a full tool call (name + arguments).
pub struct Verdict {
    pub safety: ToolSafety,
    /// When the *arguments* (not the name) are what flagged the mutation, a short
    /// human explanation — shown in the Mutation Plan so the call is legible.
    pub arg_reason: Option<String>,
}

/// Classify a tool call by name **and** arguments. Fail-safe and upgrade-only.
pub fn classify_call(name: &str, args: &Value) -> Verdict {
    let base = classify(name);
    // The name already flagged a mutation — arguments can't downgrade it, so stop.
    if base.is_mutating() {
        return Verdict {
            safety: base,
            arg_reason: None,
        };
    }
    // The name looks read-only: this is the dangerous case. Inspect the arguments.
    match args_reveal_mutation(args) {
        Some((risk, reason)) => Verdict {
            safety: ToolSafety::Mutating { risk },
            arg_reason: Some(reason),
        },
        None => Verdict {
            safety: base,
            arg_reason: None,
        },
    }
}

/// Does any argument reveal a mutation on an otherwise read-looking tool?
fn args_reveal_mutation(args: &Value) -> Option<(Risk, String)> {
    let obj = args.as_object()?;

    // 1. HTTP method — a read-looking `fetch`/`request` with a writing method.
    for key in ["method", "http_method"] {
        if let Some(m) = obj.get(key).and_then(Value::as_str) {
            if let Some(risk) = http_method_mutation(m) {
                return Some((
                    risk,
                    format!(
                        "`{key}: {}` is a writing HTTP method",
                        m.trim().to_ascii_uppercase()
                    ),
                ));
            }
        }
    }

    // 2. Operation/action discriminator — an arg that *names* the real action.
    //    Reuse the engine on the value (deny-wins applies here too).
    for key in ["operation", "action", "verb", "mode", "op"] {
        if let Some(v) = obj.get(key).and_then(Value::as_str) {
            if let ToolSafety::Mutating { risk } = classify(v) {
                return Some((
                    risk,
                    format!("`{key}: {}` is a mutating operation", truncate(v, 40)),
                ));
            }
        }
    }

    // 3. SQL — a `query`/`sql` whose leading keyword mutates the database.
    for key in ["query", "sql", "statement"] {
        if let Some(q) = obj.get(key).and_then(Value::as_str) {
            if let Some((risk, verb)) = sql_mutation(q) {
                return Some((
                    risk,
                    format!("SQL `{verb}` in `{key}` mutates the database"),
                ));
            }
        }
    }

    // 4. Shell — a `command`/`cmd`/`script` with a destructive program or redirect.
    for key in ["command", "cmd", "script"] {
        if let Some(c) = obj.get(key).and_then(Value::as_str) {
            if let Some(reason) = shell_mutation(c) {
                return Some((Risk::High, format!("`{key}`: {reason}")));
            }
        }
    }

    None
}

/// Writing HTTP methods → mutating. Read methods and unknowns → no upgrade.
fn http_method_mutation(m: &str) -> Option<Risk> {
    match m.trim().to_ascii_uppercase().as_str() {
        "GET" | "HEAD" | "OPTIONS" | "TRACE" => None,
        "DELETE" => Some(Risk::High),
        "POST" | "PUT" | "PATCH" => Some(Risk::Medium),
        _ => None,
    }
}

const SQL_HIGH: &[&str] = &["DROP", "TRUNCATE", "DELETE", "ALTER", "GRANT", "REVOKE"];
const SQL_MED: &[&str] = &["INSERT", "UPDATE", "CREATE", "REPLACE", "MERGE", "UPSERT"];

/// The leading SQL keyword, if it's a mutation. `SELECT`/`WITH`/`SHOW` → `None`.
fn sql_mutation(q: &str) -> Option<(Risk, &'static str)> {
    let first = q
        .split(|c: char| !c.is_ascii_alphabetic())
        .find(|s| !s.is_empty())?
        .to_ascii_uppercase();
    if let Some(v) = SQL_HIGH.iter().find(|v| **v == first) {
        return Some((Risk::High, v));
    }
    if let Some(v) = SQL_MED.iter().find(|v| **v == first) {
        return Some((Risk::Medium, v));
    }
    None
}

/// Programs that unambiguously mutate the host — a curated denylist (not the name
/// classifier, to avoid flagging `git status`-style read commands).
const DESTRUCTIVE_SHELL: &[&str] = &[
    "rm", "rmdir", "dd", "mkfs", "shred", "mv", "chmod", "chown", "truncate", "kill", "killall",
];

/// A destructive program or a write redirect anywhere in a command line.
fn shell_mutation(cmd: &str) -> Option<String> {
    if cmd.contains('>') {
        return Some("writes via redirect (`>`)".to_string());
    }
    for tok in cmd.split(|c: char| c.is_whitespace() || matches!(c, '|' | ';' | '&' | '(')) {
        let base = tok.trim().rsplit('/').next().unwrap_or(tok);
        if DESTRUCTIVE_SHELL.contains(&base) {
            return Some(format!("runs `{base}`"));
        }
    }
    None
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn is_mut(name: &str, args: serde_json::Value) -> bool {
        classify_call(name, &args).safety.is_mutating()
    }

    #[test]
    fn http_method_upgrades_a_read_looking_fetch() {
        // The headline case: `fetch` is a read verb, but the method mutates.
        assert!(is_mut("fetch", json!({"url": "x", "method": "DELETE"})));
        assert!(is_mut("request", json!({"method": "post"})));
        // GET stays read-only.
        assert!(!is_mut("fetch", json!({"url": "x", "method": "GET"})));
        assert!(!is_mut("fetch", json!({"url": "x"})));
        // and the reason is surfaced
        let v = classify_call("fetch", &json!({"method": "DELETE"}));
        assert!(v.arg_reason.unwrap().contains("DELETE"));
    }

    #[test]
    fn sql_verb_upgrades_a_read_looking_query() {
        assert!(is_mut("query", json!({"sql": "UPDATE users SET x=1"})));
        assert!(is_mut(
            "query",
            json!({"query": "  delete from t where id=1"})
        ));
        assert!(is_mut("run_query", json!({"query": "DROP TABLE users"})));
        // SELECT stays read-only.
        assert!(!is_mut("query", json!({"sql": "SELECT * FROM users"})));
    }

    #[test]
    fn operation_discriminator_is_classified() {
        assert!(is_mut("resource", json!({"operation": "delete"})));
        assert!(is_mut("execute", json!({"action": "create_user"})));
        assert!(!is_mut("get_thing", json!({"operation": "read"})));
    }

    #[test]
    fn destructive_command_in_a_read_looking_tool() {
        assert!(is_mut("check", json!({"command": "rm -rf /tmp/x"})));
        assert!(is_mut("analyze", json!({"cmd": "echo hi > out.txt"})));
        // a genuinely read-only command is not flagged
        assert!(!is_mut("check", json!({"command": "cat /etc/hostname"})));
    }

    #[test]
    fn a_mutating_name_stays_mutating_and_args_never_downgrade() {
        // delete_file is mutating by name; benign args can't make it read-only.
        let v = classify_call("delete_file", &json!({"method": "GET"}));
        assert!(v.safety.is_mutating());
        assert!(
            v.arg_reason.is_none(),
            "name caught it; no arg reason needed"
        );
    }
}

/// Adversarial regression suite.
///
/// These are not hypotheticals. Every case here was fired at a live
/// `@modelcontextprotocol/server-filesystem` through the proxy, and the run was
/// validated with a positive control: the same `write_file` call, with Foreguard
/// removed from the path, really does overwrite the target. So each variant below
/// represents a mutation that would have landed on disk had the classifier let it
/// through.
///
/// Two of these are caught by the fail-safe default rather than by recognising the
/// trick (the fullwidth homoglyph and the zero-width space). That is worth stating
/// plainly: the outcome is correct because anything unrecognised is treated as
/// mutating, not because Foreguard normalises Unicode. Fail-safe covers the
/// attacks nobody enumerated, which is the whole reason it is the default.
#[cfg(test)]
mod evasion {
    use super::*;
    use serde_json::json;

    fn mutating(name: &str) -> bool {
        classify_call(name, &json!({"path": "/tmp/x", "content": "E"}))
            .safety
            .is_mutating()
    }

    /// Every one of these is really a write. None may be classified read-only.
    #[test]
    fn name_obfuscation_never_downgrades_a_write() {
        let variants = [
            ("plain", "write_file"),
            ("upper", "WRITE_FILE"),
            ("title", "Write_File"),
            ("mixed", "wRiTe_FiLe"),
            ("hyphen", "write-file"),
            ("dot", "write.file"),
            ("camel", "writeFile"),
            ("space", "write file"),
            ("padded", "  write_file  "),
            ("compound, read verb first", "read_and_write_file"),
            ("compound, get first", "get_or_delete_file"),
            ("reassuring prefix", "safe_write_file"),
            ("lying prefix", "definitely_read_only_write_file"),
            ("fullwidth homoglyph", "ｗrite_file"),
            ("zero-width space", "write\u{200b}file"),
        ];
        for (label, name) in variants {
            assert!(
                mutating(name),
                "ESCAPE: {label} ({name:?}) was classified read-only; a real write would have executed"
            );
        }
    }

    /// A read-looking name whose *arguments* carry the mutation.
    #[test]
    fn argument_hidden_mutations_never_downgrade() {
        let cases = [
            (
                "http delete",
                "fetch",
                json!({"url": "https://x", "method": "DELETE"}),
            ),
            ("sql drop", "query", json!({"sql": "DROP TABLE users"})),
            (
                "shell rm",
                "check",
                json!({"command": "rm -rf /tmp/sandbox"}),
            ),
            (
                "operation field",
                "read_thing",
                json!({"operation": "delete", "path": "/tmp/k"}),
            ),
        ];
        for (label, name, args) in cases {
            assert!(
                classify_call(name, &args).safety.is_mutating(),
                "ESCAPE: {label} ({name}) was classified read-only"
            );
        }
    }

    /// The other direction. Genuinely read-only tools from the real filesystem
    /// server must not be flagged, or the proxy is too noisy to leave installed.
    #[test]
    fn real_read_only_tools_are_not_false_positives() {
        for name in [
            "read_file",
            "read_text_file",
            "read_media_file",
            "read_multiple_files",
            "list_directory",
            "list_directory_with_sizes",
            "search_files",
            "get_file_info",
            "list_allowed_directories",
        ] {
            assert!(
                !classify_call(name, &json!({"path": "/tmp/x"}))
                    .safety
                    .is_mutating(),
                "FALSE POSITIVE: {name} is read-only on the real server but was intercepted"
            );
        }
    }

    /// The real server's genuinely destructive tools. These must always intercept.
    #[test]
    fn real_mutating_tools_are_always_caught() {
        for name in ["write_file", "edit_file", "create_directory", "move_file"] {
            assert!(
                mutating(name),
                "ESCAPE: {name} mutates on the real server but was let through"
            );
        }
    }
}
