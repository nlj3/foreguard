//! Append-only audit ledger.
//!
//! With `--ledger <path>`, the proxy records one JSON line per tool call: what the
//! agent asked for, how Foreguard classified it, whether untrusted data was driving
//! it, and what actually happened (forwarded, dry-run, executed, or denied). The
//! result is a replayable, greppable record of a whole agent session — the answer to
//! "what did my agent actually try to do, and what did we let through?"
//!
//! Append-only and flushed per line, so a crash mid-session still leaves every
//! decision up to that point on disk. This is an honest audit log, not a
//! tamper-proof one: anything with write access to the file can edit it.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::Value;

/// One recorded decision. Fields that don't apply (a read-only call has no risk,
/// effect, or taint) are omitted from the JSON.
#[derive(Serialize)]
pub struct Entry<'a> {
    /// Unix milliseconds when the decision was made.
    pub ts: u64,
    pub tool: &'a str,
    /// `"read-only"` or `"mutation"`.
    pub kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk: Option<&'a str>,
    /// The concrete effect, e.g. `deletes /etc/passwd`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effect: Option<&'a str>,
    /// The tainted token, when untrusted data was found driving this call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taint: Option<&'a str>,
    /// `"forwarded"`, `"dry-run"`, `"executed"`, or `"denied"`.
    pub decision: &'a str,
    pub arguments: &'a Value,
}

/// A handle to the append-only ledger file.
pub struct Ledger {
    file: File,
}

impl Ledger {
    /// Open (creating if needed) the ledger for appending.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { file })
    }

    /// Append one entry as a JSON line, flushed immediately. Best-effort: a write
    /// error is swallowed so auditing never breaks the proxy.
    pub fn append(&mut self, entry: &Entry) {
        if let Ok(mut line) = serde_json::to_string(entry) {
            line.push('\n');
            let _ = self.file.write_all(line.as_bytes());
            let _ = self.file.flush();
        }
    }
}

/// Current time in Unix milliseconds (0 if the clock is before the epoch).
pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn appends_one_json_line_per_entry_and_omits_empty_fields() {
        let path =
            std::env::temp_dir().join(format!("fg_ledger_test_{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);

        {
            let mut l = Ledger::open(&path).unwrap();
            l.append(&Entry {
                ts: 1,
                tool: "send_email",
                kind: "mutation",
                risk: Some("high"),
                effect: Some("sends to attacker@evil.com"),
                taint: Some("attacker@evil.com"),
                decision: "denied",
                arguments: &json!({"to": "attacker@evil.com"}),
            });
            l.append(&Entry {
                ts: 2,
                tool: "read_file",
                kind: "read-only",
                risk: None,
                effect: None,
                taint: None,
                decision: "forwarded",
                arguments: &json!({"path": "/y"}),
            });
        }

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2, "one JSON line per entry");

        let e1: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(e1["tool"], "send_email");
        assert_eq!(e1["decision"], "denied");
        assert_eq!(e1["taint"], "attacker@evil.com");

        let e2: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(e2["kind"], "read-only");
        // Inapplicable fields are omitted, not null-filled.
        assert!(e2.get("risk").is_none());
        assert!(e2.get("taint").is_none());

        let _ = std::fs::remove_file(&path);
    }
}
