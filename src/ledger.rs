//! Append-only, **tamper-evident** audit ledger.
//!
//! With `--ledger <path>`, the proxy records one JSON line per tool call: what the
//! agent asked for, how Foreguard classified it, whether untrusted data was driving
//! it, how policy ruled, and what actually happened (forwarded, dry-run, executed,
//! denied, or policy-denied). The result is a replayable, greppable record of a whole
//! agent session — the answer to "what did my agent actually try to do, and what did
//! we let through?"
//!
//! ## Why it's tamper-evident
//!
//! An audit trail is only worth anything if you can tell whether it was edited after
//! the fact. Each entry carries a small `_fg` integrity envelope —
//! `{ seq, prev, hash }` — where `hash = SHA-256(prev ‖ seq ‖ canonical-payload)` and
//! `prev` is the previous entry's hash. That chains the records: changing any field
//! of any entry changes its hash, which breaks the `prev` link of *every* entry after
//! it, so [`verify`] can pin the exact line where a log was edited, truncated, or
//! reordered. Append-only and flushed per line, so a crash mid-session still leaves an
//! intact chain up to that point.
//!
//! This is **detection, not prevention**: someone with write access can still rewrite
//! the *whole* chain from the tampered point on. Defeating that needs an external
//! anchor — a signed head, or a Merkle root published to a transparency log — which is
//! where the hosted control plane goes next. The hash chain is the local, offline,
//! inspectable foundation those build on.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The `prev` link of the very first entry — a fixed sentinel so genesis is
/// unambiguous and the chain has a defined root.
const GENESIS: &str = "genesis";

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
    /// How a Cedar policy influenced this call, when one was loaded:
    /// `"blocked"` (a `forbid` matched) or `"authorized"` (a `permit` matched).
    /// Absent when no policy applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<&'a str>,
    /// `"forwarded"`, `"dry-run"`, `"executed"`, `"denied"`, or `"policy-denied"`.
    pub decision: &'a str,
    pub arguments: &'a Value,
}

/// A handle to the append-only ledger file, carrying the running chain state.
pub struct Ledger {
    file: File,
    /// The sequence number the next appended entry will carry.
    seq: u64,
    /// The hash of the last entry written — the `prev` link for the next one.
    prev_hash: String,
}

impl Ledger {
    /// Open (creating if needed) the ledger for appending. If the file already holds
    /// hashed entries, the chain is *continued* from the last one, so a reopened
    /// ledger stays a single unbroken chain rather than restarting at genesis.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let (seq, prev_hash) = std::fs::read_to_string(path)
            .ok()
            .and_then(|s| last_chain_state(&s))
            .unwrap_or((0, GENESIS.to_string()));
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file,
            seq,
            prev_hash,
        })
    }

    /// Append one entry as a JSON line, flushed immediately, extending the hash
    /// chain. Best-effort: a write error is swallowed so auditing never breaks the
    /// proxy (but the chain state is only advanced once the line is on disk).
    pub fn append(&mut self, entry: &Entry) {
        // Canonicalize the payload (Value → string) so the hash is reproducible at
        // verify time no matter how fields are ordered.
        let Ok(payload) = serde_json::to_value(entry) else {
            return;
        };
        let hash = chain_hash(&self.prev_hash, self.seq, &canonical(&payload));

        let Value::Object(mut map) = payload else {
            return;
        };
        map.insert(
            "_fg".to_string(),
            json!({ "seq": self.seq, "prev": self.prev_hash, "hash": hash }),
        );
        if let Ok(mut line) = serde_json::to_string(&Value::Object(map)) {
            line.push('\n');
            if self.file.write_all(line.as_bytes()).is_ok() {
                let _ = self.file.flush();
                self.prev_hash = hash;
                self.seq += 1;
            }
        }
    }
}

/// Canonical bytes of a payload value: serialize the `Value` to a string. Both
/// `append` (from the `Entry`) and [`verify`] (from the parsed line, minus `_fg`)
/// route through `Value → String`, so the representation — and thus the hash — is
/// identical on both sides.
fn canonical(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

/// One link of the hash chain: `SHA-256(prev ‖ seq ‖ canonical-payload)`, hex-encoded.
/// The separators keep the fields unambiguous so no two distinct inputs collide by
/// running together.
fn chain_hash(prev: &str, seq: u64, canon: &str) -> String {
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update([b'\n']);
    h.update(seq.to_string().as_bytes());
    h.update([b'\n']);
    h.update(canon.as_bytes());
    hex(&h.finalize())
}

/// Lowercase hex encoding, without pulling in a crate for it.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The `(next_seq, prev_hash)` to resume a chain from an existing ledger's tail, or
/// `None` if the last line carries no `_fg` envelope (an empty or legacy file).
fn last_chain_state(contents: &str) -> Option<(u64, String)> {
    let last = contents.lines().rev().find(|l| !l.trim().is_empty())?;
    let v: Value = serde_json::from_str(last).ok()?;
    let fg = v.get("_fg")?;
    let seq = fg.get("seq")?.as_u64()?;
    let hash = fg.get("hash")?.as_str()?.to_string();
    Some((seq + 1, hash))
}

/// The outcome of verifying a ledger's hash chain.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifyReport {
    /// Entries verified intact (all of them, if `intact`).
    pub entries: usize,
    /// True when the whole chain checked out.
    pub intact: bool,
    /// The 1-based line where verification first failed, if any.
    pub broken_line: Option<usize>,
    /// A human-readable reason for the failure.
    pub detail: Option<String>,
}

/// Verify the hash chain of a ledger file.
pub fn verify(path: &Path) -> std::io::Result<VerifyReport> {
    Ok(verify_str(&std::fs::read_to_string(path)?))
}

/// Verify the hash chain of ledger *contents* — the testable core of [`verify`].
/// Walks the entries in order, checking that each one's `prev` links to the previous
/// hash, its `seq` increments, and its content still hashes to the stored value.
/// Stops at the first break and reports where and why.
pub fn verify_str(contents: &str) -> VerifyReport {
    let mut prev = GENESIS.to_string();
    let mut expected_seq = 0u64;
    let mut count = 0usize;

    for (i, line) in contents.lines().enumerate() {
        let lineno = i + 1;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            return broken(count, lineno, "line is not valid JSON");
        };
        let Some(fg) = v.get("_fg") else {
            return broken(count, lineno, "entry has no `_fg` integrity envelope");
        };
        let (Some(seq), Some(stored_prev), Some(stored_hash)) = (
            fg.get("seq").and_then(Value::as_u64),
            fg.get("prev").and_then(Value::as_str),
            fg.get("hash").and_then(Value::as_str),
        ) else {
            return broken(count, lineno, "`_fg` envelope is malformed");
        };

        if stored_prev != prev {
            return broken(
                count,
                lineno,
                format!(
                    "chain link broken: expected prev {prev}, found {stored_prev} \
                     (an entry was inserted, deleted, or reordered)"
                ),
            );
        }
        if seq != expected_seq {
            return broken(
                count,
                lineno,
                format!("sequence gap: expected {expected_seq}, found {seq}"),
            );
        }

        // Recompute the hash over the payload — everything except the `_fg` envelope.
        let mut payload = v.clone();
        if let Value::Object(map) = &mut payload {
            map.remove("_fg");
        }
        if chain_hash(stored_prev, seq, &canonical(&payload)) != stored_hash {
            return broken(
                count,
                lineno,
                "entry content does not match its hash (it was edited)",
            );
        }

        prev = stored_hash.to_string();
        expected_seq += 1;
        count += 1;
    }

    VerifyReport {
        entries: count,
        intact: true,
        broken_line: None,
        detail: None,
    }
}

fn broken(entries: usize, line: usize, detail: impl Into<String>) -> VerifyReport {
    VerifyReport {
        entries,
        intact: false,
        broken_line: Some(line),
        detail: Some(detail.into()),
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

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("fg_ledger_{}_{}.jsonl", name, std::process::id()))
    }

    fn sample<'a>(ts: u64, tool: &'a str, args: &'a Value) -> Entry<'a> {
        Entry {
            ts,
            tool,
            kind: "mutation",
            risk: Some("high"),
            effect: None,
            taint: None,
            policy: None,
            decision: "dry-run",
            arguments: args,
        }
    }

    #[test]
    fn appends_one_json_line_per_entry_and_omits_empty_fields() {
        let path = tmp("omit");
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
                policy: None,
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
                policy: None,
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
        // And the chain verifies end to end.
        assert!(verify_str(&content).intact);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_untouched_chain_verifies() {
        let path = tmp("intact");
        let _ = std::fs::remove_file(&path);
        {
            let mut l = Ledger::open(&path).unwrap();
            for i in 0..3 {
                l.append(&sample(i, "write_file", &json!({"path": format!("f{i}")})));
            }
        }
        let report = verify(&path).unwrap();
        assert_eq!(
            report,
            VerifyReport {
                entries: 3,
                intact: true,
                broken_line: None,
                detail: None
            }
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn editing_an_entry_is_detected_at_that_line() {
        let path = tmp("edit");
        let _ = std::fs::remove_file(&path);
        {
            let mut l = Ledger::open(&path).unwrap();
            for i in 0..3 {
                l.append(&sample(i, "write_file", &json!({"path": format!("f{i}")})));
            }
        }
        // Tamper with the middle entry's payload, leaving its `_fg.hash` unchanged.
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        lines[1] = lines[1].replace("\"decision\":\"dry-run\"", "\"decision\":\"executed\"");
        let tampered = lines.join("\n");

        let report = verify_str(&tampered);
        assert!(!report.intact);
        assert_eq!(report.broken_line, Some(2), "the edited line is pinpointed");
        assert_eq!(report.entries, 1, "one entry verified before the break");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn deleting_or_reordering_an_entry_breaks_the_chain() {
        let path = tmp("delete");
        let _ = std::fs::remove_file(&path);
        {
            let mut l = Ledger::open(&path).unwrap();
            for i in 0..3 {
                l.append(&sample(i, "write_file", &json!({"path": format!("f{i}")})));
            }
        }
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();

        // Drop the middle entry: line 2 (now the old third) breaks the prev link.
        let deleted = format!("{}\n{}", lines[0], lines[2]);
        let report = verify_str(&deleted);
        assert!(!report.intact);
        assert_eq!(report.broken_line, Some(2));

        // Swap the last two entries: the reorder also breaks linkage.
        let reordered = format!("{}\n{}\n{}", lines[0], lines[2], lines[1]);
        assert!(!verify_str(&reordered).intact);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_chain_continues_across_a_reopen() {
        let path = tmp("reopen");
        let _ = std::fs::remove_file(&path);
        {
            let mut l = Ledger::open(&path).unwrap();
            l.append(&sample(1, "a", &json!({})));
        }
        {
            // Reopen and append more — must continue the same chain, not restart.
            let mut l = Ledger::open(&path).unwrap();
            l.append(&sample(2, "b", &json!({})));
            l.append(&sample(3, "c", &json!({})));
        }
        let report = verify(&path).unwrap();
        assert!(report.intact, "reopened chain stays unbroken");
        assert_eq!(report.entries, 3);
        let _ = std::fs::remove_file(&path);
    }
}
