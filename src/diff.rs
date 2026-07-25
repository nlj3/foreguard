//! Render what a mutation would actually change, as a diff.
//!
//! Foreguard's whole claim is that you can see what an agent is about to do.
//! "writes 142 bytes to config.toml" does not deliver that: it tells you a file
//! changes, not *what* changes. This module reads the file as it exists right
//! now and diffs it against what the agent proposes, so the preview shows the
//! before and after of a change that has not happened yet.
//!
//! Reading the target is deliberate. Foreguard already runs locally beside the
//! agent, and the read is the only way to make the preview real rather than
//! hypothetical. It is read-only, size-capped, and never touches a path the
//! agent did not already name in its own tool call.
//!
//! The diff itself is a plain LCS over lines. Preview-sized files do not need
//! anything cleverer, and it keeps the dependency list at zero.

use std::io::IsTerminal;

use serde_json::Value;

/// Files longer than this are summarised rather than diffed. Bounds both the
/// O(n·m) table and how much a hostile tool call can make us read.
const MAX_LINES: usize = 400;
/// Never read more than this from disk for a preview.
const MAX_BYTES: u64 = 512 * 1024;
/// Context lines kept either side of a change.
const CONTEXT: usize = 2;

/// Should we emit ANSI colour? Honours `NO_COLOR` and falls back to plain text
/// when stderr is not a terminal, so piped output stays clean.
fn use_color() -> bool {
    std::env::var_os("NO_COLOR").is_none() && std::io::stderr().is_terminal()
}

struct Paint {
    on: bool,
}

impl Paint {
    fn new() -> Self {
        Self { on: use_color() }
    }
    fn red(&self, s: &str) -> String {
        if self.on {
            format!("\x1b[31m{s}\x1b[0m")
        } else {
            s.into()
        }
    }
    fn green(&self, s: &str) -> String {
        if self.on {
            format!("\x1b[32m{s}\x1b[0m")
        } else {
            s.into()
        }
    }
    fn dim(&self, s: &str) -> String {
        if self.on {
            format!("\x1b[2m{s}\x1b[0m")
        } else {
            s.into()
        }
    }
}

/// One step of the line alignment.
#[derive(Debug, PartialEq)]
enum Op {
    Equal(usize, usize),
    Del(usize),
    Ins(usize),
}

/// Longest-common-subsequence alignment of two line slices.
fn align(a: &[&str], b: &[&str]) -> Vec<Op> {
    let (n, m) = (a.len(), b.len());
    // table[i][j] = LCS length of a[i..] and b[j..]
    let mut table = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            table[i][j] = if a[i] == b[j] {
                table[i + 1][j + 1] + 1
            } else {
                table[i + 1][j].max(table[i][j + 1])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    let mut ops = Vec::new();
    while i < n && j < m {
        if a[i] == b[j] {
            ops.push(Op::Equal(i, j));
            i += 1;
            j += 1;
        } else if table[i + 1][j] >= table[i][j + 1] {
            ops.push(Op::Del(i));
            i += 1;
        } else {
            ops.push(Op::Ins(j));
            j += 1;
        }
    }
    while i < n {
        ops.push(Op::Del(i));
        i += 1;
    }
    while j < m {
        ops.push(Op::Ins(j));
        j += 1;
    }
    ops
}

/// Which lines to show: changes plus a little context, with gaps elided.
fn visible(ops: &[Op]) -> Vec<bool> {
    let changed: Vec<bool> = ops.iter().map(|o| !matches!(o, Op::Equal(..))).collect();
    let mut show = vec![false; ops.len()];
    for (idx, &c) in changed.iter().enumerate() {
        if c {
            let lo = idx.saturating_sub(CONTEXT);
            let hi = (idx + CONTEXT).min(ops.len().saturating_sub(1));
            for s in show.iter_mut().take(hi + 1).skip(lo) {
                *s = true;
            }
        }
    }
    show
}

/// Read a file for previewing, if it is small enough to be worth showing.
fn read_capped(path: &str) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_BYTES {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// First present string among `keys`.
fn get<'a>(args: &'a Value, keys: &[&str]) -> Option<&'a str> {
    let obj = args.as_object()?;
    keys.iter()
        .find_map(|k| obj.get(*k).and_then(Value::as_str))
}

/// A rendered preview of the change a mutating call would make, or `None` when
/// the call is not a file mutation we can usefully diff.
pub fn render(tool: &str, args: &Value) -> Option<String> {
    let low = tool.to_ascii_lowercase();
    let path = get(
        args,
        &["path", "file", "filename", "filepath", "target", "dest"],
    )?;
    let p = Paint::new();

    let deleting = ["delet", "remove", "unlink", "rm", "wipe", "erase"]
        .iter()
        .any(|k| low.contains(k));

    if deleting {
        let body = read_capped(path);
        let mut out = format!("┌─ {}\n", p.red(&format!("delete {path}")));
        match body {
            Some(text) => {
                let lines: Vec<&str> = text.lines().collect();
                let shown = lines.len().min(6);
                for (n, l) in lines.iter().take(shown).enumerate() {
                    out.push_str(&format!("│ {:>3} {}\n", n + 1, p.red(&format!("- {l}"))));
                }
                if lines.len() > shown {
                    out.push_str(&format!(
                        "│     {}\n",
                        p.dim(&format!("… {} more lines", lines.len() - shown))
                    ));
                }
                out.push_str(&format!(
                    "└─ {}",
                    p.red(&format!("{} lines would be lost", lines.len()))
                ));
            }
            None => out.push_str(&format!("└─ {}", p.dim("(file not readable for preview)"))),
        }
        return Some(out);
    }

    // A write: diff the proposed content against what is on disk today.
    let proposed = get(args, &["content", "contents", "text", "data", "body"])?;
    let current = read_capped(path);
    let is_new = current.is_none();

    let cur_text = current.unwrap_or_default();
    let a: Vec<&str> = cur_text.lines().collect();
    let b: Vec<&str> = proposed.lines().collect();

    let header = if is_new {
        format!("┌─ {}\n", p.green(&format!("create {path}")))
    } else {
        format!("┌─ {path}\n")
    };

    if a.len() > MAX_LINES || b.len() > MAX_LINES {
        return Some(format!(
            "{header}│ {}\n└─ {} → {} lines",
            p.dim("(too large to diff inline)"),
            a.len(),
            b.len()
        ));
    }

    let ops = align(&a, &b);
    let show = visible(&ops);
    let (mut adds, mut dels) = (0usize, 0usize);
    let mut body = String::new();
    let mut skipping = false;

    for (idx, op) in ops.iter().enumerate() {
        match op {
            Op::Equal(i, _) => {
                if show[idx] {
                    skipping = false;
                    body.push_str(&format!("│ {:>3}   {}\n", i + 1, p.dim(a[*i])));
                } else if !skipping {
                    skipping = true;
                    body.push_str(&format!("│  {}\n", p.dim("⋮")));
                }
            }
            Op::Del(i) => {
                dels += 1;
                skipping = false;
                body.push_str(&format!(
                    "│ {:>3} {}\n",
                    i + 1,
                    p.red(&format!("- {}", a[*i]))
                ));
            }
            Op::Ins(j) => {
                adds += 1;
                skipping = false;
                body.push_str(&format!(
                    "│ {:>3} {}\n",
                    j + 1,
                    p.green(&format!("+ {}", b[*j]))
                ));
            }
        }
    }

    let summary = format!(
        "└─ {}, {}",
        p.green(&format!("+{adds}")),
        p.red(&format!("-{dels}"))
    );
    Some(format!("{header}{body}{summary}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Colour is suppressed under test because stderr is not a terminal, so
    // these assertions can match plain text.

    fn tmp(name: &str, body: &str) -> String {
        let p = std::env::temp_dir().join(format!("fg_diff_{}_{}", std::process::id(), name));
        std::fs::write(&p, body).unwrap();
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn aligns_a_single_changed_line() {
        let a = ["one", "two", "three"];
        let b = ["one", "TWO", "three"];
        let ops = align(&a, &b);
        assert_eq!(ops.iter().filter(|o| matches!(o, Op::Del(_))).count(), 1);
        assert_eq!(ops.iter().filter(|o| matches!(o, Op::Ins(_))).count(), 1);
        assert_eq!(ops.iter().filter(|o| matches!(o, Op::Equal(..))).count(), 2);
    }

    #[test]
    fn diffs_a_write_against_what_is_on_disk() {
        let path = tmp("cfg", "port = 8080\nhost = localhost\ndebug = false\n");
        let out = render(
            "write_file",
            &json!({"path": path, "content": "port = 8080\nhost = 0.0.0.0\ndebug = false\n"}),
        )
        .unwrap();

        assert!(
            out.contains("- host = localhost"),
            "shows the old line: {out}"
        );
        assert!(
            out.contains("+ host = 0.0.0.0"),
            "shows the new line: {out}"
        );
        assert!(out.contains("+1") && out.contains("-1"));
        assert!(
            !out.contains("- port = 8080"),
            "unchanged lines are not marked as changes"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_new_file_is_shown_as_a_creation() {
        let path = std::env::temp_dir()
            .join(format!("fg_diff_absent_{}", std::process::id()))
            .to_string_lossy()
            .into_owned();
        let _ = std::fs::remove_file(&path);
        let out = render(
            "write_file",
            &json!({"path": path, "content": "hello\nworld\n"}),
        )
        .unwrap();
        assert!(out.contains("create "), "labelled as a creation: {out}");
        assert!(out.contains("+ hello") && out.contains("+ world"));
        assert!(out.contains("+2"));
    }

    #[test]
    fn a_delete_shows_what_would_be_lost() {
        let path = tmp("doomed", "alpha\nbeta\n");
        let out = render("delete_file", &json!({"path": path})).unwrap();
        assert!(out.contains("delete "));
        assert!(out.contains("- alpha") && out.contains("- beta"));
        assert!(out.contains("2 lines would be lost"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn calls_without_a_diffable_file_are_skipped() {
        assert!(render("send_email", &json!({"to": "a@b.c"})).is_none());
        assert!(
            render("write_file", &json!({"path": "/tmp/x"})).is_none(),
            "no content to diff"
        );
    }
}
