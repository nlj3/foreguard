//! Score the classifier against what real MCP servers say about themselves.
//!
//! Foreguard's whole proposition is that it can judge a tool it has never seen,
//! from its name and arguments, without the server's cooperation. That is a
//! claim with a right answer, and the servers publish it: MCP's `annotations`
//! carry a `readOnlyHint` the author sets by hand.
//!
//! So: take the catalogues in `catalogues/`, captured from real servers over
//! stdio (see `scripts/capture-catalogues.mjs`), classify every tool by name
//! alone, and compare.
//!
//! ## The two errors are not equal, and the report refuses to average them
//!
//! - A **false negative** is a tool the server calls mutating and the classifier
//!   calls read-only. That is the product failing: a mutation forwarded without
//!   a preview. One is a defect.
//! - A **false positive** is the reverse: the classifier is stricter than the
//!   server. That costs a confirmation prompt, nothing more, and for a
//!   deny-wins design it is the correct direction to be wrong in.
//!
//! A single "accuracy" percentage would let one hide inside the other, so both
//! are printed, and the false negatives are listed by name.
//!
//! ## What this cannot tell you
//!
//! The hint is the *server author's* opinion, not ground truth. A server that
//! mislabels its own tool moves this number without anything changing about
//! whether foreguard is right. Tools with no declared hint (35 of 98 in the
//! current corpus) are excluded from the score entirely rather than assumed,
//! and counted separately so the denominator is visible.
//!
//! Name-only classification is used here on purpose. Arguments are what
//! `classify_call` inspects at runtime, but a catalogue has no arguments, so
//! scoring against it measures the weakest half of the classifier. The real
//! thing is at least this good.

use kedge_core::{classify, ToolSafety};
use serde::Deserialize;

/// Catalogues are embedded rather than read from disk so the command works from
/// an installed binary and cannot silently score a stale or partial copy.
/// Listing them one by one is deliberate: the corpus should be readable here.
const CATALOGUES: &[(&str, &str)] = &[
    (
        "aws-kb-retrieval",
        include_str!("../catalogues/aws-kb-retrieval.json"),
    ),
    ("context7", include_str!("../catalogues/context7.json")),
    ("everything", include_str!("../catalogues/everything.json")),
    ("filesystem", include_str!("../catalogues/filesystem.json")),
    ("github", include_str!("../catalogues/github.json")),
    ("memory", include_str!("../catalogues/memory.json")),
    ("playwright", include_str!("../catalogues/playwright.json")),
    ("postgres", include_str!("../catalogues/postgres.json")),
    ("puppeteer", include_str!("../catalogues/puppeteer.json")),
    (
        "sequential-thinking",
        include_str!("../catalogues/sequential-thinking.json"),
    ),
];

#[derive(Deserialize)]
struct Catalogue {
    slug: String,
    #[serde(rename = "serverInfo")]
    server_info: Option<ServerInfo>,
    tools: Vec<Tool>,
}

#[derive(Deserialize)]
struct ServerInfo {
    name: String,
    #[serde(default)]
    version: Option<String>,
}

#[derive(Deserialize)]
struct Tool {
    name: String,
    annotations: Option<Annotations>,
}

#[derive(Deserialize)]
struct Annotations {
    #[serde(rename = "readOnlyHint")]
    read_only_hint: Option<bool>,
}

/// One server's score.
pub struct ServerScore {
    pub slug: String,
    pub server: String,
    pub tools: usize,
    /// Tools carrying a `readOnlyHint`. Only these can be scored.
    pub scored: usize,
    pub agreed: usize,
    /// Server said mutating, classifier said read-only. The fatal class.
    pub false_negatives: Vec<String>,
    /// Server said read-only, classifier said mutating. The safe direction.
    pub false_positives: Vec<String>,
}

pub struct Report {
    pub servers: Vec<ServerScore>,
}

impl Report {
    pub fn tools(&self) -> usize {
        self.servers.iter().map(|s| s.tools).sum()
    }
    pub fn scored(&self) -> usize {
        self.servers.iter().map(|s| s.scored).sum()
    }
    pub fn agreed(&self) -> usize {
        self.servers.iter().map(|s| s.agreed).sum()
    }
    pub fn false_negatives(&self) -> usize {
        self.servers.iter().map(|s| s.false_negatives.len()).sum()
    }
    pub fn false_positives(&self) -> usize {
        self.servers.iter().map(|s| s.false_positives.len()).sum()
    }
    pub fn agreement_pct(&self) -> f64 {
        if self.scored() == 0 {
            return 0.0;
        }
        self.agreed() as f64 * 100.0 / self.scored() as f64
    }
}

/// Score every embedded catalogue. Panics on a malformed fixture, which can
/// only happen if a committed file was hand-edited into nonsense.
pub fn score() -> Report {
    let mut servers = Vec::new();
    for (slug, raw) in CATALOGUES {
        let cat: Catalogue = serde_json::from_str(raw)
            .unwrap_or_else(|e| panic!("catalogue {slug} is malformed: {e}"));

        let mut s = ServerScore {
            slug: cat.slug.clone(),
            server: cat
                .server_info
                .as_ref()
                .map(|i| match &i.version {
                    Some(v) => format!("{} {}", i.name, v),
                    None => i.name.clone(),
                })
                .unwrap_or_else(|| "(unnamed)".into()),
            tools: cat.tools.len(),
            scored: 0,
            agreed: 0,
            false_negatives: Vec::new(),
            false_positives: Vec::new(),
        };

        for t in &cat.tools {
            let Some(declared_read_only) = t.annotations.as_ref().and_then(|a| a.read_only_hint)
            else {
                continue; // no opinion published; not scoreable
            };
            s.scored += 1;
            let ours_read_only = matches!(classify(&t.name), ToolSafety::ReadOnly);
            match (declared_read_only, ours_read_only) {
                (a, b) if a == b => s.agreed += 1,
                // Server: mutating. Us: read-only. The one that matters.
                (false, true) => s.false_negatives.push(t.name.clone()),
                // Server: read-only. Us: mutating. Stricter than asked.
                (true, false) => s.false_positives.push(t.name.clone()),
                _ => unreachable!(),
            }
        }
        servers.push(s);
    }
    servers.sort_by(|a, b| a.slug.cmp(&b.slug));
    Report { servers }
}

/// The human-readable table. Deterministic: no timings, no clock, sorted.
pub fn render(r: &Report) -> String {
    let mut out = String::from("foreguard vs declared readOnlyHint\n\n");
    out.push_str("server                  tools  scored  agree   FN   FP\n");
    out.push_str("──────────────────────────────────────────────────────\n");
    for s in &r.servers {
        out.push_str(&format!(
            "  {:<20} {:>5} {:>7} {:>6} {:>4} {:>4}\n",
            s.slug,
            s.tools,
            s.scored,
            s.agreed,
            s.false_negatives.len(),
            s.false_positives.len(),
        ));
    }
    out.push_str(&format!(
        "\n  {:<20} {:>5} {:>7} {:>6} {:>4} {:>4}\n",
        "TOTAL",
        r.tools(),
        r.scored(),
        r.agreed(),
        r.false_negatives(),
        r.false_positives(),
    ));

    out.push_str(&format!(
        "\nagreement {:.1}% of {} scoreable tools ({} of {} carry no readOnlyHint\nand are excluded rather than assumed)\n",
        r.agreement_pct(),
        r.scored(),
        r.tools() - r.scored(),
        r.tools(),
    ));

    // The two error classes, never averaged together.
    if r.false_negatives() == 0 {
        out.push_str(
            "\nfalse negatives: 0. No tool a server calls mutating was judged read-only.\n",
        );
    } else {
        out.push_str("\nFALSE NEGATIVES (a mutation would have been forwarded unpreviewed):\n");
        for s in &r.servers {
            for n in &s.false_negatives {
                out.push_str(&format!("  {}::{}\n", s.slug, n));
            }
        }
    }
    if r.false_positives() > 0 {
        out.push_str(&format!(
            "\nfalse positives ({}): stricter than the server asked for, which is the\nsafe direction for a deny-wins classifier. Each costs a confirmation, not a\nmissed mutation.\n",
            r.false_positives()
        ));
        for s in &r.servers {
            for n in &s.false_positives {
                out.push_str(&format!("  {}::{}\n", s.slug, n));
            }
        }
    }

    // Who these actually are. Without this the table is ten slugs someone could
    // have made up; with it, each row names the server that answered
    // `tools/list` and the version string it reported for itself.
    out.push_str("\ncaptured from (server name and version as each reported it):\n");
    for s in &r.servers {
        out.push_str(&format!("  {:<20} {}\n", s.slug, s.server));
    }

    out.push_str(
        "\nThe hint is the server author's opinion, not ground truth: a mislabelled tool\n\
         moves this number without anything changing here. Classification is by name\n\
         only, because a catalogue has no arguments to inspect, so this measures the\n\
         weaker half of what runs at proxy time.\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every embedded catalogue parses and is non-empty. A fixture that silently
    /// became `{}` would otherwise shrink the corpus and improve the score.
    #[test]
    fn every_catalogue_loads_and_has_tools() {
        for (slug, raw) in CATALOGUES {
            let c: Catalogue = serde_json::from_str(raw).unwrap_or_else(|e| panic!("{slug}: {e}"));
            assert!(!c.tools.is_empty(), "{slug} has no tools");
            assert_eq!(&c.slug, slug, "catalogue slug does not match its filename");
        }
    }

    /// The corpus is not allowed to shrink quietly: a percentage over a smaller
    /// denominator is a different claim wearing the same number.
    #[test]
    fn the_corpus_is_the_size_it_is_published_as() {
        let r = score();
        assert_eq!(r.servers.len(), 10, "server count changed");
        assert_eq!(r.tools(), 98, "tool count changed");
        assert_eq!(r.scored(), 63, "scoreable tool count changed");
    }

    /// The kill criterion, written before the measurement: one false negative
    /// invalidates the approach. This is the assertion that is allowed to fail.
    #[test]
    fn no_mutating_tool_is_judged_read_only() {
        let r = score();
        assert_eq!(
            r.false_negatives(),
            0,
            "a mutating tool was classified read-only:\n{}",
            render(&r)
        );
    }
}
