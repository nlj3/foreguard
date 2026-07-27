//! Pin the numbers nlj.dev publishes for Foreguard.
//!
//! The site used to quote "84.6% agreement, 80 tools, 10 servers" with
//! `cargo test -p kedge-core ecosystem` as the command to reproduce it. That
//! command passes and prints nothing: the test under it asserts 38 hand-listed
//! names classify as expected, with no per-server grouping and no comparison
//! against any declared hint. The published figures came from a one-off that
//! lived in neither repository, so nothing could contradict them.
//!
//! Now `foreguard ecosystem` computes them from catalogues captured off real
//! servers, and this diffs its output against the checked-in golden. To accept
//! a deliberate change:
//!
//! ```sh
//! cargo build && ./target/debug/foreguard ecosystem > tests/golden/ecosystem_report.txt
//! ```
//!
//! and then read the diff. A moved percentage means either the classifier
//! changed or a server changed what it claims about itself, and both are worth
//! knowing before the number goes back on a website.

use std::process::Command;

const GOLDEN: &str = "tests/golden/ecosystem_report.txt";

fn binary() -> std::path::PathBuf {
    // The integration test binary lives in target/<profile>/deps, so the CLI is
    // two levels up. Beats hardcoding "debug" and breaking under --release.
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("foreguard")
}

#[test]
fn the_published_ecosystem_report_still_says_what_it_says() {
    let out = Command::new(binary())
        .arg("ecosystem")
        .output()
        .expect("run `foreguard ecosystem`");
    assert!(out.status.success(), "the command failed");
    let actual = String::from_utf8(out.stdout).expect("utf8");

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(GOLDEN);
    let expected = std::fs::read_to_string(&path).expect("golden is checked in");

    assert_eq!(
        expected.trim_end(),
        actual.trim_end(),
        "\n\nThe ecosystem report changed.\n\
         nlj.dev quotes these figures, so the site is now wrong.\n\n\
         Regenerate with:\n  \
         cargo build && ./target/debug/foreguard ecosystem > {GOLDEN}\n\
         then update the finding in mac-portfolio/src/content/projects.js in the\n\
         same change.\n"
    );
}

/// The golden is text, and text can be hand-edited into agreeing with itself.
/// This asserts the claim the site actually makes, in a form no amount of
/// editing the golden can satisfy.
#[test]
fn the_headline_claim_holds() {
    let out = Command::new(binary())
        .arg("ecosystem")
        .output()
        .expect("run `foreguard ecosystem`");
    let text = String::from_utf8(out.stdout).expect("utf8");

    // The kill criterion, written before the measurement: one mutating tool
    // judged read-only invalidates the approach. This is the line that is
    // allowed to fail.
    assert!(
        text.contains("false negatives: 0."),
        "a mutating tool was classified read-only:\n{text}"
    );

    // The denominator is part of the claim. A percentage over a corpus that
    // quietly halved is a different statement wearing the same number.
    assert!(
        text.contains("81.0% of 63 scoreable tools"),
        "the headline figure moved:\n{text}"
    );
    assert!(
        text.contains("TOTAL                   98"),
        "the corpus size changed:\n{text}"
    );
}
