//! A local approval surface, because the terminal one has nowhere to draw.
//!
//! `--approve` asks the human by opening `/dev/tty`. That works when you run the
//! proxy by hand. It does not work in the case foreguard is actually built for:
//! an MCP host spawns it as a stdio child, and a GUI host (the Claude desktop
//! app, a VS Code or Cursor extension) has no controlling terminal at all.
//! Opening `/dev/tty` there fails with ENXIO, the approver reads that as "no",
//! and promote-to-live silently degrades to dry-run forever. Even under a
//! terminal host it is wrong: the host owns the TUI, and two processes reading
//! the same tty is a fight, not a prompt.
//!
//! So the decision moves to a page on loopback. Same gate, same fail-safe, a
//! render target that exists.
//!
//! ## This is an approval authority, so the rules are tighter than a dev server
//!
//! Anything that can talk to this port can authorise a mutation. Therefore:
//!
//! - **Loopback only.** A non-loopback bind is refused outright, not warned about.
//! - **A 256-bit token** from `/dev/urandom`, required on every request and
//!   compared without early exit. It is in the URL, so a page that cannot read
//!   the URL cannot forge a request.
//! - **`Host` is validated.** A browser pointed at an attacker-controlled name
//!   that resolves to 127.0.0.1 (DNS rebinding) sends that name in `Host`; only
//!   loopback literals are accepted.
//! - **No CORS headers, ever.** No `Access-Control-Allow-Origin` means a
//!   cross-origin script cannot read a reply, and `POST /decide` requires
//!   `Content-Type: application/json`, which forces a preflight that is never
//!   answered.
//! - **Fail-safe everywhere.** Timeout, a dropped socket, a malformed request,
//!   the page being closed: every one of them resolves to *deny*. The only path
//!   to "yes" is an explicit click carrying the token.
//!
//! One approval is outstanding at a time, which is not a simplification: the
//! proxy awaits the decision inline before pumping the next message, so a second
//! request cannot exist while the first is unanswered.

use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// How long a mutation waits for a human before it is denied.
///
/// Long enough to walk back to the keyboard, short enough that a forgotten
/// prompt does not wedge an agent run forever. Expiry is a *denial*: the call
/// stays a dry-run, which is the same answer as closing the tab.
const DECISION_TIMEOUT: Duration = Duration::from_secs(180);

/// Nothing legitimate sends a large request here. Caps the read so a peer
/// cannot make the server allocate.
const MAX_REQUEST_BYTES: usize = 8 * 1024;

/// What the human is being asked to allow.
#[derive(Clone)]
pub struct ApprovalRequest {
    pub tool: String,
    pub risk: &'static str,
    /// The concrete effect, when foreguard could describe one.
    pub effect: Option<String>,
    /// Set when untrusted data is driving this call (Rule of Two).
    pub taint: Option<String>,
}

#[derive(Debug)]
struct Pending {
    payload: String, // pre-rendered JSON, so the HTTP path does no formatting
    tx: oneshot::Sender<bool>,
}

#[derive(Debug)]
pub struct ApprovalUi {
    /// The full URL including the token. Printed for the human; never logged
    /// anywhere it would outlive the process.
    url: String,
    token: String,
    pending: Arc<Mutex<Option<Pending>>>,
    /// The browser is opened once, on the first approval, not at startup: a
    /// proxy that pops a window the moment it launches is obnoxious, and until
    /// something needs approving there is nothing to look at.
    opened: AtomicBool,
}

impl ApprovalUi {
    /// Bind and start serving. Refuses any non-loopback address.
    pub async fn bind(addr: &str) -> Result<Arc<Self>> {
        let sock: SocketAddr = addr
            .parse()
            .with_context(|| format!("`{addr}` is not a valid host:port"))?;
        if !is_loopback(&sock.ip()) {
            bail!(
                "refusing to bind the approval UI to {sock}: anything that reaches this port can \
                 approve a mutation, so it is loopback-only by design"
            );
        }

        let listener = TcpListener::bind(sock)
            .await
            .with_context(|| format!("could not bind {sock}"))?;
        let bound = listener.local_addr()?;
        let token = random_token()?;

        let ui = Arc::new(ApprovalUi {
            url: format!("http://{bound}/?t={token}"),
            token,
            pending: Arc::new(Mutex::new(None)),
            opened: AtomicBool::new(false),
        });

        let serving = Arc::clone(&ui);
        tokio::spawn(async move {
            loop {
                let Ok((stream, peer)) = listener.accept().await else {
                    continue;
                };
                // Belt and braces: the socket is bound to loopback, so a
                // non-loopback peer should be impossible. If one ever appears,
                // it is not getting a reply.
                if !is_loopback(&peer.ip()) {
                    continue;
                }
                let s = Arc::clone(&serving);
                tokio::spawn(async move {
                    let _ = s.serve(stream).await;
                });
            }
        });

        Ok(ui)
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Put a request in front of the human and wait. Returns `false` on timeout,
    /// on a closed channel, and on anything else that is not an explicit yes.
    pub async fn request(&self, req: ApprovalRequest) -> bool {
        let (tx, rx) = oneshot::channel();
        let payload = json!({
            "tool": req.tool,
            "risk": req.risk,
            "effect": req.effect,
            "taint": req.taint,
        })
        .to_string();

        {
            let mut slot = self.pending.lock().expect("pending lock");
            // A previous request that timed out may still be sitting here.
            // Replacing it is correct: its waiter has already given up and
            // been told no.
            *slot = Some(Pending { payload, tx });
        }

        if !self.opened.swap(true, Ordering::SeqCst) {
            open_browser(&self.url);
        }
        eprintln!("⏸  waiting for approval at {}", self.url);

        let decision = match tokio::time::timeout(DECISION_TIMEOUT, rx).await {
            Ok(Ok(v)) => v,
            // Timed out, or the sender was dropped. Both mean no human said yes.
            _ => {
                eprintln!(
                    "⏱  no decision within {}s — denied (the call stays a dry-run)",
                    DECISION_TIMEOUT.as_secs()
                );
                false
            }
        };

        *self.pending.lock().expect("pending lock") = None;
        decision
    }

    async fn serve(&self, mut stream: TcpStream) -> Result<()> {
        let head = match read_head(&mut stream).await {
            Some(h) => h,
            None => return respond(&mut stream, 400, "text/plain", b"bad request").await,
        };

        let Some((method, target)) = request_line(&head) else {
            return respond(&mut stream, 400, "text/plain", b"bad request").await;
        };

        // DNS rebinding: a name the attacker controls that resolves to 127.0.0.1
        // arrives with that name in Host. Only loopback literals are allowed.
        if !host_is_loopback(&head) {
            return respond(&mut stream, 403, "text/plain", b"bad host").await;
        }

        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        if !token_ok(query, &self.token) {
            // Deliberately not "wrong token": nothing here confirms guesses.
            return respond(&mut stream, 404, "text/plain", b"not found").await;
        }

        match (method, path) {
            ("GET", "/") => {
                respond(
                    &mut stream,
                    200,
                    "text/html; charset=utf-8",
                    PAGE.as_bytes(),
                )
                .await
            }
            ("GET", "/pending") => {
                let body = self
                    .pending
                    .lock()
                    .expect("pending lock")
                    .as_ref()
                    .map(|p| p.payload.clone())
                    .unwrap_or_else(|| "null".to_string());
                respond(&mut stream, 200, "application/json", body.as_bytes()).await
            }
            ("POST", "/decide") => {
                // Requiring JSON forces a CORS preflight for cross-origin
                // callers, and this server never answers one.
                if !header_contains(&head, "content-type", "application/json") {
                    return respond(&mut stream, 415, "text/plain", b"expected json").await;
                }
                let approve = read_body(&mut stream, &head)
                    .await
                    .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                    .and_then(|v| v.get("approve").and_then(serde_json::Value::as_bool))
                    // Anything unparseable is not a yes.
                    .unwrap_or(false);

                let taken = self.pending.lock().expect("pending lock").take();
                if let Some(p) = taken {
                    let _ = p.tx.send(approve);
                }
                eprintln!(
                    "{}  decision from the approval UI",
                    if approve { "✅" } else { "🚫" }
                );
                respond(&mut stream, 200, "application/json", b"{\"ok\":true}").await
            }
            _ => respond(&mut stream, 404, "text/plain", b"not found").await,
        }
    }
}

fn is_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// 32 bytes of kernel randomness, hex encoded. `/dev/urandom` rather than a
/// crate: this is the one secret in the process and it should not depend on a
/// dependency graph.
fn random_token() -> Result<String> {
    let mut buf = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .context("opening /dev/urandom for the approval token")?
        .read_exact(&mut buf)
        .context("reading the approval token")?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// Compare without an early exit on the first differing byte.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn token_ok(query: &str, expected: &str) -> bool {
    query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .any(|(k, v)| k == "t" && constant_time_eq(v, expected))
}

fn request_line(head: &str) -> Option<(&str, &str)> {
    let first = head.lines().next()?;
    let mut parts = first.split(' ');
    Some((parts.next()?, parts.next()?))
}

fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines()
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
}

fn header_contains(head: &str, name: &str, needle: &str) -> bool {
    header_value(head, name)
        .map(|v| v.to_ascii_lowercase().contains(needle))
        .unwrap_or(false)
}

fn host_is_loopback(head: &str) -> bool {
    let Some(host) = header_value(head, "host") else {
        return false; // HTTP/1.1 requires it; absence is not something to tolerate here
    };
    let name = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    let name = name.trim_start_matches('[').trim_end_matches(']');
    name == "127.0.0.1" || name == "localhost" || name == "::1"
}

/// Read up to the end of headers, bounded.
async fn read_head(stream: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_REQUEST_BYTES {
            return None;
        }
        if let Some(i) = find_head_end(&buf) {
            // Keep the remainder: it is the start of the body.
            let head = String::from_utf8(buf[..i].to_vec()).ok()?;
            HEAD_REMAINDER.with(|r| *r.borrow_mut() = buf[i + 4..].to_vec());
            return Some(head);
        }
    }
}

thread_local! {
    /// Body bytes that arrived in the same read as the headers. A tiny buffer
    /// rather than restructuring the reader, and safe because a connection is
    /// handled start to finish on one task.
    static HEAD_REMAINDER: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

async fn read_body(stream: &mut TcpStream, head: &str) -> Option<Vec<u8>> {
    let len: usize = header_value(head, "content-length")?.parse().ok()?;
    if len > MAX_REQUEST_BYTES {
        return None;
    }
    let mut body = HEAD_REMAINDER.with(|r| r.borrow_mut().split_off(0));
    body.truncate(len);
    while body.len() < len {
        let mut chunk = vec![0u8; len - body.len()];
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Some(body)
}

async fn respond(stream: &mut TcpStream, status: u16, ctype: &str, body: &[u8]) -> Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        415 => "Unsupported Media Type",
        _ => "Error",
    };
    // No Access-Control-Allow-Origin: a cross-origin script must not be able to
    // read any of this. Cache-Control because an approval must never be served
    // from a cache.
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

/// Best-effort. A failure here is invisible and harmless: the URL is on stderr
/// and the human can open it themselves.
///
/// `FOREGUARD_NO_OPEN=1` suppresses it, for headless runs, for tests, and for
/// anyone who would rather a background proxy did not reach for their browser.
fn open_browser(url: &str) {
    if std::env::var_os("FOREGUARD_NO_OPEN").is_some() {
        return;
    }
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let _ = std::process::Command::new(opener)
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

const PAGE: &str = include_str!("ui.html");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_non_loopback_bind_is_refused() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt.block_on(ApprovalUi::bind("0.0.0.0:0")).unwrap_err();
        assert!(
            err.to_string().contains("loopback-only"),
            "expected a loopback refusal, got: {err}"
        );
    }

    #[test]
    fn tokens_are_unique_and_long() {
        let a = random_token().unwrap();
        let b = random_token().unwrap();
        assert_eq!(a.len(), 64, "32 bytes hex encoded");
        assert_ne!(a, b, "two tokens in a row must not match");
    }

    #[test]
    fn token_comparison_rejects_prefixes_and_wrong_lengths() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
        assert!(!constant_time_eq("ab", "abc"));
        assert!(!constant_time_eq("", "a"));
    }

    #[test]
    fn only_an_exact_token_in_the_query_is_accepted() {
        assert!(token_ok("t=secret", "secret"));
        assert!(token_ok("x=1&t=secret", "secret"));
        assert!(!token_ok("t=secre", "secret"));
        assert!(!token_ok("t=secrets", "secret"));
        assert!(!token_ok("token=secret", "secret"));
        assert!(!token_ok("", "secret"));
    }

    /// The DNS-rebinding guard. A name that resolves to 127.0.0.1 still arrives
    /// with the attacker's name in Host, and that must not be enough.
    #[test]
    fn host_must_be_a_loopback_literal() {
        let h = |v: &str| format!("GET / HTTP/1.1\r\nHost: {v}");
        assert!(host_is_loopback(&h("127.0.0.1:7878")));
        assert!(host_is_loopback(&h("localhost:7878")));
        assert!(host_is_loopback(&h("[::1]:7878")));
        assert!(!host_is_loopback(&h("evil.example.com:7878")));
        assert!(!host_is_loopback(&h("127.0.0.1.evil.com")));
        assert!(!host_is_loopback("GET / HTTP/1.1\r\nAccept: */*"));
    }

    // ── the real server, over real sockets ─────────────────────────────
    // The helpers above are unit-testable in isolation, which is exactly why
    // they are not enough: the question is whether the assembled server
    // enforces any of it. These speak HTTP to a live listener.

    /// Minimal client: send a raw request, return (status, headers, body).
    async fn http(addr: &str, raw: &str) -> (u16, String, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(addr).await.expect("connect");
        s.write_all(raw.as_bytes()).await.expect("write");
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.expect("read");
        let text = String::from_utf8_lossy(&buf).into_owned();
        let status = text
            .split(' ')
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        (status, head.to_string(), body.to_string())
    }

    async fn ui_on_free_port() -> (std::sync::Arc<ApprovalUi>, String, String) {
        let ui = ApprovalUi::bind("127.0.0.1:0").await.expect("bind");
        // url is http://127.0.0.1:PORT/?t=TOKEN
        let rest = ui.url().trim_start_matches("http://").to_string();
        let (addr, token) = rest.split_once("/?t=").expect("url shape");
        (
            std::sync::Arc::clone(&ui),
            addr.to_string(),
            token.to_string(),
        )
    }

    fn get(path: &str, host: &str) -> String {
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
    }

    #[tokio::test]
    async fn without_the_token_nothing_is_reachable() {
        let (_ui, addr, token) = ui_on_free_port().await;
        for path in ["/", "/pending", "/decide"] {
            let (status, _, _) = http(&addr, &get(path, &addr)).await;
            assert_eq!(status, 404, "{path} answered without a token");
        }
        // And with it, the page is served.
        let (status, _, body) = http(&addr, &get(&format!("/?t={token}"), &addr)).await;
        assert_eq!(status, 200);
        assert!(body.contains("approval required") || body.contains("foreguard"));
    }

    /// DNS rebinding, end to end: correct token, attacker-controlled Host.
    #[tokio::test]
    async fn a_non_loopback_host_header_is_refused_even_with_the_token() {
        let (_ui, addr, token) = ui_on_free_port().await;
        let raw = get(&format!("/pending?t={token}"), "evil.example.com");
        let (status, _, _) = http(&addr, &raw).await;
        assert_eq!(status, 403, "a rebound host was served");
    }

    #[tokio::test]
    async fn no_cors_header_is_ever_sent() {
        let (_ui, addr, token) = ui_on_free_port().await;
        let (_, head, _) = http(&addr, &get(&format!("/?t={token}"), &addr)).await;
        assert!(
            !head
                .to_ascii_lowercase()
                .contains("access-control-allow-origin"),
            "a CORS header would let a cross-origin page read approvals:\n{head}"
        );
    }

    #[tokio::test]
    async fn pending_is_null_until_something_needs_approving() {
        let (_ui, addr, token) = ui_on_free_port().await;
        let (status, _, body) = http(&addr, &get(&format!("/pending?t={token}"), &addr)).await;
        assert_eq!(status, 200);
        assert_eq!(body.trim(), "null");
    }

    /// The whole loop: a request appears, the page reads it, a click resolves it.
    #[tokio::test]
    async fn an_approval_round_trips_and_the_decision_reaches_the_caller() {
        let (ui, addr, token) = ui_on_free_port().await;

        let asking = {
            let ui = std::sync::Arc::clone(&ui);
            tokio::spawn(async move {
                ui.request(ApprovalRequest {
                    tool: "delete_file".into(),
                    risk: "high",
                    effect: Some("deletes /etc/passwd".into()),
                    taint: Some("attacker@evil.com".into()),
                })
                .await
            })
        };

        // Wait for it to show up the way the page would.
        let mut body = String::new();
        for _ in 0..100 {
            let (_, _, b) = http(&addr, &get(&format!("/pending?t={token}"), &addr)).await;
            if b.trim() != "null" {
                body = b;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            body.contains("delete_file"),
            "pending never appeared: {body}"
        );
        assert!(
            body.contains("deletes /etc/passwd"),
            "effect missing: {body}"
        );
        assert!(body.contains("attacker@evil.com"), "taint missing: {body}");

        let payload = r#"{"approve":true}"#;
        let raw = format!(
            "POST /decide?t={token} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        );
        let (status, _, _) = http(&addr, &raw).await;
        assert_eq!(status, 200);

        assert!(
            asking.await.expect("join"),
            "the approval did not reach the caller"
        );
    }

    /// The same path, answered no. This is the one that must never be a yes by
    /// accident, so it is asserted separately rather than assumed symmetric.
    #[tokio::test]
    async fn a_denial_reaches_the_caller_as_false() {
        let (ui, addr, token) = ui_on_free_port().await;
        let asking = {
            let ui = std::sync::Arc::clone(&ui);
            tokio::spawn(async move {
                ui.request(ApprovalRequest {
                    tool: "write_file".into(),
                    risk: "medium",
                    effect: None,
                    taint: None,
                })
                .await
            })
        };
        for _ in 0..100 {
            let (_, _, b) = http(&addr, &get(&format!("/pending?t={token}"), &addr)).await;
            if b.trim() != "null" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let payload = r#"{"approve":false}"#;
        let raw = format!(
            "POST /decide?t={token} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        );
        http(&addr, &raw).await;
        assert!(
            !asking.await.expect("join"),
            "a denial came back as approval"
        );
    }

    /// A form POST is the shape a cross-origin page can send without a preflight.
    /// It must not be able to approve anything.
    #[tokio::test]
    async fn a_form_content_type_cannot_approve() {
        let (_ui, addr, token) = ui_on_free_port().await;
        let payload = "approve=true";
        let raw = format!(
            "POST /decide?t={token} HTTP/1.1\r\nHost: {addr}\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        );
        let (status, _, _) = http(&addr, &raw).await;
        assert_eq!(status, 415, "a simple cross-origin POST was accepted");
    }

    /// Garbage in the body is not an approval.
    #[tokio::test]
    async fn an_unparseable_body_denies() {
        let (ui, addr, token) = ui_on_free_port().await;
        let asking = {
            let ui = std::sync::Arc::clone(&ui);
            tokio::spawn(async move {
                ui.request(ApprovalRequest {
                    tool: "rm".into(),
                    risk: "high",
                    effect: None,
                    taint: None,
                })
                .await
            })
        };
        for _ in 0..100 {
            let (_, _, b) = http(&addr, &get(&format!("/pending?t={token}"), &addr)).await;
            if b.trim() != "null" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let payload = "not json at all";
        let raw = format!(
            "POST /decide?t={token} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        );
        http(&addr, &raw).await;
        assert!(!asking.await.expect("join"), "garbage was read as approval");
    }

    #[test]
    fn headers_are_matched_case_insensitively() {
        let head = "POST /decide HTTP/1.1\r\nCONTENT-TYPE: Application/JSON\r\nHost: localhost";
        assert!(header_contains(head, "content-type", "application/json"));
        assert!(!header_contains(head, "content-type", "text/plain"));
    }
}
