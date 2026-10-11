//! The **live LLM spend gateway** — the front-end that makes [`crate::spend`] real.
//!
//! `foreguard meter` proves the enforcement logic offline over a stream of recorded
//! responses. This turns that same core into a **transparent HTTP proxy**: point an
//! agent's `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` at Foreguard instead of the real
//! API, and every model call flows through the budget kill switch. Once cumulative
//! spend crosses the budget, the gateway **refuses the next request before it is even
//! sent upstream** — the retry loop is stopped, not merely alerted on.
//!
//! Design, matching Foreguard's ethos:
//! - **Loopback only.** The gateway binds `127.0.0.1`; it is a local sidecar, not a
//!   shared service.
//! - **It never handles credentials.** The caller's own `Authorization` / `x-api-key`
//!   header is passed straight through to the upstream — Foreguard stores no keys.
//! - **Fail-safe.** A budget that is already crossed refuses pre-flight; an upstream
//!   error surfaces as `502`; nothing about metering can make a call cost *less* than
//!   it did.
//!
//! The forwarding is abstracted behind [`Forwarder`] so the enforcement/metering loop
//! is testable with an in-memory upstream — [`ReqwestForwarder`] is the production one.
//!
//! Current limitation, stated honestly: responses are **buffered**, not streamed
//! token-by-token. Usage is read from the whole response (non-streaming JSON, or a
//! best-effort scan of a buffered SSE body), so an interactive client sees the reply
//! arrive at once. True pass-through streaming with inline metering is the next step.

use std::sync::Arc;

use anyhow::{Context, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use crate::spend::{PriceTable, SpendMeter, Usage};

/// Cap on a request body we'll buffer, so a hostile `Content-Length` can't OOM us.
const MAX_BODY: usize = 64 * 1024 * 1024;

/// A parsed inbound HTTP request — enough of one to forward upstream.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// An HTTP response, on its way back to the caller.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// A small JSON response synthesized by the gateway itself (budget refusal,
    /// upstream error), carrying the current spend headers.
    fn synthetic(status: u16, body: Value, spent: u64, budget: Option<u64>) -> Self {
        let body = body.to_string().into_bytes();
        let mut headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("x-foreguard-spent-cents".to_string(), spent.to_string()),
        ];
        if let Some(b) = budget {
            headers.push(("x-foreguard-budget-cents".to_string(), b.to_string()));
        }
        Self {
            status,
            headers,
            body,
        }
    }
}

/// The upstream call, abstracted so the gateway's enforcement/metering loop can be
/// tested against an in-memory upstream instead of the network.
pub trait Forwarder: Send + Sync {
    fn forward(
        &self,
        req: &HttpRequest,
    ) -> impl std::future::Future<Output = Result<HttpResponse>> + Send;
}

/// The gateway's decision core: a budget-enforcing meter around an upstream. Holds
/// the [`SpendMeter`] behind a mutex so many in-flight requests share one running
/// total; the lock is only ever held for the cheap check/charge, never across the
/// upstream round-trip.
pub struct GatewayCore {
    meter: Mutex<SpendMeter>,
    default_model: String,
}

impl GatewayCore {
    pub fn new(meter: SpendMeter, default_model: String) -> Self {
        Self {
            meter: Mutex::new(meter),
            default_model,
        }
    }

    /// Handle one request: enforce the budget, forward if allowed, meter the reply.
    pub async fn handle<F: Forwarder>(&self, req: HttpRequest, fwd: &F) -> HttpResponse {
        // Pre-flight: refuse before forwarding if the budget is already crossed.
        {
            let m = self.meter.lock().await;
            if !m.allow_request() {
                return HttpResponse::synthetic(
                    429,
                    json!({
                        "error": {
                            "type": "foreguard_budget_exceeded",
                            "message": "spend budget reached; request refused by Foreguard and NOT sent upstream",
                        }
                    }),
                    m.spent_cents(),
                    m.budget_cents(),
                );
            }
        }

        // Forward (no lock held across the await).
        let mut resp = match fwd.forward(&req).await {
            Ok(r) => r,
            Err(e) => {
                let m = self.meter.lock().await;
                return HttpResponse::synthetic(
                    502,
                    json!({
                        "error": { "type": "foreguard_upstream_error", "message": e.to_string() }
                    }),
                    m.spent_cents(),
                    m.budget_cents(),
                );
            }
        };

        // Meter the reply and stamp the running total onto the response.
        let (model, usage) = meter_from_body(&resp.body, &self.default_model);
        let (spent, budget) = {
            let mut m = self.meter.lock().await;
            if let Some(u) = usage {
                m.charge(&model, &u);
            }
            (m.spent_cents(), m.budget_cents())
        };
        // Drop framing headers we're about to re-derive, then add the spend headers.
        resp.headers.retain(|(k, _)| {
            ![
                "content-length",
                "transfer-encoding",
                "connection",
                "content-encoding",
            ]
            .iter()
            .any(|h| k.eq_ignore_ascii_case(h))
        });
        resp.headers
            .push(("x-foreguard-spent-cents".to_string(), spent.to_string()));
        if let Some(b) = budget {
            resp.headers
                .push(("x-foreguard-budget-cents".to_string(), b.to_string()));
        }
        resp
    }
}

/// Extract `(model, usage)` from a response body — non-streaming JSON first, then a
/// best-effort scan of a buffered SSE stream (summing `message_start` input with the
/// final `message_delta`/usage-chunk output). Returns `usage = None` when nothing
/// meterable is present, so an odd body is charged nothing rather than mis-charged.
fn meter_from_body(body: &[u8], default_model: &str) -> (String, Option<Usage>) {
    // Non-streaming: the whole body is one JSON object.
    if let Ok(v) = serde_json::from_slice::<Value>(body) {
        return (model_of(&v, default_model), Usage::from_response(&v));
    }
    // Streaming SSE: accumulate across `data:` events.
    let text = String::from_utf8_lossy(body);
    let mut model = default_model.to_string();
    let (mut input, mut output, mut any) = (0u64, 0u64, false);
    for line in text.lines() {
        let Some(data) = line.trim_start().strip_prefix("data:") else {
            continue;
        };
        let data = data.trim();
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(data) else {
            continue;
        };
        if let Some(m) = model_field(&v) {
            model = m;
        }
        if let Some(u) = Usage::from_response(&v) {
            any = true;
            // `message_start` carries input; `message_delta` carries cumulative
            // output. Taking the max of each is a safe aggregation for both.
            input = input.max(u.input_tokens);
            output = output.max(u.output_tokens);
        }
    }
    (
        model,
        any.then_some(Usage {
            input_tokens: input,
            output_tokens: output,
        }),
    )
}

/// The model named by a response, top-level or nested under `message`, else default.
fn model_of(v: &Value, default: &str) -> String {
    model_field(v).unwrap_or_else(|| default.to_string())
}

fn model_field(v: &Value) -> Option<String> {
    v.get("model")
        .or_else(|| v.get("message").and_then(|m| m.get("model")))
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// The production [`Forwarder`]: a `reqwest` client pointed at the real API base.
pub struct ReqwestForwarder {
    client: reqwest::Client,
    base: String,
}

impl ReqwestForwarder {
    pub fn new(base: impl Into<String>) -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .build()
                .context("building HTTP client")?,
            base: base.into().trim_end_matches('/').to_string(),
        })
    }

    /// Headers we don't forward: hop-by-hop framing, and anything the client sets
    /// per-connection. `accept-encoding` is dropped so the reply comes back
    /// uncompressed and its usage stays readable.
    fn skip_request_header(name: &str) -> bool {
        [
            "host",
            "content-length",
            "connection",
            "transfer-encoding",
            "accept-encoding",
        ]
        .iter()
        .any(|h| name.eq_ignore_ascii_case(h))
    }
}

impl Forwarder for ReqwestForwarder {
    async fn forward(&self, req: &HttpRequest) -> Result<HttpResponse> {
        let method =
            reqwest::Method::from_bytes(req.method.as_bytes()).context("invalid HTTP method")?;
        let url = format!("{}{}", self.base, req.path);
        let mut rb = self.client.request(method, &url);
        for (k, v) in &req.headers {
            if !Self::skip_request_header(k) {
                rb = rb.header(k, v);
            }
        }
        // Ask for an uncompressed reply so we can read usage out of it.
        rb = rb.header("accept-encoding", "identity");
        let resp = rb
            .body(req.body.clone())
            .send()
            .await
            .context("forwarding request upstream")?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body = resp
            .bytes()
            .await
            .context("reading upstream body")?
            .to_vec();
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

/// Run the gateway: bind loopback, forward every request through the budget.
pub async fn run_gateway(
    addr: String,
    upstream: String,
    budget: Option<f64>,
    model: Option<String>,
    prices: PriceTable,
) -> Result<()> {
    let budget_cents = budget.map(|d| (d * 100.0).round() as u64);
    let meter = SpendMeter::new(budget_cents, prices);
    let core = Arc::new(GatewayCore::new(
        meter,
        model.unwrap_or_else(|| "unknown".into()),
    ));
    let fwd = Arc::new(ReqwestForwarder::new(&upstream)?);

    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    let local = listener.local_addr().map(|a| a.to_string()).unwrap_or(addr);
    match budget_cents {
        Some(b) => eprintln!(
            "foreguard gateway on http://{local} → {upstream} · budget {} (refused once crossed).",
            crate::dollars(b)
        ),
        None => eprintln!("foreguard gateway on http://{local} → {upstream} · metering only."),
    }

    loop {
        let (stream, _) = listener.accept().await.context("accepting connection")?;
        let core = core.clone();
        let fwd = fwd.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, &core, fwd.as_ref()).await {
                eprintln!("foreguard gateway: connection error: {e}");
            }
        });
    }
}

/// One connection: read a request, run it through the core, write the response.
async fn handle_conn<F: Forwarder>(stream: TcpStream, core: &GatewayCore, fwd: &F) -> Result<()> {
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    if let Some(req) = read_request(&mut reader).await? {
        let resp = core.handle(req, fwd).await;
        write_response(&mut write, &resp).await?;
    }
    Ok(())
}

/// Read one HTTP/1.1 request (request line, headers, `Content-Length` body). Returns
/// `None` if the connection closed before a request arrived.
pub(crate) async fn read_request<R>(reader: &mut R) -> Result<Option<HttpRequest>>
where
    R: AsyncBufReadExt + Unpin,
{
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).await? == 0 {
        return Ok(None); // connection closed with no request
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or("/").to_string();

    let mut headers = Vec::new();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await? == 0 {
            break;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break; // end of headers
        }
        if let Some((k, v)) = line.split_once(':') {
            let (k, v) = (k.trim(), v.trim());
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.parse().unwrap_or(0);
            }
            headers.push((k.to_string(), v.to_string()));
        }
    }
    if content_length > MAX_BODY {
        anyhow::bail!("request body exceeds {MAX_BODY} bytes");
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).await?;
    }
    Ok(Some(HttpRequest {
        method,
        path,
        headers,
        body,
    }))
}

/// Write an HTTP/1.1 response and close (one request per connection).
pub(crate) async fn write_response<W: AsyncWrite + Unpin>(
    w: &mut W,
    resp: &HttpResponse,
) -> Result<()> {
    let mut head = format!("HTTP/1.1 {} {}\r\n", resp.status, reason(resp.status));
    for (k, v) in &resp.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\n", resp.body.len()));
    head.push_str("Connection: close\r\n\r\n");
    w.write_all(head.as_bytes()).await?;
    w.write_all(&resp.body).await?;
    w.flush().await?;
    Ok(())
}

/// The reason phrases the gateway itself emits.
fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        429 => "Too Many Requests",
        502 => "Bad Gateway",
        _ => "OK",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// An in-memory upstream that returns a canned response and counts calls, so the
    /// enforcement logic can be tested without a network.
    struct FakeForwarder {
        resp: HttpResponse,
        calls: AtomicUsize,
    }
    impl FakeForwarder {
        fn new(status: u16, body: Value) -> Self {
            Self {
                resp: HttpResponse {
                    status,
                    headers: vec![("content-type".into(), "application/json".into())],
                    body: body.to_string().into_bytes(),
                },
                calls: AtomicUsize::new(0),
            }
        }
    }
    impl Forwarder for FakeForwarder {
        async fn forward(&self, _req: &HttpRequest) -> Result<HttpResponse> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.resp.clone())
        }
    }

    fn req() -> HttpRequest {
        HttpRequest {
            method: "POST".into(),
            path: "/v1/messages".into(),
            headers: vec![("authorization".into(), "Bearer sk-test".into())],
            body: b"{}".to_vec(),
        }
    }

    fn header<'a>(resp: &'a HttpResponse, name: &str) -> Option<&'a str> {
        resp.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    #[tokio::test]
    async fn meters_a_reply_and_stamps_the_running_total() {
        let core = GatewayCore::new(
            SpendMeter::new(None, PriceTable::builtin()),
            "unknown".into(),
        );
        let up = FakeForwarder::new(
            200,
            json!({"model":"claude-opus-4-8","usage":{"input_tokens":1_000_000,"output_tokens":0}}),
        );
        let resp = core.handle(req(), &up).await;
        assert_eq!(resp.status, 200);
        assert_eq!(
            up.calls.load(Ordering::SeqCst),
            1,
            "the request was forwarded"
        );
        // opus input 1500 c/Mtok × 1M = 1500 cents.
        assert_eq!(header(&resp, "x-foreguard-spent-cents"), Some("1500"));
    }

    #[tokio::test]
    async fn refuses_once_the_budget_is_crossed_without_forwarding() {
        // Budget $10 = 1000 c. First call costs $15 (1M opus input) → trips the switch.
        let core = GatewayCore::new(
            SpendMeter::new(Some(1000), PriceTable::builtin()),
            "unknown".into(),
        );
        let up = FakeForwarder::new(
            200,
            json!({"model":"claude-opus-4-8","usage":{"input_tokens":1_000_000,"output_tokens":0}}),
        );
        let first = core.handle(req(), &up).await;
        assert_eq!(first.status, 200, "the first request goes through");

        let second = core.handle(req(), &up).await;
        assert_eq!(second.status, 429, "over budget → refused");
        assert_eq!(
            up.calls.load(Ordering::SeqCst),
            1,
            "the refused request was NEVER sent upstream"
        );
        assert!(String::from_utf8_lossy(&second.body).contains("budget"));
    }

    #[tokio::test]
    async fn a_502_is_returned_when_the_upstream_fails() {
        struct Broken;
        impl Forwarder for Broken {
            async fn forward(&self, _req: &HttpRequest) -> Result<HttpResponse> {
                anyhow::bail!("connection refused")
            }
        }
        let core = GatewayCore::new(
            SpendMeter::new(None, PriceTable::builtin()),
            "unknown".into(),
        );
        let resp = core.handle(req(), &Broken).await;
        assert_eq!(resp.status, 502);
        assert!(String::from_utf8_lossy(&resp.body).contains("upstream"));
    }

    #[test]
    fn meters_streaming_sse_bodies() {
        let sse = "event: message_start\n\
                   data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-5\",\"usage\":{\"input_tokens\":100000,\"output_tokens\":1}}}\n\n\
                   event: message_delta\n\
                   data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":100000}}\n\n\
                   data: [DONE]\n\n";
        let (model, usage) = meter_from_body(sse.as_bytes(), "unknown");
        assert_eq!(model, "claude-sonnet-5");
        assert_eq!(
            usage,
            Some(Usage {
                input_tokens: 100_000,
                output_tokens: 100_000
            })
        );
    }

    /// End-to-end over loopback: a real `ReqwestForwarder` against a one-shot fake
    /// upstream, exercising the actual HTTP client path (no external network).
    #[tokio::test]
    async fn reqwest_forwarder_round_trips_against_a_local_upstream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Fake upstream: accept one connection, reply with a fixed JSON body.
        let up = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut reader = BufReader::new(read);
            let _ = read_request(&mut reader).await.unwrap();
            let resp = HttpResponse {
                status: 200,
                headers: vec![("content-type".into(), "application/json".into())],
                body: br#"{"model":"gpt-5","usage":{"prompt_tokens":10,"completion_tokens":5}}"#
                    .to_vec(),
            };
            write_response(&mut write, &resp).await.unwrap();
        });

        let fwd = ReqwestForwarder::new(format!("http://127.0.0.1:{port}")).unwrap();
        let resp = fwd.forward(&req()).await.unwrap();
        assert_eq!(resp.status, 200);
        assert!(String::from_utf8_lossy(&resp.body).contains("gpt-5"));
        up.await.unwrap();
    }
}
