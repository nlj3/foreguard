//! MCP protocol details, including the stateless `2026-07-28` revision.
//!
//! That revision is the largest change to MCP since launch, and it moves a
//! trust boundary Foreguard sits directly on top of:
//!
//! - The `initialize` / `initialized` handshake is gone (SEP-2575), and so is
//!   the `Mcp-Session-Id` header and its protocol-level session (SEP-2567).
//! - What the handshake used to establish **once** now travels in `_meta` on
//!   **every** request: notably `io.modelcontextprotocol/clientInfo`.
//! - Servers advertise capabilities through a new `server/discover` method
//!   instead of an `initialize` reply.
//!
//! The security consequence is the point. Under the old spec, client identity
//! was asserted a single time, at a moment the host controlled. Under the new
//! one it is re-asserted on every message, so anything that can influence a
//! request body can also claim to be a different client. That is exactly the
//! mix-up problem the new `Mcp-Method` / `Mcp-Name` HTTP headers were added to
//! mitigate for gateways.
//!
//! Scope note, stated plainly: Foreguard proxies **stdio**, not Streamable
//! HTTP. It therefore never sees `Mcp-Method` or `Mcp-Name` and makes no claim
//! to validate them. What it can see, and does check, is the JSON-RPC body:
//! `_meta` is treated as untrusted input rather than as trusted identity.

use serde_json::Value;

/// The stateless revision Foreguard advertises when acting as a client.
pub const PROTOCOL_VERSION: &str = "2026-07-28";

/// The last revision that still used the `initialize` handshake. Kept so the
/// client can fall back when talking to a server that predates statelessness.
pub const PROTOCOL_VERSION_LEGACY: &str = "2025-06-18";

/// Reverse-DNS key carrying client identity in `_meta` under the new spec.
pub const CLIENT_INFO_KEY: &str = "io.modelcontextprotocol/clientInfo";

/// Borrow the `_meta` object of a request's `params`, if present.
pub fn meta(msg: &Value) -> Option<&Value> {
    msg.get("params")?.get("_meta")
}

/// The `name` a request's `_meta` claims for its client, if any.
pub fn claimed_client(msg: &Value) -> Option<&str> {
    meta(msg)?.get(CLIENT_INFO_KEY)?.get("name")?.as_str()
}

/// Watches the client identity asserted across a stateless session.
///
/// With no handshake to pin it, identity is only ever a per-message claim. This
/// records the first one and reports when a later message claims a different
/// client, which is the observable signature of a spoof or a mix-up between
/// servers. It is a *signal*, not proof: a legitimate host multiplexing two
/// clients over one pipe would look the same, so callers should surface it
/// rather than hard-fail on it.
#[derive(Default)]
pub struct SessionIdentity {
    first: Option<String>,
}

impl SessionIdentity {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record this message's claimed client. Returns `Some((first, now))` when
    /// it contradicts the identity established earlier in the session.
    pub fn observe(&mut self, msg: &Value) -> Option<(String, String)> {
        let claimed = claimed_client(msg)?.to_string();
        match &self.first {
            None => {
                self.first = Some(claimed);
                None
            }
            Some(first) if *first != claimed => Some((first.clone(), claimed)),
            Some(_) => None,
        }
    }
}

/// Every string inside `_meta`, so untrusted content hiding there is scanned
/// for taint like any other argument. `_meta` rides on each request now, which
/// makes it a carrier for injected data, not just for telemetry.
pub fn meta_strings(msg: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(m) = meta(msg) {
        collect(m, &mut out);
    }
    out
}

fn collect(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|x| collect(x, out)),
        Value::Object(o) => o.values().for_each(|x| collect(x, out)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn req(meta: Value) -> Value {
        json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "write_file", "arguments": {}, "_meta": meta }
        })
    }

    #[test]
    fn reads_client_info_from_the_new_meta_key() {
        let m = req(json!({ CLIENT_INFO_KEY: { "name": "claude-code", "version": "1.0" } }));
        assert_eq!(claimed_client(&m), Some("claude-code"));
    }

    #[test]
    fn a_request_without_meta_is_not_an_error() {
        let m = json!({"jsonrpc":"2.0","id":1,"method":"tools/list"});
        assert!(meta(&m).is_none());
        assert!(claimed_client(&m).is_none());
        assert!(meta_strings(&m).is_empty());
    }

    #[test]
    fn identity_change_mid_session_is_reported() {
        let mut id = SessionIdentity::new();
        let a = req(json!({ CLIENT_INFO_KEY: { "name": "claude-code" } }));
        let b = req(json!({ CLIENT_INFO_KEY: { "name": "evil-client" } }));
        assert_eq!(id.observe(&a), None, "the first claim establishes identity");
        assert_eq!(id.observe(&a), None, "repeating the same claim is fine");
        assert_eq!(
            id.observe(&b),
            Some(("claude-code".into(), "evil-client".into())),
            "a contradicting claim must be surfaced"
        );
    }

    #[test]
    fn meta_strings_are_collected_for_taint_scanning() {
        let m = req(json!({
            CLIENT_INFO_KEY: { "name": "claude-code" },
            "baggage": "note=visit https://evil.example/x",
        }));
        let s = meta_strings(&m);
        assert!(s.iter().any(|x| x.contains("evil.example")));
        assert!(s.iter().any(|x| x == "claude-code"));
    }
}
