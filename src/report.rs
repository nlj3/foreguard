//! **Loop closers** — the wires between a local Foreguard instance and the control
//! plane ([`crate::gateway`] governs spend; this reports to and pulls from the fleet).
//!
//! - [`run_report`] ships the local audit ledger's *new* entries to the control
//!   plane's `/v1/ingest`, resuming from the server's last accepted `seq` so a
//!   re-run sends only what's new and the server can linkage-verify the batch.
//! - [`fetch_policy_source`] pulls the central Cedar policy from a URL so a fleet of
//!   proxies enforces one policy pushed from one place.
//!
//! The ingest/admin token is never a CLI argument — it comes from the
//! `FOREGUARD_INGEST_TOKEN` environment variable, so it can't leak into a process
//! list or shell history.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

/// From a ledger's contents, the entries whose `_fg.seq` is greater than
/// `after_seq` — the ones the control plane hasn't accepted yet. Order preserved.
pub fn select_new_entries(ledger_contents: &str, after_seq: i64) -> Vec<Value> {
    ledger_contents
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| {
            v.get("_fg")
                .and_then(|f| f.get("seq"))
                .and_then(Value::as_i64)
                .map(|seq| seq > after_seq)
                .unwrap_or(false)
        })
        .collect()
}

/// The ledger's current head — the last entry's `(seq, hash)` — to attest.
pub fn ledger_head(contents: &str) -> Option<(i64, String)> {
    let last = contents.lines().rev().find(|l| !l.trim().is_empty())?;
    let v: Value = serde_json::from_str(last).ok()?;
    let fg = v.get("_fg")?;
    let seq = fg.get("seq")?.as_i64()?;
    let hash = fg.get("hash")?.as_str()?.to_string();
    Some((seq, hash))
}

/// GET `{base}/v1/head?instance=` → the server's last accepted `seq` for this
/// instance (`-1` if unknown, so a fresh reporter sends from `seq` 0).
async fn server_head(
    client: &reqwest::Client,
    base: &str,
    instance: &str,
    token: &str,
) -> Result<i64> {
    let resp = client
        .get(format!("{}/v1/head", base.trim_end_matches('/')))
        .query(&[("instance", instance)])
        .bearer_auth(token)
        .send()
        .await
        .context("requesting /v1/head")?;
    if !resp.status().is_success() {
        bail!(
            "/v1/head returned {} — check the URL and FOREGUARD_INGEST_TOKEN",
            resp.status()
        );
    }
    let v: Value = resp.json().await.context("parsing /v1/head")?;
    Ok(v.get("last_seq").and_then(Value::as_i64).unwrap_or(-1))
}

/// Ship a ledger's new entries (and optionally the current spend) to the control
/// plane. Idempotent across re-runs: only entries past the server's head are sent.
pub async fn run_report(
    ledger: std::path::PathBuf,
    to: String,
    instance: String,
    spent_cents: Option<u64>,
    key_path: Option<std::path::PathBuf>,
    token: String,
) -> Result<()> {
    let contents = std::fs::read_to_string(&ledger)
        .with_context(|| format!("reading ledger {}", ledger.display()))?;
    let client = reqwest::Client::new();

    let head = server_head(&client, &to, &instance, &token).await?;
    let entries = select_new_entries(&contents, head);
    let n = entries.len();
    if n == 0 && spent_cents.is_none() && key_path.is_none() {
        eprintln!("foreguard report: nothing new past seq {head}; already up to date.");
        return Ok(());
    }

    let mut body = json!({ "instance": instance, "entries": entries });
    if let Some(c) = spent_cents {
        body["spent_cents"] = json!(c);
    }
    // Attest the current ledger head with the instance's signing key, if given, so
    // the control plane can prove the audit trail wasn't rewritten downstream.
    if let Some(kp_path) = &key_path {
        let kp = crate::signing::KeyPair::load(kp_path)?;
        if let Some((seq, hash)) = ledger_head(&contents) {
            let msg = crate::signing::head_message(&instance, seq, &hash);
            body["signed_head"] = json!({
                "seq": seq,
                "hash": hash,
                "pubkey": kp.public_base64(),
                "sig": kp.sign_base64(&msg),
            });
        }
    }
    let resp = client
        .post(format!("{}/v1/ingest", to.trim_end_matches('/')))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .context("posting /v1/ingest")?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!("/v1/ingest returned {status}: {text}");
    }
    eprintln!(
        "foreguard report: sent {n} entr{} past seq {head} to {to} — {text}",
        if n == 1 { "y" } else { "ies" }
    );
    Ok(())
}

/// Fetch central Cedar policy text from a URL (the control plane's `/v1/policy`, or
/// any URL that serves policy). Accepts a `{ "cedar": "…" }` JSON body or a raw
/// Cedar body, so it works with the control plane and with a plain file server alike.
pub async fn fetch_policy_source(url: &str, token: Option<&str>) -> Result<String> {
    let client = reqwest::Client::new();
    let mut rb = client.get(url);
    if let Some(t) = token {
        rb = rb.bearer_auth(t);
    }
    let resp = rb
        .send()
        .await
        .with_context(|| format!("fetching policy from {url}"))?;
    if !resp.status().is_success() {
        bail!("policy URL {url} returned {}", resp.status());
    }
    let body = resp.text().await.context("reading policy body")?;
    if let Ok(v) = serde_json::from_str::<Value>(&body) {
        if let Some(c) = v.get("cedar").and_then(Value::as_str) {
            return Ok(c.to_string());
        }
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::{read_request, write_response, HttpResponse};
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use std::sync::Arc;
    use tokio::io::BufReader;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    const LEDGER: &str = r#"{"tool":"a","_fg":{"seq":0,"prev":"genesis","hash":"h0"}}
{"tool":"b","_fg":{"seq":1,"prev":"h0","hash":"h1"}}
{"tool":"c","_fg":{"seq":2,"prev":"h1","hash":"h2"}}"#;

    fn ok_json(body: Value) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.to_string().into_bytes(),
        }
    }

    #[test]
    fn selects_only_entries_past_the_head() {
        let got = select_new_entries(LEDGER, 0); // after seq 0 → seq 1, 2
        assert_eq!(got.len(), 2);
        assert_eq!(got[0]["tool"], "b");
        assert!(
            select_new_entries(LEDGER, 2).is_empty(),
            "nothing past the tail"
        );
        assert_eq!(
            select_new_entries(LEDGER, -1).len(),
            3,
            "a fresh server gets all"
        );
    }

    #[tokio::test]
    async fn report_sends_only_new_entries_and_spend() {
        let captured: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let cap = captured.clone();
        let server = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let (read, mut write) = stream.into_split();
                let mut reader = BufReader::new(read);
                if let Ok(Some(req)) = read_request(&mut reader).await {
                    let resp = if req.path.starts_with("/v1/head") {
                        // Server already has seq 0 and 1 → only seq 2 is new.
                        ok_json(json!({"instance":"x","last_seq":1,"last_hash":"h1"}))
                    } else {
                        let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
                        *cap.lock().await = Some(body);
                        ok_json(json!({"ok":true,"accepted":1}))
                    };
                    let _ = write_response(&mut write, &resp).await;
                }
            }
        });

        let path = std::env::temp_dir().join(format!("fg_report_{}.jsonl", std::process::id()));
        std::fs::write(&path, LEDGER).unwrap();
        run_report(
            path.clone(),
            format!("http://127.0.0.1:{port}"),
            "x".into(),
            Some(4250),
            None,
            "tok".into(),
        )
        .await
        .unwrap();

        let body = captured.lock().await.clone().expect("ingest was called");
        assert_eq!(body["instance"], "x");
        assert_eq!(body["spent_cents"], 4250);
        let entries = body["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1, "only seq 2 is past the head");
        assert_eq!(entries[0]["tool"], "c");

        server.abort();
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn report_signs_the_head_when_a_key_is_given() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let captured: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let cap = captured.clone();
        let server = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let (read, mut write) = stream.into_split();
                let mut reader = BufReader::new(read);
                if let Ok(Some(req)) = read_request(&mut reader).await {
                    let resp = if req.path.starts_with("/v1/head") {
                        ok_json(json!({"last_seq":-1}))
                    } else {
                        *cap.lock().await = Some(serde_json::from_slice(&req.body).unwrap());
                        ok_json(json!({"ok":true,"accepted":3,"attested":true}))
                    };
                    let _ = write_response(&mut write, &resp).await;
                }
            }
        });

        // Write a signing key.
        let key_path = std::env::temp_dir().join(format!("fg_rk_{}.key", std::process::id()));
        let seed = crate::signing::generate_seed().unwrap();
        crate::signing::write_seed(&key_path, &seed).unwrap();

        let led = std::env::temp_dir().join(format!("fg_rl_{}.jsonl", std::process::id()));
        std::fs::write(&led, LEDGER).unwrap();
        run_report(
            led.clone(),
            format!("http://127.0.0.1:{port}"),
            "signed".into(),
            None,
            Some(key_path.clone()),
            "tok".into(),
        )
        .await
        .unwrap();

        let body = captured.lock().await.clone().expect("ingest was called");
        let sh = &body["signed_head"];
        assert_eq!(sh["seq"], 2, "attests the ledger tail");
        assert_eq!(sh["hash"], "h2");

        // The signature verifies over the canonical head with the reported pubkey.
        let pk: [u8; 32] = STANDARD
            .decode(sh["pubkey"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let sig: [u8; 64] = STANDARD
            .decode(sh["sig"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let msg = crate::signing::head_message("signed", 2, "h2");
        assert!(VerifyingKey::from_bytes(&pk)
            .unwrap()
            .verify(msg.as_bytes(), &Signature::from_bytes(&sig))
            .is_ok());

        server.abort();
        let _ = std::fs::remove_file(&key_path);
        let _ = std::fs::remove_file(&led);
    }

    #[tokio::test]
    async fn fetch_policy_accepts_json_and_raw_bodies() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            for i in 0..2 {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let (read, mut write) = stream.into_split();
                let mut reader = BufReader::new(read);
                let _ = read_request(&mut reader).await;
                let resp = if i == 0 {
                    ok_json(json!({"cedar":"permit(principal, action, resource);","updated":1}))
                } else {
                    HttpResponse {
                        status: 200,
                        headers: vec![("content-type".into(), "text/plain".into())],
                        body: b"forbid(principal, action, resource);".to_vec(),
                    }
                };
                let _ = write_response(&mut write, &resp).await;
            }
        });
        let url = format!("http://127.0.0.1:{port}/v1/policy");
        let as_json = fetch_policy_source(&url, Some("tok")).await.unwrap();
        assert!(
            as_json.contains("permit(principal"),
            "extracts .cedar from JSON"
        );
        let as_raw = fetch_policy_source(&url, None).await.unwrap();
        assert!(
            as_raw.contains("forbid(principal"),
            "falls back to a raw body"
        );
        server.abort();
    }
}
