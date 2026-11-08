//! Loopback integration test for the REAL Lighthouse [`LiveBackend`] HTTP/1.1
//! client (`src/live.rs`), gated behind the `live` cargo feature.
//!
//! Spec: `docs/specs/POSTERN-DATA-FILECOIN-DESIGN.md`, §4 ("`LighthouseBackend`
//! — the MVP live impl"). Where `src/live.rs`'s in-module `#[cfg(test)]` unit
//! tests drive the client from a hand-built [`LiveConfig`], this file exercises
//! the crate's PUBLIC surface end-to-end the way an operator wires it: it sets
//! the real `LIGHTHOUSE_UPLOAD_URL` / `LIGHTHOUSE_GATEWAY_URL` /
//! `LIGHTHOUSE_DEAL_STATUS_URL` env overrides at a loopback mock and builds the
//! backend through [`LiveBackend::from_env`] — the same path production uses to
//! point at a local TLS proxy.
//!
//! # What the mock proves
//!
//! A single in-process `std::net::TcpListener` on `127.0.0.1:0` speaks enough
//! of the Lighthouse wire to close the loop, with ZERO network egress and NO
//! signup:
//!
//! * `POST /api/v0/add` — parses the `multipart/form-data` body, stashes the
//!   uploaded (already-sealed, opaque) bytes, and answers
//!   `{"Name":…,"Hash":"<cid>","Size":…}` exactly like the real `add`.
//! * `GET /ipfs/<cid>` — the retrieval gateway; serves the stashed blob back.
//! * `GET …/deal_status?cid=<cid>` — the persistence probe; returns a deal JSON
//!   array so the client's best-effort parser has something real to parse.
//!
//! The assertions: `put_car -> get` round-trips **byte-identically** (the
//! transport is faithful — integrity is re-verified upstream, never here),
//! `deal_status` parses into a typed [`DealStatus::DealActive`], and an
//! `https://` upload target is refused with the typed TLS-guidance rejection
//! (the client links no TLS in-crate, by design).
//!
//! Honesty: this is a loopback mock, not the real provider — it proves the
//! client's wire behaviour, not that Lighthouse works. The operator-gated LIVE
//! smoke test lives in `src/live.rs` (`#[ignore]`d) and is the only thing that
//! touches a real endpoint.

#![cfg(feature = "live")]

use bloch_data::live::{
    LiveBackend, ENV_API_KEY, ENV_DEAL_STATUS_URL, ENV_GATEWAY_URL, ENV_UPLOAD_URL,
};
use bloch_data::{BackendError, Cid, DealInfo, DealStatus, StorageBackend};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

/// The provider-reported CID the loopback `add` hands back. It is an opaque
/// locator string (this crate never inspects a CID), stored verbatim and used
/// as the `/ipfs/<cid>` gateway path on retrieval.
const MOCK_CID: &str = "bafkreiloopbackintegrationtestcidvalue00000000000000000000";

/// `std::env` is process-global; the two env-mutating tests in this binary are
/// serialized through this guard so their `set_var`/`remove_var` never race.
static ENV_GUARD: Mutex<()> = Mutex::new(());

/// A one-in-process loopback Lighthouse mock. Bound on `127.0.0.1:0`; its base
/// URL is `http://127.0.0.1:<ephemeral-port>`.
struct MockLighthouse {
    base: String,
}

/// Bind a loopback listener and spawn a background router thread that serves
/// the three Lighthouse routes for the life of the test process. The uploaded
/// blob is shared between the `add` and gateway handlers via `store`.
fn spawn_mock() -> MockLighthouse {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local_addr");
    let store: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(mut s) => handle(&mut s, Arc::clone(&store)),
                Err(_) => continue,
            }
        }
    });
    MockLighthouse {
        base: format!("http://{addr}"),
    }
}

/// Serve one connection: read the request, route on method+path, reply, then
/// half-close so the client's `read_to_end` (it sends `Connection: close`)
/// returns.
fn handle(stream: &mut TcpStream, store: Arc<Mutex<Vec<u8>>>) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));

    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }
    let request_line = request_line.trim_end().to_string();

    let mut content_length = 0usize;
    let mut boundary = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim();
            if k == "content-length" {
                content_length = v.parse().unwrap_or(0);
            } else if k == "content-type" {
                if let Some(i) = v.find("boundary=") {
                    boundary = v[i + "boundary=".len()..].to_string();
                }
            }
        }
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).expect("read request body");
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    let response = if method == "POST" && target.starts_with("/api/v0/add") {
        // Stash the sealed bytes carried inside the multipart part, then answer
        // the flat Lighthouse `add` JSON shape.
        let file_bytes = extract_multipart_file(&body, &boundary);
        *store.lock().unwrap() = file_bytes;
        http_response(
            "200 OK",
            format!("{{\"Name\":\"blob\",\"Hash\":\"{MOCK_CID}\",\"Size\":\"{content_length}\"}}")
                .as_bytes(),
        )
    } else if method == "GET" && target.starts_with("/ipfs/") {
        // Retrieval gateway: serve the stashed blob verbatim.
        let blob = store.lock().unwrap().clone();
        http_response("200 OK", &blob)
    } else if method == "GET" && target.contains("deal_status") {
        // Persistence probe: one active on-chain deal for the parser to read.
        let json = br#"[{"dealId":424242,"storageProvider":"f099999","expirationEpoch":7777777}]"#;
        http_response("200 OK", json)
    } else {
        http_response("404 Not Found", b"unknown loopback route")
    };

    let _ = stream.write_all(&response);
    let _ = stream.flush();
    let _ = stream.shutdown(Shutdown::Write);
}

/// Pull the file bytes out of a single-part `multipart/form-data` body: they sit
/// between the part's header terminator (`\r\n\r\n`) and the closing
/// `\r\n--<boundary>` delimiter.
fn extract_multipart_file(body: &[u8], boundary: &str) -> Vec<u8> {
    let start = match find_sub(body, b"\r\n\r\n") {
        Some(i) => i + 4,
        None => return body.to_vec(),
    };
    let rest = &body[start..];
    let closing = format!("\r\n--{boundary}");
    let end = find_sub(rest, closing.as_bytes()).unwrap_or(rest.len());
    rest[..end].to_vec()
}

/// Build a minimal HTTP/1.1 response (status line + `Content-Length` + body).
fn http_response(status_line: &str, body: &[u8]) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(format!("HTTP/1.1 {status_line}\r\n").as_bytes());
    r.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    r.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    r.extend_from_slice(body);
    r
}

fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

/// The core acceptance loop: wire the env overrides at the loopback mock, build
/// the backend the production way (`from_env`), and prove
/// `put_car -> get` is byte-identical and `deal_status` parses to a typed
/// [`DealStatus::DealActive`]. Pure loopback, no signup, no network egress.
#[test]
fn loopback_put_get_roundtrip_and_deal_status_via_from_env() {
    let _g = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let mock = spawn_mock();

    std::env::set_var(ENV_API_KEY, "loopback-test-key-abc123");
    std::env::set_var(ENV_UPLOAD_URL, format!("{}/api/v0/add", mock.base));
    std::env::set_var(ENV_GATEWAY_URL, format!("{}/ipfs", mock.base));
    std::env::set_var(
        ENV_DEAL_STATUS_URL,
        format!("{}/api/lighthouse/deal_status", mock.base),
    );

    let mut backend = LiveBackend::from_env().expect("from_env with loopback overrides");

    // Postern-SEALED-shaped bytes: opaque, non-plaintext, containing NULs and
    // CRLF so the multipart round-trip is proven on binary content, not ASCII.
    let sealed: Vec<u8> = {
        let mut v = b"POSTERN-SEALED-loopback-".to_vec();
        v.extend_from_slice(&[0x00, 0x01, 0x02, 0x0d, 0x0a, 0xff, 0xfe, 0x7f]);
        v.extend_from_slice(b"-ciphertext-not-plaintext-\r\n-end");
        v
    };

    // 1) Upload: the provider returns a CID LOCATOR, stored verbatim.
    let cid = backend.put_car(&sealed).expect("loopback put_car");
    assert_eq!(
        cid,
        Cid(MOCK_CID.as_bytes().to_vec()),
        "put_car must store the provider CID string verbatim as the locator"
    );

    // 2) Retrieve by CID and assert byte-for-byte identity.
    let fetched = backend.get(&cid).expect("loopback get");
    assert_eq!(
        fetched, sealed,
        "get must round-trip the uploaded ciphertext byte-identically"
    );

    // 3) Persistence probe: the deal JSON parses into a typed active deal.
    let status = backend.deal_status(&cid).expect("loopback deal_status");
    assert_eq!(
        status,
        DealStatus::DealActive(vec![DealInfo {
            deal_id: Some(424242),
            provider: "f099999".to_string(),
            end_epoch: Some(7_777_777),
        }]),
        "deal_status must parse the loopback deal JSON into a typed DealActive"
    );

    std::env::remove_var(ENV_API_KEY);
    std::env::remove_var(ENV_UPLOAD_URL);
    std::env::remove_var(ENV_GATEWAY_URL);
    std::env::remove_var(ENV_DEAL_STATUS_URL);
}

/// An `https://` upload target (the crate default host, or an operator typo)
/// must be refused with the typed TLS-guidance rejection rather than silently
/// failing — the client links no TLS in-crate, so HTTPS is out of reach and
/// says so, pointing at the `LIGHTHOUSE_*_URL` proxy override.
#[test]
fn https_upload_target_returns_typed_rejection() {
    let _g = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());

    std::env::set_var(ENV_API_KEY, "loopback-test-key-abc123");
    std::env::set_var(
        ENV_UPLOAD_URL,
        "https://node.lighthouse.storage/api/v0/add",
    );
    std::env::remove_var(ENV_GATEWAY_URL);
    std::env::remove_var(ENV_DEAL_STATUS_URL);

    let mut backend = LiveBackend::from_env().expect("from_env accepts an https override string");
    let err = backend
        .put_car(b"opaque-sealed-bytes")
        .expect_err("https upload target must be rejected");

    match err {
        BackendError::Unavailable(m) => {
            assert!(m.contains("TLS"), "rejection should mention TLS: {m}");
            assert!(
                m.contains("LIGHTHOUSE_"),
                "rejection should point at the LIGHTHOUSE_*_URL proxy override: {m}"
            );
        }
        other => panic!("expected typed Unavailable rejection, got {other:?}"),
    }

    std::env::remove_var(ENV_API_KEY);
    std::env::remove_var(ENV_UPLOAD_URL);
}
