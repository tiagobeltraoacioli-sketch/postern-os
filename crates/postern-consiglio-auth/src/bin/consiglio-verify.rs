// SPDX-License-Identifier: MIT OR Apache-2.0
//! `consiglio-verify` — the REAL wallet-login verifier as a stdin/stdout tool.
//!
//! This is the native side of "wire the Rust verifier behind the JS bridge".
//! The console's JavaScript (which cannot run the hybrid Falcon ‖ ML-DSA
//! verifier itself) spawns this binary and pipes it one login attempt as JSON;
//! it reconstructs the exact domain-separated login transcript and verifies the
//! signature with the SAME `bloch_crypto::crypto::verify` the node uses. It
//! replaces the reference `"SIG(...)"` string stub with real cryptography.
//!
//! It is a PURE verifier: it holds no keys, no state, and no session logic — it
//! answers exactly one question, "does this signature verify over this login
//! transcript for this public key?", and prints a one-line JSON verdict.
//! Fail-closed: any malformed input or verification failure yields `ok:false`.
//!
//! ## Wire contract (stdin, one JSON object)
//! ```json
//! { "public_key_b64": "<hybrid PQ pubkey>",
//!   "signature_b64":  "<hybrid PQ signature>",
//!   "org_id": "acme", "user_id": "alice",
//!   "nonce_hex": "<64 hex chars>", "issued_at": 1752300000 }
//! ```
//! ## stdout (one JSON object)
//! `{"ok":true}` on a valid signature, else `{"ok":false,"reason":"..."}`.

use postern_consiglio_auth::challenge::{Challenge, DEFAULT_TTL_SECS};
use serde::Deserialize;

#[derive(Deserialize)]
struct VerifyRequest {
    public_key_b64: String,
    signature_b64: String,
    org_id: String,
    user_id: String,
    nonce_hex: String,
    issued_at: i64,
}

fn main() {
    let mut input = String::new();
    if std::io::Read::read_to_string(&mut std::io::stdin(), &mut input).is_err() {
        return fail("could not read stdin");
    }
    let req: VerifyRequest = match serde_json::from_str(&input) {
        Ok(r) => r,
        Err(e) => return fail(&format!("invalid request json: {e}")),
    };

    let public_key = match b64(&req.public_key_b64) {
        Some(v) => v,
        None => return fail("public_key_b64 is not valid base64"),
    };
    let signature = match b64(&req.signature_b64) {
        Some(v) => v,
        None => return fail("signature_b64 is not valid base64"),
    };
    let nonce = match unhex32(&req.nonce_hex) {
        Some(n) => n,
        None => return fail("nonce_hex must be 64 hex chars"),
    };

    // Reconstruct the EXACT transcript the wallet signed. Reusing Challenge here
    // guarantees byte-identical domain separation with the server verifier.
    let challenge = Challenge {
        org_id: req.org_id,
        user_id: req.user_id,
        nonce,
        issued_at: req.issued_at,
        // expires_at is not part of the transcript; a value keeps the type whole.
        expires_at: req.issued_at + DEFAULT_TTL_SECS,
    };
    let transcript = challenge.transcript();

    // THE REAL PQ CHECK — hybrid Falcon ‖ ML-DSA, no bespoke crypto.
    let ok = bloch_crypto::crypto::verify(&public_key, &transcript, &signature);
    if ok {
        println!("{{\"ok\":true}}");
    } else {
        fail("post-quantum signature verification failed");
    }
}

fn fail(reason: &str) {
    // Escape the reason minimally for a valid one-line JSON string.
    let escaped = reason.replace('\\', "\\\\").replace('"', "\\\"");
    println!("{{\"ok\":false,\"reason\":\"{escaped}\"}}");
}

/// Minimal standard base64 decoder (no external dep — the crate is dep-light).
fn b64(s: &str) -> Option<Vec<u8>> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lut = [255u8; 256];
    for (i, &c) in T.iter().enumerate() {
        lut[c as usize] = i as u8;
    }
    let clean: Vec<u8> = s.bytes().filter(|&b| b != b'\n' && b != b'\r' && b != b' ').collect();
    let clean: &[u8] = clean.strip_suffix(b"==").or_else(|| clean.strip_suffix(b"=")).unwrap_or(&clean);
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in clean {
        let v = lut[c as usize];
        if v == 255 {
            return None;
        }
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}
