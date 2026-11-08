// SPDX-License-Identifier: MIT OR Apache-2.0
//! `consiglio-sign` — DEMO-ONLY wallet signer, to exercise `consiglio-verify`.
//!
//! Production signing lives in the wallet (`postern-wallet` CLI); this exists so
//! the console self-check can produce a REAL hybrid-PQ login attempt to feed the
//! real verifier — proving the JS bridge runs genuine cryptography, not a stub.
//!
//! It generates a fresh hybrid keypair, signs a login transcript for the given
//! `(org, user, nonce, issued_at)`, and prints the exact request JSON
//! `consiglio-verify` consumes on stdin. Add `--tamper` to flip a signature bit
//! (so the verifier must reject it).
//!
//! Usage: `consiglio-sign <org> <user> <nonce_hex> <issued_at> [--tamper]`

use postern_consiglio_auth::challenge::{Challenge, DEFAULT_TTL_SECS};
use postern_consiglio_auth::client::sign_challenge;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        eprintln!("usage: consiglio-sign <org> <user> <nonce_hex> <issued_at> [--tamper]");
        std::process::exit(2);
    }
    let org = args[1].clone();
    let user = args[2].clone();
    let nonce = match unhex32(&args[3]) {
        Some(n) => n,
        None => {
            eprintln!("nonce_hex must be 64 hex chars");
            std::process::exit(2);
        }
    };
    let issued_at: i64 = args[4].parse().unwrap_or(0);
    let tamper = args.iter().any(|a| a == "--tamper");

    let (pk, sk) = bloch_crypto::crypto::generate_keypair();
    let challenge = Challenge {
        org_id: org.clone(),
        user_id: user.clone(),
        nonce,
        issued_at,
        expires_at: issued_at + DEFAULT_TTL_SECS,
    };
    let mut resp = sign_challenge(&challenge, &pk, &sk).expect("sign");
    if tamper {
        resp.signature[0] ^= 0xff;
    }

    // Emit exactly the request JSON that consiglio-verify reads.
    println!(
        "{{\"public_key_b64\":\"{}\",\"signature_b64\":\"{}\",\"org_id\":\"{}\",\"user_id\":\"{}\",\"nonce_hex\":\"{}\",\"issued_at\":{}}}",
        b64(&resp.public_key),
        b64(&resp.signature),
        json_escape(&org),
        json_escape(&user),
        args[3],
        issued_at,
    );
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn b64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(T[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(T[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
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
