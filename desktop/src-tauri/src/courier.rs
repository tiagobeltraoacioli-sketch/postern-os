// SPDX-License-Identifier: MIT OR Apache-2.0
//! Courier — the real postern-courier hybrid post-quantum payload seal behind
//! the desktop's `courier_*` #[tauri::command]s (replacing the pane's
//! classical ECDH-P256 preview KEM).
//!
//! The seal is `postern_courier`'s ML-KEM-1024 + X25519 hybrid (HKDF-SHA-256
//! combiner → XChaCha20-Poly1305): a break of either KEM leg alone leaves the
//! payload protected by the other. The commands here are the CRYPTO surface
//! only — generate a recipient identity, seal bytes to a public key, open a
//! sealed envelope with the secret key. Moving the sealed bytes between the
//! two people goes through `postern_courier::drop_transport`'s
//! `DropSender`/`DropFetcher` trait seam: this build keeps the crate's
//! `onion-transport` feature OFF (no Tor process, no arti, no network) and
//! tests/courier_core.rs exercises the seal → drop → open pipeline offline
//! through the crate's in-memory `MockDrop`. The live ephemeral-onion drop
//! stays behind that same seam in postern-courier, with its live end-to-end
//! test `#[ignore]`-gated there.
//!
//! Like `hygiene`/`terem`/`vault`, this module is re-exported from src/lib.rs
//! so integration tests (tests/courier_core.rs) can drive the pure envelope
//! functions without a live Tauri app — the same deliberate, disclosed
//! dual-compile (see Cargo.toml's `[lib]` comment).
//!
//! ## Honesty labels (carried, never weakened)
//!
//! - **UNAUDITED reference prototype**, like everything in this repo,
//!   pre-mainnet. The PQ legs are pre-1.0 RustCrypto `ml-kem`/`ml-dsa` —
//!   exactly why the classical X25519 leg exists.
//! - **Mock-transport tested only — NO live-anonymity claim.** No onion drop
//!   ran here; this build ships the crypto seal with the transport seam left
//!   mock/offline. Sealing does not anonymize anything: payload size, timing,
//!   and endpoints remain observable to whatever transport eventually carries
//!   the bytes (the AEAD is length-revealing, no padding).
//! - **Key authenticity is out-of-band**: `courier_seal` encrypts to whatever
//!   public key it is given. Compare `fingerprint` readings over a channel
//!   both people already trust, or an active MITM who substitutes their own
//!   key reads everything.
//! - A bare sealed envelope has **no sender authentication** — anyone holding
//!   the recipient's public key can produce one. postern-courier's opt-in
//!   `sender_auth` + `replay` modules close that at the payload layer (see
//!   `receive_verified`, exercised in tests/courier_core.rs); these commands
//!   do not silently claim it.
//!
//! Every response carries the [`HONESTY`] text so the pane can never present
//! this as an audited or live-anonymous transport.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use postern_courier::{generate_recipient, key_fingerprint, open, seal, SealedPayload};
use serde_json::{json, Value};
use zeroize::Zeroizing;

/// Mandatory per-response honesty text. Surfaced verbatim in every
/// `courier_*` result's `honesty` field so the UI can never overclaim. The
/// phrases "UNAUDITED reference prototype", "mock-transport tested only" and
/// "no live-anonymity claim" are load-bearing (tests assert them).
pub const HONESTY: &str = "UNAUDITED reference prototype — hybrid PQ seal (ML-KEM-1024 + X25519 \
     → XChaCha20-Poly1305, pre-1.0 RustCrypto PQ legs). Mock-transport tested only: no live onion \
     drop runs in this build, so there is no live-anonymity claim — payload size/timing/endpoints \
     stay observable to any transport. Authenticate the recipient key out-of-band (compare \
     fingerprints); a bare sealed payload has no sender authentication.";

/// Envelope format tag (`v` field of the sealed JSON). Bump alongside any
/// change to [`encode_inner`]'s framing or postern-courier's wire version.
pub const ENVELOPE_V: &str = "postern-courier/2";

/// Hard cap on the embedded file name so a hostile envelope cannot declare a
/// multi-gigabyte "name" and force a giant allocation at decode time.
const MAX_NAME_LEN: usize = 4096;

// ─────────────────────────────────────────────────────────────────────────────
// Pure, testable core (no State, no IO) — what tests/courier_core.rs drives.
// ─────────────────────────────────────────────────────────────────────────────

/// Frame `(name, bytes)` into the plaintext the seal covers:
/// `u32-le name_len ‖ name_utf8 ‖ bytes`. The file name travels INSIDE the
/// seal on purpose — carrying it in the clear next to the ciphertext would
/// leak it to whatever transport moves the envelope.
pub fn encode_inner(name: &str, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let name_bytes = name.as_bytes();
    if name_bytes.len() > MAX_NAME_LEN {
        return Err(format!("file name too long ({} bytes, max {MAX_NAME_LEN})", name_bytes.len()));
    }
    let mut inner = Zeroizing::new(Vec::with_capacity(4 + name_bytes.len() + bytes.len()));
    inner.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
    inner.extend_from_slice(name_bytes);
    inner.extend_from_slice(bytes);
    Ok(inner)
}

/// Decode [`encode_inner`]'s framing back to `(name, bytes)`. Fail closed: a
/// short header, an oversized/overflowing name length, or non-UTF-8 name is
/// "corrupt payload", never a partial parse.
pub fn decode_inner(inner: &[u8]) -> Result<(String, Vec<u8>), String> {
    let name_len = inner
        .get(0..4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize)
        .ok_or("corrupt payload: short header")?;
    if name_len > MAX_NAME_LEN {
        return Err("corrupt payload: name length over cap".into());
    }
    let end = 4usize
        .checked_add(name_len)
        .filter(|e| *e <= inner.len())
        .ok_or("corrupt payload: name length past end")?;
    let name = std::str::from_utf8(&inner[4..end])
        .map_err(|_| "corrupt payload: name is not UTF-8")?
        .to_string();
    Ok((name, inner[end..].to_vec()))
}

/// Pure core of [`courier_seal`]: seal `bytes` (with `name` framed inside the
/// plaintext) to the base64 recipient public key. Returns the envelope JSON
/// the pane hands to the recipient: `{ v, sealedB64, fingerprint, honesty }`.
/// The fingerprint echoes the KEY THE PAYLOAD WAS SEALED TO, for out-of-band
/// comparison — it does not authenticate anything by itself.
pub fn seal_envelope(recipient_public_b64: &str, name: &str, bytes: &[u8]) -> Result<Value, String> {
    let public = B64
        .decode(recipient_public_b64.trim())
        .map_err(|e| format!("invalid recipient public key base64: {e}"))?;
    let inner = encode_inner(name, bytes)?;
    let sealed = seal(&public, &inner).map_err(|e| e.to_string())?;
    Ok(json!({
        "v": ENVELOPE_V,
        "sealedB64": B64.encode(sealed.to_bytes()),
        "fingerprint": key_fingerprint(&public),
        "honesty": HONESTY,
    }))
}

/// Pure core of [`courier_open`]: open an envelope produced by
/// [`seal_envelope`] with the base64 hybrid secret key. Fail closed: wrong
/// version tag, bad base64, a tampered/truncated wire blob, or the wrong key
/// is an error — never partial plaintext. Returns `{ name, bytesB64, honesty }`.
pub fn open_envelope(recipient_secret_b64: &str, sealed: &Value) -> Result<Value, String> {
    match sealed.get("v").and_then(Value::as_str) {
        Some(ENVELOPE_V) => {}
        Some(other) => return Err(format!("unsupported envelope version '{other}'")),
        None => return Err("not a postern-courier envelope (missing 'v')".into()),
    }
    let wire_b64 = sealed
        .get("sealedB64")
        .and_then(Value::as_str)
        .ok_or("not a postern-courier envelope (missing 'sealedB64')")?;
    let wire = B64
        .decode(wire_b64.trim())
        .map_err(|e| format!("invalid sealed payload base64: {e}"))?;
    let secret = Zeroizing::new(
        B64.decode(recipient_secret_b64.trim())
            .map_err(|e| format!("invalid recipient secret key base64: {e}"))?,
    );
    let payload = SealedPayload::from_bytes(&wire).map_err(|e| e.to_string())?;
    let inner = Zeroizing::new(open(&secret, &payload).map_err(|e| e.to_string())?);
    let (name, bytes) = decode_inner(&inner)?;
    Ok(json!({
        "name": name,
        "bytesB64": B64.encode(&bytes),
        "honesty": HONESTY,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// The #[tauri::command] surface (matches ../src/modules/courier.js exactly).
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a fresh hybrid recipient identity (ML-KEM-1024 ‖ X25519, OS
/// CSPRNG). Returns base64 `public`/`secret` plus the human-comparable
/// `fingerprint` for out-of-band key authentication. The pane holds the
/// secret in page memory only; nothing is persisted by the backend.
#[tauri::command]
pub fn courier_generate_recipient() -> Value {
    let r = generate_recipient();
    json!({
        "public": B64.encode(&r.public),
        "secret": B64.encode(&r.secret),
        "fingerprint": key_fingerprint(&r.public),
        "honesty": HONESTY,
    })
    // `r` drops here → Recipient's Drop zeroizes the secret key bytes.
}

/// Seal a file to a recipient's base64 public key. `bytes_b64` is the file's
/// standard base64 (the pane's `UI.toB64`); `name` is framed INSIDE the seal
/// (see [`encode_inner`]) so the transport never sees it. Returns the
/// envelope JSON the sender hands to the recipient out-of-band or over the
/// (future, trait-seamed) drop.
#[tauri::command]
pub fn courier_seal(
    recipient_public: String,
    bytes_b64: String,
    name: Option<String>,
) -> Result<Value, String> {
    let bytes = Zeroizing::new(
        B64.decode(bytes_b64.trim())
            .map_err(|e| format!("invalid payload base64: {e}"))?,
    );
    seal_envelope(&recipient_public, name.as_deref().unwrap_or("payload.bin"), &bytes)
}

/// Open a sealed envelope with the recipient's base64 hybrid secret key.
/// Fail closed on any tamper/mismatch (see [`open_envelope`]).
#[tauri::command]
pub fn courier_open(recipient_secret: String, sealed: Value) -> Result<Value, String> {
    open_envelope(&recipient_secret, &sealed)
}
