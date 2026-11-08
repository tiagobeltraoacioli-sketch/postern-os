// SPDX-License-Identifier: MIT OR Apache-2.0
//! Keys — the real postern-keys passkey/FIDO2 ES256 credential core behind
//! the desktop's `keys_*` #[tauri::command]s (replacing the pane's WebCrypto
//! preview that kept keys in page localStorage).
//!
//! One WebAuthn **ES256** (P-256) credential per relying party, created by
//! `postern_keys::create_credential`, signing authentication assertions via
//! `Credential::sign_assertion` and verified locally with
//! `postern_keys::verify_assertion` — the full authenticate round trip, in
//! process. Credentials are held in a `tauri::State<Mutex<Vec<Credential>>>`
//! in RAM: `postern-keys` statically asserts its `SigningKey` is
//! `ZeroizeOnDrop` and keeps the PRF seed in a `Zeroizing` buffer, so
//! removing a credential (or exiting the app) wipes the private material
//! from RAM. Nothing is persisted — vault-sealing the credential records
//! (`Credential::to_vault_record`) is the documented follow-up, not something
//! this surface silently claims.
//!
//! Like `hygiene`/`terem`/`vault`/`courier`, this module is re-exported from
//! src/lib.rs so integration tests (tests/keys_core.rs) can drive the pure
//! `*_impl` cores against a plain `Vec<Credential>` without a live Tauri app
//! — the same deliberate, disclosed dual-compile (see Cargo.toml's `[lib]`
//! comment).
//!
//! ## Honesty labels (carried, never weakened)
//!
//! - **UNAUDITED reference prototype**, like everything in this repo.
//! - **SOFTWARE authenticator**: the private keys live in this app's ordinary
//!   process RAM (zeroized on drop) — NOT a hardware security key, and **not
//!   a TEE until real hardware**. RAM-only also means credentials do NOT
//!   survive an app restart in this build.
//! - **Classical crypto by ecosystem necessity**: WebAuthn relying parties
//!   accept ES256/P-256, not PQ signatures — no PQ passkey claim is made.
//! - This is the credential core behind a demo pane, not a CTAP2/browser
//!   integration — no site can use these passkeys yet.
//!
//! Every response carries the [`HONESTY`] text so the pane can never present
//! this as hardware-backed or production auth.

use std::sync::Mutex;

use postern_keys::{create_credential, verify_assertion, Credential};
use serde_json::{json, Value};
use tauri::State;

use crate::sha256::Sha256;

/// Mandatory per-response honesty text. Surfaced verbatim in every `keys_*`
/// result's `honesty` field. The phrases "UNAUDITED reference prototype",
/// "software authenticator" and "not a TEE until real hardware" are
/// load-bearing (tests assert them).
pub const HONESTY: &str = "UNAUDITED reference prototype — SOFTWARE authenticator: ES256 private \
     keys live in this app's RAM only (zeroized on drop, lost on restart), not in a hardware key, \
     and not a TEE until real hardware. Classical P-256 by WebAuthn-ecosystem necessity; no \
     CTAP2/browser integration is wired, so no site consumes these passkeys yet.";

/// Domain-separation prefix for hashing the pane's hex challenge into the
/// 32-byte `client_data_hash` slot of the assertion (this demo surface has no
/// browser `clientDataJSON`; the domain tag keeps these signatures inert
/// outside this surface).
const CHALLENGE_DOMAIN: &[u8] = b"postern-keys/desktop-challenge/v1";

/// WebAuthn authenticator-data flags: UP (user present) only — honest for a
/// software authenticator with no user-verification hardware (no UV bit).
const FLAG_UP: u8 = 0x01;

/// All credentials, in RAM only (see module docs). `pub` so main.rs can
/// `.manage()` it and tests can build one.
#[derive(Default)]
pub struct KeysState(pub Mutex<Vec<Credential>>);

// ─────────────────────────────────────────────────────────────────────────────
// Pure, testable core (no State) — what tests/keys_core.rs drives.
// ─────────────────────────────────────────────────────────────────────────────

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finish()
}

/// Build the WebAuthn `authenticator_data` for an assertion:
/// `SHA-256(rp_id) (32) ‖ flags (1, UP only) ‖ sign counter (u32-BE)` —
/// the standard 37-byte layout. Pure, so verifiers (tests, a future RP side)
/// can reconstruct the exact signed bytes.
pub fn authenticator_data(rp_id: &str, counter: u32) -> Vec<u8> {
    let mut ad = Vec::with_capacity(37);
    ad.extend_from_slice(&sha256(rp_id.as_bytes()));
    ad.push(FLAG_UP);
    ad.extend_from_slice(&counter.to_be_bytes());
    ad
}

/// Hash the pane's challenge string into the assertion's 32-byte
/// `client_data_hash` slot, under [`CHALLENGE_DOMAIN`]. Pure.
pub fn challenge_hash(challenge: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CHALLENGE_DOMAIN);
    h.update(&(challenge.len() as u64).to_le_bytes());
    h.update(challenge.as_bytes());
    h.finish()
}

/// The per-credential JSON the pane renders: identity + public material only
/// (hex credential id, hex SEC1 public key, sign count) — never the private
/// key — plus the mandatory honesty text on every entry.
fn credential_json(c: &Credential) -> Value {
    json!({
        "rpId": c.rp_id,
        "credentialId": hex::encode(c.credential_id),
        "publicKey": hex::encode(c.public_key()),
        "signCount": c.counter(),
        "honesty": HONESTY,
    })
}

/// Pure core of [`keys_create`]: create a fresh ES256 credential for `rp_id`
/// and append it to `creds`. Rejects a blank relying party.
pub fn create_impl(creds: &mut Vec<Credential>, rp_id: &str) -> Result<Value, String> {
    let rp_id = rp_id.trim();
    if rp_id.is_empty() {
        return Err("relying party is required (e.g. github.com)".into());
    }
    let cred = create_credential(rp_id);
    let out = credential_json(&cred);
    creds.push(cred);
    Ok(out)
}

/// Pure core of [`keys_list`]: every credential's public listing (see
/// [`credential_json`] — each entry carries the honesty text).
pub fn list_impl(creds: &[Credential]) -> Vec<Value> {
    creds.iter().map(credential_json).collect()
}

/// Pure core of [`keys_sign`]: bump the credential's monotonic counter, build
/// the assertion ([`authenticator_data`] ‖ implied [`challenge_hash`]), sign
/// it, and verify the signature locally with `postern_keys::verify_assertion`
/// before answering. Fail closed: an unknown credential id or a blank
/// challenge is an error, never a fake signature.
pub fn sign_impl(
    creds: &mut [Credential],
    credential_id: &str,
    challenge: &str,
) -> Result<Value, String> {
    let challenge = challenge.trim();
    if challenge.is_empty() {
        return Err("challenge is required".into());
    }
    let want = credential_id.trim().to_ascii_lowercase();
    let cred = creds
        .iter_mut()
        .find(|c| hex::encode(c.credential_id) == want)
        .ok_or_else(|| format!("no credential '{credential_id}'"))?;

    let counter = cred.next_counter();
    let auth_data = authenticator_data(&cred.rp_id, counter);
    let ch = challenge_hash(challenge);
    let signature = cred.sign_assertion(&auth_data, &ch);
    // Local verification — the full RP-side check, not a claimed one.
    let verified = verify_assertion(&cred.public_key(), &auth_data, &ch, &signature);
    Ok(json!({
        "signature": hex::encode(&signature),
        "authenticatorData": hex::encode(&auth_data),
        "signCount": counter,
        "verifiedLocally": verified,
        "honesty": HONESTY,
    }))
}

/// Pure core of [`keys_remove`]: drop the credential (its `Drop` zeroizes the
/// private key + PRF seed from RAM). Removing a non-existent id is an error.
pub fn remove_impl(creds: &mut Vec<Credential>, credential_id: &str) -> Result<Value, String> {
    let want = credential_id.trim().to_ascii_lowercase();
    let before = creds.len();
    creds.retain(|c| hex::encode(c.credential_id) != want);
    if creds.len() == before {
        return Err(format!("no credential '{credential_id}'"));
    }
    Ok(json!({ "removed": true, "honesty": HONESTY }))
}

// ─────────────────────────────────────────────────────────────────────────────
// The #[tauri::command] surface (matches ../src/modules/keys.js exactly).
// ─────────────────────────────────────────────────────────────────────────────

/// Create a passkey credential for a relying party (RAM only — see [`HONESTY`]).
#[tauri::command]
pub fn keys_create(state: State<KeysState>, rp_id: String) -> Result<Value, String> {
    create_impl(&mut state.0.lock().unwrap(), &rp_id)
}

/// List credentials (public material only; the private keys never leave the
/// backend). Each entry carries the honesty text.
#[tauri::command]
pub fn keys_list(state: State<KeysState>) -> Vec<Value> {
    list_impl(&state.0.lock().unwrap())
}

/// Sign a challenge with a credential and locally verify the assertion —
/// the full authenticate round trip, in process.
#[tauri::command]
pub fn keys_sign(
    state: State<KeysState>,
    credential_id: String,
    challenge: String,
) -> Result<Value, String> {
    sign_impl(&mut state.0.lock().unwrap(), &credential_id, &challenge)
}

/// Remove a credential — its private key + PRF seed are zeroized on drop.
#[tauri::command]
pub fn keys_remove(state: State<KeysState>, credential_id: String) -> Result<Value, String> {
    remove_impl(&mut state.0.lock().unwrap(), &credential_id)
}
