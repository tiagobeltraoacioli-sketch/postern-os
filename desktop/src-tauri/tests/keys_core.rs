// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests for the desktop Keys backend (src/keys.rs), driven
//! through the `bloch_desktop` library facade (src/lib.rs) — the same
//! disclosed dual-compile pattern as tests/vault_core.rs. No Tauri app is
//! spun up: the pure `*_impl` cores are exercised against a plain
//! `Vec<Credential>`, and every assertion signature is checked with
//! `postern_keys::verify_assertion` — the real RP-side verification, not a
//! mocked one. Everything under test is UNAUDITED, pre-mainnet: a SOFTWARE
//! authenticator (keys in app RAM, not a hardware key, not a TEE until real
//! hardware).

use bloch_desktop::keys::{
    authenticator_data, challenge_hash, create_impl, list_impl, remove_impl, sign_impl, HONESTY,
};
use postern_keys::{verify_assertion, Credential};
use serde_json::Value;

fn as_str<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or_else(|| panic!("missing '{k}' in {v}"))
}

// ── create → sign → verify_assertion round trip ─────────────────────────────

#[test]
fn create_sign_verify_round_trip() {
    let mut creds: Vec<Credential> = Vec::new();
    let created = create_impl(&mut creds, "example.com").expect("create");
    assert_eq!(as_str(&created, "rpId"), "example.com");
    assert_eq!(created["signCount"], 0);
    let cred_id = as_str(&created, "credentialId").to_string();
    let public_key = hex::decode(as_str(&created, "publicKey")).unwrap();

    let signed = sign_impl(&mut creds, &cred_id, "deadbeef01").expect("sign");
    assert_eq!(signed["signCount"], 1, "counter bumps monotonically from 0");
    assert_eq!(signed["verifiedLocally"], true);

    // Independently reconstruct the signed bytes and verify with the crate's
    // real RP-side check — proving the command's `verifiedLocally` is not
    // self-referential.
    let auth_data = authenticator_data("example.com", 1);
    assert_eq!(hex::decode(as_str(&signed, "authenticatorData")).unwrap(), auth_data);
    assert_eq!(auth_data.len(), 37, "rp-id hash (32) + flags (1) + counter (4)");
    let ch = challenge_hash("deadbeef01");
    let sig = hex::decode(as_str(&signed, "signature")).unwrap();
    assert!(verify_assertion(&public_key, &auth_data, &ch, &sig));

    // A second sign keeps counting up and stays verifiable.
    let signed2 = sign_impl(&mut creds, &cred_id, "deadbeef02").unwrap();
    assert_eq!(signed2["signCount"], 2);
    assert_eq!(signed2["verifiedLocally"], true);
}

// ── wrong challenge / wrong credential fail ─────────────────────────────────

#[test]
fn wrong_challenge_does_not_verify() {
    let mut creds: Vec<Credential> = Vec::new();
    let created = create_impl(&mut creds, "example.com").unwrap();
    let cred_id = as_str(&created, "credentialId").to_string();
    let public_key = hex::decode(as_str(&created, "publicKey")).unwrap();

    let signed = sign_impl(&mut creds, &cred_id, "challenge-A").unwrap();
    let auth_data = hex::decode(as_str(&signed, "authenticatorData")).unwrap();
    let sig = hex::decode(as_str(&signed, "signature")).unwrap();

    // The signature is bound to challenge-A: a different challenge's hash
    // must not verify against it.
    assert!(!verify_assertion(&public_key, &auth_data, &challenge_hash("challenge-B"), &sig));
    // Nor does a tampered authenticator_data (counter flipped).
    let other_ad = authenticator_data("example.com", 999);
    assert!(!verify_assertion(&public_key, &other_ad, &challenge_hash("challenge-A"), &sig));
}

#[test]
fn wrong_credential_cannot_impersonate() {
    let mut creds: Vec<Credential> = Vec::new();
    let a = create_impl(&mut creds, "site.example").unwrap();
    let b = create_impl(&mut creds, "site.example").unwrap();
    let a_id = as_str(&a, "credentialId").to_string();
    let b_public = hex::decode(as_str(&b, "publicKey")).unwrap();

    let signed = sign_impl(&mut creds, &a_id, "challenge").unwrap();
    let auth_data = hex::decode(as_str(&signed, "authenticatorData")).unwrap();
    let sig = hex::decode(as_str(&signed, "signature")).unwrap();
    // b's public key must NOT verify a's assertion.
    assert!(!verify_assertion(&b_public, &auth_data, &challenge_hash("challenge"), &sig));

    // Signing with an unknown credential id fails closed, and never signs.
    assert!(sign_impl(&mut creds, "00ff00ff00ff00ff00ff00ff00ff00ff", "c").is_err());
    // A blank challenge is refused (no signature over nothing).
    assert!(sign_impl(&mut creds, &a_id, "   ").is_err());
}

// ── list / remove lifecycle (RAM only) ──────────────────────────────────────

#[test]
fn list_and_remove_lifecycle() {
    let mut creds: Vec<Credential> = Vec::new();
    assert!(list_impl(&creds).is_empty());
    // A blank relying party is refused.
    assert!(create_impl(&mut creds, "   ").is_err());

    let c1 = create_impl(&mut creds, "one.example").unwrap();
    let _c2 = create_impl(&mut creds, "two.example").unwrap();
    assert_eq!(list_impl(&creds).len(), 2);

    // Remove drops the credential (its Drop zeroizes key + PRF seed in RAM).
    let removed = remove_impl(&mut creds, as_str(&c1, "credentialId")).unwrap();
    assert_eq!(removed["removed"], true);
    let left = list_impl(&creds);
    assert_eq!(left.len(), 1);
    assert_eq!(as_str(&left[0], "rpId"), "two.example");

    // Removing a non-existent id fails closed.
    assert!(remove_impl(&mut creds, as_str(&c1, "credentialId")).is_err());
}

// ── mandatory honesty text on every response ────────────────────────────────

#[test]
fn every_response_carries_the_honesty_text() {
    for needle in [
        "UNAUDITED reference prototype",
        "SOFTWARE authenticator",
        "not a TEE until real hardware",
        "RAM",
    ] {
        assert!(HONESTY.contains(needle), "HONESTY lost '{needle}'");
    }

    let mut creds: Vec<Credential> = Vec::new();
    let created = create_impl(&mut creds, "example.com").unwrap();
    assert_eq!(as_str(&created, "honesty"), HONESTY);
    let listed = list_impl(&creds);
    assert_eq!(as_str(&listed[0], "honesty"), HONESTY);
    let cred_id = as_str(&created, "credentialId").to_string();
    let signed = sign_impl(&mut creds, &cred_id, "ch").unwrap();
    assert_eq!(as_str(&signed, "honesty"), HONESTY);
    let removed = remove_impl(&mut creds, &cred_id).unwrap();
    assert_eq!(as_str(&removed, "honesty"), HONESTY);
}
