// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests for the desktop Vestnik custody backend
//! (src/vestnik.rs), driven through the `bloch_desktop` library facade
//! (src/lib.rs) — the same disclosed dual-compile pattern as
//! tests/vault_core.rs and tests/courier_core.rs. No Tauri app is spun up,
//! and — deliberately — NO matrix client, NO homeserver and NO network: the
//! "SavedSession" sealed here is a FABRICATED, clearly-not-real JSON shape
//! (`.invalid` domain, `FABRICATED` token), because what this layer owns is
//! CUSTODY (vault-held recipient secret + opaque blob at rest), not the
//! messenger. Everything under test is UNAUDITED, pre-mainnet.

use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use bloch_desktop::vault::Unlocked;
use bloch_desktop::vestnik::{
    load_blob_impl, read_recipient_public, read_session_blob, recipient_init_impl,
    session_open_impl, store_blob_impl, write_recipient_public, HONESTY, NO_BLOB_ERROR,
    NO_RECIPIENT_PUBLIC_ERROR, RECIPIENT_ENTRY,
};
use postern_courier::{generate_recipient, key_fingerprint, seal};
use postern_vault::Vault;
use serde_json::{json, Value};
use zeroize::Zeroizing;

fn as_str<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or_else(|| panic!("missing '{k}' in {v}"))
}

/// A fresh, UNLOCKED, empty vault guard — the state `vestnik_recipient_init`
/// requires. Fixed key/salt: these tests exercise custody wiring, not the
/// Argon2id KDF (tests/vault_core.rs owns that).
fn unlocked_guard() -> Option<Unlocked> {
    Some(Unlocked { vault: Vault::new(), key: Zeroizing::new([7u8; 32]), salt: vec![1u8; 16] })
}

/// A FABRICATED SavedSession-shaped JSON document. The shape mirrors
/// postern-messenger's `matrix::SavedSession { user_id, device_id,
/// access_token }`, but every value is loudly fake: `.invalid` is an
/// IETF-reserved unresolvable TLD and the token names itself fabricated.
/// No matrix login produced this and it authenticates nowhere.
fn fabricated_session() -> Value {
    json!({
        "user_id": "@fabricated-user:offline.invalid",
        "device_id": "FABRICATEDDEVICE",
        "access_token": "syt_FABRICATED_test_only_not_a_real_token",
    })
}

/// Unique scratch path for one test's blob file (under the OS temp dir).
fn scratch_blob(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "bloch-desktop-vestnik-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir.join("vestnik-session.sealed")
}

// ── the full custody flow: unlock → init → seal → store → load → open ───────

#[test]
fn init_seal_store_load_open_round_trip() {
    let mut guard = unlocked_guard();

    // Init: the secret lands in the vault, only public + fingerprint return.
    let init = recipient_init_impl(&mut guard).expect("init on an unlocked vault");
    let public = B64.decode(as_str(&init, "public")).expect("public is base64");
    assert_eq!(as_str(&init, "fingerprint"), key_fingerprint(&public));
    assert_eq!(as_str(&init, "entry"), RECIPIENT_ENTRY);
    assert!(init.get("secret").is_none(), "the secret must NEVER leave the vault");
    let custodied = guard.as_ref().unwrap().vault.get(RECIPIENT_ENTRY).expect("custodied");
    assert!(!custodied.is_empty(), "custody entry holds the secret");

    // Seal the FABRICATED session to the custodied identity's public key —
    // exactly what SavedSession::seal_to does, minus the matrix client.
    let session = fabricated_session();
    let plaintext = serde_json::to_vec(&session).unwrap();
    let wire = seal(&public, &plaintext).expect("seal").to_bytes();

    // Store → load: the blob round-trips byte-exact as opaque bytes.
    let path = scratch_blob("roundtrip");
    let stored = store_blob_impl(&path, &B64.encode(&wire)).expect("store");
    assert_eq!(stored["stored"], true);
    assert_eq!(stored["bytes"], wire.len());
    let loaded = load_blob_impl(&path).expect("load");
    assert_eq!(B64.decode(as_str(&loaded, "sealedB64")).unwrap(), wire);

    // Open with the vault-custodied secret: the exact JSON comes back.
    let blob = read_session_blob(&path).expect("blob on disk");
    let opened = session_open_impl(&guard, &blob).expect("open with the custodied secret");
    assert_eq!(opened["session"], session);

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

// ── fail closed: locked vault ────────────────────────────────────────────────

#[test]
fn locked_vault_refuses_init_and_open() {
    let mut locked: Option<Unlocked> = None;
    let err = recipient_init_impl(&mut locked).unwrap_err();
    assert!(err.contains("locked"), "unexpected error: {err}");
    assert!(locked.is_none(), "a refused init must not unlock anything");

    // Open must fail closed on a locked vault even with a perfectly valid blob.
    let rcpt = generate_recipient();
    let wire = seal(&rcpt.public, b"{\"k\":1}").unwrap().to_bytes();
    let err = session_open_impl(&locked, &wire).unwrap_err();
    assert!(err.contains("locked"), "unexpected error: {err}");
}

// ── fail closed: foreign secret / tampered blob / missing custody entry ─────

#[test]
fn foreign_secret_cannot_open_the_blob() {
    // The vault custodies identity A; the blob was sealed to a DIFFERENT
    // identity B. Opening with A's secret must fail closed (courier is
    // deliberately coarse: wrong key vs tamper is not distinguished).
    let mut guard = unlocked_guard();
    recipient_init_impl(&mut guard).expect("init identity A");

    let foreign = generate_recipient(); // identity B — never enters the vault
    let plaintext = serde_json::to_vec(&fabricated_session()).unwrap();
    let wire = seal(&foreign.public, &plaintext).unwrap().to_bytes();

    let err = session_open_impl(&guard, &wire).unwrap_err();
    assert!(err.contains("open failed"), "unexpected error: {err}");
}

#[test]
fn tampered_blob_fails_closed() {
    let mut guard = unlocked_guard();
    let init = recipient_init_impl(&mut guard).unwrap();
    let public = B64.decode(as_str(&init, "public")).unwrap();
    let mut wire = seal(&public, &serde_json::to_vec(&fabricated_session()).unwrap())
        .unwrap()
        .to_bytes();
    let last = wire.len() - 1;
    wire[last] ^= 0x01; // flip one AEAD-body bit
    let err = session_open_impl(&guard, &wire).unwrap_err();
    assert!(err.contains("open failed"), "unexpected error: {err}");
}

#[test]
fn open_without_a_custodied_recipient_fails_closed() {
    // Unlocked vault, but vestnik_recipient_init never ran: no custody entry.
    let guard = unlocked_guard();
    let rcpt = generate_recipient();
    let wire = seal(&rcpt.public, b"{}").unwrap().to_bytes();
    let err = session_open_impl(&guard, &wire).unwrap_err();
    assert!(err.contains("no Vestnik session recipient"), "unexpected error: {err}");
}

#[test]
fn opened_plaintext_must_be_a_json_document() {
    // A blob that authenticates and decrypts fine but does not hold JSON is
    // an error — never raw bytes handed to the pane as a "session".
    let mut guard = unlocked_guard();
    let init = recipient_init_impl(&mut guard).unwrap();
    let public = B64.decode(as_str(&init, "public")).unwrap();
    let wire = seal(&public, b"not json at all").unwrap().to_bytes();
    let err = session_open_impl(&guard, &wire).unwrap_err();
    assert!(err.contains("JSON session document"), "unexpected error: {err}");
}

// ── fail closed: no silent custody-key overwrite ─────────────────────────────

#[test]
fn second_init_refuses_to_overwrite_the_custody_entry() {
    let mut guard = unlocked_guard();
    recipient_init_impl(&mut guard).expect("first init");
    let before = guard.as_ref().unwrap().vault.get(RECIPIENT_ENTRY).unwrap().to_vec();

    let err = recipient_init_impl(&mut guard).unwrap_err();
    assert!(err.contains("already custodied"), "unexpected error: {err}");

    let after = guard.as_ref().unwrap().vault.get(RECIPIENT_ENTRY).unwrap();
    assert_eq!(after, &before[..], "the custodied secret must be untouched");
}

// ── missing blob: a clean, specific first-run error ──────────────────────────

#[test]
fn missing_blob_is_a_clean_error() {
    let path = scratch_blob("missing"); // parent dir never created
    let err = read_session_blob(&path).unwrap_err();
    assert_eq!(err, NO_BLOB_ERROR);
    let err = load_blob_impl(&path).unwrap_err();
    assert_eq!(err, NO_BLOB_ERROR);
}

// ── store refuses junk (fail closed, nothing lands on disk) ─────────────────

#[test]
fn store_refuses_bad_base64_and_non_courier_bytes() {
    let path = scratch_blob("junk");
    assert!(store_blob_impl(&path, "not base64!!").is_err(), "bad base64 refused");
    let err = store_blob_impl(&path, &B64.encode(b"random junk, not a courier wire")).unwrap_err();
    assert!(err.contains("refusing to store"), "unexpected error: {err}");
    assert!(!path.exists(), "a refused store must leave nothing on disk");
}

// ── recipient PUBLIC half: persisted, non-secret, fail-closed read ──────────

#[test]
fn recipient_public_round_trips_and_missing_file_is_the_clean_error() {
    let dir = scratch_blob("pubhalf");
    let path = dir.parent().unwrap().join("vestnik-recipient.pub");

    // Missing file → the clean, specific error (NOT a guessed key), which
    // must spell out the explicit-rotation escape hatch for pre-extension
    // recipients (backward compatibility is by clean refusal, never magic).
    let err = read_recipient_public(&path).unwrap_err();
    assert_eq!(err, NO_RECIPIENT_PUBLIC_ERROR);
    assert!(err.contains("vestnik_recipient_init"), "must say how to fix it");
    assert!(err.contains("vault_remove"), "must name the explicit rotation");

    // Write → read round-trips the exact public key bytes.
    let rcpt = generate_recipient();
    write_recipient_public(&path, &rcpt.public).expect("write public half");
    assert_eq!(read_recipient_public(&path).expect("read back"), rcpt.public.to_vec());

    // Corrupt (non-base64) content fails closed.
    std::fs::write(&path, "not base64!!").unwrap();
    let err = read_recipient_public(&path).unwrap_err();
    assert!(err.contains("not valid base64"), "unexpected error: {err}");

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

// ── mandatory honesty text on every response ─────────────────────────────────

#[test]
fn every_response_carries_the_honesty_text() {
    // Load-bearing phrases: losing any is a release blocker, not a wording nit.
    // ("does not yet run the matrix client" was retired when the opt-in
    // vestnik-matrix client landed — the new truth is pinned instead.)
    for needle in [
        "UNAUDITED",
        "only in a vestnik-matrix build",
        "only on user action",
        "never in CI",
        "SavedSession blob ONLY",
        "not post-quantum",
        "social graph",
        "not a TEE until real hardware",
    ] {
        assert!(HONESTY.contains(needle), "HONESTY lost '{needle}'");
    }
    assert!(
        !HONESTY.contains("does not yet run the matrix client"),
        "the pre-vestnik-matrix wording must be gone — the client now exists behind the feature"
    );

    let mut guard = unlocked_guard();
    let init = recipient_init_impl(&mut guard).unwrap();
    assert_eq!(as_str(&init, "honesty"), HONESTY);

    let public = B64.decode(as_str(&init, "public")).unwrap();
    let wire = seal(&public, &serde_json::to_vec(&fabricated_session()).unwrap())
        .unwrap()
        .to_bytes();

    let path = scratch_blob("honesty");
    let stored = store_blob_impl(&path, &B64.encode(&wire)).unwrap();
    assert_eq!(as_str(&stored, "honesty"), HONESTY);
    let loaded = load_blob_impl(&path).unwrap();
    assert_eq!(as_str(&loaded, "honesty"), HONESTY);
    let opened = session_open_impl(&guard, &wire).unwrap();
    assert_eq!(as_str(&opened, "honesty"), HONESTY);

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}
