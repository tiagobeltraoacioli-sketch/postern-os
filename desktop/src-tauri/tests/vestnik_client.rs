// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests for the desktop Vestnik MATRIX CLIENT layer
//! (src/vestnik_client.rs, opt-in `vestnik-matrix` cargo feature — this test
//! target is `required-features` gated), driven through the `bloch_desktop`
//! library facade like every sibling suite (the disclosed dual-compile).
//!
//! FULLY OFFLINE, deliberately: the "homeserver" is matrix-sdk's own
//! `MatrixMockServer` (a LOOPBACK wiremock instance — `testing` feature,
//! dev-dependency only). No real homeserver is ever contacted by any test
//! here, matching the module's honesty contract: homeserver contact happens
//! ONLY on user action in a shipped vestnik-matrix build, never in CI. The
//! credentials/tokens below are FABRICATED mock fixtures (`.invalid`
//! domains) that authenticate nowhere. Everything under test is UNAUDITED,
//! pre-mainnet.

use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use bloch_desktop::vault::Unlocked;
use bloch_desktop::vestnik::{read_session_blob, recipient_init_impl, store_blob_impl};
use bloch_desktop::vestnik_client::{
    login_impl, logout_impl, open_saved_session, restore_impl, rooms_impl, seal_impl, send_impl,
    status_json, sync_once_impl, HONESTY, NOT_LOGGED_IN,
};
use matrix_sdk::ruma::{device_id, owned_device_id, room_id, user_id};
use matrix_sdk::test_utils::mocks::{LoginResponseTemplate200, MatrixMockServer};
use postern_courier::{generate_recipient, seal};
use postern_messenger::matrix::{MatrixMessenger, SavedSession};
use postern_vault::Vault;
use serde_json::Value;
use zeroize::Zeroizing;

const MOCK_TOKEN: &str = "syt_FABRICATED_mock_only_not_a_real_token";

/// A fresh, UNLOCKED, empty vault guard (same fixture as
/// tests/vestnik_custody.rs — custody wiring, not the KDF, is under test).
fn unlocked_guard() -> Option<Unlocked> {
    Some(Unlocked { vault: Vault::new(), key: Zeroizing::new([7u8; 32]), salt: vec![1u8; 16] })
}

/// Unique scratch dir for one test (under the OS temp dir).
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "bloch-desktop-vestnik-client-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn as_str<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or_else(|| panic!("missing '{k}' in {v}"))
}

/// Start a loopback MatrixMockServer with the endpoints every flow here
/// touches: /versions (the plain Client fetches it before its first
/// request), /login (fabricated fixture), and the E2EE machine's
/// /keys/upload + /keys/query (serviced during sync).
///
/// NOTE on tokens: several MatrixMockServer prebuilt mocks default to
/// `expect_default_access_token()` — they only match requests bearing the
/// mock framework's own default token ("1234"). Our login fixture issues the
/// distinctive [`MOCK_TOKEN`] instead (so the seal test can prove the bearer
/// token never appears in the sealed blob), so every token-expecting mock
/// must be re-pinned to it or it silently falls through to wiremock's
/// non-JSON 404.
async fn mock_homeserver() -> MatrixMockServer {
    let server = MatrixMockServer::new().await;
    server.mock_versions().ok().mount().await;
    server
        .mock_login()
        .ok_with(LoginResponseTemplate200::new(
            MOCK_TOKEN,
            device_id!("VESTNIKDEV"),
            user_id!("@vestnik:mock.invalid"),
        ))
        .mount()
        .await;
    server.mock_upload_keys().expect_access_token(MOCK_TOKEN).ok().mount().await;
    server.mock_query_keys().expect_access_token(MOCK_TOKEN).ok().mount().await;
    server
}

// ── the whole point: login → seal → store → open → restore, offline ─────────

#[tokio::test]
async fn login_seal_store_open_restore_round_trip() {
    let server = mock_homeserver().await;
    let store = scratch("roundtrip-store");
    let blob_dir = scratch("roundtrip-blob");

    // LOGIN (user action, against the loopback mock only).
    let mut slot: Option<MatrixMessenger> = None;
    let out = login_impl(
        &mut slot,
        &server.uri(),
        "vestnik",
        "correct-horse-not-a-real-password",
        &store,
        "store-pass-not-a-secret",
    )
    .await
    .expect("login against the loopback MatrixMockServer");
    assert_eq!(out["logged_in"], true);
    assert_eq!(as_str(&out, "user_id"), "@vestnik:mock.invalid");
    assert_eq!(as_str(&out, "device_id"), "VESTNIKDEV");
    assert_eq!(as_str(&out, "honesty"), HONESTY);
    assert_eq!(status_json(true, slot.is_some())["logged_in"], true);

    // CUSTODY: the recipient secret goes into the unlocked vault; the seal
    // uses only the returned (non-secret) public half.
    let mut guard = unlocked_guard();
    let init = recipient_init_impl(&mut guard).expect("recipient init");
    let public = B64.decode(as_str(&init, "public")).expect("public is base64");

    // SEAL the live session to the custodied identity.
    let sealed = seal_impl(&slot, &public).expect("seal the live session");
    assert_eq!(as_str(&sealed, "honesty"), HONESTY);
    let sealed_b64 = as_str(&sealed, "sealedB64");
    let wire = B64.decode(sealed_b64).unwrap();
    assert!(
        !wire.windows(MOCK_TOKEN.len()).any(|w| w == MOCK_TOKEN.as_bytes()),
        "the sealed blob must not contain the bearer token in plaintext"
    );

    // STORE through the custody layer's framing-checked path (reused core).
    let blob_path = blob_dir.join("vestnik-session.sealed");
    let stored = store_blob_impl(&blob_path, sealed_b64).expect("store");
    assert_eq!(stored["stored"], true);

    // OPEN with the vault-custodied secret → the typed SavedSession back.
    let blob = read_session_blob(&blob_path).expect("blob on disk");
    let session = open_saved_session(&guard, &blob).expect("open with the custodied secret");
    assert_eq!(session.user_id.as_str(), "@vestnik:mock.invalid");
    assert_eq!(session.device_id.as_str(), "VESTNIKDEV");
    assert_eq!(session.access_token, MOCK_TOKEN);

    // LOGOUT is a local drop (no network call; token honestly NOT
    // invalidated server-side).
    let out = logout_impl(&mut slot);
    assert_eq!(out["logged_out"], true);
    assert_eq!(as_str(&out, "honesty"), HONESTY);
    assert!(as_str(&out, "note").contains("NOT invalidated"));
    assert!(slot.is_none());

    // RESTORE into a fresh persistent store — local-only (no request goes to
    // the mock, so this passing proves plumbing, not token validity —
    // exactly what the response's honesty note says).
    let store2 = scratch("roundtrip-store2");
    let restored = restore_impl(
        &mut slot,
        session,
        &server.uri(),
        &store2,
        "second-store-pass-not-a-secret",
    )
    .await
    .expect("restore is local-only and must succeed offline");
    assert_eq!(restored["restored"], true);
    assert_eq!(as_str(&restored, "user_id"), "@vestnik:mock.invalid");
    assert_eq!(as_str(&restored, "device_id"), "VESTNIKDEV");
    assert_eq!(as_str(&restored, "honesty"), HONESTY);
    assert!(as_str(&restored, "note").contains("not validated"));
    assert!(slot.is_some(), "the restored client is running");

    for d in [&store, &blob_dir, &store2] {
        let _ = std::fs::remove_dir_all(d);
    }
}

// ── fail closed: locked vault / missing custody / tampered blob ─────────────

#[test]
fn restore_path_fails_closed_on_locked_vault_missing_recipient_and_tampered_blob() {
    // Custody identity A in the vault; a real SavedSession sealed to it.
    let mut guard = unlocked_guard();
    let init = recipient_init_impl(&mut guard).expect("init identity A");
    let public = B64.decode(as_str(&init, "public")).unwrap();
    let session = SavedSession {
        user_id: user_id!("@fabricated:offline.invalid").to_owned(),
        device_id: owned_device_id!("FABRICATEDDEVICE"),
        access_token: MOCK_TOKEN.to_owned(),
    };
    let wire = session.seal_to(&public).expect("seal_to");

    // Locked vault → error, never a session.
    let locked: Option<Unlocked> = None;
    let err = open_saved_session(&locked, &wire).unwrap_err();
    assert!(err.contains("locked"), "unexpected error: {err}");

    // Unlocked vault but NO custody entry → error telling them to init.
    let empty = unlocked_guard();
    let err = open_saved_session(&empty, &wire).unwrap_err();
    assert!(err.contains("no Vestnik session recipient"), "unexpected error: {err}");

    // Tampered blob → error (courier AEAD, deliberately coarse).
    let mut tampered = wire.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let err = open_saved_session(&guard, &tampered).unwrap_err();
    assert!(err.contains("open failed"), "unexpected error: {err}");

    // A blob sealed to a FOREIGN identity B → same coarse fail-closed error.
    let foreign = generate_recipient();
    let foreign_wire = session.seal_to(&foreign.public).expect("seal to B");
    let err = open_saved_session(&guard, &foreign_wire).unwrap_err();
    assert!(err.contains("open failed"), "unexpected error: {err}");

    // A blob that opens fine but is NOT a SavedSession document → error,
    // never a half-typed session.
    let junk_wire = seal(&public, b"{\"k\":1}").unwrap().to_bytes();
    let err = open_saved_session(&guard, &junk_wire).unwrap_err();
    assert!(err.contains("did not contain a SavedSession"), "unexpected error: {err}");

    // And the happy path still works, so the failures above are the checks,
    // not broken fixtures.
    let opened = open_saved_session(&guard, &wire).expect("matching secret opens");
    assert_eq!(opened, session);
}

// ── fail closed: every client core refuses before a login/restore ───────────

#[tokio::test]
async fn client_cores_refuse_cleanly_when_no_client_runs() {
    let slot: Option<MatrixMessenger> = None;
    assert_eq!(seal_impl(&slot, b"irrelevant").unwrap_err(), NOT_LOGGED_IN);
    assert_eq!(sync_once_impl(&slot).await.unwrap_err(), NOT_LOGGED_IN);
    assert_eq!(rooms_impl(&slot).await.unwrap_err(), NOT_LOGGED_IN);
    assert_eq!(send_impl(&slot, "!x:mock.invalid", "hi").await.unwrap_err(), NOT_LOGGED_IN);
    assert_eq!(status_json(true, false)["logged_in"], false);
}

// ── the tier wall at the send path, surfaced VERBATIM ───────────────────────

#[tokio::test]
async fn tier_gated_send_refusal_is_surfaced_verbatim_and_rooms_report_bridged() {
    let server = mock_homeserver().await;
    // Fail-closed classification fixtures: the room has NO m.room.encryption
    // state (a proper JSON M_NOT_FOUND 404 → NotEncrypted) and no members —
    // anything not provably internal E2EE is bridged. Token re-pin: see
    // mock_homeserver()'s note.
    server
        .mock_room_state_encryption()
        .expect_access_token(MOCK_TOKEN)
        .plain()
        .mount()
        .await;
    server.mock_get_members().ok(vec![]).mount().await;

    let store = scratch("send-store");
    let mut slot: Option<MatrixMessenger> = None;
    login_impl(
        &mut slot,
        &server.uri(),
        "vestnik",
        "correct-horse-not-a-real-password",
        &store,
        "store-pass-not-a-secret",
    )
    .await
    .expect("login against the loopback mock");

    // Make the (unencrypted) room known to the client via a mocked sync.
    let room_id = room_id!("!bridged:mock.invalid");
    server.sync_joined_room(slot.as_ref().unwrap().client(), room_id).await;

    // Our own sync core also runs cleanly against the loopback mock.
    server.mock_sync().ok(|_builder| {}).mount().await;
    let synced = sync_once_impl(&slot).await.expect("sync_once against the loopback mock");
    assert_eq!(synced["synced"], true);
    assert_eq!(as_str(&synced, "honesty"), HONESTY);

    // Room list: fail-closed bridged tier, with the crate's own badge string.
    let rooms = rooms_impl(&slot).await.expect("rooms");
    let list = rooms["rooms"].as_array().expect("rooms array");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["room_id"], room_id.as_str());
    assert_eq!(list[0]["tier"], "bridged");
    assert_eq!(list[0]["badge"], "\u{26a0} Bridged — not E2EE");
    assert_eq!(as_str(&rooms, "honesty"), HONESTY);

    // Send into the bridged room: refused, and the refusal text is the
    // crate's NotInternalE2ee Display VERBATIM — no rewording, no silent
    // downgrade.
    let err = send_impl(&slot, room_id.as_str(), "hello").await.unwrap_err();
    assert_eq!(
        err,
        format!(
            "refusing to send: room {room_id} is classified BridgedExternal, \
             not InternalE2ee — no silent downgrade"
        )
    );

    let _ = std::fs::remove_dir_all(&store);
}

// ── double-login guard + honesty pins ────────────────────────────────────────

#[tokio::test]
async fn second_login_refuses_while_a_client_runs() {
    let server = mock_homeserver().await;
    let store = scratch("double-login");
    let mut slot: Option<MatrixMessenger> = None;
    login_impl(&mut slot, &server.uri(), "vestnik", "pw-not-real", &store, "sp").await.expect("first login");
    let err = login_impl(&mut slot, &server.uri(), "vestnik", "pw-not-real", &store, "sp")
        .await
        .unwrap_err();
    assert!(err.contains("already running"), "unexpected error: {err}");
    assert!(err.contains("vestnik_logout"), "must say how to fix it");
    let _ = std::fs::remove_dir_all(&store);
}

#[test]
fn honesty_text_keeps_every_load_bearing_phrase() {
    for needle in [
        "UNAUDITED",
        "vestnik-matrix",
        "ONLY when the user acts",
        "never in CI",
        "app startup",
        "social graph",
        "no Tor",
        "not post-quantum",
        "SavedSession blob ONLY",
        "SDK-layer",
        "NOT PQ-vault-wrapped",
        "not a TEE until real hardware",
    ] {
        assert!(HONESTY.contains(needle), "vestnik_client::HONESTY lost '{needle}'");
    }
    let status = status_json(true, false);
    assert_eq!(status["built"], true);
    assert_eq!(status["logged_in"], false);
    assert_eq!(status["honesty"].as_str(), Some(HONESTY));
}
