// SPDX-License-Identifier: MIT OR Apache-2.0
//! Vestnik — the desktop MATRIX CLIENT layer, behind the opt-in
//! `vestnik-matrix` cargo feature (OFF by default; mirrors the
//! `vault-keychain` pattern exactly).
//!
//! With the feature ON this module drives postern-messenger's
//! `MatrixMessenger` (matrix-rust-sdk, Apache-2.0 — never Element/AGPL)
//! from the desktop backend: password login into a persistent SDK sqlite
//! store under the app data dir, one-shot sync, the fail-closed room list,
//! the tier-gated send (the `NotInternalE2ee` refusal is surfaced
//! VERBATIM — no silent downgrade, no rewording), and the sealed-session
//! bridge to the custody layer in `vestnik.rs`:
//!
//! - `vestnik_session_seal` — `session()` → `SavedSession::seal_to` the
//!   custodied recipient PUBLIC key (persisted, non-secret, by
//!   `vestnik_recipient_init` — see [`crate::vestnik::RECIPIENT_PUBLIC_FILE`])
//!   → stored via the SAME [`crate::vestnik::store_blob_impl`] path the
//!   custody commands use. Sealing never opens the vault.
//! - `vestnik_restore` — [`crate::vestnik::read_session_blob`] →
//!   [`crate::vestnik::session_open_impl`] with the VAULT-custodied secret →
//!   `MatrixMessenger::restore`. Fail-closed on a locked vault, a missing
//!   custody entry, a foreign secret, or a tampered blob — the landed pure
//!   cores are REUSED, never duplicated.
//!
//! With the feature OFF, every command below still exists (always registered
//! in `generate_handler!`) and returns the clean [`MATRIX_NOT_BUILT`] error —
//! never a silent no-op — and `vestnik_matrix_status` reports
//! `{ built: false, logged_in: false, honesty }` so the pane gates on REAL
//! capability (the `vault_keychain` `available: false` pattern), never on a
//! UI-side assumption.
//!
//! Like the sibling modules, this one is re-exported from src/lib.rs so
//! integration tests drive the pure `*_impl` cores without a live Tauri app
//! (tests/vestnik_client.rs against matrix-sdk's loopback `MatrixMockServer`;
//! tests/vestnik_client_stub.rs for the feature-off error shape) — the same
//! deliberate, disclosed dual-compile (see Cargo.toml's `[lib]` comment).
//!
//! ## Honesty labels (carried on EVERY response, never weakened)
//!
//! - **UNAUDITED pre-release**, like everything in this repo.
//! - **Built-with-feature-only**: no matrix code exists in a default build.
//! - **A homeserver is contacted ONLY when the user acts** (login / sync /
//!   send) — never in CI, never at app startup. The offline test suite
//!   proves shapes and refusals against a loopback mock, not live behavior.
//! - **The homeserver sees the social graph** (rooms, timestamps, who talks
//!   to whom) — there is NO Tor wiring on this path (postern-messenger's
//!   `PHASE1_REMAINING` ledger keeps that item open).
//! - **Megolm/Olm is classical Curve25519 — not post-quantum.**
//! - **Sealed-at-rest covers the SavedSession blob ONLY**; the SDK's sqlite
//!   store passphrase is SDK-layer encryption only, NOT PQ-vault-wrapped.
//! - **The vault custody of the recipient secret is a SOFTWARE seal** — not
//!   a TEE until real hardware (`vault::HONESTY`).

use serde_json::{json, Value};

#[cfg(feature = "vestnik-matrix")]
use std::path::Path;

#[cfg(feature = "vestnik-matrix")]
use base64::engine::general_purpose::STANDARD as B64;
#[cfg(feature = "vestnik-matrix")]
use base64::Engine as _;
#[cfg(feature = "vestnik-matrix")]
use postern_courier::key_fingerprint;
#[cfg(feature = "vestnik-matrix")]
use postern_messenger::matrix::{MatrixMessenger, SavedSession};
#[cfg(feature = "vestnik-matrix")]
use postern_messenger::SecurityTier;
#[cfg(feature = "vestnik-matrix")]
use tauri::{AppHandle, Manager as _, State};

#[cfg(feature = "vestnik-matrix")]
use crate::vault::{Unlocked, VaultState};

/// Mandatory per-response honesty text for the matrix-client layer. Surfaced
/// verbatim in every `vestnik_*` client-command result's `honesty` field
/// (and in `vestnik_matrix_status` in BOTH build flavors) so the UI can
/// never overclaim. The phrases "UNAUDITED", "vestnik-matrix",
/// "ONLY when the user acts", "never in CI", "app startup", "social graph",
/// "no Tor", "not post-quantum", "SavedSession blob ONLY" and "SDK-layer"
/// are load-bearing (tests assert them).
pub const HONESTY: &str = "UNAUDITED pre-release — Vestnik matrix client: present only in a \
     vestnik-matrix build, and a homeserver is contacted ONLY when the user acts (login / \
     sync / send) — never in CI, never at app startup. The homeserver sees the social graph \
     (rooms, timestamps, who talks to whom); no Tor wiring on this path. Matrix Megolm/Olm \
     stays classical Curve25519 — not post-quantum. Sealed-at-rest covers the SavedSession \
     blob ONLY (hybrid ML-KEM-1024 + X25519 courier seal; the recipient secret is a \
     software-vault entry — not a TEE until real hardware), and the SDK's sqlite store \
     passphrase is SDK-layer encryption only — NOT PQ-vault-wrapped.";

/// Error every `vestnik_*` client command returns when the binary was built
/// without the `vestnik-matrix` cargo feature. A clean, honest refusal —
/// never a silent no-op. (Mirrors `vault::KEYCHAIN_NOT_BUILT`.)
/// (With the feature ON only the feature-off stubs that use it are compiled
/// out, so the bin target would flag it dead — hence the allow; the lib
/// target still exports it for tests.)
#[cfg_attr(feature = "vestnik-matrix", allow(dead_code))]
pub const MATRIX_NOT_BUILT: &str = "not built with matrix support — rebuild bloch-desktop \
     with the `vestnik-matrix` cargo feature (--features vestnik-matrix)";

/// The clean fail-closed error for client commands before a login/restore.
/// (Feature-off bin target compiles out every user — hence the allow; the
/// lib target still exports it for tests.)
#[cfg_attr(not(feature = "vestnik-matrix"), allow(dead_code))]
pub const NOT_LOGGED_IN: &str =
    "no matrix client is running — vestnik_login or vestnik_restore first";

/// Directory name (under the app data dir) of the SDK's persistent sqlite
/// store. HONESTY: the store passphrase encrypts it at the SDK layer only —
/// it is NOT PQ-vault-wrapped (postern-messenger `PHASE1_REMAINING` item 4).
#[cfg_attr(not(feature = "vestnik-matrix"), allow(dead_code))]
pub const MATRIX_STORE_DIR: &str = "vestnik-matrix-store";

/// The device display name this desktop registers on login.
#[cfg_attr(not(feature = "vestnik-matrix"), allow(dead_code))]
pub const DEVICE_DISPLAY_NAME: &str = "Postern Desktop (Vestnik)";

/// The `vestnik_matrix_status` shape, pure and identical in both build
/// flavors: `{ built, logged_in, honesty }`. The pane MUST gate its live
/// claim and its login form on `built` — the commands are always registered,
/// so command registration alone would overclaim a no-feature build.
pub fn status_json(built: bool, logged_in: bool) -> Value {
    json!({ "built": built, "logged_in": logged_in, "honesty": HONESTY })
}

/// Managed state: at most one running `MatrixMessenger` (feature on); a
/// field-less placeholder otherwise (managed unconditionally so `main.rs`
/// needs no cfg gymnastics). A tokio `Mutex` because the client is used
/// across `.await`s inside Tauri's (tokio) runtime.
#[derive(Default)]
pub struct VestnikClientState {
    #[cfg(feature = "vestnik-matrix")]
    pub client: tokio::sync::Mutex<Option<MatrixMessenger>>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure, testable cores (feature `vestnik-matrix`; no AppHandle/State) — what
// tests/vestnik_client.rs drives against the loopback MatrixMockServer.
// ─────────────────────────────────────────────────────────────────────────────

/// One tier string for the wire: the pane maps it onto its byte-pinned
/// badge/disclosure constants (which byte-match the Rust crate's).
#[cfg(feature = "vestnik-matrix")]
fn tier_str(tier: SecurityTier) -> &'static str {
    match tier {
        SecurityTier::InternalE2ee => "internal",
        SecurityTier::BridgedExternal => "bridged",
    }
}

/// Pure core of `vestnik_login`: password login into the SDK's persistent
/// sqlite store at `store_path` (passphrase-encrypted at the SDK layer ONLY —
/// not PQ-vault-wrapped). This is the user acting — the ONLY places a
/// homeserver is ever contacted are this, sync, and send. Fail closed: a
/// second login while a client runs is an error (logout first), and any
/// SDK/login failure surfaces as-is.
#[cfg(feature = "vestnik-matrix")]
pub async fn login_impl(
    slot: &mut Option<MatrixMessenger>,
    homeserver: &str,
    username: &str,
    password: &str,
    store_path: &Path,
    store_passphrase: &str,
) -> Result<Value, String> {
    if slot.is_some() {
        return Err("a matrix client is already running — vestnik_logout first".into());
    }
    let messenger = MatrixMessenger::login_password_persistent(
        homeserver,
        username,
        password,
        DEVICE_DISPLAY_NAME,
        store_path,
        store_passphrase,
    )
    .await
    .map_err(|e| e.to_string())?;
    let out = json!({
        "logged_in": true,
        "user_id": messenger.user_id().map(|u| u.to_string()),
        "device_id": messenger.device_id().map(|d| d.to_string()),
        "honesty": HONESTY,
    });
    *slot = Some(messenger);
    Ok(out)
}

/// Pure core of `vestnik_session_seal` (minus the store step, which is
/// [`crate::vestnik::store_blob_impl`] — reused, not duplicated): snapshot
/// the live login as a `SavedSession` and seal it to the custodied recipient
/// PUBLIC key. Returns `{ sealedB64, bytes, fingerprint, honesty }`. Fail
/// closed: no client / no session → error. The vault is NOT needed here —
/// sealing uses only the non-secret public half.
#[cfg(feature = "vestnik-matrix")]
pub fn seal_impl(
    slot: &Option<MatrixMessenger>,
    recipient_public: &[u8],
) -> Result<Value, String> {
    let messenger = slot.as_ref().ok_or(NOT_LOGGED_IN)?;
    let session = messenger
        .session()
        .ok_or("the matrix client reports no logged-in session — nothing to seal")?;
    let sealed = session.seal_to(recipient_public).map_err(|e| e.to_string())?;
    Ok(json!({
        "sealedB64": B64.encode(&sealed),
        "bytes": sealed.len(),
        "fingerprint": key_fingerprint(recipient_public),
        "honesty": HONESTY,
    }))
}

/// Open a stored sealed blob into a typed `SavedSession` with the
/// VAULT-custodied recipient secret — the restore path's first half.
/// REUSES [`crate::vestnik::session_open_impl`] (the landed fail-closed pure
/// core: locked vault / missing entry / foreign secret / tampered blob all
/// error), then requires the opened JSON to actually be a `SavedSession`
/// document.
#[cfg(feature = "vestnik-matrix")]
pub fn open_saved_session(guard: &Option<Unlocked>, blob: &[u8]) -> Result<SavedSession, String> {
    let opened = crate::vestnik::session_open_impl(guard, blob)?;
    let session = opened
        .get("session")
        .cloned()
        .ok_or("internal: session_open_impl returned no session field")?;
    serde_json::from_value(session).map_err(|_| {
        "the sealed blob opened but did not contain a SavedSession \
         (user_id/device_id/access_token) document"
            .to_string()
    })
}

/// Pure core of `vestnik_restore`'s second half: rebuild the persistent
/// client at `store_path` and restore `session` into it. HONEST (from
/// `MatrixMessenger::restore`): this writes LOCAL state only — no request
/// goes to the homeserver, so a revoked/expired token restores
/// "successfully" here and only fails on the next user-initiated call.
#[cfg(feature = "vestnik-matrix")]
pub async fn restore_impl(
    slot: &mut Option<MatrixMessenger>,
    session: SavedSession,
    homeserver: &str,
    store_path: &Path,
    store_passphrase: &str,
) -> Result<Value, String> {
    if slot.is_some() {
        return Err("a matrix client is already running — vestnik_logout first".into());
    }
    let messenger = MatrixMessenger::restore(homeserver, store_path, store_passphrase, session)
        .await
        .map_err(|e| e.to_string())?;
    let out = json!({
        "restored": true,
        "user_id": messenger.user_id().map(|u| u.to_string()),
        "device_id": messenger.device_id().map(|d| d.to_string()),
        "note": "restore rebuilds the LOCAL client only — the token is not validated \
                 against the homeserver until the next user-initiated request",
        "honesty": HONESTY,
    });
    *slot = Some(messenger);
    Ok(out)
}

/// Pure core of `vestnik_sync_once`: one sync round-trip (user action — this
/// contacts the homeserver). Fail closed when no client runs.
#[cfg(feature = "vestnik-matrix")]
pub async fn sync_once_impl(slot: &Option<MatrixMessenger>) -> Result<Value, String> {
    let messenger = slot.as_ref().ok_or(NOT_LOGGED_IN)?;
    messenger.sync_once().await.map_err(|e| e.to_string())?;
    Ok(json!({ "synced": true, "honesty": HONESTY }))
}

/// Pure core of `vestnik_rooms`: the fail-closed room list —
/// `[{ room_id, name, tier, badge, is_direct }]`, `tier` ∈
/// {"internal","bridged"} via postern-messenger's never-defaulted
/// classification (`badge` is the crate's own pinned string, so the wire
/// carries the single source of truth alongside). Reads local sync state —
/// no network call.
#[cfg(feature = "vestnik-matrix")]
pub async fn rooms_impl(slot: &Option<MatrixMessenger>) -> Result<Value, String> {
    let messenger = slot.as_ref().ok_or(NOT_LOGGED_IN)?;
    let rooms = messenger.room_list().await.map_err(|e| e.to_string())?;
    let rooms: Vec<Value> = rooms
        .into_iter()
        .map(|r| {
            json!({
                "room_id": r.room_id.to_string(),
                "name": r.name,
                "tier": tier_str(r.tier),
                "badge": r.tier.badge(),
                "is_direct": r.is_direct,
            })
        })
        .collect();
    Ok(json!({ "rooms": rooms, "honesty": HONESTY }))
}

/// Pure core of `vestnik_send`: tier-gated E2EE send (user action — this
/// contacts the homeserver). The `MatrixError::NotInternalE2ee` refusal is
/// surfaced VERBATIM via its `Display` ("refusing to send: room … is
/// classified …, not InternalE2ee — no silent downgrade") — never reworded,
/// never softened, never downgraded silently.
#[cfg(feature = "vestnik-matrix")]
pub async fn send_impl(
    slot: &Option<MatrixMessenger>,
    room_id: &str,
    body: &str,
) -> Result<Value, String> {
    let messenger = slot.as_ref().ok_or(NOT_LOGGED_IN)?;
    let room_id = matrix_sdk::ruma::RoomId::parse(room_id)
        .map_err(|e| format!("invalid room id '{room_id}': {e}"))?;
    let event_id = messenger
        .send_text(&room_id, body)
        .await
        .map_err(|e| e.to_string())?; // verbatim, including the tier refusal
    Ok(json!({ "event_id": event_id.to_string(), "honesty": HONESTY }))
}

/// Pure core of `vestnik_logout`: drop the local client. HONEST: local only —
/// the homeserver-side access token is NOT invalidated (that would itself be
/// a network call; this command never makes one).
#[cfg(feature = "vestnik-matrix")]
pub fn logout_impl(slot: &mut Option<MatrixMessenger>) -> Value {
    let was_running = slot.take().is_some();
    json!({
        "logged_out": was_running,
        "note": "local drop only — the homeserver-side access token is NOT invalidated \
                 by this command (no network call is made)",
        "honesty": HONESTY,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// App-side plumbing + the #[tauri::command] surface (feature ON).
// ─────────────────────────────────────────────────────────────────────────────

/// On-disk location of the SDK's persistent sqlite store (app data dir).
#[cfg(feature = "vestnik-matrix")]
fn matrix_store_path(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    Ok(dir.join(MATRIX_STORE_DIR))
}

/// `{ built: true, logged_in, honesty }` — the pane's capability gate.
/// Purely local: never contacts a homeserver.
#[cfg(feature = "vestnik-matrix")]
#[tauri::command]
pub async fn vestnik_matrix_status(state: State<'_, VestnikClientState>) -> Result<Value, String> {
    let slot = state.client.lock().await;
    Ok(status_json(true, slot.is_some()))
}

/// Password login (USER ACTION — contacts the homeserver) into the
/// persistent SDK sqlite store under the app data dir. HONEST:
/// `store_passphrase` encrypts that store at the SDK layer only — it is NOT
/// PQ-vault-wrapped.
#[cfg(feature = "vestnik-matrix")]
#[tauri::command]
pub async fn vestnik_login(
    app: AppHandle,
    state: State<'_, VestnikClientState>,
    homeserver: String,
    username: String,
    password: String,
    store_passphrase: String,
) -> Result<Value, String> {
    let store = matrix_store_path(&app)?;
    let mut slot = state.client.lock().await;
    login_impl(&mut slot, &homeserver, &username, &password, &store, &store_passphrase).await
}

/// Seal the live session to the custodied recipient public key and store the
/// blob through the custody layer's own framing-checked path. No homeserver
/// contact; no vault unlock needed (public half only).
#[cfg(feature = "vestnik-matrix")]
#[tauri::command]
pub async fn vestnik_session_seal(
    app: AppHandle,
    state: State<'_, VestnikClientState>,
) -> Result<Value, String> {
    let public =
        crate::vestnik::read_recipient_public(&crate::vestnik::recipient_public_path(&app)?)?;
    let sealed = {
        let slot = state.client.lock().await;
        seal_impl(&slot, &public)?
    };
    let sealed_b64 = sealed["sealedB64"].as_str().expect("seal_impl always sets sealedB64");
    let stored =
        crate::vestnik::store_blob_impl(&crate::vestnik::session_blob_path(&app)?, sealed_b64)?;
    Ok(json!({
        "sealed": true,
        "stored": stored["stored"],
        "bytes": sealed["bytes"],
        "fingerprint": sealed["fingerprint"],
        "honesty": HONESTY,
    }))
}

/// Restore the client from the stored sealed blob, opened with the
/// VAULT-custodied secret. Fail closed on a locked vault, a missing custody
/// entry, a missing blob, or a tampered blob (the reused custody cores).
/// LOCAL only — no homeserver request happens here.
#[cfg(feature = "vestnik-matrix")]
#[tauri::command]
pub async fn vestnik_restore(
    app: AppHandle,
    state: State<'_, VestnikClientState>,
    vault: State<'_, VaultState>,
    homeserver: String,
    store_passphrase: String,
) -> Result<Value, String> {
    let blob = crate::vestnik::read_session_blob(&crate::vestnik::session_blob_path(&app)?)?;
    // Scope the (std) vault guard strictly before any await — it is not Send
    // and must never be held across one.
    let session = {
        let guard = vault.0.lock().unwrap();
        open_saved_session(&guard, &blob)?
    };
    let store = matrix_store_path(&app)?;
    let mut slot = state.client.lock().await;
    restore_impl(&mut slot, session, &homeserver, &store, &store_passphrase).await
}

/// One sync round-trip (USER ACTION — contacts the homeserver).
#[cfg(feature = "vestnik-matrix")]
#[tauri::command]
pub async fn vestnik_sync_once(state: State<'_, VestnikClientState>) -> Result<Value, String> {
    let slot = state.client.lock().await;
    sync_once_impl(&slot).await
}

/// The fail-closed room list from local sync state (no network call — rooms
/// appear after user-initiated syncs).
#[cfg(feature = "vestnik-matrix")]
#[tauri::command]
pub async fn vestnik_rooms(state: State<'_, VestnikClientState>) -> Result<Value, String> {
    let slot = state.client.lock().await;
    rooms_impl(&slot).await
}

/// Tier-gated E2EE send (USER ACTION — contacts the homeserver). The
/// NotInternalE2ee refusal is surfaced verbatim.
#[cfg(feature = "vestnik-matrix")]
#[tauri::command]
pub async fn vestnik_send(
    state: State<'_, VestnikClientState>,
    room_id: String,
    body: String,
) -> Result<Value, String> {
    let slot = state.client.lock().await;
    send_impl(&slot, &room_id, &body).await
}

/// Drop the local client (no network call; token NOT invalidated server-side
/// — see [`logout_impl`]).
#[cfg(feature = "vestnik-matrix")]
#[tauri::command]
pub async fn vestnik_logout(state: State<'_, VestnikClientState>) -> Result<Value, String> {
    let mut slot = state.client.lock().await;
    Ok(logout_impl(&mut slot))
}

// ─────────────────────────────────────────────────────────────────────────────
// Feature OFF: the same command names, honestly refusing. Registered
// unconditionally in generate_handler! so the frontend always gets a clean
// error shape (never a missing-command panic, never a silent no-op) — the
// exact `vault_keychain_*` stub pattern.
// ─────────────────────────────────────────────────────────────────────────────

/// `{ built: false, logged_in: false, honesty }` — the pane's capability
/// gate honestly reports the feature is not compiled in.
#[cfg(not(feature = "vestnik-matrix"))]
#[tauri::command]
pub fn vestnik_matrix_status() -> Result<Value, String> {
    Ok(status_json(false, false))
}

/// Feature-off stub: a clean [`MATRIX_NOT_BUILT`] refusal.
#[cfg(not(feature = "vestnik-matrix"))]
#[tauri::command]
pub fn vestnik_login() -> Result<Value, String> {
    Err(MATRIX_NOT_BUILT.into())
}

/// Feature-off stub — see [`vestnik_login`]'s stub doc.
#[cfg(not(feature = "vestnik-matrix"))]
#[tauri::command]
pub fn vestnik_session_seal() -> Result<Value, String> {
    Err(MATRIX_NOT_BUILT.into())
}

/// Feature-off stub — see [`vestnik_login`]'s stub doc.
#[cfg(not(feature = "vestnik-matrix"))]
#[tauri::command]
pub fn vestnik_restore() -> Result<Value, String> {
    Err(MATRIX_NOT_BUILT.into())
}

/// Feature-off stub — see [`vestnik_login`]'s stub doc.
#[cfg(not(feature = "vestnik-matrix"))]
#[tauri::command]
pub fn vestnik_sync_once() -> Result<Value, String> {
    Err(MATRIX_NOT_BUILT.into())
}

/// Feature-off stub — see [`vestnik_login`]'s stub doc.
#[cfg(not(feature = "vestnik-matrix"))]
#[tauri::command]
pub fn vestnik_rooms() -> Result<Value, String> {
    Err(MATRIX_NOT_BUILT.into())
}

/// Feature-off stub — see [`vestnik_login`]'s stub doc.
#[cfg(not(feature = "vestnik-matrix"))]
#[tauri::command]
pub fn vestnik_send() -> Result<Value, String> {
    Err(MATRIX_NOT_BUILT.into())
}

/// Feature-off stub — see [`vestnik_login`]'s stub doc.
#[cfg(not(feature = "vestnik-matrix"))]
#[tauri::command]
pub fn vestnik_logout() -> Result<Value, String> {
    Err(MATRIX_NOT_BUILT.into())
}
