// SPDX-License-Identifier: MIT OR Apache-2.0
//! Vestnik — the desktop CUSTODY layer for the Matrix client's sealed
//! session, behind the `vestnik_*` #[tauri::command]s.
//!
//! postern-messenger's `matrix::SavedSession` can be sealed at rest with the
//! workspace's hybrid X25519 + ML-KEM-1024 courier seal, but that crate is
//! explicit about scope: *"custody of the courier recipient secret is the
//! caller's — vault integration is the desktop layer's job"*. This module is
//! exactly that job, and NOTHING more:
//!
//! - [`vestnik_recipient_init`] — generate a `postern_courier` hybrid
//!   recipient identity and custody the SECRET as a reserved entry in the
//!   postern-vault ([`RECIPIENT_ENTRY`], write-through sealed to disk like
//!   every vault mutation). Requires an UNLOCKED vault; fails closed when
//!   locked. Returns only the public key + fingerprint — the secret never
//!   leaves the vault. The NON-SECRET public half is additionally persisted
//!   under the app data dir ([`RECIPIENT_PUBLIC_FILE`]) so the
//!   `vestnik-matrix` client layer can seal a fresh `SavedSession` to it
//!   without unsealing the vault (backward-compatible: recipients initialized
//!   before this file existed keep opening blobs fine — only the SEAL path
//!   needs the file, and it fails with the clean
//!   [`NO_RECIPIENT_PUBLIC_ERROR`] explaining the explicit rotation).
//! - [`vestnik_session_store`] / [`vestnik_session_load`] — persist/read the
//!   opaque sealed `SavedSession` blob under the app data dir. The desktop
//!   treats it as bytes: it is never opened here (store only checks the
//!   courier wire framing so junk is refused at store time, fail closed).
//! - [`vestnik_session_open`] — courier-open the stored blob with the
//!   vault-custodied secret and return the JSON payload. Fail closed on a
//!   locked vault, a missing recipient entry, a foreign/wrong secret, or a
//!   tampered blob — never partial plaintext.
//!
//! Deliberately NOT here: running the matrix client itself. That lives in
//! `vestnik_client.rs` behind the opt-in `vestnik-matrix` cargo feature
//! (OFF by default — matrix-sdk is a heavy dependency tree and the default
//! desktop build stays lean). The desktop runs the matrix client only in a
//! vestnik-matrix build, only on user action — never in CI, never at app
//! startup — and the Vestnik pane gates on the real
//! `vestnik_matrix_status.built` capability, never on an assumption.
//!
//! Like `courier`/`vault`, this module is re-exported from src/lib.rs so
//! integration tests (tests/vestnik_custody.rs) can drive the pure `_impl`
//! functions without a live Tauri app — the same deliberate, disclosed
//! dual-compile (see Cargo.toml's `[lib]` comment).
//!
//! ## Honesty labels (carried, never weakened)
//!
//! - **UNAUDITED pre-release**, like everything in this repo.
//! - **Sealed-at-rest covers the SavedSession blob ONLY** (postern-messenger's
//!   `SEALED_SESSION_LIMITS` scope): Matrix Megolm/Olm transport crypto stays
//!   classical Curve25519 (not post-quantum), the SDK's sqlite store
//!   passphrase is NOT PQ-vault-wrapped, and a homeserver still sees the
//!   social graph.
//! - **The vault is a SOFTWARE seal** — not a TEE until real hardware (see
//!   `vault::HONESTY`); custodying the recipient secret there protects it
//!   with Argon2id + XChaCha20-Poly1305, nothing hardware-backed.
//! - **Whoever opens the vault opens the session**: the sealed blob contains
//!   a bearer access token; opening it with the custodied secret yields a
//!   credential that can act as that Matrix device.
//!
//! Every response carries the [`HONESTY`] text so the pane can never present
//! this as a live messenger or a hardware-custodied secret.

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use postern_courier::{generate_recipient, key_fingerprint, open, SealedPayload};
use serde_json::{json, Value};
use tauri::{AppHandle, Manager, State};
use zeroize::Zeroizing;

use crate::vault::{Unlocked, VaultState};

/// Mandatory per-response honesty text. Surfaced verbatim in every
/// `vestnik_*` result's `honesty` field so the UI can never overclaim. The
/// phrases "UNAUDITED", "only in a vestnik-matrix build, only on user
/// action", "SavedSession blob ONLY", "not post-quantum", "social graph" and
/// "not a TEE until real hardware" are load-bearing (tests assert them).
pub const HONESTY: &str = "UNAUDITED pre-release — Vestnik CUSTODY layer: the desktop runs \
     the matrix client only in a vestnik-matrix build, only on user action (never in CI, \
     never at app startup); these custody commands themselves contact no homeserver. \
     Sealed-at-rest covers the SavedSession blob ONLY, via the hybrid ML-KEM-1024 + \
     X25519 courier seal; the recipient secret is a software-vault entry (Argon2id + \
     XChaCha20-Poly1305 — not a TEE until real hardware). Matrix Megolm/Olm stays classical \
     Curve25519 — not post-quantum — and a homeserver still sees the social graph (rooms, \
     timestamps, who talks to whom).";

/// The reserved vault entry name custodying the courier recipient SECRET
/// (standard base64 of `postern_courier::Recipient::secret`). Reserved:
/// [`recipient_init_impl`] refuses to overwrite it silently — rotating the
/// custody key orphans any blob sealed to the old public key, so rotation
/// must be an explicit `vault_remove` first.
pub const RECIPIENT_ENTRY: &str = "vestnik/session-recipient";

/// File name of the opaque sealed SavedSession blob under the app data dir.
pub const BLOB_FILE: &str = "vestnik-session.sealed";

/// File name (app data dir) of the NON-SECRET public half of the custodied
/// recipient identity: standard base64 of `postern_courier::Recipient::public`,
/// one line. Written by [`vestnik_recipient_init`] so the `vestnik-matrix`
/// client layer can seal a fresh `SavedSession` to the custodied identity
/// WITHOUT unsealing the vault (the public key is not a secret; the vault
/// keeps only the secret half). Backward-compatible extension: recipients
/// initialized before this file existed keep working for load/open — only
/// the seal path needs it, and that path fails with the clean
/// [`NO_RECIPIENT_PUBLIC_ERROR`].
pub const RECIPIENT_PUBLIC_FILE: &str = "vestnik-recipient.pub";

/// The clean, specific error when the public half is not on disk. A recipient
/// custodied before [`RECIPIENT_PUBLIC_FILE`] existed cannot be re-derived
/// (the vault holds only the secret and there is no secret→public derivation
/// on postern-courier's surface), so the fix is the same explicit rotation
/// the overwrite refusal documents: `vault_remove` the entry, then re-run
/// `vestnik_recipient_init` — which orphans blobs sealed to the old key, so
/// it is never done silently.
/// (Only the feature-gated client layer READS this path in the bin target,
/// so a no-feature bin build would flag it dead — hence the allow; the lib
/// target still exports it for tests. Same disclosed pattern as
/// vestnik_client.rs's feature-off constants.)
#[cfg_attr(not(feature = "vestnik-matrix"), allow(dead_code))]
pub const NO_RECIPIENT_PUBLIC_ERROR: &str = "no custodied recipient PUBLIC key is on disk — run \
     vestnik_recipient_init first. If a recipient was initialized before the public half was \
     persisted, rotate it explicitly (vault_remove the custody entry, then vestnik_recipient_init \
     again — this orphans any blob sealed to the old key, which is why it is never automatic).";

/// The clean, specific error for "nothing stored yet" — a missing blob is a
/// first-run state, not a corrupt one, and the pane needs to tell them apart.
pub const NO_BLOB_ERROR: &str =
    "no sealed Vestnik session blob is stored yet — nothing to load";

// ─────────────────────────────────────────────────────────────────────────────
// Pure, testable core (no AppHandle) — what tests/vestnik_custody.rs drives.
// ─────────────────────────────────────────────────────────────────────────────

/// Pure core of [`vestnik_recipient_init`]: generate a hybrid recipient
/// identity (ML-KEM-1024 ‖ X25519, OS CSPRNG) and put its SECRET into the
/// unlocked vault under [`RECIPIENT_ENTRY`]. Fail closed:
///   * locked vault            → error (custody requires the vault key in RAM);
///   * entry already present   → error (no silent overwrite of a custody
///     secret — a rotation orphans every blob sealed to the old key, so it
///     must be an explicit remove first).
///
/// Returns `{ public, fingerprint, entry, honesty }` — the PUBLIC half only.
/// The caller (the live command) is responsible for the write-through
/// re-seal to disk, exactly like `vault_put`.
pub fn recipient_init_impl(guard: &mut Option<Unlocked>) -> Result<Value, String> {
    let u = guard
        .as_mut()
        .ok_or("vault is locked — unlock it before initializing the Vestnik session recipient")?;
    if u.vault.get(RECIPIENT_ENTRY).is_some() {
        return Err(format!(
            "a Vestnik session recipient is already custodied in the vault ('{RECIPIENT_ENTRY}') — \
             refusing to overwrite it silently. Rotating it orphans any session blob sealed to \
             the old key: remove the entry explicitly first if that is what you want."
        ));
    }
    let r = generate_recipient();
    let secret_b64 = Zeroizing::new(B64.encode(&r.secret));
    u.vault.put(RECIPIENT_ENTRY, secret_b64.as_bytes());
    Ok(json!({
        "public": B64.encode(&r.public),
        "fingerprint": key_fingerprint(&r.public),
        "entry": RECIPIENT_ENTRY,
        "honesty": HONESTY,
    }))
    // `r` drops here → Recipient's Drop zeroizes the secret key bytes; the
    // custody copy lives sealed in the vault (wiped from RAM on lock/panic).
}

/// Pure core of [`vestnik_session_open`]: open the sealed SavedSession wire
/// blob with the vault-custodied recipient secret and return the JSON
/// payload as `{ session, honesty }`. Fail closed at every step:
///   * locked vault                     → error;
///   * no [`RECIPIENT_ENTRY`] custodied → error (init first);
///   * corrupt custody entry            → error;
///   * malformed wire framing           → error;
///   * wrong/foreign secret OR tampered blob → error (the courier seal is
///     deliberately coarse here — AEAD failure never says which);
///   * plaintext that is not a JSON document → error, never raw bytes.
pub fn session_open_impl(guard: &Option<Unlocked>, blob: &[u8]) -> Result<Value, String> {
    let u = guard
        .as_ref()
        .ok_or("vault is locked — unlock it before opening the sealed Vestnik session")?;
    let entry = u.vault.get(RECIPIENT_ENTRY).ok_or(concat!(
        "no Vestnik session recipient is custodied in the vault — ",
        "run vestnik_recipient_init first"
    ))?;
    let entry = std::str::from_utf8(entry)
        .map_err(|_| format!("vault entry '{RECIPIENT_ENTRY}' is not UTF-8 base64 — corrupt custody entry"))?;
    let secret = Zeroizing::new(
        B64.decode(entry.trim())
            .map_err(|e| format!("vault entry '{RECIPIENT_ENTRY}' is not valid base64 ({e}) — corrupt custody entry"))?,
    );
    let payload = SealedPayload::from_bytes(blob).map_err(|e| e.to_string())?;
    let inner = Zeroizing::new(open(&secret, &payload).map_err(|e| e.to_string())?);
    let session: Value = serde_json::from_slice(&inner)
        .map_err(|_| "sealed blob opened but did not contain a JSON session document".to_string())?;
    Ok(json!({ "session": session, "honesty": HONESTY }))
}

/// Pure core of [`vestnik_session_store`]: decode the base64 wire blob and
/// persist it at `path`. The desktop treats the blob as OPAQUE bytes — it is
/// never opened here — but it must at least parse as the courier's versioned
/// wire framing ([`SealedPayload::from_bytes`]), so junk is refused at store
/// time instead of surfacing as a confusing failure at open time (fail
/// closed, and no partial/garbage file ever lands on disk).
pub fn store_blob_impl(path: &Path, sealed_b64: &str) -> Result<Value, String> {
    let bytes = B64
        .decode(sealed_b64.trim())
        .map_err(|e| format!("invalid sealed session base64: {e}"))?;
    SealedPayload::from_bytes(&bytes)
        .map_err(|e| format!("refusing to store: not a postern-courier sealed payload ({e})"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create session blob dir: {e}"))?;
    }
    std::fs::write(path, &bytes).map_err(|e| format!("write session blob: {e}"))?;
    Ok(json!({ "stored": true, "bytes": bytes.len(), "honesty": HONESTY }))
}

/// Pure core of [`vestnik_session_load`]: read the stored blob back as
/// `{ sealedB64, honesty }`. A missing blob is the clean [`NO_BLOB_ERROR`],
/// distinct from an IO failure.
pub fn load_blob_impl(path: &Path) -> Result<Value, String> {
    let bytes = read_session_blob(path)?;
    Ok(json!({ "sealedB64": B64.encode(&bytes), "honesty": HONESTY }))
}

/// Read the sealed blob bytes at `path`. Missing file → [`NO_BLOB_ERROR`]
/// (a first-run state the pane can present honestly); any other IO error is
/// reported as what it is.
pub fn read_session_blob(path: &Path) -> Result<Vec<u8>, String> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(NO_BLOB_ERROR.into()),
        Err(e) => Err(format!("read session blob: {e}")),
    }
}

/// Persist the NON-SECRET public half of the custodied recipient at `path`
/// (standard base64, one line — see [`RECIPIENT_PUBLIC_FILE`]). Pure fs
/// helper so tests drive it without an AppHandle.
pub fn write_recipient_public(path: &Path, public: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create recipient-public dir: {e}"))?;
    }
    std::fs::write(path, B64.encode(public)).map_err(|e| format!("write recipient public: {e}"))
}

/// Read the recipient public key back from [`write_recipient_public`]'s file.
/// Fail closed: missing file → the clean [`NO_RECIPIENT_PUBLIC_ERROR`];
/// anything unreadable/undecodable is an error, never a guessed key.
/// (Bin-target caller is the feature-gated seal path in vestnik_client.rs —
/// see the allow note on [`NO_RECIPIENT_PUBLIC_ERROR`].)
#[cfg_attr(not(feature = "vestnik-matrix"), allow(dead_code))]
pub fn read_recipient_public(path: &Path) -> Result<Vec<u8>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(NO_RECIPIENT_PUBLIC_ERROR.into())
        }
        Err(e) => return Err(format!("read recipient public: {e}")),
    };
    B64.decode(text.trim())
        .map_err(|e| format!("recipient public file is not valid base64 ({e}) — corrupt file"))
}

// ─────────────────────────────────────────────────────────────────────────────
// App-side plumbing (AppHandle + fs) and the #[tauri::command] surface
// (matches ../src/modules/messenger.js — the Vestnik pane).
// ─────────────────────────────────────────────────────────────────────────────

/// On-disk location of the sealed SavedSession blob (app data dir, next to
/// the vault file). `pub(crate)` so the `vestnik-matrix` client layer
/// (vestnik_client.rs) stores/loads the SAME blob through the SAME pure
/// cores — one file, one format, never a duplicate path.
pub(crate) fn session_blob_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    Ok(dir.join(BLOB_FILE))
}

/// On-disk location of the recipient's NON-SECRET public half
/// ([`RECIPIENT_PUBLIC_FILE`], app data dir). `pub(crate)` for the same
/// reason as [`session_blob_path`].
pub(crate) fn recipient_public_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    Ok(dir.join(RECIPIENT_PUBLIC_FILE))
}

/// Initialize the Vestnik session recipient: generate the hybrid identity,
/// custody the secret in the UNLOCKED vault under [`RECIPIENT_ENTRY`], and
/// write-through re-seal the vault to disk (like every vault mutation). The
/// NON-SECRET public half is also persisted under the app data dir
/// ([`RECIPIENT_PUBLIC_FILE`]) so a `vestnik-matrix` build can seal a session
/// to it without unsealing the vault.
/// Returns `{ public, fingerprint, entry, honesty }` — never the secret.
#[tauri::command]
pub fn vestnik_recipient_init(app: AppHandle, state: State<VaultState>) -> Result<Value, String> {
    let mut guard = state.0.lock().unwrap();
    let out = recipient_init_impl(&mut guard)?;
    // Write-through: persist the mutated vault immediately, same as vault_put
    // (a lock/panic then only has to evict RAM).
    let u = guard.as_ref().expect("recipient_init_impl succeeded ⇒ unlocked");
    let sealed = u.vault.seal(&u.key).map_err(|e| e.to_string())?;
    crate::vault::write_vault_file(&app, &u.salt, &sealed)?;
    // Persist the public half (NOT a secret) so the seal path never needs the
    // vault open. Decoding our own just-encoded base64 cannot fail.
    let public = B64
        .decode(out["public"].as_str().expect("recipient_init_impl always sets public"))
        .expect("recipient_init_impl emits valid base64");
    write_recipient_public(&recipient_public_path(&app)?, &public)?;
    Ok(out)
}

/// Persist the opaque sealed SavedSession blob (standard base64 of the
/// courier wire bytes) under the app data dir. Framing-checked, never opened.
#[tauri::command]
pub fn vestnik_session_store(app: AppHandle, sealed_b64: String) -> Result<Value, String> {
    store_blob_impl(&session_blob_path(&app)?, &sealed_b64)
}

/// Read the stored sealed SavedSession blob back as base64. Missing blob →
/// the clean [`NO_BLOB_ERROR`].
#[tauri::command]
pub fn vestnik_session_load(app: AppHandle) -> Result<Value, String> {
    load_blob_impl(&session_blob_path(&app)?)
}

/// Open the STORED sealed SavedSession blob with the vault-custodied
/// recipient secret and return the JSON payload. Fail closed on a locked
/// vault, a missing custody entry, a missing blob, a wrong/foreign secret,
/// or a tampered blob (see [`session_open_impl`]).
#[tauri::command]
pub fn vestnik_session_open(app: AppHandle, state: State<VaultState>) -> Result<Value, String> {
    let blob = read_session_blob(&session_blob_path(&app)?)?;
    let guard = state.0.lock().unwrap();
    session_open_impl(&guard, &blob)
}
