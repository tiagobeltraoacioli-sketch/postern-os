// SPDX-License-Identifier: MIT OR Apache-2.0
//! Vault + Panic — real cores (postern-vault, postern-panic) behind the
//! desktop's `vault_*` / `panic` #[tauri::command]s.
//!
//! The vault is backed by `postern_vault::Vault` (Argon2id passphrase KDF +
//! the versioned, context-bound XChaCha20-Poly1305 seal). Secrets live sealed
//! at rest in one file under the app data dir; unlocking derives the key from
//! the passphrase and holds the decrypted vault + key in memory. Every
//! mutation write-throughs (re-seals to disk immediately), so a lock/panic
//! only has to evict RAM.
//!
//! Like `hygiene`/`terem`, this module is also re-exported from src/lib.rs so
//! integration tests (tests/vault_core.rs) can drive its pure functions —
//! the on-disk encode/decode ([`encode_vault_file`]/[`decode_vault_file`]),
//! the status-JSON builder ([`status_json`]), and the TOTP command core
//! ([`totp_code_impl`]) — without a live Tauri app. Same deliberate,
//! disclosed dual-compile (see Cargo.toml's `[lib]` comment).
//!
//! ## Honesty labels (carried, never weakened)
//!
//! - **This is not a TEE.** The seal is Argon2id + XChaCha20-Poly1305 in
//!   ordinary process memory and an ordinary file — [`HONESTY`] ("not a TEE
//!   until real hardware") rides on every status result so the UI can never
//!   present the vault as hardware-backed. No StrongBox/Secure Enclave/SEV
//!   key-wrap exists here (blocked: no real hardware); an OS keychain would
//!   not be a TEE either.
//! - **Keychain unlock is a SOFTWARE convenience, not hardware protection**
//!   (`vault-keychain` cargo feature, OFF by default): the vault key is
//!   stored in the OS login keychain (macOS Keychain / freedesktop Secret
//!   Service) and is released to any process running as this user. Not a TEE
//!   until real hardware (no StrongBox / Secure Enclave / SEV key-wrap
//!   exists here) — UNAUDITED, like everything in this repo. [`KEYCHAIN_HONESTY`]
//!   rides on every status result (inside the `keychain` object) so the UI
//!   can never present keychain unlock as hardware-backed. With the feature
//!   OFF, the `vault_keychain_*` commands return a clean "not built with
//!   keychain support" error — never a silent no-op.
//! - **UNAUDITED**, like everything in this repo, pre-mainnet.
//! - **Fail closed**: a locked vault, a missing entry, a corrupt file, or a
//!   malformed base32 TOTP secret is an error — never a fake code, never a
//!   silently-empty vault.

use std::path::PathBuf;
use std::sync::Mutex;

use postern_panic::PanicSession;
#[cfg(feature = "vault-keychain")]
use postern_vault::keychain::KeyStore;
use postern_vault::{derive_key, generate_salt, totp::Totp, Vault};
use serde_json::{json, Value};
use tauri::{AppHandle, Manager, State};
use zeroize::Zeroizing;

/// Mandatory per-status honesty text: the vault is a SOFTWARE seal.
/// Surfaced verbatim in the status JSON's `honesty` field so the pane can
/// never claim hardware backing. The exact phrase "not a TEE until real
/// hardware" is load-bearing (tests assert it).
pub const HONESTY: &str = "not a TEE until real hardware — Argon2id + XChaCha20-Poly1305 \
     software seal in ordinary process memory and an ordinary file, UNAUDITED. No StrongBox / \
     Secure Enclave / SEV key-wrap exists here.";

/// Mandatory keychain honesty text, surfaced verbatim in every status
/// answer's `keychain.honesty` field (present whether or not the
/// `vault-keychain` feature is compiled in, so the pane always carries the
/// disclosure). Load-bearing — tests assert it verbatim.
pub const KEYCHAIN_HONESTY: &str = "keychain unlock is a SOFTWARE convenience, not hardware \
     protection: the vault key is stored in the OS login keychain (macOS Keychain / freedesktop \
     Secret Service) and is released to any process running as this user. Not a TEE until real \
     hardware (no StrongBox / Secure Enclave / SEV key-wrap exists here) — UNAUDITED, like \
     everything in this repo.";

/// The one fixed keychain account name every `vault_keychain_*` command uses
/// — this app manages at most one vault file, so there is exactly one
/// enrollable key. (The OS-side namespace is postern-vault's
/// `"com.posternlabs.vault"` service; this is the account within it.)
/// (With the feature OFF everything that uses it is compiled out, so the
/// bin target would flag it dead — hence the allow; the lib target still
/// exports it for tests.)
#[cfg_attr(not(feature = "vault-keychain"), allow(dead_code))]
pub const KEYCHAIN_ACCOUNT: &str = "bloch-desktop-vault";

/// Error every `vault_keychain_*` command returns when the binary was built
/// without the `vault-keychain` cargo feature. A clean, honest refusal —
/// never a silent no-op. (With the feature ON only the feature-off stubs
/// that use it are compiled out, so the bin target would flag it dead —
/// hence the allow; the lib target still exports it for tests.)
#[cfg_attr(feature = "vault-keychain", allow(dead_code))]
pub const KEYCHAIN_NOT_BUILT: &str =
    "not built with keychain support — rebuild bloch-desktop with the `vault-keychain` cargo feature";

/// The unlocked, in-memory vault plus what's needed to re-seal it. Dropping
/// this wipes the key (`Zeroizing`) and the vault's secrets (`Vault`'s own
/// `Drop`). Fields are `pub` ONLY so tests/vault_core.rs can build one to
/// drive [`totp_code_impl`] — the running app never hands this out.
pub struct Unlocked {
    pub vault: Vault,
    pub key: Zeroizing<[u8; 32]>,
    pub salt: Vec<u8>,
}

/// At most one unlocked vault at a time; `None` means locked (or no vault yet).
#[derive(Default)]
pub struct VaultState(pub Mutex<Option<Unlocked>>);

// ─────────────────────────────────────────────────────────────────────────────
// Pure, testable core (no AppHandle, no IO) — what tests/vault_core.rs drives.
// ─────────────────────────────────────────────────────────────────────────────

/// Encode the on-disk vault file: `u32-le salt_len ‖ salt ‖ sealed`.
/// The salt is public (it is a KDF salt, not a secret); the sealed blob is
/// the postern-vault ciphertext.
pub fn encode_vault_file(salt: &[u8], sealed: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + salt.len() + sealed.len());
    buf.extend_from_slice(&(salt.len() as u32).to_le_bytes());
    buf.extend_from_slice(salt);
    buf.extend_from_slice(sealed);
    buf
}

/// Decode `(salt, sealed)` back out of [`encode_vault_file`]'s format.
/// Fail closed: a short header, a length that overflows, or a `salt_len`
/// pointing past the end of the file is "corrupt", never a partial parse.
pub fn decode_vault_file(buf: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let salt_len = buf
        .get(0..4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize)
        .ok_or("vault file is corrupt")?;
    let end = 4usize
        .checked_add(salt_len)
        .filter(|e| *e <= buf.len())
        .ok_or("vault file is corrupt")?;
    Ok((buf[4..end].to_vec(), buf[end..].to_vec()))
}

/// The status shape the UI reads:
/// `{ exists, unlocked, count, honesty, keychain: { available, enrolled, honesty } }`.
/// `unlocked_count` is `Some(n)` when the vault is unlocked with `n` entries,
/// `None` when locked. The `honesty` field ([`HONESTY`]) is mandatory — every
/// status answer carries the "not a TEE until real hardware" disclosure —
/// and so is `keychain.honesty` ([`KEYCHAIN_HONESTY`]): the keychain object
/// is present in EVERY status answer (with `available: false` when the
/// `vault-keychain` feature is off or the OS store is unreachable), so the
/// pane can never present keychain unlock as hardware protection.
///
/// * `keychain_available` — an OS keychain backend is compiled in AND
///   reachable right now (macOS Keychain / freedesktop Secret Service).
/// * `keychain_enrolled` — a vault key is currently stored under
///   [`KEYCHAIN_ACCOUNT`] (i.e. `vault_unlock_keychain` would find one).
pub fn status_json(
    exists: bool,
    unlocked_count: Option<usize>,
    keychain_available: bool,
    keychain_enrolled: bool,
) -> Value {
    let (unlocked, count) = match unlocked_count {
        Some(n) => (true, n),
        None => (false, 0usize),
    };
    json!({
        "exists": exists,
        "unlocked": unlocked,
        "count": count,
        "honesty": HONESTY,
        "keychain": {
            "available": keychain_available,
            "enrolled": keychain_enrolled,
            "honesty": KEYCHAIN_HONESTY,
        },
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure keychain cores (feature `vault-keychain`) — written against
// `&mut dyn KeyStore` so tests/vault_core.rs drives them with postern-vault's
// RAM-only InMemoryKeyStore, no OS keychain needed in CI. The live commands
// hand them the real per-OS backend (see `os_keystore` below).
//
// HONESTY (mandatory, carried verbatim in KEYCHAIN_HONESTY): keychain unlock
// is a SOFTWARE convenience, not hardware protection — the vault key is
// stored in the OS login keychain (macOS Keychain / freedesktop Secret
// Service) and is released to any process running as this user. Not a TEE
// until real hardware (no StrongBox / Secure Enclave / SEV key-wrap exists
// here) — UNAUDITED, like everything in this repo.
// ─────────────────────────────────────────────────────────────────────────────

/// Pure core of `vault_keychain_enable`: store the CURRENTLY-UNLOCKED vault
/// key in `store` under `account`. Fail closed: a locked vault is an error —
/// there is no key in RAM to enroll, and this must never derive or invent one.
#[cfg(feature = "vault-keychain")]
pub fn keychain_enable_impl(
    guard: &Option<Unlocked>,
    store: &mut dyn KeyStore,
    account: &str,
) -> Result<(), String> {
    let u = guard.as_ref().ok_or("vault is locked — unlock it before enabling keychain unlock")?;
    store.store(account, &u.key).map_err(|e| e.to_string())
}

/// Pure core of `vault_unlock_keychain`: unlock the sealed vault with the key
/// stored in `store` under `account` — no passphrase. The enrolled key is
/// fetched with ONE `retrieve` and used directly: no passphrase exists on
/// this path, so an empty store is an explicit error (fail closed) — there is
/// deliberately no derive fallback that could burn Argon2id on an empty
/// passphrase and report a misleading "wrong key" (and no
/// retrieve-then-refetch window where the entry could vanish in between).
/// A stale enrolled key (the vault was re-created since) also fails closed
/// at `Vault::open`.
#[cfg(feature = "vault-keychain")]
pub fn unlock_keychain_impl(
    store: &mut dyn KeyStore,
    account: &str,
    salt: &[u8],
    sealed: &[u8],
) -> Result<Unlocked, String> {
    let key = store.retrieve(account).map_err(|e| e.to_string())?.ok_or(
        "no vault key is enrolled in the OS keychain — unlock with the passphrase, then enable keychain unlock",
    )?;
    let vault = Vault::open(sealed, &key).map_err(|e| e.to_string())?;
    Ok(Unlocked { vault, key, salt: salt.to_vec() })
}

/// Pure core of `vault_keychain_forget`: delete the enrolled key from `store`.
/// Returns whether one existed (deleting a non-enrolled account is a clean
/// `false`, not an error — forget is idempotent). After this,
/// [`unlock_keychain_impl`] fails closed until re-enabled.
#[cfg(feature = "vault-keychain")]
pub fn keychain_forget_impl(store: &mut dyn KeyStore, account: &str) -> Result<bool, String> {
    store.delete(account).map_err(|e| e.to_string())
}

/// Pure core behind the passphrase `vault_unlock` command **when the
/// `vault-keychain` feature is built**: unlock the master key preferring the
/// OS-keychain-wrapped key over re-deriving it. Routes through postern-vault's
/// [`unwrap_or_derive`](postern_vault::keychain::unwrap_or_derive) — if a key
/// is enrolled under `account` it is used **directly**, so the master key is
/// OS-keychain-wrapped and the expensive Argon2id KDF is skipped; only when
/// the store has no entry does it fall back to deriving from `passphrase`.
/// Either way the resulting key must open `sealed` or this fails closed.
///
/// HONESTY (mandatory, [`KEYCHAIN_HONESTY`]): the enrolled key sits in the OS
/// login keychain (macOS Keychain via postern-vault's `MacKeyStore` under the
/// `keychain-macos` feature) and is released to any process running as this
/// user — a SOFTWARE convenience, **not** a TEE. Not a TEE until the Postern
/// Container; a Secure-Enclave (SE) wrap is a *future* integration — no
/// StrongBox / Secure Enclave / SEV key-wrap exists here. UNAUDITED.
///
/// Written against `&dyn KeyStore` (retrieve is `&self`) so tests drive it
/// with postern-vault's RAM-only `InMemoryKeyStore`; the live `vault_unlock`
/// hands it the real per-OS backend (`os_keystore`), see `open_with_passphrase`.
#[cfg(feature = "vault-keychain")]
pub fn unlock_prefer_keychain_impl(
    store: &dyn KeyStore,
    account: &str,
    passphrase: &[u8],
    salt: &[u8],
    sealed: &[u8],
) -> Result<Unlocked, String> {
    let key = postern_vault::keychain::unwrap_or_derive(store, account, passphrase, salt)
        .map_err(|e| e.to_string())?;
    let vault = Vault::open(sealed, &key).map_err(|e| e.to_string())?;
    Ok(Unlocked { vault, key, salt: salt.to_vec() })
}

/// Pure core of [`vault_totp_code`]: given the (possibly locked) vault guard,
/// an entry name and a Unix timestamp, produce `{ code, period,
/// remaining_secs }` — or fail closed:
///   * locked vault           → error (no code);
///   * missing entry          → error (no code);
///   * non-UTF-8 entry        → error (no code);
///   * malformed base32 seed  → error (NEVER a fake code).
///
/// The entry value is expected to be a base32 (RFC 4648) TOTP secret exactly
/// as issuers hand them out (`otpauth://` QR payloads: case/whitespace/
/// padding-insensitive). Codes use the ecosystem default — SHA-1, 6 digits,
/// 30 s — via `Totp::from_base32_default` (RFC 6238).
pub fn totp_code_impl(guard: &Option<Unlocked>, name: &str, unix_secs: u64) -> Result<Value, String> {
    let u = guard.as_ref().ok_or("vault is locked")?;
    let bytes = u.vault.get(name).ok_or_else(|| format!("no secret '{name}'"))?;
    let encoded = std::str::from_utf8(bytes)
        .map_err(|_| format!("secret '{name}' is not a UTF-8 base32 TOTP secret"))?;
    let totp = Totp::from_base32_default(encoded.trim())
        .map_err(|e| format!("secret '{name}' is not a valid base32 TOTP secret: {e}"))?;
    let period = totp.period(); // ≥ 1, validated at construction
    Ok(json!({
        "code": totp.code_at(unix_secs),
        "period": period,
        "remaining_secs": period - (unix_secs % period),
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// App-side plumbing (AppHandle + fs) and the #[tauri::command] surface.
// ─────────────────────────────────────────────────────────────────────────────

/// On-disk location of the single sealed vault (`salt_len ‖ salt ‖ sealed`).
fn vault_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    Ok(dir.join("vault.postern"))
}

/// Persist the salt (public) alongside the sealed blob (see [`encode_vault_file`]).
/// `pub(crate)` so `vestnik::vestnik_recipient_init` can write-through its
/// vault mutation (custodying the courier recipient secret) exactly like
/// `vault_put` does — same file, same format, same fail-closed semantics.
pub(crate) fn write_vault_file(app: &AppHandle, salt: &[u8], sealed: &[u8]) -> Result<(), String> {
    let path = vault_path(app)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create vault dir: {e}"))?;
    }
    std::fs::write(&path, encode_vault_file(salt, sealed)).map_err(|e| format!("write vault: {e}"))
}

/// Read back the `(salt, sealed)` written by [`write_vault_file`].
fn read_vault_file(app: &AppHandle) -> Result<(Vec<u8>, Vec<u8>), String> {
    let buf = std::fs::read(vault_path(app)?).map_err(|e| format!("read vault: {e}"))?;
    decode_vault_file(&buf)
}

/// The real per-OS [`KeyStore`] behind the live `vault_keychain_*` commands
/// (the pure `*_impl` cores above never construct one — tests hand them an
/// `InMemoryKeyStore`). One backend per target, matching the `vault-keychain`
/// feature's mapping in Cargo.toml:
///   macOS → postern-vault's `MacKeyStore` (login Keychain);
///   Linux → postern-vault's `SecretServiceKeyStore` (freedesktop Secret
///           Service over D-Bus; connecting can fail — honest error, no mock);
///   elsewhere → an honest "no OS keychain backend" error.
/// NOT a TEE on any of them — see [`KEYCHAIN_HONESTY`].
#[cfg(feature = "vault-keychain")]
fn os_keystore() -> Result<Box<dyn KeyStore>, String> {
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(postern_vault::keychain_macos::MacKeyStore::new()))
    }
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(
            postern_vault::keychain_linux::SecretServiceKeyStore::new().map_err(|e| e.to_string())?,
        ))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err("no OS keychain backend exists for this platform".into())
    }
}

/// `(available, enrolled)` for the status JSON's `keychain` object.
/// Fail closed: an unreachable store (no D-Bus Secret Service provider, a
/// locked/erroring keychain) reports `available: false` / `enrolled: false`
/// rather than guessing.
#[cfg(feature = "vault-keychain")]
fn keychain_status_flags() -> (bool, bool) {
    match os_keystore() {
        Ok(store) => {
            // The Zeroizing key copy is dropped (wiped) immediately —
            // only its presence is reported.
            let enrolled = matches!(store.retrieve(KEYCHAIN_ACCOUNT), Ok(Some(_)));
            (true, enrolled)
        }
        Err(_) => (false, false),
    }
}

/// Feature off: no backend is compiled in — never available, never enrolled.
/// The status JSON still carries the `keychain` object (with its mandatory
/// [`KEYCHAIN_HONESTY`] text) so the pane's disclosure does not depend on
/// how the binary was built.
#[cfg(not(feature = "vault-keychain"))]
fn keychain_status_flags() -> (bool, bool) {
    (false, false)
}

/// Derive the master key from the passphrase (Argon2id) and open the sealed
/// vault. The always-available unlock path — no OS keychain involved.
fn derive_and_open(salt: &[u8], sealed: &[u8], passphrase: &[u8]) -> Result<Unlocked, String> {
    let key = derive_key(passphrase, salt).map_err(|e| e.to_string())?;
    let vault = Vault::open(sealed, &key).map_err(|e| e.to_string())?;
    Ok(Unlocked { vault, key, salt: salt.to_vec() })
}

/// Unlock the vault file with the user's passphrase. **With the
/// `vault-keychain` feature on**, prefers an OS-keychain-wrapped master key:
/// if a key is enrolled under [`KEYCHAIN_ACCOUNT`] it is used directly
/// (Argon2id skipped — the key is OS-keychain-wrapped, not re-derived), via
/// [`unlock_prefer_keychain_impl`]/`unwrap_or_derive`→`MacKeyStore`. A
/// missing enrollment falls through to the passphrase KDF inside
/// `unwrap_or_derive`; an unreachable keychain or a *stale* enrolled key (one
/// that no longer opens the file) must never break a valid passphrase, so
/// this falls back to [`derive_and_open`]. NOT a TEE — see [`KEYCHAIN_HONESTY`].
#[cfg(feature = "vault-keychain")]
fn open_with_passphrase(salt: &[u8], sealed: &[u8], passphrase: &[u8]) -> Result<Unlocked, String> {
    if let Ok(store) = os_keystore() {
        if let Ok(unlocked) =
            unlock_prefer_keychain_impl(store.as_ref(), KEYCHAIN_ACCOUNT, passphrase, salt, sealed)
        {
            return Ok(unlocked);
        }
        // Enrolled key was stale/absent-and-passphrase-wrong or the store
        // erred: fall through to a clean passphrase derive rather than letting
        // a keychain hiccup block a legitimate passphrase unlock.
    }
    derive_and_open(salt, sealed, passphrase)
}

/// Feature-off: no OS keychain backend is compiled in, so unlock always
/// derives the master key from the passphrase.
#[cfg(not(feature = "vault-keychain"))]
fn open_with_passphrase(salt: &[u8], sealed: &[u8], passphrase: &[u8]) -> Result<Unlocked, String> {
    derive_and_open(salt, sealed, passphrase)
}

/// Status for the live app: on-disk existence + in-memory lock state +
/// keychain availability/enrollment.
fn vault_status_value(app: &AppHandle, guard: &Option<Unlocked>) -> Value {
    let exists = vault_path(app).map(|p| p.exists()).unwrap_or(false);
    let (kc_available, kc_enrolled) = keychain_status_flags();
    status_json(exists, guard.as_ref().map(|u| u.vault.names().len()), kc_available, kc_enrolled)
}

/// Current vault status (no secrets leave the backend). Always carries the
/// [`HONESTY`] disclosure.
#[tauri::command]
pub fn vault_status(app: AppHandle, state: State<VaultState>) -> Value {
    let guard = state.0.lock().unwrap();
    vault_status_value(&app, &guard)
}

/// Create a new empty vault, sealed under an Argon2id key from `passphrase`.
#[tauri::command]
pub fn vault_create(app: AppHandle, state: State<VaultState>, passphrase: String) -> Result<Value, String> {
    if vault_path(&app)?.exists() {
        return Err("a vault already exists — unlock it or discard it first".into());
    }
    if passphrase.len() < 8 {
        return Err("passphrase must have at least 8 characters".into());
    }
    let salt = generate_salt();
    let key = derive_key(passphrase.as_bytes(), &salt).map_err(|e| e.to_string())?;
    let vault = Vault::new();
    let sealed = vault.seal(&key).map_err(|e| e.to_string())?;
    write_vault_file(&app, &salt, &sealed)?;
    let mut guard = state.0.lock().unwrap();
    *guard = Some(Unlocked { vault, key, salt: salt.to_vec() });
    Ok(vault_status_value(&app, &guard))
}

/// Unlock the sealed vault with the user's `passphrase`. With the
/// `vault-keychain` feature on this prefers an OS-keychain-wrapped master key
/// when one is enrolled (Argon2id skipped — the key is OS-keychain-wrapped,
/// not re-derived; see [`open_with_passphrase`]); otherwise, and always
/// without the feature, it re-derives the key from the passphrase. NOT a TEE
/// — see [`KEYCHAIN_HONESTY`].
#[tauri::command]
pub fn vault_unlock(app: AppHandle, state: State<VaultState>, passphrase: String) -> Result<Value, String> {
    let (salt, sealed) = read_vault_file(&app)?;
    let unlocked = open_with_passphrase(&salt, &sealed, passphrase.as_bytes())?;
    let mut guard = state.0.lock().unwrap();
    *guard = Some(unlocked);
    Ok(vault_status_value(&app, &guard))
}

/// Lock the vault: evict the key + decrypted secrets from RAM (ciphertext at rest).
#[tauri::command]
pub fn vault_lock(app: AppHandle, state: State<VaultState>) -> Value {
    let mut guard = state.0.lock().unwrap();
    *guard = None;
    vault_status_value(&app, &guard)
}

/// Names of the sealed secrets (never the values). Sorted (BTreeMap order).
#[tauri::command]
pub fn vault_list(state: State<VaultState>) -> Result<Vec<String>, String> {
    let guard = state.0.lock().unwrap();
    guard.as_ref().map(|u| u.vault.names()).ok_or_else(|| "vault is locked".into())
}

/// Reveal one secret by name (UTF-8). Locked → error.
#[tauri::command]
pub fn vault_get(state: State<VaultState>, name: String) -> Result<String, String> {
    let guard = state.0.lock().unwrap();
    let u = guard.as_ref().ok_or("vault is locked")?;
    match u.vault.get(&name) {
        Some(bytes) => String::from_utf8(bytes.to_vec()).map_err(|_| "secret is not valid UTF-8".into()),
        None => Err(format!("no secret '{name}'")),
    }
}

/// Store (or replace) a secret, then re-seal to disk immediately (write-through).
#[tauri::command]
pub fn vault_put(app: AppHandle, state: State<VaultState>, name: String, secret: String) -> Result<(), String> {
    let mut guard = state.0.lock().unwrap();
    let u = guard.as_mut().ok_or("vault is locked")?;
    u.vault.put(&name, secret.as_bytes());
    let sealed = u.vault.seal(&u.key).map_err(|e| e.to_string())?;
    write_vault_file(&app, &u.salt, &sealed)
}

/// Remove a secret (wiped from RAM), then re-seal to disk.
#[tauri::command]
pub fn vault_remove(app: AppHandle, state: State<VaultState>, name: String) -> Result<(), String> {
    let mut guard = state.0.lock().unwrap();
    let u = guard.as_mut().ok_or("vault is locked")?;
    u.vault.remove(&name);
    let sealed = u.vault.seal(&u.key).map_err(|e| e.to_string())?;
    write_vault_file(&app, &u.salt, &sealed)
}

/// Delete the sealed vault file (ciphertext and all). Irreversible.
#[tauri::command]
pub fn vault_discard(app: AppHandle, state: State<VaultState>) -> Result<Value, String> {
    let path = vault_path(&app)?;
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| format!("discard vault: {e}"))?;
    }
    let mut guard = state.0.lock().unwrap();
    *guard = None;
    Ok(vault_status_value(&app, &guard))
}

/// Current TOTP code for the entry `name`, whose value must be a base32
/// (RFC 4648) TOTP secret. Returns `{ code, period, remaining_secs }`
/// (RFC 6238, ecosystem default SHA-1 / 6 digits / 30 s). Fail closed —
/// locked vault, missing entry, or malformed base32 is an error, never a
/// fake code. The code is derived in-process from the unlocked vault; the
/// seed itself never leaves the backend.
#[tauri::command]
pub fn vault_totp_code(state: State<VaultState>, name: String) -> Result<Value, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch")?
        .as_secs();
    let guard = state.0.lock().unwrap();
    totp_code_impl(&guard, &name, now)
}

// ── keychain commands (opt-in `vault-keychain` feature) ─────────────────────
//
// HONESTY (mandatory): keychain unlock is a SOFTWARE convenience, not
// hardware protection — the vault key is stored in the OS login keychain
// (macOS Keychain / freedesktop Secret Service) and is released to any
// process running as this user. Not a TEE until real hardware (no StrongBox /
// Secure Enclave / SEV key-wrap exists here) — UNAUDITED, like everything in
// this repo. The same text ships to the UI verbatim as KEYCHAIN_HONESTY in
// every status answer.

/// Enroll the CURRENTLY-UNLOCKED vault key in the OS keychain under the fixed
/// [`KEYCHAIN_ACCOUNT`], so `vault_unlock_keychain` can later unlock without
/// the passphrase. Locked vault → error (nothing to enroll). Opt-in only —
/// nothing is ever enrolled implicitly. See the honesty block above: this is
/// a convenience trade-off, not added protection.
#[cfg(feature = "vault-keychain")]
#[tauri::command]
pub fn vault_keychain_enable(app: AppHandle, state: State<VaultState>) -> Result<Value, String> {
    let guard = state.0.lock().unwrap();
    let mut store = os_keystore()?;
    keychain_enable_impl(&guard, store.as_mut(), KEYCHAIN_ACCOUNT)?;
    Ok(vault_status_value(&app, &guard))
}

/// Unlock the sealed vault with the key enrolled in the OS keychain — no
/// passphrase (one `KeyStore::retrieve`, used directly). Fail closed: no
/// enrolled key, an unreachable keychain, or a stale key that no longer opens
/// the vault file is an error — never a silently-empty vault.
#[cfg(feature = "vault-keychain")]
#[tauri::command]
pub fn vault_unlock_keychain(app: AppHandle, state: State<VaultState>) -> Result<Value, String> {
    let (salt, sealed) = read_vault_file(&app)?;
    let mut store = os_keystore()?;
    let unlocked = unlock_keychain_impl(store.as_mut(), KEYCHAIN_ACCOUNT, &salt, &sealed)?;
    let mut guard = state.0.lock().unwrap();
    *guard = Some(unlocked);
    Ok(vault_status_value(&app, &guard))
}

/// Delete the enrolled vault key from the OS keychain. Idempotent (forgetting
/// when nothing is enrolled is not an error). Does NOT lock the vault or
/// touch the sealed file — it only removes the passphrase-less unlock path,
/// so the next unlock requires the passphrase again.
#[cfg(feature = "vault-keychain")]
#[tauri::command]
pub fn vault_keychain_forget(app: AppHandle, state: State<VaultState>) -> Result<Value, String> {
    let mut store = os_keystore()?;
    keychain_forget_impl(store.as_mut(), KEYCHAIN_ACCOUNT)?;
    let guard = state.0.lock().unwrap();
    Ok(vault_status_value(&app, &guard))
}

/// Feature-off stub: the command exists so the UI gets a clean, honest
/// "not built with keychain support" error ([`KEYCHAIN_NOT_BUILT`]) —
/// never a silent no-op, never a missing-command panic from the frontend.
#[cfg(not(feature = "vault-keychain"))]
#[tauri::command]
pub fn vault_keychain_enable() -> Result<Value, String> {
    Err(KEYCHAIN_NOT_BUILT.into())
}

/// Feature-off stub — see [`vault_keychain_enable`]'s stub doc.
#[cfg(not(feature = "vault-keychain"))]
#[tauri::command]
pub fn vault_unlock_keychain() -> Result<Value, String> {
    Err(KEYCHAIN_NOT_BUILT.into())
}

/// Feature-off stub — see [`vault_keychain_enable`]'s stub doc.
#[cfg(not(feature = "vault-keychain"))]
#[tauri::command]
pub fn vault_keychain_forget() -> Result<Value, String> {
    Err(KEYCHAIN_NOT_BUILT.into())
}

/// PANIC (postern-panic): instant denial-of-access re-lock. Hands the live vault
/// + key to `PanicSession::panic`, which seals to ciphertext and evicts the key
/// and decrypted secrets from RAM. The on-disk blob is already current (every
/// mutation writes through), so nothing is destroyed — only re-locked. Idempotent.
#[tauri::command]
pub fn panic(app: AppHandle, state: State<VaultState>) -> Result<Value, String> {
    let mut guard = state.0.lock().unwrap();
    if let Some(u) = guard.take() {
        let mut session = PanicSession::unlocked(u.vault, *u.key);
        session.panic().map_err(|e| e.to_string())?;
        // `session` is now Locked (key already evicted); it drops here.
    }
    Ok(vault_status_value(&app, &guard))
}
