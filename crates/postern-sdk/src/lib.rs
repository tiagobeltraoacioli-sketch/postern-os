//! # Postern SDK — one UniFFI surface for the whole Postern product suite.
//!
//! This crate is a single `cdylib` **facade**: instead of the app layer
//! (Android / iOS / desktop) shipping a separate UniFFI binding per product,
//! everything is folded into ONE `postern_sdk` library with ONE
//! `setup_scaffolding!()` and ONE generated Kotlin/Swift binding.
//!
//! Each module is a thin wrapper that delegates straight to the pure product
//! core — no crypto or logic is reimplemented here. The wrappers follow the
//! `mobile/core/src/ffi.rs` conventions: `Arc<Object>` for stateful handles,
//! `#[derive(uniffi::Record)]` for plain data, and one typed
//! [`PosternError`] that every core's error maps into.
//!
//! Products exposed (v0.1):
//! - **wallet**  — folds in `bloch_mobile::WalletCore` (its own FFI is now a
//!   default-on `ffi` feature, disabled here so scaffolding isn't registered
//!   twice) + the JSON-RPC body helpers.
//! - **vault**   — `postern_vault::Vault` + the opaque `VaultKey` handle
//!   (Argon2id derivation happens Rust-side; the key never crosses the FFI
//!   unless explicitly exported for TEE wrapping).
//! - **courier** — ML-KEM sealed messaging (`generate_recipient`/`seal`/`open`).
//! - **seal**    — device attestation verification + self-audit.
//! - **hygiene** — metadata scrubbing for OOXML / PDF / JPEG.
//! - **panic**   — a panic-lockable secret session (instant re-lock /
//!   denial-of-access; NOT deniable and NOT coercion-resistant — see the
//!   honest-limits doc on `panic::PanicSession`).
//! - **deniable** — the plausible-deniability dual-slot container
//!   (hidden-volume construction; the coercion-resistance piece the panic
//!   session does not claim — with its own honest limits).
//! - **keys**    — WebAuthn/FIDO-style P-256 credentials.
//!
//! ## Secret-handling policy at this boundary
//!
//! Secrets (mnemonics, private keys, derived vault keys) are NEVER exposed as
//! fields of a `uniffi::Record` — UniFFI lowers Records into Kotlin `data class`
//! / Swift `struct` values whose auto-generated `toString()`/`description`
//! would print the secret into logs and crash reports. Instead every secret
//! lives behind an opaque object handle (`Arc<Object>`) whose accessor returns
//! the secret only on an explicit, documented call. Rust-side intermediate
//! copies are wrapped in `zeroize::Zeroizing` so they are wiped before drop.
//!
//! Skipped for v0.1 (per the SDK plan): `postern-tor` (async/heavy),
//! `postern-quarantine`, `postern-messenger`.

// ── Native facade (UniFFI over the whole product suite) ──────────────────────
// Everything under `cfg(feature = "native")` is the Kotlin/Swift/desktop cdylib.
// The `wasm` build (browser seam) compiles NONE of it — it links only the
// pure-Rust cores that cross to wasm32-unknown-unknown (see `mod wasm`), because
// the wallet path pulls bloch-crypto's PQClean C, which does not build for wasm.

// The ONE UniFFI scaffolding registration for the entire suite. Must be at the
// crate root. Because `bloch-mobile` is pulled in with `default-features =
// false`, its own scaffolding is compiled out — so this is the only one, and the
// cdylib links cleanly.
#[cfg(feature = "native")]
uniffi::setup_scaffolding!();

#[cfg(feature = "native")]
mod error;
#[cfg(feature = "native")]
pub use error::PosternError;

/// Convert an FFI `Vec<u8>` into a fixed `[u8; N]`, or a typed error naming the
/// expected length. Keeps the FFI signatures byte-slice friendly while the
/// cores keep their fixed-size array guarantees.
#[cfg(feature = "native")]
fn to_array<const N: usize>(bytes: &[u8], what: &str) -> Result<[u8; N], PosternError> {
    bytes
        .try_into()
        .map_err(|_| PosternError::from(format!("{what} must be {N} bytes, got {}", bytes.len())))
}

/// Lock a mutex, RECOVERING from poisoning instead of panicking.
///
/// Every `Mutex` in this crate guards a plain in-memory map/state machine whose
/// invariants hold between core calls, so a poisoned lock (a panic while the
/// guard was held) leaves data that is safe to keep using. Panicking here would
/// cross the UniFFI boundary and abort the host app — for `PanicSession` that
/// would mean crashing during a duress scenario, the worst possible time.
#[cfg(feature = "native")]
fn lock_recover<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(feature = "native")]
mod courier;
#[cfg(feature = "native")]
mod deniable;
#[cfg(feature = "native")]
mod hygiene;
#[cfg(feature = "native")]
mod keys;
#[cfg(feature = "native")]
mod panic;
#[cfg(feature = "native")]
mod seal;
#[cfg(feature = "native")]
mod vault;
#[cfg(feature = "native")]
mod wallet;

// ── Browser seam (wasm32) ────────────────────────────────────────────────────
// The subset the HTML front-ends reach through `globalThis.PosternSDK`:
// Argon2id at-rest KDF + AEAD seal/open. Compiled only for the wasm target so it
// can never perturb the native build.
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
mod wasm;
