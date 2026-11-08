// SPDX-License-Identifier: MIT OR Apache-2.0

//! UniFFI surface for the phone-as-signer flow (feature `ffi`).
//!
//! This exposes [`MobileSignerHandle`] to Kotlin/Swift via `#[uniffi::export]`
//! proc-macros. It deliberately does **NOT** call `uniffi::setup_scaffolding!()`:
//! the ONE shipped scaffolding for the whole product suite lives in
//! `crates/postern-sdk`, and the repo enforces exactly one
//! (`mobile/ci/check-one-setup-scaffolding.sh`).
//!
//! COMPILE MODEL (honest): `setup_scaffolding!()` is what emits the crate-root
//! `UniFfiTag` and the builtin `FfiConverter` impls the proc-macros reference. So
//! this module is **fold-only**: it is written to compile *inside* the
//! `postern-sdk` facade (which owns that scaffolding), NOT standalone. Building
//! this crate with `--features ffi` on its own will fail with "cannot find
//! `UniFfiTag`" — that is expected, and adding a second `setup_scaffolding!()`
//! here to make it build alone is exactly what the rails forbid. The DEFAULT
//! build (no `ffi`) and the whole test suite compile and pass standalone; the
//! pure-Rust engine ([`crate::MobileSigner`] etc.) is fully exercised there.
//!
//! ADAPTER to wire it (out of scope here — touches `crates/postern-sdk`): add
//! `postern-mobile-signer = { path = "../../mobile/signer", features = ["ffi"] }`
//! to the facade's `Cargo.toml` and `pub use postern_mobile_signer::ffi::*;` from
//! its `lib.rs`. The facade's single scaffolding then collects these exports. The
//! mobile image is **UNBOOTED** — nothing ships from here on its own.
//!
//! Honesty carried to the boundary: every [`Prompt`] carries the standing
//! "not a hardware wallet" disclosure; the PQ key is in RAM at sign time
//! (software keystore, not hardware); and there is no ambient auto-approve — a
//! caller must present the request's own nonce for each sign.

use std::sync::{Arc, Mutex};

use crate::facade::{MobileSigner, PresenceMethod, PresenceProof, Prompt};

/// The FFI error surfaced to Kotlin/Swift. One flat, message-carrying variant —
/// fail-closed: any refusal (replay, undecodable, declined, presence mismatch)
/// arrives here as a decline, never a silent success.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    /// A signing/protocol refusal or a bad argument. The message is safe to show;
    /// it never contains key material.
    #[error("{0}")]
    Signer(String),
}

impl From<crate::MobileError> for FfiError {
    fn from(e: crate::MobileError) -> Self {
        FfiError::Signer(e.to_string())
    }
}

fn bad(msg: impl Into<String>) -> FfiError {
    FfiError::Signer(msg.into())
}

/// An opaque handle to the phone-side signer for one paired session. Held behind
/// a `Mutex` so the foreign side can drive it from any thread.
#[derive(uniffi::Object)]
pub struct MobileSignerHandle {
    inner: Mutex<MobileSigner>,
}

#[uniffi::export]
impl MobileSignerHandle {
    /// Build the signer from a BIP39 mnemonic and bind it to a paired session.
    ///
    /// SECURITY: `phrase` is the wallet's ONLY backup — never log it; drop the
    /// foreign-side string promptly (it is GC-managed and cannot be wiped here).
    /// `session_id` must be the 16-byte protocol session id from pairing.
    #[uniffi::constructor]
    pub fn from_mnemonic(
        phrase: String,
        testnet: bool,
        session_id: Vec<u8>,
        peer_device: String,
    ) -> Result<Arc<MobileSignerHandle>, FfiError> {
        let sid = to_session_id(&session_id)?;
        let ms = MobileSigner::from_mnemonic(&phrase, testnet, sid, peer_device)?;
        Ok(Arc::new(MobileSignerHandle { inner: Mutex::new(ms) }))
    }

    /// The wallet's receiving address (public).
    pub fn address(&self) -> String {
        self.lock().address()
    }

    /// Feed a raw request frame received over the paired channel. Returns the
    /// WYSIWYS [`Prompt`] to render, or fails closed on any replay/decode refusal.
    pub fn receive_frame(&self, request_frame: Vec<u8>) -> Result<Prompt, FfiError> {
        Ok(self.lock().receive_frame(&request_frame)?)
    }

    /// Approve + sign the pending request after the OS confirmed user presence.
    /// `req_nonce_hex` MUST be the pending prompt's `req_nonce_hex` (per-sign
    /// presence; there is no blanket auto-approve). Returns the approval frame to
    /// send back over the channel.
    pub fn approve(
        &self,
        req_nonce_hex: String,
        method: PresenceMethod,
    ) -> Result<Vec<u8>, FfiError> {
        let nonce = to_nonce(&req_nonce_hex)?;
        let presence = PresenceProof::granted(nonce, method);
        Ok(self.lock().approve(presence)?)
    }

    /// Approve a single-tap login WITHOUT a prompt iff a live, un-revoked grant
    /// covers it. Never covers a value transfer. `now_unix` is the current time.
    pub fn approve_single_tap_by_grant(&self, now_unix: i64) -> Result<Vec<u8>, FfiError> {
        Ok(self.lock().approve_single_tap_by_grant(now_unix)?)
    }

    /// Decline the pending request. Nothing is signed; the sequence never advances.
    pub fn decline(&self) -> Result<(), FfiError> {
        Ok(self.lock().decline()?)
    }

    /// Attach a time-boxed, revocable single-tap login grant for `org`.
    pub fn set_login_grant(&self, org: String, expires_at_unix: i64) {
        self.lock().set_login_grant(org, expires_at_unix);
    }

    /// Revoke any attached grant ("revoke this laptop"). Monotonic.
    pub fn revoke_grant(&self) {
        self.lock().revoke_grant();
    }
}

impl MobileSignerHandle {
    fn lock(&self) -> std::sync::MutexGuard<'_, MobileSigner> {
        // Recover from a poisoned lock: the signer holds no invariant that a panic
        // could corrupt into an unsafe state (it only holds public request state).
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn to_session_id(bytes: &[u8]) -> Result<[u8; 16], FfiError> {
    bytes
        .try_into()
        .map_err(|_| bad(format!("session_id must be 16 bytes, got {}", bytes.len())))
}

fn to_nonce(hexstr: &str) -> Result<[u8; 32], FfiError> {
    let v = hex::decode(hexstr).map_err(|e| bad(format!("bad req_nonce hex: {e}")))?;
    v.as_slice()
        .try_into()
        .map_err(|_| bad(format!("req_nonce must be 32 bytes, got {}", v.len())))
}
