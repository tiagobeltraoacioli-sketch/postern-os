// SPDX-License-Identifier: MIT OR Apache-2.0
//! # Postern SDK — the browser seam (wasm32)
//!
//! This module is the WASM half of the one wiring seam. The HTML front-ends
//! (Chiave, Sotto, Vedetta, Tolmach, …) are strict-CSP single files that do
//! their crypto in WebCrypto today. The seam lets a host shell (or a relaxed-CSP
//! build) hand those pages the **real audited cores** instead, exposed as
//! `globalThis.PosternSDK` by the reference loader in `wasm/postern-sdk.js`.
//!
//! ## What this build backs FOR REAL (kills stand-in **S2**)
//!
//! - **Argon2id at-rest KDF** — `postern_core::kdf` (the memory-hard KDF the
//!   product uses at rest), replacing the front-ends' PBKDF2 stand-in.
//! - **AEAD seal/open** — `postern_core::aead` key-committing
//!   XChaCha20-Poly1305 (versioned, context-bound), the exact `postern-vault`
//!   at-rest construction.
//!
//! ## What this build DOES NOT back (stand-in **S1** stays labeled)
//!
//! - **Hybrid PQ signing** (Falcon-1024 ‖ ML-DSA-65). `bloch-crypto` links
//!   PQClean **C** (`cc` + `libc`) and does **not** build for
//!   `wasm32-unknown-unknown`. So in a browser the login/spend signature stays a
//!   *classical stand-in* (WebCrypto) — honestly labeled — until a pure-Rust PQ
//!   backend lands. The native (UniFFI) build has the real PQ wallet; this WASM
//!   build deliberately excludes it. `has_pq_sign()` returns `false` here so the
//!   page keeps its honest label rather than ever showing a fake "PQ" state.
//!
//! Every secret (the derived 32-byte key) lives behind the opaque
//! [`VaultKey`] handle — its bytes stay in wasm linear memory and are never
//! copied into the JS GC heap (which cannot be zeroized). The handle is wiped on
//! drop. This mirrors the native facade's `VaultKey` policy exactly.

use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// The SDK crate version (so the loader can pin/compare).
#[wasm_bindgen(js_name = sdkVersion)]
pub fn sdk_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// One-line honest description of what this WASM build actually provides.
#[wasm_bindgen(js_name = backendLabel)]
pub fn backend_label() -> String {
    "postern-sdk/wasm — real Argon2id(64 MiB, t=3) at-rest KDF + XChaCha20-Poly1305 AEAD \
     (postern-core / postern-vault). Hybrid PQ signing is NOT in this build \
     (bloch-crypto PQClean C does not target wasm32)."
        .to_string()
}

/// The KDF this build actually runs — the honest label for the UI to show.
/// NOTE: the pinned params are 64 MiB / t=3 (postern-core at-rest tier), not the
/// 256 MiB / t=4 some design docs aspire to. This reports the truth.
#[wasm_bindgen(js_name = kdfLabel)]
pub fn kdf_label() -> String {
    "Argon2id (m=65536 KiB, t=3, p=1)".to_string()
}

/// Capability probe: this build performs a real at-rest KDF.
#[wasm_bindgen(js_name = hasKdf)]
pub fn has_kdf() -> bool {
    true
}

/// Capability probe: this build performs real AEAD seal/open.
#[wasm_bindgen(js_name = hasAead)]
pub fn has_aead() -> bool {
    true
}

/// Capability probe: this build does NOT perform hybrid PQ signing (see the
/// module doc). The front-end must keep its labeled classical stand-in.
#[wasm_bindgen(js_name = hasPqSign)]
pub fn has_pq_sign() -> bool {
    false
}

/// Why PQ signing is unavailable in the browser build — surfaced verbatim so the
/// page can show an honest reason next to its stand-in label.
#[wasm_bindgen(js_name = pqUnavailableReason)]
pub fn pq_unavailable_reason() -> String {
    "Hybrid Falcon-1024 ‖ ML-DSA-65 lives in bloch-crypto, which links PQClean C and \
     does not build for wasm32-unknown-unknown. Use the native/UniFFI shell for real PQ \
     signing, or wait for a pure-Rust PQ backend. Until then this page signs with a labeled \
     classical stand-in."
        .to_string()
}

/// A fresh 16-byte KDF salt (store it alongside the sealed blob).
#[wasm_bindgen(js_name = generateSalt)]
pub fn generate_salt() -> Vec<u8> {
    postern_core::kdf::generate_salt().to_vec()
}

/// A 32-byte at-rest key behind an OPAQUE handle.
///
/// Deliberately a wasm-bindgen object, not a `Uint8Array`: the key material
/// stays in wasm linear memory (zeroized when the handle is freed) instead of
/// being copied into the JS GC heap where it could not be wiped. Derive it from
/// a passphrase with [`VaultKey::derive`]; seal/open ride on the handle.
#[wasm_bindgen]
pub struct VaultKey {
    inner: Zeroizing<[u8; 32]>,
}

#[wasm_bindgen]
impl VaultKey {
    /// Argon2id-derive the at-rest key from a passphrase + salt. `salt` must be
    /// at least 8 bytes (use [`generate_salt`] for a fresh 16-byte one). The
    /// derived key never crosses back into JS.
    #[wasm_bindgen(js_name = deriveArgon2id)]
    pub fn derive(passphrase: &[u8], salt: &[u8]) -> Result<VaultKey, JsError> {
        let key = postern_vault::derive_key(passphrase, salt)
            .map_err(|e| JsError::new(&e.to_string()))?;
        // `derive_key` already returns a `Zeroizing<[u8; 32]>`; move it straight
        // into the handle (no bare-array copy of the key material).
        Ok(VaultKey { inner: key })
    }

    /// Wrap externally provided 32-byte key bytes (e.g. released by a host TEE)
    /// in an opaque handle. Errors if `key` is not exactly 32 bytes.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(key: &[u8]) -> Result<VaultKey, JsError> {
        let k: [u8; 32] = key
            .try_into()
            .map_err(|_| JsError::new(&format!("vault key must be 32 bytes, got {}", key.len())))?;
        Ok(VaultKey { inner: Zeroizing::new(k) })
    }

    /// Seal (encrypt) `plaintext` under this key, bound to `context` (the AAD /
    /// domain tag). Returns the versioned, key-committing Postern seal
    /// (`0x02 ‖ nonce ‖ commit ‖ ct`). A fresh nonce is drawn per call.
    #[wasm_bindgen(js_name = aeadSeal)]
    pub fn aead_seal(&self, context: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
        let key: &[u8; 32] = &self.inner;
        postern_core::aead::seal_with_context(key, context, plaintext)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Open (decrypt) a blob sealed under the same key + `context`. Throws on a
    /// wrong key or tampered blob — all-or-nothing, no partial plaintext.
    #[wasm_bindgen(js_name = aeadOpen)]
    pub fn aead_open(&self, context: &[u8], sealed: &[u8]) -> Result<Vec<u8>, JsError> {
        let key: &[u8; 32] = &self.inner;
        postern_core::aead::open_with_context(key, context, sealed)
            .map_err(|e| JsError::new(&e.to_string()))
    }
}
