// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
//
//! Bloch persistence — sealed-at-rest session/message store. **Business/Enterprise
//! edition only.** Pre-release and **UNAUDITED**.
//!
//! The messenger transport (`crates/postern-messenger`, `matrix` slice) runs on
//! the SDK's in-memory store today: Megolm sessions and replay state do NOT
//! survive a restart (its own honest-limit note). This crate is the app-layer
//! answer — a local store that survives a restart by sealing itself **at rest**
//! with the **canonical Postern seal** ([`postern_core::aead`]): XChaCha20-Poly1305,
//! versioned, key-committing, and context-bound. That is the SAME seal
//! `crates/postern-vault` uses for secrets at rest; we reference it, we do not
//! reimplement crypto.
//!
//! Honest scope:
//! - Message **bodies** stay end-to-end encrypted by the transport. This store
//!   holds session material + message **envelopes**; sealing at rest is an
//!   ADDITIONAL local-device protection, not a replacement for E2EE.
//! - Metadata is still org-visible (the homeserver sees the social graph).
//!   Sealing the local copy does not make Bloch "fully private".
//! - The 32-byte store key is **local** to the device (from a device passphrase
//!   via `postern_core::kdf`, an OS keystore, or [`random_key`]). It is never
//!   uploaded and never embedded in the sealed blob.
//!
//! The JS/ESM module in `../sealed-store.mjs` is the app's primary implementation;
//! this Rust core demonstrates the same rail against the REAL Postern seal.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroize;

/// Context string binding Bloch persistence blobs to this product/format (see
/// [`postern_core::aead::seal_with_context`]). A blob sealed by another Postern
/// product under the same 32-byte key can NOT be opened as a Bloch store.
pub const STORE_CONTEXT: &[u8] = b"bloch-comms/persistence/v1";

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("seal failed")]
    Seal,
    #[error("open failed — wrong key, wrong context, or tampered data")]
    Open,
    #[error("corrupt store data")]
    Corrupt,
    #[error("serialization failed: {0}")]
    Serde(String),
}

impl From<postern_core::aead::SealError> for StoreError {
    fn from(e: postern_core::aead::SealError) -> Self {
        use postern_core::aead::SealError::*;
        match e {
            Seal => StoreError::Seal,
            Open => StoreError::Open,
            Corrupt => StoreError::Corrupt,
        }
    }
}

/// A device's persisted verification snapshot (mirrors `../../verification/`).
/// Fail-closed default is `trusted = false`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceSnapshot {
    pub identity_key: String,
    pub trusted: bool,
    pub method: Option<String>,
}

/// A message envelope — the AT-REST form (e.g. the transport's Megolm ciphertext
/// reference). This crate never sees plaintext bodies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope {
    pub conv_id: String,
    pub sender: String,
    pub at: String,
    pub tier: String,
    /// Opaque at-rest payload reference (ciphertext id / handle), never plaintext.
    pub envelope: String,
}

/// The decrypted, in-memory store. Sealed as a whole via [`SealedStore::seal`].
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SealedStore {
    /// Opaque Megolm session records keyed by session/device id.
    pub sessions: BTreeMap<String, String>,
    /// Device verification snapshots keyed by device id.
    pub devices: BTreeMap<String, DeviceSnapshot>,
    /// Message envelopes in append order.
    pub messages: Vec<Envelope>,
}

impl SealedStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put_session(&mut self, id: impl Into<String>, record: impl Into<String>) {
        self.sessions.insert(id.into(), record.into());
    }

    pub fn get_session(&self, id: &str) -> Option<&str> {
        self.sessions.get(id).map(|s| s.as_str())
    }

    pub fn put_device(&mut self, device_id: impl Into<String>, snap: DeviceSnapshot) {
        self.devices.insert(device_id.into(), snap);
    }

    pub fn append_message(&mut self, env: Envelope) {
        self.messages.push(env);
    }

    pub fn messages_for<'a>(&'a self, conv_id: &'a str) -> impl Iterator<Item = &'a Envelope> + 'a {
        self.messages.iter().filter(move |m| m.conv_id == conv_id)
    }

    /// Seal the whole store at rest with a 32-byte LOCAL key, bound to
    /// [`STORE_CONTEXT`]. The plaintext serialization is zeroized before return.
    pub fn seal(&self, key: &[u8; 32]) -> Result<Vec<u8>, StoreError> {
        let mut plain =
            serde_json::to_vec(self).map_err(|e| StoreError::Serde(e.to_string()))?;
        let sealed = postern_core::aead::seal_with_context(key, STORE_CONTEXT, &plain);
        plain.zeroize(); // never leave the serialized store in freed heap
        Ok(sealed?)
    }

    /// Open a sealed store with the 32-byte local key. FAIL-CLOSED: a wrong key,
    /// wrong context, or tampered blob returns an error and NO store. This is how
    /// sessions survive a restart: reopen with the local key.
    pub fn open(sealed: &[u8], key: &[u8; 32]) -> Result<SealedStore, StoreError> {
        let mut plain = postern_core::aead::open_with_context(key, STORE_CONTEXT, sealed)?;
        let store = serde_json::from_slice(&plain).map_err(|_| StoreError::Corrupt);
        plain.zeroize();
        store
    }
}

/// Generate a fresh random 32-byte LOCAL store key from postern-core's own
/// CSPRNG (two 16-byte salts concatenated). Keep it on-device; never upload it.
/// For a passphrase-derived key, use `postern_core::kdf` instead.
pub fn random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(&postern_core::kdf::generate_salt());
    key[16..].copy_from_slice(&postern_core::kdf::generate_salt());
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        [7u8; 32]
    }

    #[test]
    fn sessions_survive_a_restart_via_seal_open() {
        let mut store = SealedStore::new();
        store.put_session("dev-ana", "megolm-session-blob");
        store.put_device(
            "dev-ana",
            DeviceSnapshot { identity_key: "ED:AAAA".into(), trusted: true, method: Some("sas".into()) },
        );
        store.append_message(Envelope {
            conv_id: "chan-1".into(),
            sender: "Ana".into(),
            at: "2026-07-12T00:00:00Z".into(),
            tier: "E2EE (Postern)".into(),
            envelope: "ct-ref-1".into(),
        });

        let sealed = store.seal(&key()).unwrap();
        // Blob is opaque ciphertext — no plaintext leaks.
        assert!(!sealed
            .windows(b"megolm-session-blob".len())
            .any(|w| w == b"megolm-session-blob"));

        // "Restart": reopen from the sealed bytes with the local key.
        let reopened = SealedStore::open(&sealed, &key()).unwrap();
        assert_eq!(reopened.get_session("dev-ana"), Some("megolm-session-blob"));
        assert_eq!(reopened.messages_for("chan-1").count(), 1);
        assert!(reopened.devices.get("dev-ana").unwrap().trusted);
    }

    #[test]
    fn fail_closed_on_wrong_key_or_tamper() {
        let mut store = SealedStore::new();
        store.put_session("d", "s");
        let sealed = store.seal(&key()).unwrap();

        // Wrong key -> Open error, no store.
        assert!(matches!(SealedStore::open(&sealed, &[9u8; 32]), Err(StoreError::Open)));

        // Tamper the ciphertext body -> authentication fails.
        let mut bad = sealed.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(SealedStore::open(&bad, &key()).is_err());
    }

    #[test]
    fn context_binding_isolates_from_other_products() {
        let store = SealedStore::new();
        let sealed = store.seal(&key()).unwrap();
        // Opening under the vault's context (not ours) must fail — domain sep.
        assert!(
            postern_core::aead::open_with_context(&key(), b"postern-vault/v1", &sealed).is_err()
        );
    }
}
