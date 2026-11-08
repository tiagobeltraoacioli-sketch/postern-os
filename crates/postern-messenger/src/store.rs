// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Postern Labs
//! Persistence for the default [`crate::channel`] Megolm path — pre-release,
//! **UNAUDITED**.
//!
//! This module closes the crate's long-stated **"in-memory only"** gap for the
//! Postern-native path: a [`SecureChannel`](crate::channel::SecureChannel)
//! saves its Megolm sessions **and its replay bookkeeping** through a
//! [`SessionStore`] so both survive a process restart. Two stores ship:
//!
//! - [`FileSessionStore`] — a single JSON file on disk (the real product store).
//! - [`MemorySessionStore`] — an in-process cell, for tests and ephemeral use.
//!
//! # What "encrypted at rest" means here (be exact)
//!
//! The Megolm session material is **never written in the clear**. Each session
//! is serialized with vodozemac's own **encrypted pickle**
//! (`pickle().encrypt(&key)` → `GroupSession::from_encrypted`), a ChaCha20-
//! Poly1305 blob keyed by a 32-byte [`PickleKey`]. The [`PersistedState`] this
//! module stores therefore contains only opaque ciphertext strings plus the
//! replay watermark (message indices already seen — not secret, but integrity-
//! relevant). The store itself sees no plaintext key material.
//!
//! HONEST LIMIT: in a shipped Postern build the [`PickleKey`] is unwrapped from
//! the **PQ vault** (`postern-vault`) at unlock and zeroized after; wiring that
//! is out of this crate's scope. Here the key is **caller-supplied** — if the
//! caller hard-codes or logs it, "encrypted at rest" buys nothing. The replay
//! watermark is NOT authenticated across a store swap: an attacker who can
//! replace the whole state file with an older one can roll replay protection
//! back (rollback is the store medium's concern — use an integrity-checked
//! location; the PQ vault path addresses this in the shipped build).

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The 32-byte key that encrypts every session pickle at rest (vodozemac
/// encrypted-pickle key). Held in a [`Zeroizing`] wrapper so it is wiped from
/// RAM on drop. In production this is unwrapped from the PQ vault; here the
/// caller supplies it (see the module-level honest limit).
pub type PickleKey = Zeroizing<[u8; 32]>;

/// One receiver session as persisted: the vodozemac **encrypted** inbound
/// pickle plus the replay watermark (indices already decrypted). Both are
/// needed to resume decryption AND keep rejecting replays across a restart.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedInbound {
    /// vodozemac `InboundGroupSession` encrypted pickle (opaque ciphertext).
    pub session: String,
    /// Message indices this receiver has already accepted. Persisting these is
    /// what makes replay rejection survive a restart (the in-memory-only gap
    /// [`crate::megolm_reference`] documents).
    pub seen: Vec<u32>,
}

/// A crash-consistent snapshot of a [`SecureChannel`](crate::channel::SecureChannel):
/// the encrypted outbound session plus every peer's encrypted inbound session
/// and replay watermark. Everything here is either ciphertext or non-secret
/// bookkeeping, so it is safe to hand to any [`SessionStore`] medium.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedState {
    /// Schema version — bumped if the on-disk shape ever changes so an old
    /// file is rejected loudly instead of mis-parsed.
    pub version: u32,
    /// vodozemac `GroupSession` encrypted pickle (this identity's own outbound
    /// Megolm session — the ratchet that encrypts outgoing messages).
    pub outbound: String,
    /// Every registered peer inbound session, keyed by Megolm session id.
    pub inbound: Vec<(String, PersistedInbound)>,
}

impl PersistedState {
    /// The current on-disk schema version.
    pub const VERSION: u32 = 1;
}

/// Errors from a [`SessionStore`].
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("store i/o failed: {0}")]
    Io(String),
    #[error("store (de)serialization failed: {0}")]
    Serde(String),
    #[error("unsupported persisted-state version {found} (this build expects {expected})")]
    Version { found: u32, expected: u32 },
}

/// A place a [`SecureChannel`](crate::channel::SecureChannel) persists its
/// encrypted session state. Implementations move opaque [`PersistedState`]
/// bytes to and from some medium; they never see plaintext key material.
///
/// `save` MUST make the new state durable before returning (the channel calls
/// it after every ratchet advance, so a crash right after a send cannot lose
/// the fact that a message index was consumed — which would otherwise reopen
/// the replay window).
pub trait SessionStore {
    /// Persist `state`, overwriting any previous snapshot, durably.
    fn save(&mut self, state: &PersistedState) -> Result<(), StoreError>;
    /// Load the last-persisted snapshot, or `None` if nothing was ever saved.
    fn load(&self) -> Result<Option<PersistedState>, StoreError>;
}

/// A [`SessionStore`] backed by a single JSON file — the real product store.
/// Writes are done to a sibling temp file and `rename`d over the target so a
/// crash mid-write leaves the previous good snapshot intact (atomic replace on
/// the same filesystem), never a truncated one.
pub struct FileSessionStore {
    path: std::path::PathBuf,
}

impl FileSessionStore {
    /// A store persisting to `path` (created on first `save`; its parent
    /// directory must already exist).
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The file this store reads and writes.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl SessionStore for FileSessionStore {
    fn save(&mut self, state: &PersistedState) -> Result<(), StoreError> {
        let json = serde_json::to_vec_pretty(state).map_err(|e| StoreError::Serde(e.to_string()))?;
        // Write-then-rename for atomic replacement: a crash never leaves a
        // half-written state file that would wipe replay protection.
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &json).map_err(|e| StoreError::Io(e.to_string()))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(())
    }

    fn load(&self) -> Result<Option<PersistedState>, StoreError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(StoreError::Io(e.to_string())),
        };
        let state: PersistedState =
            serde_json::from_slice(&bytes).map_err(|e| StoreError::Serde(e.to_string()))?;
        if state.version != PersistedState::VERSION {
            return Err(StoreError::Version {
                found: state.version,
                expected: PersistedState::VERSION,
            });
        }
        Ok(Some(state))
    }
}

/// An in-process [`SessionStore`] — a shared cell holding the last snapshot.
/// For tests and ephemeral sessions. Cloning shares the same backing cell, so
/// a channel built from a clone sees what a previous channel saved (this is how
/// the "survives a drop/reload" property is tested without touching disk).
#[derive(Clone, Default)]
pub struct MemorySessionStore {
    cell: std::sync::Arc<std::sync::Mutex<Option<PersistedState>>>,
}

impl MemorySessionStore {
    /// An empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl SessionStore for MemorySessionStore {
    fn save(&mut self, state: &PersistedState) -> Result<(), StoreError> {
        *self.cell.lock().expect("MemorySessionStore mutex poisoned") = Some(state.clone());
        Ok(())
    }

    fn load(&self) -> Result<Option<PersistedState>, StoreError> {
        Ok(self.cell.lock().expect("MemorySessionStore mutex poisoned").clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PersistedState {
        PersistedState {
            version: PersistedState::VERSION,
            outbound: "enc-outbound-pickle".into(),
            inbound: vec![(
                "sess-1".into(),
                PersistedInbound { session: "enc-inbound-pickle".into(), seen: vec![0, 1, 2] },
            )],
        }
    }

    #[test]
    fn memory_store_roundtrips_and_shares_backing() {
        let mut a = MemorySessionStore::new();
        assert!(a.load().unwrap().is_none(), "empty store loads None");
        a.save(&sample()).unwrap();
        // A clone shares the cell — models a fresh channel reopening the store.
        let b = a.clone();
        assert_eq!(b.load().unwrap().unwrap(), sample());
    }

    #[test]
    fn file_store_roundtrips_across_new_instances() {
        let dir = std::env::temp_dir().join(format!("postern-msg-store-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        let _ = std::fs::remove_file(&path);

        assert!(FileSessionStore::new(&path).load().unwrap().is_none());

        let mut store = FileSessionStore::new(&path);
        store.save(&sample()).unwrap();

        // A brand-new store instance (models a process restart) sees the state.
        let reopened = FileSessionStore::new(&path);
        assert_eq!(reopened.load().unwrap().unwrap(), sample());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn file_store_rejects_a_future_version_loudly() {
        let dir = std::env::temp_dir().join(format!("postern-msg-ver-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        let mut bad = sample();
        bad.version = 999;
        std::fs::write(&path, serde_json::to_vec(&bad).unwrap()).unwrap();

        match FileSessionStore::new(&path).load() {
            Err(StoreError::Version { found: 999, expected }) => {
                assert_eq!(expected, PersistedState::VERSION);
            }
            other => panic!("expected a Version error, got {other:?}"),
        }
        std::fs::remove_file(&path).ok();
    }
}
