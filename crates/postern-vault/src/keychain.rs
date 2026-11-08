//! Feature-gated key-wrap abstraction for the vault key (`keychain` cargo
//! feature, off by default).
//!
//! This module defines a [`KeyStore`] trait for stashing the vault's 32-byte
//! key under an account name, plus [`unwrap_or_derive`], a small helper that
//! prefers a stored key and falls back to the crate's Argon2id
//! [`derive_key`](crate::derive_key) when the store has no entry.
//!
//! ## NOT a TEE
//!
//! **Be honest about what a `KeyStore` backend is.** An OS keychain
//! (macOS Keychain, the Secret Service on Linux, Windows Credential Manager,
//! Android `Keystore` without a StrongBox-backed key, …) is a **software**
//! credential store: it gates access on your login session / OS user account
//! and typically encrypts its own database at rest, but the vault key still
//! passes through normal process memory and the OS can be coerced (root,
//! debugger, another process running as you) into handing it back. That is
//! **not** hardware isolation.
//!
//! A real Trusted Execution Environment — Android StrongBox / Keymint, or
//! Apple's Secure Enclave — holds the *wrapping* key inside dedicated,
//! attestable hardware and never releases it to the OS or app process; only
//! wrap/unwrap operations cross the boundary. **No such TEE-backed backend
//! exists in this crate.** Wiring one up (StrongBox on Android, Secure
//! Enclave on iOS/macOS) is a *planned app-layer integration*, same as noted
//! in the crate-level "What this crate does NOT do (yet)" disclosure in
//! `lib.rs` — this module does not change that: it only defines the trait
//! shape a future TEE backend would implement, plus a RAM-only backend for
//! tests.
//!
//! Until a real hardware backend lands, the only [`KeyStore`] shipped here is
//! [`InMemoryKeyStore`], explicitly labelled **SCAFFOLD** below — do not
//! mistake it, or any future plain-OS-keychain backend, for TEE-grade
//! protection.

use crate::{derive_key, VaultError};
use std::collections::HashMap;
use zeroize::{Zeroize, Zeroizing};

/// Linux freedesktop Secret Service (D-Bus)-backed [`KeyStore`], gated on
/// `keychain-linux` (macOS is not a Secret Service host, so this is a no-op
/// re-export off Linux or without the feature). See
/// [`crate::keychain_linux`] for the implementation and its "NOT a TEE" /
/// BLOCKED-on-this-host disclosures.
#[cfg(all(target_os = "linux", feature = "keychain-linux"))]
pub use crate::keychain_linux::SecretServiceKeyStore;

/// Stores, retrieves, and deletes a 32-byte vault key by account name.
///
/// Implementors decide *where* the key lives (RAM, OS keychain, eventually a
/// TEE) — see the module-level "NOT a TEE" disclosure for why an OS keychain
/// backend is not equivalent to hardware isolation.
pub trait KeyStore {
    /// Store (or replace) the 32-byte key under `account`.
    fn store(&mut self, account: &str, key: &[u8; 32]) -> Result<(), VaultError>;

    /// Fetch the 32-byte key for `account`, if one is stored.
    ///
    /// The key is returned in a [`Zeroizing`] wrapper so the caller's copy is
    /// wiped on drop even if the caller forgets — a bare `[u8; 32]` return
    /// would leave the vault key sitting in whatever stack/heap slot the
    /// caller parked it in. (RAM hygiene, not a TEE — see the module docs.)
    fn retrieve(&self, account: &str) -> Result<Option<Zeroizing<[u8; 32]>>, VaultError>;

    /// Remove the key for `account`. Returns whether one existed.
    fn delete(&mut self, account: &str) -> Result<bool, VaultError>;
}

/// **SCAFFOLD** — a RAM-only [`KeyStore`] backend that exists so the
/// key-wrap flow ([`unwrap_or_derive`] and callers of [`KeyStore`]) is
/// unit-testable without any real credential store or hardware present.
///
/// Keys placed here live only in process memory for the lifetime of this
/// struct (zeroized on `delete`/replace/drop, matching [`crate::Vault`]'s
/// RAM hygiene) and are gone the moment it is dropped or the process exits.
/// This is **not** a persistent store, **not** an OS keychain, and — per the
/// module docs above — nowhere close to a TEE. It is only useful for tests
/// and local development wiring.
#[derive(Default)]
pub struct InMemoryKeyStore {
    entries: HashMap<String, [u8; 32]>,
}

impl InMemoryKeyStore {
    /// A fresh, empty scaffold store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeyStore for InMemoryKeyStore {
    fn store(&mut self, account: &str, key: &[u8; 32]) -> Result<(), VaultError> {
        if let Some(mut old) = self.entries.insert(account.to_string(), *key) {
            old.zeroize();
        }
        Ok(())
    }

    fn retrieve(&self, account: &str) -> Result<Option<Zeroizing<[u8; 32]>>, VaultError> {
        Ok(self.entries.get(account).copied().map(Zeroizing::new))
    }

    fn delete(&mut self, account: &str) -> Result<bool, VaultError> {
        match self.entries.remove(account) {
            Some(mut key) => {
                key.zeroize();
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

impl Drop for InMemoryKeyStore {
    fn drop(&mut self) {
        for key in self.entries.values_mut() {
            key.zeroize();
        }
    }
}

/// Get the vault's 32-byte key: prefer whatever `store` has under `account`,
/// and fall back to deriving one from `passphrase`/`salt` with the crate's
/// Argon2id [`derive_key`](crate::derive_key) (at-rest tier: 64 MiB, t = 3)
/// when the store has no entry for `account`.
///
/// This does not itself persist a freshly derived key back into `store` —
/// callers that want that should call [`KeyStore::store`] explicitly once
/// they trust the derived key.
pub fn unwrap_or_derive(
    store: &dyn KeyStore,
    account: &str,
    passphrase: &[u8],
    salt: &[u8],
) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    if let Some(key) = store.retrieve(account)? {
        return Ok(key);
    }
    derive_key(passphrase, salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_store_round_trip() {
        let mut store = InMemoryKeyStore::new();
        let key = [42u8; 32];

        assert!(store.retrieve("alice").unwrap().is_none());

        store.store("alice", &key).unwrap();
        assert_eq!(store.retrieve("alice").unwrap().map(|k| *k), Some(key));

        assert!(store.delete("alice").unwrap());
        assert!(store.retrieve("alice").unwrap().is_none());
        // Deleting again is a no-op, not an error.
        assert!(!store.delete("alice").unwrap());
    }

    /// Regression (zeroize gap): `KeyStore::retrieve` must hand the vault key
    /// back inside a `Zeroizing` wrapper, never as a bare `[u8; 32]` the
    /// caller has to remember to wipe. This is a compile-time contract — the
    /// explicit type annotation below stops compiling if the trait regresses
    /// to returning a bare array — plus a runtime round-trip through the
    /// wrapper.
    #[test]
    fn retrieve_returns_a_self_wiping_key() {
        let mut store = InMemoryKeyStore::new();
        let key = [7u8; 32];
        store.store("carol", &key).unwrap();

        // Load-bearing type annotation: a bare `Option<[u8; 32]>` here is the
        // regression this test exists to prevent.
        let got: Option<Zeroizing<[u8; 32]>> = store.retrieve("carol").unwrap();
        assert_eq!(got.as_deref(), Some(&key));
    }

    #[test]
    fn unwrap_or_derive_uses_stored_key_when_present() {
        let mut store = InMemoryKeyStore::new();
        let stored_key = [9u8; 32];
        store.store("bob", &stored_key).unwrap();

        // Passphrase/salt are deliberately wrong for what the stored key
        // would derive to — if the fallback fired, this would not match.
        let key = unwrap_or_derive(&store, "bob", b"irrelevant passphrase", b"irrelevant-salt!").unwrap();
        assert_eq!(*key, stored_key);
    }

    #[test]
    fn unwrap_or_derive_falls_back_to_argon2id_when_store_is_empty() {
        let store = InMemoryKeyStore::new();
        let passphrase = b"correct horse battery staple";
        let salt = b"postern-salt-16b";

        let via_fallback = unwrap_or_derive(&store, "nobody", passphrase, salt).unwrap();
        let via_direct = derive_key(passphrase, salt).unwrap();
        assert_eq!(*via_fallback, *via_direct);
    }
}
