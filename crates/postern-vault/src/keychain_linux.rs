//! Linux freedesktop Secret Service (D-Bus)-backed [`KeyStore`]
//! (`keychain-linux` cargo feature, off by default; requires the `keychain`
//! feature too — see `keychain.rs`).
//!
//! Backed by the [`secret-service`](https://docs.rs/secret-service) crate
//! (MIT OR Apache-2.0 — permissive, no GPL/AGPL), which speaks the
//! freedesktop [Secret Service D-Bus
//! API](https://specifications.freedesktop.org/secret-service/latest/)
//! directly (pure-Rust `zbus` transport, no `libdbus` system dev headers
//! needed) against whatever provider owns the session bus name
//! `org.freedesktop.secrets` — typically `gnome-keyring` or KeePassXC's
//! Secret Service integration.
//!
//! ## NOT a TEE
//!
//! Same caveat as the crate-level disclosure in `keychain.rs`: the Secret
//! Service is a **software** credential store gated on the login session,
//! not hardware isolation. See `keychain.rs`'s module docs for the full
//! disclosure — it applies verbatim here.
//!
//! ## VERIFIED: live D-Bus store→retrieve→delete round-trip (still NOT a TEE)
//!
//! This module was authored on macOS (Darwin), which has no D-Bus session bus
//! and no Secret Service provider, so the round-trip test
//! [`tests::live_secret_service_round_trip`] stays `#[ignore]`d by default (a
//! bare Linux build host without a running `gnome-keyring`/KeePassXC would
//! still fail it). It has now been **run for real** against a live
//! `gnome-keyring` daemon inside a throwaway Linux container, exercising a true
//! store → retrieve → delete → retrieve → delete round-trip over the session
//! D-Bus. Transcribed live result (2026-07-18):
//!
//! ```text
//! === HOST INFO ===
//! Linux 6.12.76-linuxkit #1 SMP x86_64 GNU/Linux
//! PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
//! === SECRET SERVICE PROVIDER ===
//! gnome-keyring-daemon: 42.1
//! === bus names ===
//!       string "org.freedesktop.secrets"   # provider owns the well-known name
//! === RUNNING IGNORED TEST ===
//! running 1 test
//! test keychain_linux::tests::live_secret_service_round_trip ... ok
//! test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 29 filtered out
//! ```
//!
//! Reproduce on any Linux desktop session (or container) with a D-Bus session
//! bus and a Secret Service provider running:
//!
//! ```text
//! cargo test -p postern-vault --features keychain-linux -- --ignored keychain_linux::tests::live_secret_service_round_trip
//! ```
//!
//! **Honest scope of this evidence:** the round-trip proves the D-Bus wire
//! path, item attributes, secret encoding, and delete semantics work against a
//! real freedesktop Secret Service. It says **nothing** about hardware
//! isolation — the Secret Service (`gnome-keyring`/KeePassXC) is a **software**
//! credential store gated on the login session, so the **OS keychain is NOT a
//! TEE**, exactly as the disclosure above states.

use crate::keychain::KeyStore;
use crate::VaultError;
use secret_service::blocking::SecretService;
use secret_service::EncryptionType;
use std::collections::HashMap;
use zeroize::{Zeroize, Zeroizing};

/// Item attribute distinguishing postern-vault's items from every other
/// app's items in the shared default collection.
const SERVICE_ATTR: &str = "service";
const SERVICE_VALUE: &str = "com.posternlabs.vault";
/// Item attribute holding the caller-supplied account name — this is the key
/// `KeyStore::store`/`retrieve`/`delete` index by.
const ACCOUNT_ATTR: &str = "account";

/// **NOT a TEE** — see the module docs above. A freedesktop Secret Service
/// (D-Bus)-backed [`KeyStore`]: stores the wrapped 32-byte vault key as a
/// collection item in the user's default Secret Service collection, keyed by
/// `account` (plus a fixed `service` attribute so postern-vault's items are
/// distinguishable from every other app's items sharing that collection).
pub struct SecretServiceKeyStore {
    service: SecretService<'static>,
}

impl SecretServiceKeyStore {
    /// Connect to the session D-Bus and negotiate a Secret Service session
    /// (Diffie-Hellman-encrypted transport, matching the crate's `Dh`
    /// [`EncryptionType`]). Fails if there is no D-Bus session bus, or no
    /// Secret Service provider (`gnome-keyring`, KeePassXC, `kwallet`, …) is
    /// running to own `org.freedesktop.secrets`.
    pub fn new() -> Result<Self, VaultError> {
        let service = SecretService::connect(EncryptionType::Dh)
            .map_err(|e| VaultError::KeyStore(format!("secret service connect failed: {e}")))?;
        Ok(Self { service })
    }

    fn attributes(account: &str) -> HashMap<&str, &str> {
        HashMap::from([(SERVICE_ATTR, SERVICE_VALUE), (ACCOUNT_ATTR, account)])
    }
}

impl KeyStore for SecretServiceKeyStore {
    fn store(&mut self, account: &str, key: &[u8; 32]) -> Result<(), VaultError> {
        let collection = self
            .service
            .get_default_collection()
            .map_err(|e| VaultError::KeyStore(format!("get default collection failed: {e}")))?;
        collection
            .create_item(
                "Postern Vault key",
                Self::attributes(account),
                key,
                true, // replace: an existing item with the same attributes is overwritten
                "application/octet-stream",
            )
            .map_err(|e| VaultError::KeyStore(format!("create item failed: {e}")))?;
        Ok(())
    }

    fn retrieve(&self, account: &str) -> Result<Option<Zeroizing<[u8; 32]>>, VaultError> {
        let found = self
            .service
            .search_items(Self::attributes(account))
            .map_err(|e| VaultError::KeyStore(format!("search items failed: {e}")))?;
        let item = match found.unlocked.first().or_else(|| found.locked.first()) {
            Some(item) => item,
            None => return Ok(None),
        };
        if item
            .is_locked()
            .map_err(|e| VaultError::KeyStore(format!("is_locked failed: {e}")))?
        {
            item.unlock()
                .map_err(|e| VaultError::KeyStore(format!("unlock failed: {e}")))?;
        }
        let mut secret = item
            .get_secret()
            .map_err(|e| VaultError::KeyStore(format!("get secret failed: {e}")))?;
        let key: Result<[u8; 32], _> = secret.as_slice().try_into();
        secret.zeroize(); // wipe the intermediate Vec regardless of outcome
        let key = key.map_err(|_| {
            VaultError::KeyStore(format!(
                "stored secret for account {account:?} is not 32 bytes"
            ))
        })?;
        Ok(Some(Zeroizing::new(key)))
    }

    fn delete(&mut self, account: &str) -> Result<bool, VaultError> {
        let found = self
            .service
            .search_items(Self::attributes(account))
            .map_err(|e| VaultError::KeyStore(format!("search items failed: {e}")))?;
        let mut deleted = false;
        for item in found.unlocked.iter().chain(found.locked.iter()) {
            item.delete()
                .map_err(|e| VaultError::KeyStore(format!("delete item failed: {e}")))?;
            deleted = true;
        }
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **VERIFIED live — see the module-level "VERIFIED" doc above for the
    /// transcribed pass.** Still `#[ignore]`d by default because it needs an
    /// external, running Secret Service provider: it can't run on the macOS dev
    /// host (no D-Bus), and would fail on a bare Linux build host with no
    /// `gnome-keyring`/KeePassXC owning `org.freedesktop.secrets`.
    ///
    /// Exercises a real store → retrieve → delete → retrieve → delete round
    /// trip against a live freedesktop Secret Service. Requires a Linux session
    /// with a D-Bus session bus and a Secret Service provider (`gnome-keyring`,
    /// KeePassXC, …) running. Confirmed passing against `gnome-keyring` 42.1 on
    /// Debian 12 (bookworm) on 2026-07-18. Run explicitly with:
    ///
    /// ```text
    /// cargo test -p postern-vault --features keychain-linux -- --ignored keychain_linux::tests::live_secret_service_round_trip
    /// ```
    #[test]
    #[ignore = "needs a live Secret Service provider (gnome-keyring/KeePassXC) owning org.freedesktop.secrets — VERIFIED passing on Debian 12 / gnome-keyring 42.1 (2026-07-18); still ignored by default as no such daemon runs on the macOS dev host or a bare build host"]
    fn live_secret_service_round_trip() {
        let account = "postern-vault-test-account";
        let key = [7u8; 32];

        let mut store = SecretServiceKeyStore::new().expect("connect to Secret Service");

        store.store(account, &key).expect("store key");
        assert_eq!(store.retrieve(account).unwrap().map(|k| *k), Some(key), "round-trip must return the stored key");

        assert!(store.delete(account).unwrap(), "delete must report an existing entry was removed");
        assert!(store.retrieve(account).unwrap().is_none(), "key must be gone after delete");
        assert!(!store.delete(account).unwrap(), "deleting again is a no-op, not an error");
    }
}
