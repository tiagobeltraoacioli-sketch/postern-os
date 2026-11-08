//! macOS login-Keychain-backed [`crate::keychain::KeyStore`] (`keychain-macos`
//! cargo feature, off by default, only compiled `#[cfg(target_os = "macos")]`).
//!
//! [`MacKeyStore`] stores the vault's 32-byte key as a **generic-password**
//! Keychain item — service `"com.posternlabs.vault"`, account = the
//! caller-supplied name — via the [`security-framework`](security_framework)
//! crate (MIT OR Apache-2.0; already transitively present in this workspace's
//! `Cargo.lock`, no GPL/AGPL). Reads/writes go to whatever keychain
//! `SecItemAdd`/`SecItemCopyMatching`/`SecItemDelete` resolve to for the
//! current process — ordinarily the user's **login keychain**.
//!
//! ## NOT a TEE
//!
//! Same disclosure as `keychain.rs`: the macOS Keychain is a **software**
//! credential store gated on the login session, not the Secure Enclave. A
//! generic-password item is not hardware-wrapped by this code — it is
//! encrypted by the Keychain's own at-rest database encryption and released
//! to any process running as the user (subject to the item's ACL, which this
//! module does not customize beyond the default). Wiring an actual
//! Secure-Enclave wrap is a separate, unimplemented future integration.
//!
//! ## Why the round-trip test is `#[ignore]`d
//!
//! `SecItemAdd`/`SecItemCopyMatching` against the login keychain can prompt
//! the user for keychain-unlock consent, and unconditionally fail in a
//! headless / non-interactive session (CI runners, `ssh` without a logged-in
//! GUI session, a locked login keychain). The round-trip test below is
//! **real** — it exercises the actual Keychain APIs — but it is honestly
//! `#[ignore]`d rather than pretending to be CI-safe. Run it manually with
//! `cargo test -p postern-vault --features keychain-macos -- --ignored`
//! from an interactive session with the login keychain unlocked.

use crate::keychain::KeyStore;
use crate::VaultError;
use security_framework::base::Error as SfError;
use security_framework::passwords::{delete_generic_password, get_generic_password, set_generic_password};
use zeroize::{Zeroize, Zeroizing};

/// The Keychain service name under which every vault key is stored,
/// regardless of account. Matches the crate-level `"com.posternlabs.vault"`
/// namespace convention.
const SERVICE: &str = "com.posternlabs.vault";

/// macOS Security.framework `errSecItemNotFound` — returned by
/// `SecItemCopyMatching`/`SecItemDelete` when no matching item exists. Not
/// exposed as a named constant by the `security-framework` crate at this
/// version, so it is checked by its stable numeric `OSStatus` value (Apple's
/// `<Security/SecBase.h>`).
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

/// A [`KeyStore`] backed by the macOS login Keychain. See the module docs for
/// the "NOT a TEE" disclosure and the honest reason the round-trip test is
/// `#[ignore]`d.
#[derive(Default)]
pub struct MacKeyStore;

impl MacKeyStore {
    /// A fresh handle. `MacKeyStore` holds no state of its own — every call
    /// goes straight to the OS Keychain APIs.
    pub fn new() -> Self {
        Self
    }
}

fn is_not_found(e: &SfError) -> bool {
    e.code() == ERR_SEC_ITEM_NOT_FOUND
}

impl KeyStore for MacKeyStore {
    fn store(&mut self, account: &str, key: &[u8; 32]) -> Result<(), VaultError> {
        // `set_generic_password` creates-or-updates, so a prior key under the
        // same account is atomically replaced rather than duplicated.
        set_generic_password(SERVICE, account, key)
            .map_err(|e| VaultError::KeyStore(format!("keychain store failed: {e}")))
    }

    fn retrieve(&self, account: &str) -> Result<Option<Zeroizing<[u8; 32]>>, VaultError> {
        match get_generic_password(SERVICE, account) {
            Ok(mut bytes) => {
                let result = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                    VaultError::KeyStore(format!(
                        "keychain entry for {account:?} is not a 32-byte key ({} bytes)",
                        bytes.len()
                    ))
                });
                bytes.zeroize(); // wipe the intermediate Vec regardless of outcome
                result.map(|key| Some(Zeroizing::new(key)))
            }
            Err(e) if is_not_found(&e) => Ok(None),
            Err(e) => Err(VaultError::KeyStore(format!("keychain retrieve failed: {e}"))),
        }
    }

    fn delete(&mut self, account: &str) -> Result<bool, VaultError> {
        match delete_generic_password(SERVICE, account) {
            Ok(()) => Ok(true),
            Err(e) if is_not_found(&e) => Ok(false),
            Err(e) => Err(VaultError::KeyStore(format!("keychain delete failed: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exercises the real macOS login Keychain: store → retrieve → delete →
    /// retrieve-again for a throwaway account. **Not run in headless CI** —
    /// `SecItemAdd`/`SecItemCopyMatching` can prompt for keychain-unlock
    /// consent and unconditionally fail without an unlocked, interactive
    /// login session. Run manually:
    /// `cargo test -p postern-vault --features keychain-macos -- --ignored`
    #[test]
    #[ignore = "needs a real, unlocked, interactive macOS login keychain — not available in headless CI"]
    fn live_keychain_round_trip() {
        let account = "postern-vault-test-live-round-trip";
        let mut store = MacKeyStore::new();
        let key = [0x5Au8; 32];

        // Clean slate in case a previous run left an entry behind.
        let _ = store.delete(account);
        assert!(store.retrieve(account).unwrap().is_none());

        store.store(account, &key).unwrap();
        assert_eq!(store.retrieve(account).unwrap().map(|k| *k), Some(key));

        // Replacing an existing entry must not error or duplicate.
        let key2 = [0xA5u8; 32];
        store.store(account, &key2).unwrap();
        assert_eq!(store.retrieve(account).unwrap().map(|k| *k), Some(key2));

        assert!(store.delete(account).unwrap());
        assert!(store.retrieve(account).unwrap().is_none());
        // Deleting again is a no-op, not an error.
        assert!(!store.delete(account).unwrap());
    }

    /// Full **vault-level** round-trip against the real login Keychain, the way
    /// the desktop's `vault_keychain_enable` → lock → `vault_unlock_keychain` →
    /// `vault_keychain_forget` commands drive `MacKeyStore`: seal a real
    /// [`crate::Vault`] holding a secret under a random key, enroll that key in
    /// the Keychain (enable), drop everything in RAM (lock), re-fetch the key
    /// from the Keychain and re-open the sealed vault with NO passphrase
    /// (unlock), assert the secret survived byte-for-byte, then delete the key
    /// (forget) and confirm the passphrase-less path is fail-closed afterwards.
    ///
    /// Same honesty caveat as the module docs — the Keychain is a **software**
    /// credential store, **not** a TEE. And same `#[ignore]` reason as
    /// `live_keychain_round_trip`: it hits the real login Keychain, so it needs
    /// an unlocked, interactive session. Run manually:
    /// `cargo test -p postern-vault --features vault-keychain -- --ignored`
    #[test]
    #[ignore = "needs a real, unlocked, interactive macOS login keychain — not available in headless CI"]
    fn live_vault_enable_lock_unlock_forget_round_trip() {
        use crate::Vault;

        let account = "postern-vault-test-live-vault-round-trip";
        let mut store = MacKeyStore::new();

        // A random per-run 32-byte key (two fresh 16-byte salts concatenated)
        // so a crashed prior run can't shadow this one, and a real secret
        // sealed under it.
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(&crate::generate_salt());
        key[16..].copy_from_slice(&crate::generate_salt());
        let secret = b"alice@example.com totp/DEADBEEF";

        let mut vault = Vault::new();
        vault.put("email", secret);
        let sealed = vault.seal(&key).unwrap();

        // Clean slate.
        let _ = store.delete(account);

        // ── enable: enroll the live vault key in the OS Keychain ──
        store.store(account, &key).unwrap();

        // ── lock: evict the key + decrypted vault from RAM (only ciphertext
        //    and the Keychain-held key remain). ──
        drop(vault);
        // Prove we are not secretly relying on the in-RAM key below.
        let mut zeroed = key;
        zeroed.zeroize();

        // ── unlock via Keychain (no passphrase): re-fetch the key, re-open. ──
        let fetched = store
            .retrieve(account)
            .unwrap()
            .expect("the enrolled key must be retrievable from the login Keychain");
        let reopened = Vault::open(&sealed, &fetched).expect("keychain key must open the sealed vault");
        assert_eq!(
            reopened.get("email"),
            Some(&secret[..]),
            "the secret must survive the seal → Keychain → open round-trip byte-for-byte"
        );

        // ── forget: delete the enrolled key; the passphrase-less path is now
        //    fail-closed (retrieve returns None), and forget is idempotent. ──
        assert!(store.delete(account).unwrap(), "the key was enrolled");
        assert!(
            store.retrieve(account).unwrap().is_none(),
            "after forget, no key may remain — the passphrase-less unlock must fail closed"
        );
        assert!(!store.delete(account).unwrap(), "forget is idempotent");
    }
}
