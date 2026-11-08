//! Postern Panic — the Panic Lock (a Postern Labs product; the approved form of
//! Deadbolt, see `docs/specs/POSTERN-DEADBOLT.md`).
//!
//! ## What this is — canonical honest description
//!
//! A **denial-of-access re-lock**: one call seals the vault to ciphertext and
//! **evicts the key + decrypted secrets from RAM**. Everything becomes
//! **at-rest ciphertext — unreadable but NOT destroyed.** The legitimate owner
//! reopens later with the key (re-derived from the passphrase or released by
//! the TEE on re-auth).
//!
//! ## What this is NOT (do not market it otherwise)
//!
//! [`PanicSession`] is **not a duress feature and not deniable**:
//!
//! - The locked state is **plainly observable** ([`PanicSession::is_locked`]
//!   returns `true`; the app shows a locked vault). An observer knows data
//!   exists and is locked.
//! - There is **no decoy**: a coercer can simply compel the one real key. A
//!   user who believes "panic" buys them coercion-resistance is endangered by
//!   that belief, not protected.
//! - Any wording like "duress lock", "seal under duress", or "deniable" for
//!   this type is an **overclaim** — the accurate phrase is
//!   **"instant panic re-lock (denial of access)"**.
//!
//! For actual plausible deniability — a decoy passphrase that opens a decoy
//! vault, with the hidden vault's existence computationally unprovable from the
//! stored bytes — see the [`deniable`] module, and read its honest limits
//! before surfacing it in a product.
//!
//! Ethics (the founder's chosen "best format"): the panic re-lock protects a
//! theft victim by **denial of access**, and — because it **destroys nothing** —
//! it **cannot be misused to destroy evidence.** The destructive erase variant
//! is deliberately deferred (see the spec).
//!
//! On a device, `panic()` is the wiring behind the panic gesture; it composes
//! with screen-lock + TEE key eviction. This crate is the verifiable core,
//! reusing `postern-vault`'s AEAD seal.

use postern_vault::{Vault, VaultError};
use zeroize::{Zeroize, Zeroizing};

pub mod deniable;

/// A session that is either unlocked (secrets usable in RAM) or locked (only the
/// sealed ciphertext remains — no key, no plaintext in memory).
///
/// The key is held in a [`Zeroizing`] wrapper (non-`Copy`), so it is wiped on
/// every drop path — explicit [`PanicSession::panic`], state swap, or session
/// teardown — without relying on manual `zeroize` calls at each site.
enum State {
    Unlocked { vault: Vault, key: Zeroizing<[u8; 32]> },
    Locked { sealed: Vec<u8> },
}

/// A vault guarded by a panic re-lock. **Denial of access only — not a duress /
/// deniability mechanism** (see the crate docs; the locked state is observable
/// and there is no decoy).
pub struct PanicSession {
    state: State,
}

impl PanicSession {
    /// Start unlocked with a decrypted vault and its 32-byte key (from the TEE or
    /// an Argon2 passphrase — see `postern_vault::derive_key`). The caller's key
    /// copy is wiped before returning.
    pub fn unlocked(vault: Vault, mut key: [u8; 32]) -> Self {
        let state = State::Unlocked { vault, key: Zeroizing::new(key) };
        key.zeroize();
        Self { state }
    }

    /// Whether the session is currently locked. NOTE: this observability is
    /// exactly why the panic lock is not deniable — anyone holding the device
    /// can see that a locked vault exists.
    pub fn is_locked(&self) -> bool {
        matches!(self.state, State::Locked { .. })
    }

    /// **PANIC.** Instantly re-lock: seal the vault to ciphertext, then wipe the
    /// decrypted secrets and the key from RAM. Nothing is destroyed — only the
    /// at-rest ciphertext remains. Idempotent (a second panic is a no-op). Returns
    /// `Err` (leaving state unchanged) only if sealing itself fails.
    pub fn panic(&mut self) -> Result<(), VaultError> {
        // Seal first — on failure, state is untouched (no data loss).
        let sealed = match &self.state {
            State::Unlocked { vault, key } => vault.seal(key)?,
            State::Locked { .. } => return Ok(()),
        };
        // Swap in the locked state. Dropping the old Unlocked zeroizes both the
        // key (Zeroizing) and the vault's secrets (Vault::drop).
        let old = std::mem::replace(&mut self.state, State::Locked { sealed });
        drop(old);
        Ok(())
    }

    /// Reopen with the key (re-derived from the passphrase / released by the TEE
    /// on re-auth). Wrong key → `Err`, session stays locked. No-op if unlocked.
    /// The caller's key copy is wiped on every path.
    pub fn unlock(&mut self, mut key: [u8; 32]) -> Result<(), VaultError> {
        if let State::Locked { sealed } = &self.state {
            match Vault::open(sealed, &key) {
                Ok(vault) => {
                    self.state = State::Unlocked { vault, key: Zeroizing::new(key) };
                    key.zeroize();
                }
                Err(e) => {
                    key.zeroize();
                    return Err(e);
                }
            }
        } else {
            // Already unlocked: don't leave the caller's key copy lingering.
            key.zeroize();
        }
        Ok(())
    }

    /// Read a secret — only while unlocked (locked → `None`).
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        match &self.state {
            State::Unlocked { vault, .. } => vault.get(name),
            State::Locked { .. } => None,
        }
    }

    /// Store a secret — only while unlocked (returns whether it was stored).
    pub fn put(&mut self, name: &str, secret: &[u8]) -> bool {
        match &mut self.state {
            State::Unlocked { vault, .. } => {
                vault.put(name, secret);
                true
            }
            State::Locked { .. } => false,
        }
    }
}

// No manual `Drop` needed: the key lives in a `Zeroizing<[u8; 32]>` (wiped on
// drop) and `Vault` zeroizes its own secrets — every teardown path is covered.

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded() -> (PanicSession, [u8; 32]) {
        let key = [5u8; 32];
        let mut vault = Vault::new();
        vault.put("seed", b"secret mnemonic");
        (PanicSession::unlocked(vault, key), key)
    }

    #[test]
    fn panic_locks_then_unlock_restores_nothing_destroyed() {
        let (mut s, key) = seeded();
        assert_eq!(s.get("seed"), Some(&b"secret mnemonic"[..]));
        assert!(!s.is_locked());

        s.panic().unwrap();
        assert!(s.is_locked());
        assert_eq!(s.get("seed"), None, "locked → no plaintext in reach");

        // The owner reopens with the key — the data is intact (only locked, never wiped).
        s.unlock(key).unwrap();
        assert_eq!(s.get("seed"), Some(&b"secret mnemonic"[..]));
    }

    #[test]
    fn wrong_key_cannot_unlock() {
        let (mut s, _key) = seeded();
        s.panic().unwrap();
        assert!(s.unlock([9u8; 32]).is_err());
        assert!(s.is_locked(), "still locked after a bad key");
    }

    #[test]
    fn panic_is_idempotent() {
        let (mut s, key) = seeded();
        s.panic().unwrap();
        s.panic().unwrap(); // no-op, no error
        assert!(s.is_locked());
        s.unlock(key).unwrap();
        assert_eq!(s.get("seed"), Some(&b"secret mnemonic"[..]));
    }

    #[test]
    fn cannot_write_while_locked() {
        let (mut s, _key) = seeded();
        s.panic().unwrap();
        assert!(!s.put("x", b"y"), "no writes while locked");
    }
}
