//! Plausible-deniability container — a hidden-volume-style **dual-slot vault**.
//!
//! ## The mechanism
//!
//! Every container is exactly [`CONTAINER_LEN`] bytes: **two fixed-size slots**.
//! A slot is either a sealed vault (the whole slot is one context-bound,
//! key-committing AEAD ciphertext over a fixed-size padded plaintext) or pure
//! filler (a `0x02` version byte — matching the seal's wire format — followed
//! by uniform random bytes). Because XChaCha20-Poly1305 output is
//! computationally indistinguishable from random without the key:
//!
//! - A container holding **one** vault ([`seal_single`]) and a container
//!   holding a **real + decoy pair** ([`seal_with_decoy`]) are byte-for-byte
//!   indistinguishable to anyone who holds *no* key or only the **decoy** key.
//! - Under coercion the user reveals the decoy passphrase; [`open`] yields the
//!   decoy vault. Whether a second (hidden) vault exists **cannot be proven or
//!   disproven from the stored bytes** — that is the deniability.
//! - Slot order is random at seal time, and [`open`] always attempts both
//!   slots, so which slot "is" the decoy is not encoded anywhere.
//!
//! This is the mature hidden-volume construction (VeraCrypt-style), rebuilt on
//! the Postern seal (XChaCha20-Poly1305, HKDF key commitment, context-bound
//! with a `postern-panic/deniable/v1` domain).
//!
//! ## HONEST LIMITS — read before surfacing this in a product
//!
//! Deniability holds for **the container bytes, in a single snapshot**. It does
//! NOT hold against:
//!
//! - **Multi-snapshot observers.** An adversary comparing two versions of the
//!   container over time sees *which slot's bytes changed*. Updating the hidden
//!   vault while an adversary can diff snapshots (cloud backups!) breaks
//!   deniability. (Identical caveat to VeraCrypt hidden volumes.)
//! - **Environment leaks.** File timestamps, sync/backup logs, app UI state,
//!   OS telemetry, or shoulder-surfing can reveal use of a hidden vault. This
//!   module guarantees only the bytes it returns.
//! - **Coercion itself.** An adversary may demand "the other key" regardless of
//!   proof, and may not accept that none exists. Deniability changes what can
//!   be *proven*, not what a violent adversary may *do*. Ship this only with
//!   informed-consent UX (see `docs/specs/POSTERN-DEADBOLT.md`).
//! - **Data-loss trade-off (by design):** someone holding only the decoy key
//!   who re-seals with [`seal_single`] regenerates the other slot as filler —
//!   **destroying the hidden vault**. That property is required (a decoy-key
//!   holder must not be able to detect, and therefore must be able to clobber,
//!   the hidden slot). Use [`reseal`] to update one vault while leaving the
//!   other slot's bytes untouched (which is exactly the multi-snapshot leak
//!   above — the trade-off is fundamental, choose per threat model).
//!
//! Keys for the real and decoy vaults MUST be independent (different
//! passphrases and different Argon2 salts via `postern_vault::derive_key`);
//! [`seal_with_decoy`] rejects identical keys.

use postern_vault::{Vault, VaultError};
use zeroize::Zeroizing;

/// Domain-separation context for the slot seal (also bound into the AEAD AD).
const SLOT_CONTEXT: &[u8] = b"postern-panic/deniable/v1";

/// Total size of one slot on disk (one AEAD seal of a fixed-size plaintext).
pub const SLOT_LEN: usize = 64 * 1024;
/// A container is always exactly two slots, whether or not a hidden vault exists.
pub const CONTAINER_LEN: usize = 2 * SLOT_LEN;
/// Postern seal v2 overhead: version ‖ nonce ‖ commit ‖ … ‖ tag.
const SEAL_OVERHEAD: usize = 1
    + postern_core::aead::NONCE_LEN
    + postern_core::aead::COMMIT_LEN
    + postern_core::aead::TAG_LEN;
/// Fixed plaintext size inside a slot: 4-byte length prefix ‖ sealed vault ‖ pad.
const SLOT_PLAIN_LEN: usize = SLOT_LEN - SEAL_OVERHEAD;
/// Maximum size of a sealed vault that fits in a slot. `Vault::seal` output is
/// its serialized entries + seal overhead, so usable secret capacity is a few
/// hundred bytes less — plenty for keys/passwords, not a file store.
pub const SLOT_CAPACITY: usize = SLOT_PLAIN_LEN - 4;

#[derive(Debug, thiserror::Error)]
pub enum DeniableError {
    #[error("sealed vault is {0} bytes — exceeds the fixed slot capacity of {SLOT_CAPACITY} bytes")]
    TooLarge(usize),
    #[error("container must be exactly {CONTAINER_LEN} bytes")]
    BadContainer,
    #[error("real and decoy keys must be independent (got identical keys)")]
    KeysEqual,
    #[error("no slot opened with this key — wrong key or corrupt container")]
    Open,
    #[error("system randomness unavailable")]
    Rng,
    #[error(transparent)]
    Vault(#[from] VaultError),
}

fn random_bytes(buf: &mut [u8]) -> Result<(), DeniableError> {
    getrandom::getrandom(buf).map_err(|_| DeniableError::Rng)
}

/// Seal one vault into one fixed-size slot: `len ‖ sealed-vault ‖ zero-pad`,
/// all inside one context-bound AEAD seal (so the length and padding are
/// encrypted — a slot leaks nothing about the vault's size).
fn encode_slot(vault: &Vault, key: &[u8; 32]) -> Result<Vec<u8>, DeniableError> {
    let sealed = vault.seal(key)?;
    if sealed.len() > SLOT_CAPACITY {
        return Err(DeniableError::TooLarge(sealed.len()));
    }
    let mut plain = Zeroizing::new(vec![0u8; SLOT_PLAIN_LEN]);
    plain[..4].copy_from_slice(&(sealed.len() as u32).to_le_bytes());
    plain[4..4 + sealed.len()].copy_from_slice(&sealed);
    let slot = postern_core::aead::seal_with_context(key, SLOT_CONTEXT, &plain)
        .map_err(|_| DeniableError::Vault(VaultError::Seal))?;
    debug_assert_eq!(slot.len(), SLOT_LEN);
    Ok(slot)
}

/// Try to open one slot with `key`. `None` on any failure — a wrong key, a
/// filler slot, and a corrupt slot are deliberately indistinguishable.
fn decode_slot(slot: &[u8], key: &[u8; 32]) -> Option<Vault> {
    let plain = Zeroizing::new(
        postern_core::aead::open_with_context(key, SLOT_CONTEXT, slot).ok()?,
    );
    if plain.len() != SLOT_PLAIN_LEN {
        return None;
    }
    let n = u32::from_le_bytes(plain[..4].try_into().ok()?) as usize;
    if n > SLOT_CAPACITY {
        return None;
    }
    Vault::open(&plain[4..4 + n], key).ok()
}

/// A filler slot: the seal's `0x02` version byte followed by uniform random
/// bytes — indistinguishable from a real slot (whose nonce, key-commitment and
/// ciphertext are all pseudorandom) without the key.
fn filler_slot() -> Result<Vec<u8>, DeniableError> {
    let mut slot = vec![0u8; SLOT_LEN];
    random_bytes(&mut slot)?;
    slot[0] = postern_core::aead::VERSION_V2;
    Ok(slot)
}

/// Concatenate two slots in random order (the container encodes no notion of
/// "first = real").
fn assemble(a: Vec<u8>, b: Vec<u8>) -> Result<Vec<u8>, DeniableError> {
    let mut coin = [0u8; 1];
    random_bytes(&mut coin)?;
    let (first, second) = if coin[0] & 1 == 0 { (a, b) } else { (b, a) };
    let mut out = first;
    out.extend_from_slice(&second);
    Ok(out)
}

/// Seal a **real vault + decoy vault** into one container. Under coercion, the
/// user reveals the decoy key; [`open`] with it yields the decoy vault, and the
/// bytes cannot prove a second vault exists. Keys must be independent.
pub fn seal_with_decoy(
    real: &Vault,
    real_key: &[u8; 32],
    decoy: &Vault,
    decoy_key: &[u8; 32],
) -> Result<Vec<u8>, DeniableError> {
    if real_key == decoy_key {
        return Err(DeniableError::KeysEqual);
    }
    let a = encode_slot(real, real_key)?;
    let b = encode_slot(decoy, decoy_key)?;
    assemble(a, b)
}

/// Seal a **single vault** into a container whose other slot is random filler.
/// Every user gets the same two-slot shape, so *possessing* a container never
/// implies a hidden vault exists — that is what makes [`seal_with_decoy`]
/// containers deniable. WARNING: calling this on a container that previously
/// held a hidden vault discards that vault (see the module docs).
pub fn seal_single(vault: &Vault, key: &[u8; 32]) -> Result<Vec<u8>, DeniableError> {
    let a = encode_slot(vault, key)?;
    let b = filler_slot()?;
    assemble(a, b)
}

/// Open whichever vault `key` unlocks. Both slots are always attempted
/// (uniform work regardless of which slot matches). A wrong key and a
/// nonexistent hidden vault fail identically.
pub fn open(container: &[u8], key: &[u8; 32]) -> Result<Vault, DeniableError> {
    if container.len() != CONTAINER_LEN {
        return Err(DeniableError::BadContainer);
    }
    let v0 = decode_slot(&container[..SLOT_LEN], key);
    let v1 = decode_slot(&container[SLOT_LEN..], key);
    v0.or(v1).ok_or(DeniableError::Open)
}

/// Re-seal an updated `vault` into the slot that `key` currently opens, leaving
/// the **other slot's bytes untouched** (so the other vault — hidden or decoy —
/// survives without needing its key). NOTE the fundamental trade-off: an
/// adversary diffing container versions sees which slot changed (module docs).
pub fn reseal(container: &[u8], key: &[u8; 32], vault: &Vault) -> Result<Vec<u8>, DeniableError> {
    if container.len() != CONTAINER_LEN {
        return Err(DeniableError::BadContainer);
    }
    let (s0, s1) = container.split_at(SLOT_LEN);
    let in_first = decode_slot(s0, key).is_some();
    let in_second = decode_slot(s1, key).is_some();
    if !in_first && !in_second {
        return Err(DeniableError::Open);
    }
    let fresh = encode_slot(vault, key)?;
    let mut out = Vec::with_capacity(CONTAINER_LEN);
    if in_first {
        out.extend_from_slice(&fresh);
        out.extend_from_slice(s1);
    } else {
        out.extend_from_slice(s0);
        out.extend_from_slice(&fresh);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault_with(name: &str, secret: &[u8]) -> Vault {
        let mut v = Vault::new();
        v.put(name, secret);
        v
    }

    const REAL_KEY: [u8; 32] = [1u8; 32];
    const DECOY_KEY: [u8; 32] = [2u8; 32];

    #[test]
    fn real_and_decoy_keys_open_their_own_vaults() {
        let real = vault_with("seed", b"the real mnemonic");
        let decoy = vault_with("seed", b"harmless decoy data");
        let c = seal_with_decoy(&real, &REAL_KEY, &decoy, &DECOY_KEY).unwrap();
        assert_eq!(c.len(), CONTAINER_LEN);

        let opened_real = open(&c, &REAL_KEY).unwrap();
        assert_eq!(opened_real.get("seed"), Some(&b"the real mnemonic"[..]));
        let opened_decoy = open(&c, &DECOY_KEY).unwrap();
        assert_eq!(opened_decoy.get("seed"), Some(&b"harmless decoy data"[..]));
    }

    #[test]
    fn wrong_key_fails_uniformly() {
        let real = vault_with("k", b"v");
        let decoy = vault_with("k", b"d");
        let c = seal_with_decoy(&real, &REAL_KEY, &decoy, &DECOY_KEY).unwrap();
        assert!(matches!(open(&c, &[9u8; 32]), Err(DeniableError::Open)));
        // A single-vault container fails the same way with a wrong key.
        let s = seal_single(&real, &REAL_KEY).unwrap();
        assert!(matches!(open(&s, &[9u8; 32]), Err(DeniableError::Open)));
    }

    #[test]
    fn single_and_dual_containers_share_size_and_shape() {
        // The core deniability invariant this module controls: with or without
        // a hidden vault, a container is the same size, and no plaintext of
        // either vault appears in the bytes.
        let real = vault_with("seed", b"the real mnemonic");
        let decoy = vault_with("note", b"grocery list");
        let dual = seal_with_decoy(&real, &REAL_KEY, &decoy, &DECOY_KEY).unwrap();
        let single = seal_single(&decoy, &DECOY_KEY).unwrap();
        assert_eq!(dual.len(), single.len());
        for blob in [&dual, &single] {
            assert!(!blob.windows(17).any(|w| w == b"the real mnemonic"));
            assert!(!blob.windows(12).any(|w| w == b"grocery list"));
        }
        // The decoy key yields the identical decoy view in both containers —
        // it cannot tell whether a hidden vault rides in the other slot.
        assert_eq!(open(&dual, &DECOY_KEY).unwrap().get("note"), Some(&b"grocery list"[..]));
        assert_eq!(open(&single, &DECOY_KEY).unwrap().get("note"), Some(&b"grocery list"[..]));
    }

    #[test]
    fn identical_keys_are_rejected() {
        let real = vault_with("a", b"1");
        let decoy = vault_with("b", b"2");
        assert!(matches!(
            seal_with_decoy(&real, &REAL_KEY, &decoy, &REAL_KEY),
            Err(DeniableError::KeysEqual)
        ));
    }

    #[test]
    fn oversized_vault_is_rejected() {
        let mut big = Vault::new();
        big.put("blob", &vec![0u8; SLOT_CAPACITY]); // sealed size > capacity
        assert!(matches!(
            seal_single(&big, &REAL_KEY),
            Err(DeniableError::TooLarge(_))
        ));
    }

    #[test]
    fn reseal_updates_one_slot_and_preserves_the_other() {
        let real = vault_with("seed", b"v1 real");
        let decoy = vault_with("note", b"decoy");
        let c1 = seal_with_decoy(&real, &REAL_KEY, &decoy, &DECOY_KEY).unwrap();

        // The DECOY-key holder updates their vault without the real key…
        let decoy2 = vault_with("note", b"decoy v2");
        let c2 = reseal(&c1, &DECOY_KEY, &decoy2).unwrap();
        assert_eq!(open(&c2, &DECOY_KEY).unwrap().get("note"), Some(&b"decoy v2"[..]));
        // …and the hidden vault survives untouched.
        assert_eq!(open(&c2, &REAL_KEY).unwrap().get("seed"), Some(&b"v1 real"[..]));
        // Exactly one slot's bytes changed (this is also the documented
        // multi-snapshot leak — asserted here so the property stays understood).
        let changed_first = c1[..SLOT_LEN] != c2[..SLOT_LEN];
        let changed_second = c1[SLOT_LEN..] != c2[SLOT_LEN..];
        assert!(changed_first ^ changed_second);

        // A wrong key cannot reseal.
        assert!(matches!(reseal(&c1, &[9u8; 32], &decoy2), Err(DeniableError::Open)));
    }

    #[test]
    fn seal_single_over_a_dual_container_destroys_the_hidden_vault() {
        // Documented, deliberate property: a decoy-key holder re-sealing with
        // seal_single (rather than reseal) regenerates filler — the hidden
        // vault is gone. This is what makes the hidden slot undetectable.
        let real = vault_with("seed", b"real");
        let decoy = vault_with("note", b"decoy");
        let _c1 = seal_with_decoy(&real, &REAL_KEY, &decoy, &DECOY_KEY).unwrap();
        let c2 = seal_single(&decoy, &DECOY_KEY).unwrap();
        assert!(open(&c2, &DECOY_KEY).is_ok());
        assert!(matches!(open(&c2, &REAL_KEY), Err(DeniableError::Open)));
    }

    #[test]
    fn bad_container_length_is_rejected() {
        assert!(matches!(open(&[0u8; 7], &REAL_KEY), Err(DeniableError::BadContainer)));
        let real = vault_with("a", b"1");
        assert!(matches!(
            reseal(&[0u8; CONTAINER_LEN - 1], &REAL_KEY, &real),
            Err(DeniableError::BadContainer)
        ));
    }
}
