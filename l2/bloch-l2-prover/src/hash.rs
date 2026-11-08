//! Domain-separated SHAKE-256 helpers and a minimal binary Merkle root.
//!
//! The design (`BLOCH-L2-EVM-DESIGN.md` §3) specifies SHAKE-256
//! domain-separated commitments for `BatchPublicValues`, the batch tx list,
//! and the deposit root. These helpers are REAL and tested, but note the
//! Merkle tree here is the *simplified* commitment used by the placeholder
//! STF — the production guest commits Ethereum keccak-256 MPT roots for
//! state, which is `// SCAFFOLD:`-stubbed (see [`crate::sp1_stub`]).

use alloc::vec::Vec;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

/// 32-byte hash output used throughout the crate.
pub type Hash32 = [u8; 32];

/// SHAKE-256 of `domain || data`, squeezed to 32 bytes.
///
/// Domain separation: the domain string is hashed as a length-prefixed
/// (u64 LE) byte string so distinct domains can never collide by
/// concatenation ambiguity.
pub fn shake256_32(domain: &str, data: &[u8]) -> Hash32 {
    let mut hasher = Shake256::default();
    hasher.update(&(domain.len() as u64).to_le_bytes());
    hasher.update(domain.as_bytes());
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize_xof().read(&mut out);
    out
}

/// SHAKE-256 over a list of byte strings, each length-prefixed (u64 LE),
/// with a leading item count (u64 LE). Canonical: equal lists ⇒ equal hash,
/// and no concatenation ambiguity between items.
pub fn shake256_list(domain: &str, items: &[Vec<u8>]) -> Hash32 {
    let mut hasher = Shake256::default();
    hasher.update(&(domain.len() as u64).to_le_bytes());
    hasher.update(domain.as_bytes());
    hasher.update(&(items.len() as u64).to_le_bytes());
    for item in items {
        hasher.update(&(item.len() as u64).to_le_bytes());
        hasher.update(item);
    }
    let mut out = [0u8; 32];
    hasher.finalize_xof().read(&mut out);
    out
}

/// Domain for interior Merkle nodes.
const MERKLE_NODE_DOMAIN: &str = "bloch-l2/merkle-node/v0";

/// Simple binary SHAKE-256 Merkle root over pre-hashed 32-byte leaves.
///
/// Rules (documented so any re-implementation matches byte-for-byte):
/// * empty list ⇒ `[0u8; 32]`;
/// * an unpaired node at the end of a level is promoted UNCHANGED (no
///   duplication, so a single leaf's root is the leaf itself);
/// * interior node = SHAKE-256(domain ‖ left ‖ right).
///
/// This is the *simplified* deposit/withdrawal commitment for the placeholder
/// pipeline; it is NOT the production SMT/MPT from the design.
pub fn merkle_root(leaves: &[Hash32]) -> Hash32 {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<Hash32> = leaves.to_vec();
    while level.len() > 1 {
        let mut next: Vec<Hash32> = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            if pair.len() == 2 {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&pair[0]);
                buf[32..].copy_from_slice(&pair[1]);
                next.push(shake256_32(MERKLE_NODE_DOMAIN, &buf));
            } else {
                // Unpaired node promoted unchanged.
                next.push(pair[0]);
            }
        }
        level = next;
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn shake_is_deterministic_and_domain_separated() {
        let a = shake256_32("d1", b"payload");
        let b = shake256_32("d1", b"payload");
        let c = shake256_32("d2", b"payload");
        assert_eq!(a, b);
        assert_ne!(a, c);
        // Length-prefixed domain: ("ab", "c...") never equals ("a", "bc...").
        let d = shake256_32("ab", b"c");
        let e = shake256_32("a", b"bc");
        assert_ne!(d, e);
    }

    #[test]
    fn list_hash_has_no_concat_ambiguity() {
        let one = shake256_list("d", &[vec![1, 2], vec![3]]);
        let two = shake256_list("d", &[vec![1], vec![2, 3]]);
        let three = shake256_list("d", &[vec![1, 2, 3]]);
        assert_ne!(one, two);
        assert_ne!(one, three);
        assert_ne!(two, three);
    }

    #[test]
    fn merkle_root_rules() {
        assert_eq!(merkle_root(&[]), [0u8; 32]);
        let leaf = shake256_32("leaf", b"x");
        // Single leaf: root == leaf (unpaired promotion).
        assert_eq!(merkle_root(&[leaf]), leaf);
        let l2 = shake256_32("leaf", b"y");
        let root2 = merkle_root(&[leaf, l2]);
        assert_ne!(root2, leaf);
        // Order matters.
        assert_ne!(merkle_root(&[l2, leaf]), root2);
        // Three leaves: third promoted, then paired.
        let l3 = shake256_32("leaf", b"z");
        let root3 = merkle_root(&[leaf, l2, l3]);
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&root2);
        buf[32..].copy_from_slice(&l3);
        assert_eq!(root3, shake256_32(MERKLE_NODE_DOMAIN, &buf));
    }
}
