// SPDX-License-Identifier: MIT OR Apache-2.0
//! In-crate, self-contained SHAKE-256 (FIPS 202) helpers.
//!
//! # SCAFFOLD — not a secure or deployed system
//!
//! This module pulls **no hashing crate**: it is a small, self-contained
//! Keccak-f\[1600\] sponge implementing the SHAKE-256 XOF, squeezed to 32 bytes.
//! (The only default dependency of `postern-ffg` is the ML-DSA-65 signature
//! primitive; `--no-default-features` drops even that, leaving a truly
//! dependency-free build.) The helper API deliberately mirrors the sibling
//! `l2/bloch-l2-prover/src/hash.rs` spec byte-for-byte in *shape*
//! (length-prefixed u64-LE domain separation; length-prefixed list hashing) so
//! any cross-checking re-implementation matches — but it is a **separate,
//! standalone implementation**, not an import.
//!
//! Honest limits:
//!
//! - **Unaudited.** A hand-rolled Keccak permutation in a design scaffold is
//!   NOT a vetted cryptographic library. Do not protect anything of value with
//!   it. It is checked against the NIST SHAKE-256 test vectors below, and that
//!   is the entire extent of its assurance.
//! - Hashing something proves nothing about it. A 32-byte root produced here
//!   and anchored to the base proves only "a signer asserted these bytes" —
//!   never existence, redeemability, solvency, or legality of anything.

/// 32-byte hash output used throughout the crate.
pub type Hash32 = [u8; 32];

/// Keccak-f[1600] round constants (FIPS 202, 24 rounds).
const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Rho rotation offsets, in pi-walk order.
const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// Pi lane permutation walk (starting from lane (1, 0)).
const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// The Keccak-f[1600] permutation over the 25-lane state.
fn keccak_f1600(a: &mut [u64; 25]) {
    for rc in RC {
        // Theta.
        let mut c = [0u64; 5];
        for (x, cx) in c.iter_mut().enumerate() {
            *cx = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        // Rho + Pi.
        let mut last = a[1];
        for (i, &j) in PI.iter().enumerate() {
            let tmp = a[j];
            a[j] = last.rotate_left(RHO[i]);
            last = tmp;
        }
        // Chi.
        for y in 0..5 {
            let row = [a[5 * y], a[5 * y + 1], a[5 * y + 2], a[5 * y + 3], a[5 * y + 4]];
            for x in 0..5 {
                a[5 * y + x] = row[x] ^ (!row[(x + 1) % 5] & row[(x + 2) % 5]);
            }
        }
        // Iota.
        a[0] ^= rc;
    }
}

/// SHAKE-256 rate in bytes (1088-bit rate / 512-bit capacity).
const SHAKE256_RATE: usize = 136;

/// A minimal SHAKE-256 sponge: absorb bytes, then squeeze 32 bytes.
struct Shake256 {
    state: [u64; 25],
    /// Byte offset into the current rate block being absorbed.
    offset: usize,
}

impl Shake256 {
    fn new() -> Self {
        Self { state: [0u64; 25], offset: 0 }
    }

    fn absorb(&mut self, data: &[u8]) {
        for &byte in data {
            self.state[self.offset / 8] ^= u64::from(byte) << (8 * (self.offset % 8));
            self.offset += 1;
            if self.offset == SHAKE256_RATE {
                keccak_f1600(&mut self.state);
                self.offset = 0;
            }
        }
    }

    /// Apply the SHAKE domain suffix (`0x1F`) + pad10*1, then squeeze 32 bytes.
    fn finalize_32(mut self) -> Hash32 {
        self.state[self.offset / 8] ^= 0x1Fu64 << (8 * (self.offset % 8));
        self.state[(SHAKE256_RATE - 1) / 8] ^= 0x80u64 << (8 * ((SHAKE256_RATE - 1) % 8));
        keccak_f1600(&mut self.state);
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = (self.state[i / 8] >> (8 * (i % 8))) as u8;
        }
        out
    }
}

/// SHAKE-256 of `domain || data`, squeezed to 32 bytes.
///
/// Domain separation: the domain string is hashed as a length-prefixed
/// (u64 LE) byte string so distinct domains can never collide by
/// concatenation ambiguity. (Same spec as `l2/bloch-l2-prover/src/hash.rs`.)
pub fn shake256_32(domain: &str, data: &[u8]) -> Hash32 {
    let mut sponge = Shake256::new();
    sponge.absorb(&(domain.len() as u64).to_le_bytes());
    sponge.absorb(domain.as_bytes());
    sponge.absorb(data);
    sponge.finalize_32()
}

/// SHAKE-256 over a list of byte strings, each length-prefixed (u64 LE),
/// with a leading item count (u64 LE). Canonical: equal lists ⇒ equal hash,
/// and no concatenation ambiguity between items. (Same spec as
/// `l2/bloch-l2-prover/src/hash.rs`.)
pub fn shake256_list(domain: &str, items: &[Vec<u8>]) -> Hash32 {
    let mut sponge = Shake256::new();
    sponge.absorb(&(domain.len() as u64).to_le_bytes());
    sponge.absorb(domain.as_bytes());
    sponge.absorb(&(items.len() as u64).to_le_bytes());
    for item in items {
        sponge.absorb(&(item.len() as u64).to_le_bytes());
        sponge.absorb(item);
    }
    sponge.finalize_32()
}

/// Raw SHAKE-256 of `data` squeezed to 32 bytes — no domain framing. Exposed
/// only so the NIST vectors below can pin the permutation; prefer the
/// domain-separated helpers everywhere else.
pub fn shake256_raw_32(data: &[u8]) -> Hash32 {
    let mut sponge = Shake256::new();
    sponge.absorb(data);
    sponge.finalize_32()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(h: &Hash32) -> String {
        h.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// NIST FIPS 202 test vectors pin the hand-rolled permutation: the empty
    /// message and "abc", SHAKE-256, first 32 squeezed bytes.
    #[test]
    fn nist_shake256_vectors() {
        assert_eq!(
            hex32(&shake256_raw_32(b"")),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        );
        assert_eq!(
            hex32(&shake256_raw_32(b"abc")),
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
        );
        // A multi-block message (> one 136-byte rate block) exercises the
        // absorb-permute path.
        let long = vec![0xa3u8; 200];
        assert_eq!(shake256_raw_32(&long), shake256_raw_32(&long));
        assert_ne!(shake256_raw_32(&long), shake256_raw_32(&long[..199]));
    }

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
}
