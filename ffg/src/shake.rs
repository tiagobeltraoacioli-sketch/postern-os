// SPDX-License-Identifier: MIT OR Apache-2.0
//! In-crate SHAKE-256 (FIPS 202, Keccak-f[1600]) — **unaudited
//! reimplementation, reference only**.
//!
//! # SCAFFOLD — not a secure or deployed system
//!
//! This is a from-scratch, **UNAUDITED** reimplementation of SHAKE-256 written
//! so this crate pulls **no hashing crate** (its only default dependency is the
//! ML-DSA-65 signature primitive; `--no-default-features` drops that too) while
//! still being able to hash a checkpoint certificate deterministically. It
//! exists for **reference/test purposes only**:
//!
//! - It is **not** constant-time-reviewed, **not** side-channel-hardened, and
//!   has **never** been independently audited. Do not use it to protect
//!   anything of value.
//! - It is validated in-tree against official FIPS-202 / NIST SHA-3 example
//!   test vectors (see the tests below), which demonstrates *functional*
//!   correctness on those inputs — **not** security.
//! - A real deployment MUST replace this with an independently-audited
//!   implementation; independent audit of any hash/crypto code is a
//!   **blocked-on-audit** item, out of scope for this software-only reference.
//!
//! The base chain's header hash is also SHAKE-256; this module intentionally
//! does **not** import or link the base's implementation — the owned Layer-2
//! crate stays standalone and never becomes a consensus dependency of the base.

/// Keccak-f[1600] round constants (FIPS 202 §3.2.5), 24 rounds.
const ROUND_CONSTANTS: [u64; 24] = [
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

/// Rho rotation offsets (FIPS 202 §3.2.2), indexed as `x + 5*y`.
const RHO_OFFSETS: [u32; 25] = [
    0, 1, 62, 28, 27, //
    36, 44, 6, 55, 20, //
    3, 10, 43, 25, 39, //
    41, 45, 15, 21, 8, //
    18, 2, 61, 56, 14,
];

/// SHAKE-256 sponge rate in bytes: `(1600 - 2*256) / 8 = 136` (FIPS 202 §6.3).
const SHAKE_256_RATE: usize = 136;

/// The Keccak-f[1600] permutation (FIPS 202 §3). State is 25 lanes of `u64`,
/// indexed `x + 5*y`, little-endian lane encoding.
fn keccak_f1600(state: &mut [u64; 25]) {
    for &rc in &ROUND_CONSTANTS {
        // theta (§3.2.1)
        let mut c = [0u64; 5];
        for (x, cx) in c.iter_mut().enumerate() {
            *cx = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                state[x + 5 * y] ^= d;
            }
        }

        // rho (§3.2.2) + pi (§3.2.3)
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = state[x + 5 * y].rotate_left(RHO_OFFSETS[x + 5 * y]);
            }
        }

        // chi (§3.2.4)
        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] = b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
            }
        }

        // iota (§3.2.5)
        state[0] ^= rc;
    }
}

/// XOR one full rate-sized block into the sponge state (little-endian lanes).
fn absorb_block(state: &mut [u64; 25], block: &[u8]) {
    debug_assert_eq!(block.len(), SHAKE_256_RATE);
    for (lane, chunk) in state.iter_mut().zip(block.chunks_exact(8)) {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(chunk);
        *lane ^= u64::from_le_bytes(bytes);
    }
}

/// SHAKE-256 XOF (FIPS 202 §6.3): hash `input` and squeeze `output_len` bytes.
///
/// SCAFFOLD: unaudited reimplementation, reference only — see the module docs.
/// Deterministic: same input and length always yield the same bytes.
pub fn shake256(input: &[u8], output_len: usize) -> Vec<u8> {
    let mut state = [0u64; 25];

    // Absorb all full rate-sized blocks.
    let mut chunks = input.chunks_exact(SHAKE_256_RATE);
    for block in &mut chunks {
        absorb_block(&mut state, block);
        keccak_f1600(&mut state);
    }

    // Final (possibly empty) partial block with the SHAKE domain-separation
    // suffix `1111` and pad10*1 (FIPS 202 §6.3, B.2): append 0x1F, pad with
    // zeros, and set the top bit of the last rate byte.
    let remainder = chunks.remainder();
    let mut last = [0u8; SHAKE_256_RATE];
    last[..remainder.len()].copy_from_slice(remainder);
    last[remainder.len()] ^= 0x1f;
    last[SHAKE_256_RATE - 1] ^= 0x80;
    absorb_block(&mut state, &last);
    keccak_f1600(&mut state);

    // Squeeze.
    let mut out = Vec::with_capacity(output_len);
    loop {
        for lane in state.iter().take(SHAKE_256_RATE / 8) {
            for byte in lane.to_le_bytes() {
                if out.len() == output_len {
                    return out;
                }
                out.push(byte);
            }
        }
        if out.len() == output_len {
            return out;
        }
        keccak_f1600(&mut state);
    }
}

/// SHAKE-256 with a fixed 32-byte output ("SHAKE-256-32") — the certificate
/// commitment size used by [`crate::certificate`].
///
/// SCAFFOLD: unaudited reimplementation, reference only — see the module docs.
pub fn shake256_32(input: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&shake256(input, 32));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Official FIPS-202 / NIST SHA-3 example vector: SHAKE256 of the empty
    /// message, first 512 bits. Matches the NIST CSRC "SHA-3 examples"
    /// SHAKE256 sample and the XKCP test suite.
    #[test]
    fn official_vector_shake256_empty_message() {
        assert_eq!(
            hex(&shake256(b"", 64)),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f\
             d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
        );
    }

    /// Official FIPS-202 / NIST SHA-3 example vector: SHAKE256("abc"),
    /// first 512 bits.
    #[test]
    fn official_vector_shake256_abc() {
        assert_eq!(
            hex(&shake256(b"abc", 64)),
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739\
             d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"
        );
    }

    /// Multi-block SQUEEZE (272 bytes > the 136-byte rate, so the sponge is
    /// permuted mid-squeeze). Expected value cross-checked against CPython's
    /// `hashlib.shake_256(b"abc").hexdigest(272)`; its 64-byte prefix is the
    /// official NIST vector above.
    #[test]
    fn multi_block_squeeze_matches_reference_implementation() {
        assert_eq!(
            hex(&shake256(b"abc", 272)),
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739\
             d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4\
             1385141204f329979fd3047a13c5657724ada64d2470157b3cdc288620944d78\
             dbcddbd912993f0913f164fb2ce95131a2d09a3e6d51cbfc622720d7a75c6334\
             e8a2d7ec71a7cc29cf0ea610eeff1a588290a53000faa79932becec0bd3cd0b3\
             3a7e5d397fed1ada9442b99903f4dcfd8559ed3950faf40fe6f3b5d710ed3b67\
             7513771af6bfe11934817e8762d9896ba579d88d84ba7aa3cdc7055f6796f195\
             bd9ae788f2f5bb96100d6bbaff7fbc6eea24d4449a2477d172a5507dcc931412\
             fc346b1bb39b878330e026b12ddf384a"
        );
    }

    /// Multi-block ABSORB (512-byte input > the 136-byte rate, exercising the
    /// full-block absorb loop and a non-empty final partial block).
    /// Cross-checked against CPython's `hashlib.shake_256`.
    #[test]
    fn multi_block_absorb_matches_reference_implementation() {
        let msg: Vec<u8> = (0u16..512).map(|i| (i % 256) as u8).collect();
        assert_eq!(
            hex(&shake256(&msg, 32)),
            "a1d71885b0a841f03d1dc7f2738a15cc984071a17ffed5ecacb9f58720a473be"
        );
    }

    /// XOF prefix property: a shorter output is a prefix of a longer one for
    /// the same input (FIPS 202 §6.3).
    #[test]
    fn shorter_output_is_prefix_of_longer_output() {
        let long = shake256(b"postern-ffg prefix property", 300);
        let short = shake256(b"postern-ffg prefix property", 32);
        assert_eq!(&long[..32], &short[..]);
        assert_eq!(shake256_32(b"postern-ffg prefix property")[..], short[..]);
    }

    /// Determinism: same input, same bytes, every time (no RNG, no time).
    #[test]
    fn deterministic() {
        assert_eq!(shake256(b"x", 96), shake256(b"x", 96));
        assert_eq!(shake256_32(b"x"), shake256_32(b"x"));
    }
}
