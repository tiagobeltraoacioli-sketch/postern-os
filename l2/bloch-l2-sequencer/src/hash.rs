// SPDX-License-Identifier: MIT OR Apache-2.0
//! Self-contained Keccak-f[1600] sponge: keccak-256 (Ethereum, pad `0x01`)
//! and SHA3-256 (FIPS-202, pad `0x06`).
//!
//! Written in-crate so `bloch-l2-sequencer` stays zero-dependency and
//! offline-buildable (the bloch-tokens standalone pattern). Verified against
//! published FIPS-202 / Ethereum vectors in the tests below. UNAUDITED — like
//! everything in this scaffold.

const ROUNDS: usize = 24;
const RATE_256: usize = 136; // 1600/8 - 2*256/8

const RC: [u64; ROUNDS] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// The Keccak-f[1600] permutation over a 25-lane little-endian state.
fn keccak_f1600(a: &mut [u64; 25]) {
    for &rc in RC.iter() {
        // theta
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        // rho + pi
        let mut last = a[1];
        for i in 0..24 {
            let j = PI[i];
            let tmp = a[j];
            a[j] = last.rotate_left(RHO[i]);
            last = tmp;
        }
        // chi
        for y in 0..5 {
            let row = [a[5 * y], a[5 * y + 1], a[5 * y + 2], a[5 * y + 3], a[5 * y + 4]];
            for x in 0..5 {
                a[5 * y + x] = row[x] ^ ((!row[(x + 1) % 5]) & row[(x + 2) % 5]);
            }
        }
        // iota
        a[0] ^= rc;
    }
}

fn absorb_block(state: &mut [u64; 25], block: &[u8]) {
    debug_assert_eq!(block.len(), RATE_256);
    for (i, lane) in block.chunks_exact(8).enumerate() {
        state[i] ^= u64::from_le_bytes(lane.try_into().expect("8-byte chunk"));
    }
}

/// 256-bit sponge with the given domain/padding byte (`0x01` keccak, `0x06` SHA3).
fn sponge_256(pad: u8, data: &[u8]) -> [u8; 32] {
    let mut state = [0u64; 25];
    let mut chunks = data.chunks_exact(RATE_256);
    for block in &mut chunks {
        absorb_block(&mut state, block);
        keccak_f1600(&mut state);
    }
    let rem = chunks.remainder();
    let mut last = [0u8; RATE_256];
    last[..rem.len()].copy_from_slice(rem);
    last[rem.len()] ^= pad;
    last[RATE_256 - 1] ^= 0x80;
    absorb_block(&mut state, &last);
    keccak_f1600(&mut state);

    let mut out = [0u8; 32];
    for i in 0..4 {
        out[8 * i..8 * i + 8].copy_from_slice(&state[i].to_le_bytes());
    }
    out
}

/// Ethereum keccak-256.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    sponge_256(0x01, data)
}

/// keccak-256 over the concatenation of the given byte slices.
pub fn keccak256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for p in parts {
        buf.extend_from_slice(p);
    }
    keccak256(&buf)
}

/// FIPS-202 SHA3-256 (the Bloch base chain's hash; used for `batch_data_hash`).
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    sponge_256(0x06, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn keccak256_known_vectors() {
        // Ethereum's canonical empty-input hash.
        assert_eq!(
            hex(&keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            hex(&keccak256(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }

    #[test]
    fn sha3_256_known_vectors() {
        // FIPS-202 test vectors.
        assert_eq!(
            hex(&sha3_256(b"")),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(
            hex(&sha3_256(b"abc")),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }

    #[test]
    fn multi_block_input_crosses_rate_boundary() {
        // > 136 bytes forces more than one absorb block; check against the
        // one-shot digest of the same bytes and determinism across calls.
        let data = vec![0xabu8; 300];
        let a = keccak256(&data);
        let b = keccak256(&data);
        assert_eq!(a, b);
        // 136-byte input (exact rate) exercises the full-block + padding path.
        let exact = vec![0u8; 136];
        assert_ne!(keccak256(&exact), keccak256(&vec![0u8; 135]));
    }

    #[test]
    fn concat_equals_manual_concatenation() {
        let joined = keccak256(b"hello world");
        let parts = keccak256_concat(&[b"hello", b" ", b"world"]);
        assert_eq!(joined, parts);
    }
}
