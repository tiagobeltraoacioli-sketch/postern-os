// SPDX-License-Identifier: MIT OR Apache-2.0
//! OP-style deposit transaction, EIP-2718 type `0x7E` (§5 of
//! `BLOCH-L2-EVM-DESIGN.md`: `BlochDepositTx`).
//!
//! A deposit is derived from an L1 (Bloch) escrow payment carrying an `L2D0`
//! envelope; once derived at confirmation depth K it is a MANDATORY system
//! transaction: it executes FIRST in an L2 block and the sequencer cannot
//! drop it (enforced by [`crate::block::build_block`], and — in the real
//! system — by the SP1 derivation proof; nothing is proven here).
//!
//! `source_hash` derivation (per the §5 struct sketch):
//! `keccak256(deposit_id ‖ l1_block_hash)` where
//! `deposit_id = (l1_txid: [u8;32], vout: u32 LE)` — the L1 escrow txid and
//! the first vault-paying output index. NOTE: this is the spec's simplified
//! rule, not OP-Stack's exact two-level domain-separated derivation; the
//! delta is deliberate and documented here.
//!
//! Canonical byte encoding (this crate's normative scaffold format, strict
//! decode, little-endian integers):
//!
//! | offset | size | field |
//! |---|---|---|
//! | 0 | 1 | type byte `0x7E` |
//! | 1 | 32 | `source_hash` |
//! | 33 | 20 | `from` |
//! | 53 | 20 | `to` |
//! | 73 | 16 | `mint` (u128 LE wei) |
//! | 89 | 16 | `value` (u128 LE wei) |
//! | 105 | 8 | `gas_limit` (u64 LE) |
//! | 113 | 4 | `data_len` (u32 LE) |
//! | 117 | `data_len` | `data` |
//!
//! No trailing bytes allowed. `mint`/`value` are `u128`, not U256: the max
//! mint is `u64::MAX` L1 atoms × `ATOM_SCALE` 10^10 < 2^98, which fits u128
//! with headroom (documented bound; the real 0x7E envelope uses U256).
//! SCAFFOLD: the real encoding will be the RLP/EIP-2718 form the EVM sees;
//! this canonical LE form exists so ordering/batching logic has stable bytes.

use crate::hash::keccak256_concat;

/// EIP-2718 transaction type byte for deposits (OP-Stack convention, §5).
pub const DEPOSIT_TX_TYPE: u8 = 0x7E;

/// L1 atom → L2 wei scale (§1: BLCH has 8 decimals on L1, scaled by 10^10 so
/// 1 BLCH = 10^18 wei-equivalent).
pub const ATOM_SCALE: u128 = 10_000_000_000;

/// Identifies the L1 escrow deposit: `(txid, first vault-paying vout)` (§5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositId {
    pub l1_txid: [u8; 32],
    pub vout: u32,
}

/// The type-`0x7E` deposit transaction (§5 `BlochDepositTx`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositTx {
    /// `keccak256(l1_txid ‖ vout LE ‖ l1_block_hash)` — see [`source_hash`].
    pub source_hash: [u8; 32],
    /// Aliased L1 depositor (SCAFFOLD: alias derivation not implemented; the
    /// caller supplies it).
    pub from: [u8; 20],
    /// L2 recipient. SCAFFOLD: contract-creating deposits (`to = None`) are
    /// out of scope for this scaffold.
    pub to: [u8; 20],
    /// Native gas-BLCH minted to `from` before execution, in wei
    /// (= L1 atoms × [`ATOM_SCALE`]).
    pub mint: u128,
    /// Wei transferred to `to` during execution.
    pub value: u128,
    pub gas_limit: u64,
    pub data: Vec<u8>,
}

/// Derive the deposit `source_hash` (§5): `keccak256(deposit_id ‖ l1_block_hash)`
/// with `deposit_id` serialized as `l1_txid ‖ vout (u32 LE)`.
pub fn source_hash(id: &DepositId, l1_block_hash: &[u8; 32]) -> [u8; 32] {
    keccak256_concat(&[&id.l1_txid, &id.vout.to_le_bytes(), l1_block_hash])
}

/// Decode failure for the canonical deposit encoding (strict: wrong type
/// byte, truncation, or trailing bytes all reject).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DepositDecodeError {
    WrongTypeByte(u8),
    TooShort { len: usize },
    LengthMismatch { expected: usize, got: usize },
}

const FIXED_LEN: usize = 117;

impl DepositTx {
    /// Construct a deposit whose `source_hash` is derived from its L1 origin.
    pub fn from_l1(
        id: &DepositId,
        l1_block_hash: &[u8; 32],
        from: [u8; 20],
        to: [u8; 20],
        mint: u128,
        value: u128,
        gas_limit: u64,
        data: Vec<u8>,
    ) -> Self {
        Self {
            source_hash: source_hash(id, l1_block_hash),
            from,
            to,
            mint,
            value,
            gas_limit,
            data,
        }
    }

    /// Canonical byte encoding (see module docs for the layout table).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FIXED_LEN + self.data.len());
        out.push(DEPOSIT_TX_TYPE);
        out.extend_from_slice(&self.source_hash);
        out.extend_from_slice(&self.from);
        out.extend_from_slice(&self.to);
        out.extend_from_slice(&self.mint.to_le_bytes());
        out.extend_from_slice(&self.value.to_le_bytes());
        out.extend_from_slice(&self.gas_limit.to_le_bytes());
        out.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    /// Strict decode of [`encode`](Self::encode)'s output: exact length, no
    /// trailing bytes, type byte must be `0x7E`.
    pub fn decode(bytes: &[u8]) -> Result<Self, DepositDecodeError> {
        if bytes.len() < FIXED_LEN {
            return Err(DepositDecodeError::TooShort { len: bytes.len() });
        }
        if bytes[0] != DEPOSIT_TX_TYPE {
            return Err(DepositDecodeError::WrongTypeByte(bytes[0]));
        }
        let arr32 = |o: usize| -> [u8; 32] { bytes[o..o + 32].try_into().expect("32") };
        let arr20 = |o: usize| -> [u8; 20] { bytes[o..o + 20].try_into().expect("20") };
        let u128_at =
            |o: usize| u128::from_le_bytes(bytes[o..o + 16].try_into().expect("16"));
        let data_len =
            u32::from_le_bytes(bytes[113..117].try_into().expect("4")) as usize;
        let expected = FIXED_LEN + data_len;
        if bytes.len() != expected {
            return Err(DepositDecodeError::LengthMismatch {
                expected,
                got: bytes.len(),
            });
        }
        Ok(Self {
            source_hash: arr32(1),
            from: arr20(33),
            to: arr20(53),
            mint: u128_at(73),
            value: u128_at(89),
            gas_limit: u64::from_le_bytes(bytes[105..113].try_into().expect("8")),
            data: bytes[117..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> DepositTx {
        DepositTx::from_l1(
            &DepositId {
                l1_txid: [0x11; 32],
                vout: 3,
            },
            &[0x22; 32],
            [0xaa; 20],
            [0xbb; 20],
            5 * ATOM_SCALE, // 5 atoms worth of wei
            ATOM_SCALE,
            21_000,
            vec![1, 2, 3, 4],
        )
    }

    #[test]
    fn source_hash_is_deterministic_and_input_sensitive() {
        let id = DepositId {
            l1_txid: [0x11; 32],
            vout: 3,
        };
        let l1 = [0x22; 32];
        let h = source_hash(&id, &l1);
        assert_eq!(h, source_hash(&id, &l1), "deterministic");
        // vout matters
        let id2 = DepositId { vout: 4, ..id };
        assert_ne!(h, source_hash(&id2, &l1));
        // l1 block hash matters (same deposit re-derived under a different
        // L1 view gets a different source hash — reorg-visible)
        assert_ne!(h, source_hash(&id, &[0x23; 32]));
        // and it matches the documented formula
        let manual = crate::hash::keccak256_concat(&[
            &[0x11u8; 32],
            &3u32.to_le_bytes(),
            &[0x22u8; 32],
        ]);
        assert_eq!(h, manual);
    }

    #[test]
    fn encode_decode_round_trip() {
        let d = sample();
        let bytes = d.encode();
        assert_eq!(bytes[0], DEPOSIT_TX_TYPE);
        assert_eq!(bytes.len(), 117 + 4);
        let back = DepositTx::decode(&bytes).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn round_trip_empty_data() {
        let mut d = sample();
        d.data.clear();
        let bytes = d.encode();
        assert_eq!(bytes.len(), 117);
        assert_eq!(DepositTx::decode(&bytes).unwrap(), d);
    }

    #[test]
    fn strict_decode_rejects_mutations() {
        let bytes = sample().encode();
        // wrong type byte
        let mut b = bytes.clone();
        b[0] = 0x02;
        assert_eq!(
            DepositTx::decode(&b).unwrap_err(),
            DepositDecodeError::WrongTypeByte(0x02)
        );
        // truncated
        assert!(matches!(
            DepositTx::decode(&bytes[..50]).unwrap_err(),
            DepositDecodeError::TooShort { len: 50 }
        ));
        // trailing byte
        let mut b = bytes.clone();
        b.push(0x00);
        assert!(matches!(
            DepositTx::decode(&b).unwrap_err(),
            DepositDecodeError::LengthMismatch { .. }
        ));
        // data_len lies short (claims 3, carries 4)
        let mut b = bytes.clone();
        b[113..117].copy_from_slice(&3u32.to_le_bytes());
        assert!(matches!(
            DepositTx::decode(&b).unwrap_err(),
            DepositDecodeError::LengthMismatch { .. }
        ));
    }

    #[test]
    fn mint_bound_fits_u128() {
        // Max possible mint: u64::MAX atoms * 10^10 must fit u128.
        let max = (u64::MAX as u128).checked_mul(ATOM_SCALE);
        assert!(max.is_some());
    }
}
