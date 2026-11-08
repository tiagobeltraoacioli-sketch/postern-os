//! `BatchPublicValues` — the guest-committed public values, exactly as
//! `BLOCH-L2-EVM-DESIGN.md` §3 specifies, with a canonical fixed-width
//! little-endian byte encoding and a SHAKE-256 domain-separated commitment.
//!
//! REAL + TESTED: encode/decode round-trip and the commitment function. What
//! is NOT here: nothing in this module is an SP1 commitment — in the real
//! guest these bytes go through `sp1_zkvm::io::commit` (SCAFFOLD, see
//! [`crate::sp1_stub`]).

use crate::hash::{shake256_32, Hash32};

/// Domain string for the `BatchPublicValues` commitment hash — this is the
/// value the design's `prev_batch_hash` chain link carries ("SHAKE-256 of
/// previous BatchPublicValues").
pub const BPV_COMMITMENT_DOMAIN: &str = "bloch-l2/batch-public-values/v0";

/// Exact encoded length of [`BatchPublicValues`]:
/// 3×u64 fields before the trailing pair + 7×32-byte hashes + 8-byte
/// `timestamp` = 8+8+32+32+32+32+32+32+8+32+8.
pub const ENCODED_LEN: usize = 256;

/// Guest public values committed per proven batch (design §3, field-for-field).
///
/// ABI-stable canonical encoding: fixed width, little-endian integers, field
/// order exactly as declared. **SCAFFOLD context**: in this crate these values
/// are produced by a simplified placeholder STF and bound by a mock hash — no
/// zk proof, no soundness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchPublicValues {
    /// Fixed L2 chain id (e.g. a registered EIP-155 id for the testnet).
    pub l2_chain_id: u64,
    /// Strictly increasing batch index.
    pub batch_index: u64,
    /// SHAKE-256 commitment of the previous `BatchPublicValues` (chain link).
    pub prev_batch_hash: Hash32,
    /// State root before the batch. Design: keccak-256 MPT root. Here:
    /// produced by the SIMPLIFIED flat account-map commitment (placeholder).
    pub prev_state_root: Hash32,
    /// State root after the batch (same caveat as `prev_state_root`).
    pub new_state_root: Hash32,
    /// SHAKE-256 of the canonical tx list == DA blob commitment.
    pub batch_tx_commitment: Hash32,
    /// SHAKE-256 merkle root of the Bloch deposits applied in this batch.
    pub deposit_root: Hash32,
    /// Bloch (L1) block hash the deposits were read from.
    pub l1_origin_hash: Hash32,
    /// Height of `l1_origin_hash` (verifiers check depth ≥ K).
    pub l1_origin_height: u64,
    /// Root of L2→L1 withdrawal messages (design: SMT root of the
    /// L2ToL1MessagePasser storage; here: simplified merkle, placeholder).
    pub withdrawal_root: Hash32,
    /// Batch timestamp (sequencer-set, monotonic per the design).
    pub timestamp: u64,
}

/// Error decoding a `BatchPublicValues` byte string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Input was not exactly [`ENCODED_LEN`] bytes; contains the actual length.
    WrongLength(usize),
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DecodeError::WrongLength(got) => {
                write!(f, "expected {ENCODED_LEN} bytes, got {got}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {}

impl BatchPublicValues {
    /// Canonical fixed-width little-endian encoding (field order as declared).
    pub fn encode(&self) -> [u8; ENCODED_LEN] {
        let mut out = [0u8; ENCODED_LEN];
        out[0..8].copy_from_slice(&self.l2_chain_id.to_le_bytes());
        out[8..16].copy_from_slice(&self.batch_index.to_le_bytes());
        out[16..48].copy_from_slice(&self.prev_batch_hash);
        out[48..80].copy_from_slice(&self.prev_state_root);
        out[80..112].copy_from_slice(&self.new_state_root);
        out[112..144].copy_from_slice(&self.batch_tx_commitment);
        out[144..176].copy_from_slice(&self.deposit_root);
        out[176..208].copy_from_slice(&self.l1_origin_hash);
        out[208..216].copy_from_slice(&self.l1_origin_height.to_le_bytes());
        out[216..248].copy_from_slice(&self.withdrawal_root);
        out[248..256].copy_from_slice(&self.timestamp.to_le_bytes());
        out
    }

    /// Decode from the canonical encoding. Rejects any length other than
    /// exactly [`ENCODED_LEN`].
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != ENCODED_LEN {
            return Err(DecodeError::WrongLength(bytes.len()));
        }
        let u64_at = |off: usize| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&bytes[off..off + 8]);
            u64::from_le_bytes(b)
        };
        let h32_at = |off: usize| {
            let mut b = [0u8; 32];
            b.copy_from_slice(&bytes[off..off + 32]);
            b
        };
        Ok(Self {
            l2_chain_id: u64_at(0),
            batch_index: u64_at(8),
            prev_batch_hash: h32_at(16),
            prev_state_root: h32_at(48),
            new_state_root: h32_at(80),
            batch_tx_commitment: h32_at(112),
            deposit_root: h32_at(144),
            l1_origin_hash: h32_at(176),
            l1_origin_height: u64_at(208),
            withdrawal_root: h32_at(216),
            timestamp: u64_at(248),
        })
    }

    /// SHAKE-256 domain-separated commitment of the canonical encoding.
    ///
    /// This is what the NEXT batch's `prev_batch_hash` must equal (the chain
    /// link), and what the [`crate::mock::MockProof`] binds. It is a plain
    /// hash — calling it a commitment implies **no zk soundness whatsoever**.
    pub fn commitment(&self) -> Hash32 {
        shake256_32(BPV_COMMITMENT_DOMAIN, &self.encode())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample() -> BatchPublicValues {
        BatchPublicValues {
            l2_chain_id: 700_771,
            batch_index: 42,
            prev_batch_hash: [0x11; 32],
            prev_state_root: [0x22; 32],
            new_state_root: [0x33; 32],
            batch_tx_commitment: [0x44; 32],
            deposit_root: [0x55; 32],
            l1_origin_hash: [0x66; 32],
            l1_origin_height: 123_456,
            withdrawal_root: [0x77; 32],
            timestamp: 1_760_000_000,
        }
    }

    #[test]
    fn encode_decode_round_trip() {
        let pv = sample();
        let bytes = pv.encode();
        assert_eq!(bytes.len(), ENCODED_LEN);
        let back = BatchPublicValues::decode(&bytes).unwrap();
        assert_eq!(pv, back);
    }

    #[test]
    fn encoding_is_little_endian_fixed_offsets() {
        let pv = sample();
        let bytes = pv.encode();
        assert_eq!(&bytes[0..8], &700_771u64.to_le_bytes());
        assert_eq!(&bytes[8..16], &42u64.to_le_bytes());
        assert_eq!(&bytes[16..48], &[0x11; 32]);
        assert_eq!(&bytes[208..216], &123_456u64.to_le_bytes());
        assert_eq!(&bytes[248..256], &1_760_000_000u64.to_le_bytes());
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert_eq!(
            BatchPublicValues::decode(&[0u8; ENCODED_LEN - 1]),
            Err(DecodeError::WrongLength(ENCODED_LEN - 1))
        );
        assert_eq!(
            BatchPublicValues::decode(&[0u8; ENCODED_LEN + 1]),
            Err(DecodeError::WrongLength(ENCODED_LEN + 1))
        );
        assert_eq!(
            BatchPublicValues::decode(&[]),
            Err(DecodeError::WrongLength(0))
        );
    }

    #[test]
    fn every_field_occupies_its_declared_offset() {
        // Distinct per-field byte patterns pin the exact wire layout, so any
        // field reorder, offset drift, or width change is caught byte-for-byte.
        let pv = BatchPublicValues {
            l2_chain_id: u64::from_le_bytes([1, 2, 3, 4, 5, 6, 7, 8]),
            batch_index: u64::from_le_bytes([9, 10, 11, 12, 13, 14, 15, 16]),
            prev_batch_hash: [0x21; 32],
            prev_state_root: [0x22; 32],
            new_state_root: [0x23; 32],
            batch_tx_commitment: [0x24; 32],
            deposit_root: [0x25; 32],
            l1_origin_hash: [0x26; 32],
            l1_origin_height: u64::from_le_bytes([17, 18, 19, 20, 21, 22, 23, 24]),
            withdrawal_root: [0x27; 32],
            timestamp: u64::from_le_bytes([25, 26, 27, 28, 29, 30, 31, 32]),
        };
        let b = pv.encode();
        assert_eq!(&b[0..8], &pv.l2_chain_id.to_le_bytes());
        assert_eq!(&b[8..16], &pv.batch_index.to_le_bytes());
        assert_eq!(&b[16..48], &pv.prev_batch_hash);
        assert_eq!(&b[48..80], &pv.prev_state_root);
        assert_eq!(&b[80..112], &pv.new_state_root);
        assert_eq!(&b[112..144], &pv.batch_tx_commitment);
        assert_eq!(&b[144..176], &pv.deposit_root);
        assert_eq!(&b[176..208], &pv.l1_origin_hash);
        assert_eq!(&b[208..216], &pv.l1_origin_height.to_le_bytes());
        assert_eq!(&b[216..248], &pv.withdrawal_root);
        assert_eq!(&b[248..256], &pv.timestamp.to_le_bytes());
    }

    #[test]
    fn decode_encode_is_identity_on_arbitrary_bytes() {
        // The wire format is a canonical bijection over exactly ENCODED_LEN
        // bytes: every byte string decodes and re-encodes to itself, proving no
        // field is dropped, aliased, or padded. (decode ∘ encode == id on bytes)
        let mut bytes = [0u8; ENCODED_LEN];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        let pv = BatchPublicValues::decode(&bytes).unwrap();
        assert_eq!(pv.encode(), bytes);
    }

    #[test]
    fn commitment_changes_with_any_field() {
        let base = sample();
        let base_c = base.commitment();
        let mut alt = base;
        alt.batch_index += 1;
        assert_ne!(alt.commitment(), base_c);
        let mut alt2 = base;
        alt2.new_state_root[0] ^= 1;
        assert_ne!(alt2.commitment(), base_c);
        // Deterministic.
        assert_eq!(base.commitment(), base_c);
    }
}
