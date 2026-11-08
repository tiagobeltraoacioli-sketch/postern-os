//! `ExecutionWitness` — the RSP-shaped private input the host feeds the guest
//! (`BLOCH-L2-EVM-DESIGN.md` §1/§3: pre-state root, txs, sparse state-witness
//! nodes, bytecodes, ≤256 ancestor headers for BLOCKHASH, deposits).
//!
//! REAL + TESTED: the types and their canonical length-prefixed ser/de
//! round-trip. HONESTY: in the production design the `state_witness` entries
//! are keccak-256 MPT nodes verified against `pre_state_root` and the txs are
//! RLP EVM transactions executed by revm. In THIS scaffold the placeholder
//! STF (see [`crate::stf`]) interprets `state_witness` entries as flat
//! account leaves and `txs` as a toy 64-byte transfer format — NOT Ethereum.

use alloc::vec::Vec;

use crate::hash::Hash32;

/// Maximum ancestor headers carried for BLOCKHASH semantics (design: ≤256).
pub const MAX_ANCESTOR_HEADERS: usize = 256;

/// Witness wire-format version byte.
pub const WITNESS_VERSION: u8 = 0;

/// An ancestor L2 header reference (simplified to height + hash; the real
/// witness carries full Ethereum headers — SCAFFOLD, see [`crate::sp1_stub`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AncestorHeader {
    /// L2 block height of the ancestor.
    pub height: u64,
    /// Hash of the ancestor header.
    pub hash: Hash32,
}

/// A Bloch (L1) deposit to be minted at the start of the batch
/// (OP-Stack-style type-0x7E system tx in the real design; simplified here
/// to a direct balance mint in the placeholder STF).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepositEvent {
    /// Derived from the L1 escrow txid+vout (replay protection handle).
    pub source_hash: Hash32,
    /// L2 recipient address (20 bytes, Ethereum-style).
    pub recipient: [u8; 20],
    /// Amount minted on the L2 (design: L1 sats × 10^10; placeholder u128).
    pub amount: u128,
}

impl DepositEvent {
    /// Canonical fixed-width encoding: source_hash ‖ recipient ‖ amount (LE).
    pub fn encode(&self) -> [u8; 68] {
        let mut out = [0u8; 68];
        out[0..32].copy_from_slice(&self.source_hash);
        out[32..52].copy_from_slice(&self.recipient);
        out[52..68].copy_from_slice(&self.amount.to_le_bytes());
        out
    }
}

/// Host-supplied batch context: the public-value fields the guest cannot
/// derive from state (it echoes them into [`crate::BatchPublicValues`]; the
/// real verifier checks them against the L2V0 anchor and the Bloch chain).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchContext {
    /// Fixed L2 chain id.
    pub l2_chain_id: u64,
    /// Strictly increasing batch index.
    pub batch_index: u64,
    /// SHAKE-256 commitment of the previous batch's public values.
    pub prev_batch_hash: Hash32,
    /// Bloch block hash the deposits were read from.
    pub l1_origin_hash: Hash32,
    /// Height of `l1_origin_hash`.
    pub l1_origin_height: u64,
    /// Sequencer-set batch timestamp.
    pub timestamp: u64,
}

/// RSP-shaped execution witness: everything the guest needs to re-execute a
/// batch statelessly.
///
/// **Placeholder semantics in this scaffold** (each documented on the field):
/// the production meanings from the design are in the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionWitness {
    /// Batch context echoed into the public values.
    pub context: BatchContext,
    /// State root before the batch. Design: keccak-256 MPT root. Here: the
    /// simplified flat account-map commitment (see [`crate::stf`]).
    pub pre_state_root: Hash32,
    /// Raw transactions. Design: RLP EVM txs. Here: the toy 64-byte
    /// transfer format of the placeholder STF.
    pub txs: Vec<Vec<u8>>,
    /// State witness nodes. Design: sparse MPT nodes for every touched
    /// account/storage slot, keccak-verified against `pre_state_root`.
    /// Here: 44-byte flat account leaves (see [`crate::stf`]).
    pub state_witness: Vec<Vec<u8>>,
    /// Contract bytecodes keyed by code hash. UNUSED by the placeholder STF
    /// (no EVM here); carried so the witness shape matches RSP.
    pub bytecodes: Vec<Vec<u8>>,
    /// Ancestor headers for BLOCKHASH, ≤ [`MAX_ANCESTOR_HEADERS`].
    pub ancestor_headers: Vec<AncestorHeader>,
    /// Bloch deposits to mint at batch start.
    pub deposits: Vec<DepositEvent>,
}

/// Error decoding an [`ExecutionWitness`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessDecodeError {
    /// Input ended before the declared structure was complete.
    UnexpectedEof,
    /// Unknown wire-format version byte.
    BadVersion(u8),
    /// More than [`MAX_ANCESTOR_HEADERS`] ancestor headers declared.
    TooManyAncestors(u32),
    /// Bytes remained after a complete decode (encoding is canonical).
    TrailingBytes(usize),
}

impl core::fmt::Display for WitnessDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected end of witness bytes"),
            Self::BadVersion(v) => write!(f, "unknown witness version {v}"),
            Self::TooManyAncestors(n) => {
                write!(f, "{n} ancestor headers exceeds max {MAX_ANCESTOR_HEADERS}")
            }
            Self::TrailingBytes(n) => write!(f, "{n} trailing bytes after witness"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WitnessDecodeError {}

/// Minimal cursor over a byte slice (no_std-friendly).
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], WitnessDecodeError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(WitnessDecodeError::UnexpectedEof)?;
        if end > self.bytes.len() {
            return Err(WitnessDecodeError::UnexpectedEof);
        }
        let s = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, WitnessDecodeError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, WitnessDecodeError> {
        let mut b = [0u8; 4];
        b.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(b))
    }
    fn u64(&mut self) -> Result<u64, WitnessDecodeError> {
        let mut b = [0u8; 8];
        b.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(b))
    }
    fn u128(&mut self) -> Result<u128, WitnessDecodeError> {
        let mut b = [0u8; 16];
        b.copy_from_slice(self.take(16)?);
        Ok(u128::from_le_bytes(b))
    }
    fn h32(&mut self) -> Result<Hash32, WitnessDecodeError> {
        let mut b = [0u8; 32];
        b.copy_from_slice(self.take(32)?);
        Ok(b)
    }
    fn addr(&mut self) -> Result<[u8; 20], WitnessDecodeError> {
        let mut b = [0u8; 20];
        b.copy_from_slice(self.take(20)?);
        Ok(b)
    }
}

fn put_bytes_list(out: &mut Vec<u8>, list: &[Vec<u8>]) {
    out.extend_from_slice(&(list.len() as u32).to_le_bytes());
    for item in list {
        out.extend_from_slice(&(item.len() as u32).to_le_bytes());
        out.extend_from_slice(item);
    }
}

fn take_bytes_list(c: &mut Cursor<'_>) -> Result<Vec<Vec<u8>>, WitnessDecodeError> {
    let count = c.u32()? as usize;
    let mut out = Vec::new();
    for _ in 0..count {
        let len = c.u32()? as usize;
        // `take` bounds-checks against remaining input BEFORE any copy, so a
        // hostile length cannot force a huge allocation of absent data.
        out.push(c.take(len)?.to_vec());
    }
    Ok(out)
}

impl ExecutionWitness {
    /// Canonical little-endian, length-prefixed encoding:
    /// `version u8 | context (96B fixed) | pre_state_root (32B) |
    ///  txs | state_witness | bytecodes (each: count u32, then len u32 + bytes)
    ///  | ancestors (count u32, then 40B fixed each)
    ///  | deposits (count u32, then 68B fixed each)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(WITNESS_VERSION);
        out.extend_from_slice(&self.context.l2_chain_id.to_le_bytes());
        out.extend_from_slice(&self.context.batch_index.to_le_bytes());
        out.extend_from_slice(&self.context.prev_batch_hash);
        out.extend_from_slice(&self.context.l1_origin_hash);
        out.extend_from_slice(&self.context.l1_origin_height.to_le_bytes());
        out.extend_from_slice(&self.context.timestamp.to_le_bytes());
        out.extend_from_slice(&self.pre_state_root);
        put_bytes_list(&mut out, &self.txs);
        put_bytes_list(&mut out, &self.state_witness);
        put_bytes_list(&mut out, &self.bytecodes);
        out.extend_from_slice(&(self.ancestor_headers.len() as u32).to_le_bytes());
        for h in &self.ancestor_headers {
            out.extend_from_slice(&h.height.to_le_bytes());
            out.extend_from_slice(&h.hash);
        }
        out.extend_from_slice(&(self.deposits.len() as u32).to_le_bytes());
        for d in &self.deposits {
            out.extend_from_slice(&d.encode());
        }
        out
    }

    /// Decode the canonical encoding; rejects unknown versions, >256
    /// ancestors, truncated input, and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, WitnessDecodeError> {
        let mut c = Cursor { bytes, pos: 0 };
        let version = c.u8()?;
        if version != WITNESS_VERSION {
            return Err(WitnessDecodeError::BadVersion(version));
        }
        let context = BatchContext {
            l2_chain_id: c.u64()?,
            batch_index: c.u64()?,
            prev_batch_hash: c.h32()?,
            l1_origin_hash: c.h32()?,
            l1_origin_height: c.u64()?,
            timestamp: c.u64()?,
        };
        let pre_state_root = c.h32()?;
        let txs = take_bytes_list(&mut c)?;
        let state_witness = take_bytes_list(&mut c)?;
        let bytecodes = take_bytes_list(&mut c)?;
        let n_anc = c.u32()?;
        if n_anc as usize > MAX_ANCESTOR_HEADERS {
            return Err(WitnessDecodeError::TooManyAncestors(n_anc));
        }
        let mut ancestor_headers = Vec::with_capacity(n_anc as usize);
        for _ in 0..n_anc {
            ancestor_headers.push(AncestorHeader {
                height: c.u64()?,
                hash: c.h32()?,
            });
        }
        let n_dep = c.u32()? as usize;
        let mut deposits = Vec::new();
        for _ in 0..n_dep {
            deposits.push(DepositEvent {
                source_hash: c.h32()?,
                recipient: c.addr()?,
                amount: c.u128()?,
            });
        }
        if c.pos != bytes.len() {
            return Err(WitnessDecodeError::TrailingBytes(bytes.len() - c.pos));
        }
        Ok(Self {
            context,
            pre_state_root,
            txs,
            state_witness,
            bytecodes,
            ancestor_headers,
            deposits,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    pub(crate) fn sample() -> ExecutionWitness {
        ExecutionWitness {
            context: BatchContext {
                l2_chain_id: 700_771,
                batch_index: 7,
                prev_batch_hash: [0xAA; 32],
                l1_origin_hash: [0xBB; 32],
                l1_origin_height: 999,
                timestamp: 1_760_000_123,
            },
            pre_state_root: [0xCC; 32],
            txs: vec![vec![1, 2, 3], vec![], vec![0xFF; 64]],
            state_witness: vec![vec![9; 44], vec![8; 44]],
            bytecodes: vec![vec![0x60, 0x00]],
            ancestor_headers: vec![
                AncestorHeader { height: 1, hash: [1; 32] },
                AncestorHeader { height: 2, hash: [2; 32] },
            ],
            deposits: vec![DepositEvent {
                source_hash: [3; 32],
                recipient: [4; 20],
                amount: 1_000_000_000_000_000_000,
            }],
        }
    }

    #[test]
    fn round_trip() {
        let w = sample();
        let bytes = w.encode();
        let back = ExecutionWitness::decode(&bytes).unwrap();
        assert_eq!(w, back);
    }

    #[test]
    fn round_trip_empty_lists() {
        let mut w = sample();
        w.txs.clear();
        w.state_witness.clear();
        w.bytecodes.clear();
        w.ancestor_headers.clear();
        w.deposits.clear();
        let back = ExecutionWitness::decode(&w.encode()).unwrap();
        assert_eq!(w, back);
    }

    #[test]
    fn rejects_bad_version() {
        let mut bytes = sample().encode();
        bytes[0] = 9;
        assert_eq!(
            ExecutionWitness::decode(&bytes),
            Err(WitnessDecodeError::BadVersion(9))
        );
    }

    #[test]
    fn rejects_truncation_and_trailing() {
        let bytes = sample().encode();
        assert_eq!(
            ExecutionWitness::decode(&bytes[..bytes.len() - 1]),
            Err(WitnessDecodeError::UnexpectedEof)
        );
        let mut extended = bytes.clone();
        extended.push(0);
        assert_eq!(
            ExecutionWitness::decode(&extended),
            Err(WitnessDecodeError::TrailingBytes(1))
        );
    }

    #[test]
    fn re_encoding_a_decoded_witness_is_byte_identical() {
        // The encoding is canonical: decoding then re-encoding must reproduce
        // the exact bytes (no ambiguity, no reordering, no dropped fields).
        let bytes = sample().encode();
        let back = ExecutionWitness::decode(&bytes).unwrap();
        assert_eq!(back.encode(), bytes);
    }

    #[test]
    fn accepts_exactly_max_ancestors() {
        // 256 ancestors is the boundary: it decodes cleanly, while 257 is
        // rejected (see `rejects_too_many_ancestors`).
        let mut w = sample();
        w.ancestor_headers = (0..MAX_ANCESTOR_HEADERS as u64)
            .map(|height| AncestorHeader { height, hash: [0; 32] })
            .collect();
        let back = ExecutionWitness::decode(&w.encode()).unwrap();
        assert_eq!(back.ancestor_headers.len(), MAX_ANCESTOR_HEADERS);
        assert_eq!(w, back);
    }

    #[test]
    fn deposit_event_encoding_layout() {
        // Fixed 68-byte layout: source_hash(32) ‖ recipient(20) ‖ amount LE(16).
        let d = DepositEvent {
            source_hash: [0xAB; 32],
            recipient: [0xCD; 20],
            amount: 0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10,
        };
        let enc = d.encode();
        assert_eq!(enc.len(), 68);
        assert_eq!(&enc[0..32], &[0xAB; 32]);
        assert_eq!(&enc[32..52], &[0xCD; 20]);
        assert_eq!(&enc[52..68], &d.amount.to_le_bytes());
    }

    #[test]
    fn ancestor_and_deposit_counts_decode_independently() {
        // A witness with ancestors but no deposits, and vice-versa, must round
        // trip — the two trailing count-prefixed sections are not conflated.
        let mut only_ancestors = sample();
        only_ancestors.deposits.clear();
        assert_eq!(
            ExecutionWitness::decode(&only_ancestors.encode()).unwrap(),
            only_ancestors
        );

        let mut only_deposits = sample();
        only_deposits.ancestor_headers.clear();
        assert_eq!(
            ExecutionWitness::decode(&only_deposits.encode()).unwrap(),
            only_deposits
        );
    }

    #[test]
    fn rejects_too_many_ancestors() {
        let mut w = sample();
        w.ancestor_headers = (0..257u64)
            .map(|height| AncestorHeader { height, hash: [0; 32] })
            .collect();
        let bytes = w.encode();
        assert_eq!(
            ExecutionWitness::decode(&bytes),
            Err(WitnessDecodeError::TooManyAncestors(257))
        );
    }

    #[test]
    fn hostile_length_prefix_is_eof_not_alloc() {
        // A tx list claiming a 4 GiB item with no data must fail cleanly.
        let mut w = sample();
        w.txs.clear();
        let mut bytes = w.encode();
        // Locate the txs count (right after 1 + 96 + 32 bytes) and forge it.
        let off = 1 + 96 + 32;
        bytes[off..off + 4].copy_from_slice(&1u32.to_le_bytes());
        bytes.splice(off + 4..off + 4, u32::MAX.to_le_bytes());
        assert_eq!(
            ExecutionWitness::decode(&bytes),
            Err(WitnessDecodeError::UnexpectedEof)
        );
    }
}
