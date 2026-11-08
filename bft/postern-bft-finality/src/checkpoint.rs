// SPDX-License-Identifier: MIT OR Apache-2.0
//! The BFT checkpoint transcript and validator co-signatures: strict codecs.
//!
//! # SCAFFOLD — not a secure or deployed system
//!
//! A [`Checkpoint`] is the object a hashrate-weighted finality committee
//! co-signs (spec `§2`, `§4`): the committee epoch, the base height being
//! finalized, that block's hash, a hash-chain link to the previous checkpoint,
//! the epoch's **committee/weights commitment**, and the **frozen
//! `total_weight`**. A [`Vote`] is one seat's **opaque** ML-DSA-65 signature
//! over that checkpoint's canonical signing payload, tagged by the signer's
//! committee seat index.
//!
//! The `committee_commitment` and `total_weight` are **inside** the signed
//! payload (spec `§4.2`): each seat attests the exact epoch membership+weights
//! and the frozen `> 2/3` denominator, so a signature cannot be replayed under
//! a different committee or a re-normalized total.
//!
//! This module owns only the deterministic wire codecs and the canonical
//! signing payload. Whether votes covering `> 2/3` of `total_weight` exist to
//! *finalize* a checkpoint is [`crate::quorum`]'s job; whether the finalized
//! base can itself be reorged/forged is a property of the base, capped at
//! `min(base security, committee security)` (spec reorg gate).
//!
//! ## Wire layout — [`Checkpoint`] (fixed 128 bytes, all integers little-endian)
//!
//! ```text
//! offset  size  field
//! 0       8     committee_epoch      u64  LE
//! 8       8     finalized_height     u64  LE
//! 16      32    finalized_block_hash [u8; 32]
//! 48      32    prev_checkpoint_hash [u8; 32]
//! 80      32    committee_commitment [u8; 32]   // sorted (coinbase ‖ pubkey ‖ weight)
//! 112     16    total_weight         u128 LE    // FROZEN epoch total weight
//! 128 = total
//! ```
//!
//! ## Wire layout — [`Vote`] (variable length, little-endian)
//!
//! ```text
//! offset  size  field
//! 0       4     validator_index  u32 LE   (committee seat index of the signer)
//! 4       4     sig_len          u32 LE   (opaque signature byte length)
//! 8       ..    sig              [sig_len] opaque ML-DSA-65 signature bytes
//! ```
//!
//! Decoding is *strict*: exact lengths, no truncation, no trailing bytes; every
//! malformed input yields a typed [`CheckpointCodecError`], never a panic.

/// Domain-separation tag prefixed to the canonical signing payload so a
/// checkpoint signature can never be replayed as any other message. Bumped to
/// the `-v1` weighted-BFT domain (spec `§4.2`) — explicitly not an audited wire
/// format.
pub const CHECKPOINT_SIGNING_DOMAIN: &[u8] = b"POSTERN-FFG-BFT-CHECKPOINT-v1";

/// Fixed encoded size of a [`Checkpoint`]: `8 + 8 + 32 + 32 + 32 + 16 = 128`
/// bytes.
pub const CHECKPOINT_LEN: usize = 128;

/// A BFT finality checkpoint: the transcript a hashrate-weighted committee
/// co-signs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    /// The committee epoch whose weighted validator set signs this checkpoint.
    pub committee_epoch: u64,
    /// The Bloch base height being finalized by this checkpoint.
    pub finalized_height: u64,
    /// The base block hash at `finalized_height`.
    pub finalized_block_hash: [u8; 32],
    /// Hash-chain link to the previous checkpoint's canonical bytes
    /// (all-zero for the genesis checkpoint). The reader supplies the hash;
    /// this checkpoint codec stays hash-agnostic (see
    /// [`crate::anchor::link`]).
    pub prev_checkpoint_hash: [u8; 32],
    /// Commitment to the epoch's **membership+weights** — a hash over the
    /// sorted `(coinbase_addr ‖ ml_dsa_pubkey ‖ weight)` set (spec `§4.4`,
    /// `§4.6`). Signed by each seat, so every signer attests the exact
    /// committee; on a hand-off checkpoint this names the *incoming* committee
    /// (spec `§3.3`). This crate is hash-agnostic: the reader computes it.
    pub committee_commitment: [u8; 32],
    /// The **frozen** total weight of the signing committee (spec `§3.2`). It
    /// is the denominator of the `> 2/3` quorum rule and is never re-normalized
    /// mid-epoch. Signed by each seat so the denominator cannot be forged.
    pub total_weight: u128,
}

impl Checkpoint {
    /// Encode to the canonical fixed 128-byte wire form.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CHECKPOINT_LEN);
        out.extend_from_slice(&self.committee_epoch.to_le_bytes());
        out.extend_from_slice(&self.finalized_height.to_le_bytes());
        out.extend_from_slice(&self.finalized_block_hash);
        out.extend_from_slice(&self.prev_checkpoint_hash);
        out.extend_from_slice(&self.committee_commitment);
        out.extend_from_slice(&self.total_weight.to_le_bytes());
        debug_assert_eq!(out.len(), CHECKPOINT_LEN);
        out
    }

    /// Strict decode. Rejects truncation and trailing bytes with a typed
    /// [`CheckpointCodecError`]; never panics on any input.
    pub fn decode(bytes: &[u8]) -> Result<Checkpoint, CheckpointCodecError> {
        let mut cur = Cursor::new(bytes);
        let committee_epoch = cur.take_u64_le()?;
        let finalized_height = cur.take_u64_le()?;
        let finalized_block_hash = cur.take_32()?;
        let prev_checkpoint_hash = cur.take_32()?;
        let committee_commitment = cur.take_32()?;
        let total_weight = cur.take_u128_le()?;
        if !cur.is_exhausted() {
            return Err(CheckpointCodecError::TrailingBytes);
        }
        Ok(Checkpoint {
            committee_epoch,
            finalized_height,
            finalized_block_hash,
            prev_checkpoint_hash,
            committee_commitment,
            total_weight,
        })
    }

    /// The domain-separated canonical payload each seat signs.
    ///
    /// This is [`CHECKPOINT_SIGNING_DOMAIN`] followed by the canonical 128-byte
    /// checkpoint encoding — which includes `committee_commitment` and
    /// `total_weight`, so every signature binds the exact epoch membership and
    /// the frozen denominator (spec `§4.2`). Signatures are excluded (they sign
    /// this). This is the exact message passed to
    /// [`crate::quorum::CheckpointVerifier::verify`].
    pub fn canonical_signing_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CHECKPOINT_SIGNING_DOMAIN.len() + CHECKPOINT_LEN);
        out.extend_from_slice(CHECKPOINT_SIGNING_DOMAIN);
        out.extend_from_slice(&self.encode());
        out
    }
}

/// One validator's individual ML-DSA-65 co-signature over a checkpoint.
///
/// The signature is carried as **opaque bytes** — this crate never parses or
/// verifies it directly; verification is the [`crate::quorum::CheckpointVerifier`]
/// seam's job. ML-DSA has no aggregation (spec `§7`), so a full quorum carries
/// one of these per signer, each `~3309` bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vote {
    /// Committee seat index of the signing validator (position in the
    /// [`crate::committee::ValidatorSet`]).
    pub validator_index: u32,
    /// Opaque ML-DSA-65 signature bytes over the checkpoint's canonical
    /// signing payload.
    pub sig: Vec<u8>,
}

impl Vote {
    /// Encode to the canonical variable-length wire form
    /// (`validator_index` LE ‖ `sig_len` LE ‖ `sig`).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.sig.len());
        out.extend_from_slice(&self.validator_index.to_le_bytes());
        out.extend_from_slice(&(self.sig.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.sig);
        out
    }

    /// Strict decode of a single vote, requiring exact consumption (no
    /// trailing bytes). Never panics.
    pub fn decode(bytes: &[u8]) -> Result<Vote, CheckpointCodecError> {
        let mut cur = Cursor::new(bytes);
        let vote = Self::take_from(&mut cur)?;
        if !cur.is_exhausted() {
            return Err(CheckpointCodecError::TrailingBytes);
        }
        Ok(vote)
    }

    /// Take one vote off a shared cursor (used by [`decode_votes`]).
    fn take_from(cur: &mut Cursor<'_>) -> Result<Vote, CheckpointCodecError> {
        let validator_index = cur.take_u32_le()?;
        let sig_len = cur.take_u32_le()? as usize;
        let sig = cur.take(sig_len)?.to_vec();
        Ok(Vote { validator_index, sig })
    }
}

/// Encode a co-signature set: a `u32` LE count followed by each [`Vote`].
///
/// This is the reader-side aggregate of the individual votes gathered for one
/// checkpoint (spec `§4`). No aggregation of the signatures themselves — ML-DSA
/// has none; this is a plain length-prefixed sequence.
pub fn encode_votes(votes: &[Vote]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(votes.len() as u32).to_le_bytes());
    for v in votes {
        out.extend_from_slice(&v.encode());
    }
    out
}

/// Strict decode of a co-signature set encoded by [`encode_votes`]. Rejects
/// truncation and trailing bytes with a typed error; never panics.
pub fn decode_votes(bytes: &[u8]) -> Result<Vec<Vote>, CheckpointCodecError> {
    let mut cur = Cursor::new(bytes);
    let count = cur.take_u32_le()? as usize;
    let mut votes = Vec::with_capacity(count.min(1024)); // cap pre-alloc; count is untrusted
    for _ in 0..count {
        votes.push(Vote::take_from(&mut cur)?);
    }
    if !cur.is_exhausted() {
        return Err(CheckpointCodecError::TrailingBytes);
    }
    Ok(votes)
}

/// Typed decode failure. Every malformed-input class maps here; decoding never
/// panics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointCodecError {
    /// Payload ended before a required field was fully read.
    Truncated,
    /// Bytes remained after a complete, valid structure.
    TrailingBytes,
}

impl core::fmt::Display for CheckpointCodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CheckpointCodecError::Truncated => write!(f, "checkpoint codec: truncated payload"),
            CheckpointCodecError::TrailingBytes => write!(f, "checkpoint codec: trailing bytes"),
        }
    }
}

impl std::error::Error for CheckpointCodecError {}

// ── Bounds-checked cursor (no unsafe, no deps, checked arithmetic) ────────────

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CheckpointCodecError> {
        let end = self.pos.checked_add(n).ok_or(CheckpointCodecError::Truncated)?;
        if end > self.bytes.len() {
            return Err(CheckpointCodecError::Truncated);
        }
        let s = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn take_u32_le(&mut self) -> Result<u32, CheckpointCodecError> {
        let mut b = [0u8; 4];
        b.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(b))
    }

    fn take_u64_le(&mut self) -> Result<u64, CheckpointCodecError> {
        let mut b = [0u8; 8];
        b.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(b))
    }

    fn take_u128_le(&mut self) -> Result<u128, CheckpointCodecError> {
        let mut b = [0u8; 16];
        b.copy_from_slice(self.take(16)?);
        Ok(u128::from_le_bytes(b))
    }

    fn take_32(&mut self) -> Result<[u8; 32], CheckpointCodecError> {
        let mut b = [0u8; 32];
        b.copy_from_slice(self.take(32)?);
        Ok(b)
    }

    fn is_exhausted(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkpoint(epoch: u64, height: u64) -> Checkpoint {
        Checkpoint {
            committee_epoch: epoch,
            finalized_height: height,
            finalized_block_hash: [0xAB; 32],
            prev_checkpoint_hash: [0xCD; 32],
            committee_commitment: [0xEF; 32],
            total_weight: 1_000,
        }
    }

    // ── checkpoint byte layout, pinned to the spec ───────────────────────

    #[test]
    fn checkpoint_byte_layout_matches_spec() {
        let c = Checkpoint {
            committee_epoch: 0x0102_0304_0506_0708,
            finalized_height: 0x1112_1314_1516_1718,
            finalized_block_hash: [0x21; 32],
            prev_checkpoint_hash: [0x32; 32],
            committee_commitment: [0x43; 32],
            total_weight: 0x2122_2324_2526_2728_2930_3132_3334_3536,
        };
        let b = c.encode();
        assert_eq!(b.len(), CHECKPOINT_LEN);
        assert_eq!(CHECKPOINT_LEN, 128);
        assert_eq!(&b[0..8], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(&b[8..16], &0x1112_1314_1516_1718u64.to_le_bytes());
        assert_eq!(&b[16..48], &[0x21; 32]);
        assert_eq!(&b[48..80], &[0x32; 32]);
        assert_eq!(&b[80..112], &[0x43; 32]);
        assert_eq!(
            &b[112..128],
            &0x2122_2324_2526_2728_2930_3132_3334_3536u128.to_le_bytes()
        );
    }

    #[test]
    fn checkpoint_round_trip() {
        for c in [
            checkpoint(0, 0),
            checkpoint(1, 2),
            Checkpoint {
                committee_epoch: u64::MAX,
                finalized_height: u64::MAX,
                finalized_block_hash: [0x11; 32],
                prev_checkpoint_hash: [0x22; 32],
                committee_commitment: [0x33; 32],
                total_weight: u128::MAX,
            },
            Checkpoint {
                committee_epoch: 7,
                finalized_height: 9,
                finalized_block_hash: [0x00; 32],
                prev_checkpoint_hash: [0xFF; 32],
                committee_commitment: [0x00; 32],
                total_weight: 0,
            },
        ] {
            let bytes = c.encode();
            let decoded = Checkpoint::decode(&bytes).expect("valid checkpoint decodes");
            assert_eq!(decoded, c);
            assert_eq!(decoded.encode(), bytes);
        }
    }

    #[test]
    fn checkpoint_round_trip_distinct_field_bytes() {
        // Distinct bytes in each 32-byte field, so a swapped-offset bug fails.
        let mut c = checkpoint(42, 43);
        for (i, byte) in c.finalized_block_hash.iter_mut().enumerate() {
            *byte = i as u8;
        }
        for (i, byte) in c.prev_checkpoint_hash.iter_mut().enumerate() {
            *byte = 0x40 + i as u8;
        }
        for (i, byte) in c.committee_commitment.iter_mut().enumerate() {
            *byte = 0x80 + i as u8;
        }
        c.total_weight = 0x0011_2233_4455_6677_8899_AABB_CCDD_EEFF;
        assert_eq!(Checkpoint::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn checkpoint_rejects_truncation_at_every_prefix() {
        let full = checkpoint(7, 8).encode();
        for cut in 0..full.len() {
            assert_eq!(
                Checkpoint::decode(&full[..cut]),
                Err(CheckpointCodecError::Truncated),
                "cut {cut}"
            );
        }
    }

    #[test]
    fn checkpoint_rejects_trailing_bytes() {
        let mut b = checkpoint(7, 8).encode();
        b.push(0);
        assert_eq!(Checkpoint::decode(&b), Err(CheckpointCodecError::TrailingBytes));
        b.extend_from_slice(&[0xAB; 50]);
        assert_eq!(Checkpoint::decode(&b), Err(CheckpointCodecError::TrailingBytes));
    }

    #[test]
    fn signing_payload_is_domain_separated_and_deterministic() {
        let c = checkpoint(3, 4);
        let p = c.canonical_signing_payload();
        assert!(p.starts_with(CHECKPOINT_SIGNING_DOMAIN));
        assert_eq!(&p[CHECKPOINT_SIGNING_DOMAIN.len()..], &c.encode()[..]);
        assert_eq!(p, c.canonical_signing_payload());
        // A different checkpoint yields a different payload.
        assert_ne!(p, checkpoint(3, 5).canonical_signing_payload());
    }

    #[test]
    fn signing_payload_binds_committee_and_total_weight() {
        // Two checkpoints identical except for committee_commitment must sign
        // differently (each seat attests the exact membership).
        let mut a = checkpoint(3, 4);
        let mut b = a.clone();
        b.committee_commitment = [0x01; 32];
        assert_ne!(a.canonical_signing_payload(), b.canonical_signing_payload());
        // ... and identical except for the frozen total_weight (the denominator
        // cannot be silently re-normalized under the same signatures).
        a.total_weight = 500;
        let mut c = a.clone();
        c.total_weight = 501;
        assert_ne!(a.canonical_signing_payload(), c.canonical_signing_payload());
    }

    // ── vote codec ───────────────────────────────────────────────────────

    #[test]
    fn vote_round_trip() {
        for v in [
            Vote { validator_index: 0, sig: vec![] },
            Vote { validator_index: 7, sig: vec![9u8; 3309] }, // real ML-DSA-65 size
            Vote { validator_index: u32::MAX, sig: vec![1, 2, 3, 4, 5] },
        ] {
            let bytes = v.encode();
            let decoded = Vote::decode(&bytes).expect("valid vote decodes");
            assert_eq!(decoded, v);
            assert_eq!(decoded.encode(), bytes);
        }
    }

    #[test]
    fn vote_byte_layout() {
        let v = Vote { validator_index: 0x0A0B_0C0D, sig: vec![0xEE, 0xFF] };
        let b = v.encode();
        assert_eq!(&b[0..4], &0x0A0B_0C0Du32.to_le_bytes());
        assert_eq!(&b[4..8], &2u32.to_le_bytes());
        assert_eq!(&b[8..10], &[0xEE, 0xFF]);
        assert_eq!(b.len(), 10);
    }

    #[test]
    fn vote_rejects_truncation_and_trailing() {
        let full = Vote { validator_index: 5, sig: vec![1, 2, 3] }.encode();
        for cut in 0..full.len() {
            assert_eq!(Vote::decode(&full[..cut]), Err(CheckpointCodecError::Truncated), "cut {cut}");
        }
        let mut trailing = full.clone();
        trailing.push(0);
        assert_eq!(Vote::decode(&trailing), Err(CheckpointCodecError::TrailingBytes));
        // A sig_len claiming more bytes than are present must be Truncated,
        // never a panic or over-read.
        let mut lying = Vec::new();
        lying.extend_from_slice(&1u32.to_le_bytes()); // validator_index
        lying.extend_from_slice(&1000u32.to_le_bytes()); // sig_len = 1000, but no bytes follow
        assert_eq!(Vote::decode(&lying), Err(CheckpointCodecError::Truncated));
    }

    #[test]
    fn votes_set_round_trip() {
        let votes = vec![
            Vote { validator_index: 0, sig: vec![0xA0; 16] },
            Vote { validator_index: 1, sig: vec![0xA1; 32] },
            Vote { validator_index: 2, sig: vec![] },
        ];
        let bytes = encode_votes(&votes);
        assert_eq!(decode_votes(&bytes).unwrap(), votes);
        assert_eq!(decode_votes(&encode_votes(&[])).unwrap(), Vec::<Vote>::new());
    }

    #[test]
    fn votes_set_rejects_lying_count() {
        // Count says 5 votes but the buffer holds one => Truncated, no panic.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&5u32.to_le_bytes());
        bytes.extend_from_slice(&Vote { validator_index: 0, sig: vec![1] }.encode());
        assert_eq!(decode_votes(&bytes), Err(CheckpointCodecError::Truncated));
    }

    // ── malformed input never panics ─────────────────────────────────────

    #[test]
    fn decoders_never_panic_on_garbage() {
        // Deterministic xorshift byte soup, no deps: every decoder must return
        // (valid or typed-error) for every input, never panic.
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        for len in 0..600usize {
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                buf.push(state as u8);
            }
            let _ = Checkpoint::decode(&buf);
            let _ = Vote::decode(&buf);
            let _ = decode_votes(&buf);
        }
    }
}
