// SPDX-License-Identifier: MIT OR Apache-2.0
//! `BFT0` checkpoint-anchor wire format: strict encode/decode + extraction.
//!
//! # SCAFFOLD — not a secure or deployed system
//!
//! Spec: `docs/specs/POSTERN-FFG-BFT-FINALITY.md` (`§4`). Byte-for-byte in the
//! L2V0 / TKV0 idiom (`l2/bloch-l2-anchor`, `crates/bloch-tokens`): little-
//! endian, strict decode, first-envelope-wins, malformed ⇒ layer no-op, output
//! `value` MUST be `0`.
//!
//! A finalized BFT checkpoint is written to the **ownerless** Bloch base as an
//! ordinary **zero-value output** in a normal transaction that whoever pays the
//! fee can broadcast. Bloch nodes never parse `BFT0`: no new consensus rule, no
//! operator, no permission. Finality/quorum meaning lives entirely in the
//! off-consensus reader; a malformed or unsigned checkpoint anchor is a reader
//! no-op that leaves the carrying Bloch transaction valid. The base stays
//! ownerless and unchanged — this is a finality *overlay*, not a base-consensus
//! change; **coins do not vote, hashrate does**.
//!
//! An envelope is the `script_pubkey` of a **zero-value** output, fixed 165
//! bytes (all multi-byte integers little-endian):
//!
//! ```text
//! offset  size  field
//! 0       4     magic ASCII "BFT0"       (42 46 54 30)
//! 4       1     version u8 = 0x01                     // 0x01 = weighted;
//!                                                     //   0x00 (count-based) retired
//! 5       8     committee_epoch      u64  LE
//! 13      8     finalized_height     u64  LE
//! 21      32    finalized_block_hash [u8; 32]
//! 53      32    prev_checkpoint_hash [u8; 32]
//! 85      32    quorum_commitment    [u8; 32]         // sorted weighted-signer set
//! 117     32    committee_commitment [u8; 32]         // sorted membership+weights;
//!                                                     //   on a hand-off, the INCOMING committee
//! 149     16    total_weight         u128 LE          // FROZEN epoch total weight
//! 165 = total
//! ```
//!
//! The `quorum_commitment` commits to the weighted-signer set that finalized
//! this checkpoint (covering `> 2/3` of `total_weight`); the
//! `committee_commitment` commits to the epoch's sorted membership+weights; and
//! `total_weight` pins the frozen `> 2/3` denominator on-base so quorum can be
//! checked without trusting the out-of-band roster's sum (spec `§4.3`, `§4.6`).
//! None of the raw signatures ride on-base — a full ML-DSA-65 signature is
//! `~3309` bytes each, far too large; the reader reconstructs the signer set +
//! roster out of band and checks them against these commitments (via
//! [`crate::quorum`] + a real verifier). This anchor codec stays
//! **hash-agnostic** and pulls in no crypto of its own (the crate's only default
//! dependency is the `ml-dsa` verify primitive used by [`crate::quorum`];
//! `--no-default-features` drops even that).
//!
//! **Layout `version 0x00` (the retired count-based `2f+1`, 117-byte envelope)
//! is not accepted** — a reader that sees `0x00` treats it as an unsupported
//! version (reader no-op), never as a valid weighted checkpoint.
//!
//! Decoding is *strict*: exact magic, exact version, exact length (no
//! truncation, no trailing bytes). All offset arithmetic is checked; malformed
//! input always yields a typed [`EnvelopeError`], never a panic.

// ── Mirror types ──────────────────────────────────────────────────────────────
//
// `Tx` / `TxIn` / `TxOut` mirror `bloch_crypto::core::{Transaction, TxInput,
// TxOutput}` at BlochSISPoW rev dd8df3526518ba792057708a6aa0efd5a91d8e40 (the
// same mirrors `l2/bloch-l2-anchor` and `bloch-tokens` carry). Copied (not
// imported via a git dependency) so this crate stays zero-dep and offline-
// buildable; only the fields an anchor reader needs are mirrored (signature
// material omitted — the node already validated the transaction).

/// Mirror of `bloch_crypto::core::TxOutput` (rev dd8df35):
/// `{ value: u64, script_pubkey: Vec<u8> }`. The anchor convention reuses the
/// free-form `script_pubkey` field to carry the envelope bytes in a zero-value
/// output (node validation never constrains an *output* script_pubkey — that is
/// what makes this zero consensus change).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    /// Output value in BLCH base units. MUST be `0` for an anchor output.
    pub value: u64,
    /// Free-form output script carrying the envelope bytes.
    pub script_pubkey: Vec<u8>,
}

/// Mirror of `bloch_crypto::core::TxInput` (rev dd8df35), reduced to the
/// outpoint fields a reader needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIn {
    /// Previous transaction id being spent.
    pub prev_txid: [u8; 32],
    /// Index of the spent output in the previous transaction.
    pub prev_index: u32,
}

/// Mirror of `bloch_crypto::core::Transaction` (rev dd8df35), reduced to the
/// fields an envelope reader needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx {
    /// Transaction version.
    pub version: u32,
    /// Transaction inputs.
    pub inputs: Vec<TxIn>,
    /// Transaction outputs (one may carry a `BFT0` anchor envelope).
    pub outputs: Vec<TxOut>,
    /// Transaction locktime.
    pub locktime: u32,
}

// ── Wire constants ────────────────────────────────────────────────────────────

/// 4-byte magic prefix identifying a `BFT0` checkpoint-anchor envelope
/// (`42 46 54 30`). Distinct from L2V0 (`4C 32 56 30`) and TKV0.
pub const ENVELOPE_MAGIC: [u8; 4] = *b"BFT0";
/// Wire-format version this crate encodes and accepts: `0x01`, the
/// **hashrate-weighted** layout. `0x00` (the retired count-based `2f+1`) is
/// rejected as an unsupported version.
pub const ENVELOPE_VERSION: u8 = 0x01;
/// Exact encoded size of a `BFT0` checkpoint-anchor envelope:
/// `4 + 1 + 8 + 8 + 32 + 32 + 32 + 32 + 16 = 165` bytes.
pub const ENVELOPE_LEN: usize = 165;

// ── Errors ────────────────────────────────────────────────────────────────────

/// Typed decode/validation failure. Every malformed-input class maps here;
/// decoding never panics. At the anchor layer every one of these means
/// "no-op" — the Bloch transaction itself stays valid regardless.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Payload does not start with [`ENVELOPE_MAGIC`].
    BadMagic,
    /// Magic matched but the version byte is not [`ENVELOPE_VERSION`] (e.g. the
    /// retired `0x00` count-based layout).
    BadVersion(u8),
    /// Payload ended before a required field was fully read
    /// (shorter than [`ENVELOPE_LEN`]).
    Truncated,
    /// Bytes remain after a complete, valid envelope
    /// (longer than [`ENVELOPE_LEN`]).
    TrailingBytes,
    /// The output carrying the envelope has `value != 0`. Envelopes must ride
    /// zero-value outputs so no BLCH is ever locked behind them (the node's own
    /// indexer reads `script_pubkey[..20]` as an address when the script is
    /// `>= 20` bytes, so BLCH sent to an envelope output is stranded).
    NonZeroValue(u64),
    /// The envelope decoded cleanly but its `finalized_height` is **below**
    /// [`crate::FFG_ACTIVATION_HEIGHT`], so the FFG-BFT overlay is inactive for
    /// it: an activation-gated reader ([`decode_active_anchor_output`] /
    /// [`extract_active_anchor`]) treats it as no anchor. The ungated codec
    /// never produces this — it is purely an activation-gate outcome.
    Inert { finalized_height: u64, activation_height: u64 },
}

impl core::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "bft0 envelope: bad magic"),
            Self::BadVersion(v) => write!(f, "bft0 envelope: unsupported version {v}"),
            Self::Truncated => write!(f, "bft0 envelope: truncated payload"),
            Self::TrailingBytes => write!(f, "bft0 envelope: trailing bytes after payload"),
            Self::NonZeroValue(v) => write!(f, "bft0 envelope: output value must be 0, got {v}"),
            Self::Inert { finalized_height, activation_height } => write!(
                f,
                "bft0 envelope: finalized_height {finalized_height} is below FFG activation height {activation_height} (overlay inert)"
            ),
        }
    }
}

impl std::error::Error for EnvelopeError {}

// ── CheckpointEnvelope ─────────────────────────────────────────────────────────

/// A decoded `BFT0` checkpoint anchor: one finalized BFT checkpoint's
/// commitments written to Bloch as an ordinary zero-value output.
///
/// This is the *reader-side* record only. Nothing here is verified by this
/// crate — a decoded envelope is a **claim** by whoever paid the Bloch fee.
/// Verifying that `quorum_commitment` really corresponds to a set of valid
/// ML-DSA-65 signatures covering `> 2/3` of `total_weight`, and that
/// `committee_commitment` names the correct epoch membership, belongs to
/// [`crate::quorum`] plus a real verifier, which is NOT this crate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointEnvelope {
    /// Committee epoch whose weighted validator set finalized this checkpoint.
    pub committee_epoch: u64,
    /// Bloch base height finalized by this checkpoint.
    pub finalized_height: u64,
    /// Base block hash at `finalized_height`.
    pub finalized_block_hash: [u8; 32],
    /// Hash of the previous checkpoint's canonical bytes (the chain spine);
    /// all-zero for the genesis checkpoint. See [`link`].
    pub prev_checkpoint_hash: [u8; 32],
    /// 32-byte commitment to the weighted-signer set that finalized this
    /// checkpoint (covering `> 2/3` of `total_weight`) — not the signatures
    /// themselves.
    pub quorum_commitment: [u8; 32],
    /// 32-byte commitment to the epoch's sorted membership+weights
    /// (`coinbase_addr ‖ ml_dsa_pubkey ‖ weight`). On a hand-off checkpoint
    /// (epoch increment) this names the **incoming** committee, vouched by the
    /// outgoing quorum (spec `§3.3`, `§4.6`).
    pub committee_commitment: [u8; 32],
    /// The **frozen** epoch total weight of the signing committee — the pinned
    /// `> 2/3` denominator (spec `§3.2`). Never re-normalized mid-epoch; [`link`]
    /// enforces intra-epoch equality.
    pub total_weight: u128,
}

impl CheckpointEnvelope {
    /// Encode to the canonical 165-byte wire form (always decodable by
    /// [`CheckpointEnvelope::decode`]).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENVELOPE_LEN);
        out.extend_from_slice(&ENVELOPE_MAGIC);
        out.push(ENVELOPE_VERSION);
        out.extend_from_slice(&self.committee_epoch.to_le_bytes());
        out.extend_from_slice(&self.finalized_height.to_le_bytes());
        out.extend_from_slice(&self.finalized_block_hash);
        out.extend_from_slice(&self.prev_checkpoint_hash);
        out.extend_from_slice(&self.quorum_commitment);
        out.extend_from_slice(&self.committee_commitment);
        out.extend_from_slice(&self.total_weight.to_le_bytes());
        debug_assert_eq!(out.len(), ENVELOPE_LEN);
        out
    }

    /// Strict decode. Rejects bad magic, bad version, truncation and trailing
    /// bytes — each with a typed [`EnvelopeError`]. Never panics on any input.
    pub fn decode(bytes: &[u8]) -> Result<CheckpointEnvelope, EnvelopeError> {
        let mut cur = Cursor::new(bytes);

        if cur.take(4)? != ENVELOPE_MAGIC {
            return Err(EnvelopeError::BadMagic);
        }
        let version = cur.take_u8()?;
        if version != ENVELOPE_VERSION {
            return Err(EnvelopeError::BadVersion(version));
        }
        let committee_epoch = cur.take_u64_le()?;
        let finalized_height = cur.take_u64_le()?;
        let finalized_block_hash = cur.take_32()?;
        let prev_checkpoint_hash = cur.take_32()?;
        let quorum_commitment = cur.take_32()?;
        let committee_commitment = cur.take_32()?;
        let total_weight = cur.take_u128_le()?;

        if !cur.is_exhausted() {
            return Err(EnvelopeError::TrailingBytes);
        }
        Ok(CheckpointEnvelope {
            committee_epoch,
            finalized_height,
            finalized_block_hash,
            prev_checkpoint_hash,
            quorum_commitment,
            committee_commitment,
            total_weight,
        })
    }
}

// ── Extraction from a transaction ─────────────────────────────────────────────

/// Decode the envelope carried by a single output, enforcing the zero-value
/// rule: an output whose `script_pubkey` starts with [`ENVELOPE_MAGIC`] but
/// whose `value != 0` is a typed [`EnvelopeError::NonZeroValue`].
pub fn decode_anchor_output(out: &TxOut) -> Result<CheckpointEnvelope, EnvelopeError> {
    if !out.script_pubkey.starts_with(&ENVELOPE_MAGIC) {
        return Err(EnvelopeError::BadMagic);
    }
    if out.value != 0 {
        return Err(EnvelopeError::NonZeroValue(out.value));
    }
    CheckpointEnvelope::decode(&out.script_pubkey)
}

/// Extract the transaction's checkpoint-anchor envelope, if any, together with
/// the envelope's output index.
///
/// Reader rules (part of the convention, so every independent reader agrees;
/// identical to L2V0's `extract_anchor` rules):
///
/// 1. **One envelope per tx, first wins.** The lowest-index output whose
///    `script_pubkey` starts with [`ENVELOPE_MAGIC`] is *the* candidate; later
///    magic-bearing outputs are ignored, valid or not.
/// 2. **Zero value.** The candidate must have `value == 0` and decode strictly;
///    otherwise the transaction carries **no** anchor (`None`) — a malformed
///    candidate does not fall through to later outputs, which would make anchor
///    state depend on reader order. The Bloch transaction stays valid either
///    way.
pub fn extract_anchor(tx: &Tx) -> Option<(usize, CheckpointEnvelope)> {
    let (idx, candidate) = tx
        .outputs
        .iter()
        .enumerate()
        .find(|(_, o)| o.script_pubkey.starts_with(&ENVELOPE_MAGIC))?;
    decode_anchor_output(candidate).ok().map(|env| (idx, env))
}

/// **Activation-gated** decode of a single anchor output. Identical to
/// [`decode_anchor_output`] except it additionally rejects any envelope whose
/// `finalized_height` is **below** [`crate::FFG_ACTIVATION_HEIGHT`] with
/// [`EnvelopeError::Inert`]. A well-formed envelope for a pre-activation height
/// decodes fine byte-wise but is **not** an active checkpoint anchor, so this
/// gated reader refuses it — the overlay is provably inert below the height.
pub fn decode_active_anchor_output(out: &TxOut) -> Result<CheckpointEnvelope, EnvelopeError> {
    let env = decode_anchor_output(out)?;
    if !crate::is_active(env.finalized_height) {
        return Err(EnvelopeError::Inert {
            finalized_height: env.finalized_height,
            activation_height: crate::FFG_ACTIVATION_HEIGHT,
        });
    }
    Ok(env)
}

/// **Activation-gated** anchor extraction: the anchor entry point a node
/// consults. It runs [`extract_anchor`] and then enforces
/// [`crate::FFG_ACTIVATION_HEIGHT`]: an extracted envelope whose
/// `finalized_height` is below the activation height yields `None`, so the
/// overlay accepts **no** checkpoint anchor for a pre-activation height (the
/// carrying Bloch transaction stays valid either way — this is a reader gate,
/// not a consensus rule).
///
/// Acceptance begins at **exactly** block
/// [`FFG_ACTIVATION_HEIGHT`](crate::FFG_ACTIVATION_HEIGHT): an envelope at
/// exactly that `finalized_height` extracts as `Some`. The ungated
/// [`extract_anchor`] keeps its pure, height-agnostic codec behaviour; a node
/// integration routes anchor reads through **this** function.
pub fn extract_active_anchor(tx: &Tx) -> Option<(usize, CheckpointEnvelope)> {
    let (idx, env) = extract_anchor(tx)?;
    crate::is_active(env.finalized_height).then_some((idx, env))
}

// ── Canonical-chain linkage ───────────────────────────────────────────────────

/// Why `next` is not the canonical successor of `prev` (see [`link`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkError {
    /// `next.prev_checkpoint_hash` does not equal the supplied commitment to
    /// `prev`'s canonical bytes: the checkpoint chain spine does not connect.
    PrevHashMismatch,
    /// `next.committee_epoch < prev.committee_epoch`: the committee epoch went
    /// backwards (it must be monotonic — equal within an epoch, greater across
    /// a rotation).
    EpochRegressed { prev: u64, next: u64 },
    /// `next.finalized_height <= prev.finalized_height`: finality must strictly
    /// advance (checkpoints may skip base heights, so this is strictly-greater,
    /// not `+1`).
    HeightNotAdvancing { prev: u64, next: u64 },
    /// Intra-epoch (`next.committee_epoch == prev.committee_epoch`) the
    /// `committee_commitment` changed — the committee is frozen within an epoch
    /// and may only change at a rotation boundary (spec `§3.2`, `§4.6`).
    CommitteeChangedWithinEpoch,
    /// Intra-epoch the `total_weight` changed — the `> 2/3` denominator is
    /// frozen and is **never re-normalized** mid-epoch (spec `§3.2`); shrinking
    /// it would break quorum-intersection.
    TotalWeightChangedWithinEpoch { prev: u128, next: u128 },
}

impl core::fmt::Display for LinkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PrevHashMismatch => {
                write!(f, "bft0 link: next.prev_checkpoint_hash does not commit to prev")
            }
            Self::EpochRegressed { prev, next } => {
                write!(f, "bft0 link: committee_epoch {next} regressed from {prev}")
            }
            Self::HeightNotAdvancing { prev, next } => {
                write!(f, "bft0 link: finalized_height {next} does not advance past {prev}")
            }
            Self::CommitteeChangedWithinEpoch => write!(
                f,
                "bft0 link: committee_commitment changed within an epoch (frozen; rotate to change)"
            ),
            Self::TotalWeightChangedWithinEpoch { prev, next } => write!(
                f,
                "bft0 link: total_weight {next} re-normalized from {prev} within an epoch (frozen)"
            ),
        }
    }
}

impl std::error::Error for LinkError {}

/// Pure canonical-chain check: is `next` the canonical successor of `prev`?
///
/// `prev_canonical_hash` is the 32-byte commitment to `prev`'s canonical bytes
/// (`prev.encode()`), computed by the reader with its chosen hash (SHAKE-256 in
/// the spec). This anchor codec stays **hash-agnostic**, so the hash is
/// supplied by the caller rather than computed here.
///
/// Holds iff:
/// * `next.prev_checkpoint_hash == prev_canonical_hash` (the chain spine), and
/// * `next.committee_epoch >= prev.committee_epoch` (epoch monotonic), and
/// * `next.finalized_height > prev.finalized_height` (finality strictly
///   advances; checkpoints skip base heights, so strictly-greater, not `+1`),
///   and
/// * **intra-epoch** (`next.committee_epoch == prev.committee_epoch`) the
///   `committee_commitment` and `total_weight` are **unchanged** — the on-chain
///   enforcement of the no-mid-epoch-re-normalization invariant (spec `§3.2`,
///   `§4.6`). **Across a rotation** (epoch strictly greater) both may differ:
///   `committee_commitment` then names the incoming committee, vouched by the
///   outgoing quorum (the hand-off, spec `§3.3`).
///
/// This checks *linkage only*. It says nothing about whether either checkpoint
/// actually carries a valid `> 2/3`-weight quorum, nor whether the finalized
/// base can itself be reorged — those are [`crate::quorum`]'s and the base's
/// concerns.
pub fn link(
    prev: &CheckpointEnvelope,
    prev_canonical_hash: &[u8; 32],
    next: &CheckpointEnvelope,
) -> Result<(), LinkError> {
    if &next.prev_checkpoint_hash != prev_canonical_hash {
        return Err(LinkError::PrevHashMismatch);
    }
    if next.committee_epoch < prev.committee_epoch {
        return Err(LinkError::EpochRegressed {
            prev: prev.committee_epoch,
            next: next.committee_epoch,
        });
    }
    if next.finalized_height <= prev.finalized_height {
        return Err(LinkError::HeightNotAdvancing {
            prev: prev.finalized_height,
            next: next.finalized_height,
        });
    }
    // Intra-epoch: the committee and its denominator are frozen. Only a rotation
    // (strictly greater epoch) may change them.
    if next.committee_epoch == prev.committee_epoch {
        if next.committee_commitment != prev.committee_commitment {
            return Err(LinkError::CommitteeChangedWithinEpoch);
        }
        if next.total_weight != prev.total_weight {
            return Err(LinkError::TotalWeightChangedWithinEpoch {
                prev: prev.total_weight,
                next: next.total_weight,
            });
        }
    }
    Ok(())
}

// ── Bounds-checked cursor (no unsafe, no deps, checked arithmetic) ────────────

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], EnvelopeError> {
        let end = self.pos.checked_add(n).ok_or(EnvelopeError::Truncated)?;
        if end > self.bytes.len() {
            return Err(EnvelopeError::Truncated);
        }
        let s = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn take_u8(&mut self) -> Result<u8, EnvelopeError> {
        Ok(self.take(1)?[0])
    }

    fn take_u64_le(&mut self) -> Result<u64, EnvelopeError> {
        let mut b = [0u8; 8];
        b.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(b))
    }

    fn take_u128_le(&mut self) -> Result<u128, EnvelopeError> {
        let mut b = [0u8; 16];
        b.copy_from_slice(self.take(16)?);
        Ok(u128::from_le_bytes(b))
    }

    fn take_32(&mut self) -> Result<[u8; 32], EnvelopeError> {
        let mut b = [0u8; 32];
        b.copy_from_slice(self.take(32)?);
        Ok(b)
    }

    fn is_exhausted(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn env(finalized_height: u64) -> CheckpointEnvelope {
        CheckpointEnvelope {
            committee_epoch: 1,
            finalized_height,
            finalized_block_hash: [0x33; 32],
            prev_checkpoint_hash: [0x44; 32],
            quorum_commitment: [0x55; 32],
            committee_commitment: [0x66; 32],
            total_weight: 1_000,
        }
    }

    fn envelope_out(e: &CheckpointEnvelope) -> TxOut {
        TxOut { value: 0, script_pubkey: e.encode() }
    }

    fn plain_out() -> TxOut {
        TxOut { value: 5_000, script_pubkey: vec![0xEE; 20] }
    }

    fn tx(outputs: Vec<TxOut>) -> Tx {
        Tx { version: 1, inputs: vec![], outputs, locktime: 0 }
    }

    // ── byte layout pinned to the spec ───────────────────────────────────

    #[test]
    fn byte_layout_matches_spec() {
        let e = CheckpointEnvelope {
            committee_epoch: 0x0102_0304_0506_0708,
            finalized_height: 0x1112_1314_1516_1718,
            finalized_block_hash: [0xA1; 32],
            prev_checkpoint_hash: [0xB2; 32],
            quorum_commitment: [0xC3; 32],
            committee_commitment: [0xD4; 32],
            total_weight: 0x2122_2324_2526_2728_2930_3132_3334_3536,
        };
        let b = e.encode();
        assert_eq!(b.len(), ENVELOPE_LEN);
        assert_eq!(ENVELOPE_LEN, 165);
        assert_eq!(&b[0..4], b"BFT0"); // magic at 0
        assert_eq!(b[4], 0x01); // version at 4 (weighted)
        assert_eq!(&b[5..13], &0x0102_0304_0506_0708u64.to_le_bytes()); // committee_epoch at 5
        assert_eq!(&b[13..21], &0x1112_1314_1516_1718u64.to_le_bytes()); // finalized_height at 13
        assert_eq!(&b[21..53], &[0xA1; 32]); // finalized_block_hash at 21
        assert_eq!(&b[53..85], &[0xB2; 32]); // prev_checkpoint_hash at 53
        assert_eq!(&b[85..117], &[0xC3; 32]); // quorum_commitment at 85
        assert_eq!(&b[117..149], &[0xD4; 32]); // committee_commitment at 117
        assert_eq!(
            &b[149..165],
            &0x2122_2324_2526_2728_2930_3132_3334_3536u128.to_le_bytes()
        ); // total_weight at 149
    }

    // ── round trips ──────────────────────────────────────────────────────

    #[test]
    fn round_trip() {
        for e in [
            env(0),
            env(1),
            env(u64::MAX),
            CheckpointEnvelope {
                committee_epoch: 0,
                finalized_height: 0,
                finalized_block_hash: [0x00; 32],
                prev_checkpoint_hash: [0x00; 32],
                quorum_commitment: [0xFF; 32],
                committee_commitment: [0x11; 32],
                total_weight: u128::MAX,
            },
        ] {
            let bytes = e.encode();
            let decoded = CheckpointEnvelope::decode(&bytes).expect("valid envelope decodes");
            assert_eq!(decoded, e);
            assert_eq!(decoded.encode(), bytes);
        }
    }

    #[test]
    fn round_trip_distinct_field_bytes() {
        // Every 32-byte field distinct, so a swapped-offset bug cannot pass.
        let mut e = env(42);
        for (i, byte) in e.finalized_block_hash.iter_mut().enumerate() {
            *byte = i as u8;
        }
        for (i, byte) in e.prev_checkpoint_hash.iter_mut().enumerate() {
            *byte = 0x40 + i as u8;
        }
        for (i, byte) in e.quorum_commitment.iter_mut().enumerate() {
            *byte = 0x80 + i as u8;
        }
        for (i, byte) in e.committee_commitment.iter_mut().enumerate() {
            *byte = 0xC0 + i as u8;
        }
        e.total_weight = 0x0011_2233_4455_6677_8899_AABB_CCDD_EEFF;
        assert_eq!(CheckpointEnvelope::decode(&e.encode()).unwrap(), e);
    }

    // ── malformed classes → typed errors, never panics ───────────────────

    #[test]
    fn rejects_bad_magic() {
        let mut b = env(1).encode();
        b[0] ^= 0xFF;
        assert_eq!(CheckpointEnvelope::decode(&b), Err(EnvelopeError::BadMagic));
        // L2V0 magic is NOT a BFT0 envelope.
        let mut l2v0 = env(1).encode();
        l2v0[..4].copy_from_slice(b"L2V0");
        assert_eq!(CheckpointEnvelope::decode(&l2v0), Err(EnvelopeError::BadMagic));
        assert_eq!(CheckpointEnvelope::decode(b"XXXX"), Err(EnvelopeError::BadMagic));
        assert_eq!(CheckpointEnvelope::decode(&[]), Err(EnvelopeError::Truncated));
    }

    #[test]
    fn rejects_bad_version() {
        let mut b = env(1).encode();
        // The retired count-based layout used version 0x00 — must be rejected.
        b[4] = 0x00;
        assert_eq!(CheckpointEnvelope::decode(&b), Err(EnvelopeError::BadVersion(0x00)));
        b[4] = 0xFF;
        assert_eq!(CheckpointEnvelope::decode(&b), Err(EnvelopeError::BadVersion(0xFF)));
    }

    #[test]
    fn rejects_truncation_at_every_prefix() {
        let full = env(7).encode();
        for cut in 0..full.len() {
            let err = CheckpointEnvelope::decode(&full[..cut]).expect_err("strict prefix must fail");
            assert!(
                matches!(err, EnvelopeError::Truncated | EnvelopeError::BadMagic),
                "unexpected error at cut {cut}: {err:?}"
            );
        }
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut b = env(7).encode();
        b.push(0x00);
        assert_eq!(CheckpointEnvelope::decode(&b), Err(EnvelopeError::TrailingBytes));
        b.extend_from_slice(&[0xAB; 100]);
        assert_eq!(CheckpointEnvelope::decode(&b), Err(EnvelopeError::TrailingBytes));
    }

    #[test]
    fn never_panics_on_random_ish_garbage() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        for len in 0..400usize {
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                buf.push(state as u8);
            }
            let _ = CheckpointEnvelope::decode(&buf); // must not panic
        }
    }

    // ── extraction rules ─────────────────────────────────────────────────

    #[test]
    fn extract_finds_envelope_among_plain_outputs() {
        let t = tx(vec![plain_out(), envelope_out(&env(3)), plain_out()]);
        assert_eq!(extract_anchor(&t), Some((1, env(3))));
    }

    #[test]
    fn extract_none_without_envelope() {
        assert_eq!(extract_anchor(&tx(vec![plain_out(), plain_out()])), None);
        assert_eq!(extract_anchor(&tx(vec![])), None);
    }

    #[test]
    fn extract_enforces_zero_value() {
        let bad = TxOut { value: 1, script_pubkey: env(3).encode() };
        assert_eq!(extract_anchor(&tx(vec![bad.clone()])), None);
        assert_eq!(decode_anchor_output(&bad), Err(EnvelopeError::NonZeroValue(1)));
    }

    #[test]
    fn extract_first_envelope_wins() {
        // Two valid envelopes: the lowest output index wins.
        let t = tx(vec![envelope_out(&env(9)), envelope_out(&env(10))]);
        assert_eq!(extract_anchor(&t), Some((0, env(9))));

        // First candidate malformed (truncated): the tx carries NO anchor —
        // a later valid envelope must NOT be promoted.
        let mut truncated = env(9).encode();
        truncated.truncate(truncated.len() - 1);
        let t = tx(vec![
            TxOut { value: 0, script_pubkey: truncated },
            envelope_out(&env(10)),
        ]);
        assert_eq!(extract_anchor(&t), None);

        // First candidate has nonzero value: same rule, no fall-through.
        let t = tx(vec![
            TxOut { value: 7, script_pubkey: env(9).encode() },
            envelope_out(&env(10)),
        ]);
        assert_eq!(extract_anchor(&t), None);
    }

    // ── activation gate: overlay is inert below FFG_ACTIVATION_HEIGHT ─────

    #[test]
    fn gated_extract_is_none_below_activation_height() {
        // A perfectly well-formed anchor for a pre-activation height decodes
        // byte-wise but is NOT an active anchor: the gated reader returns None.
        for h in [0u64, 1, 3, crate::FFG_ACTIVATION_HEIGHT - 1] {
            let t = tx(vec![plain_out(), envelope_out(&env(h)), plain_out()]);
            // The ungated reader still extracts it (pure codec, height-agnostic).
            assert_eq!(extract_anchor(&t), Some((1, env(h))), "ungated extract at h={h}");
            // The gated reader refuses it.
            assert_eq!(extract_active_anchor(&t), None, "gated extract must be None at h={h}");
            // And the single-output gated decode reports the typed Inert error.
            assert_eq!(
                decode_active_anchor_output(&envelope_out(&env(h))),
                Err(EnvelopeError::Inert {
                    finalized_height: h,
                    activation_height: crate::FFG_ACTIVATION_HEIGHT,
                }),
            );
        }
    }

    #[test]
    fn gated_extract_acceptance_begins_exactly_at_activation_height() {
        // Exactly at the activation height, and above it, the gated reader
        // accepts the anchor just like the ungated one.
        for h in [
            crate::FFG_ACTIVATION_HEIGHT,
            crate::FFG_ACTIVATION_HEIGHT + 1,
            crate::FFG_ACTIVATION_HEIGHT + 5_000_000,
            u64::MAX,
        ] {
            let e = env(h);
            let t = tx(vec![plain_out(), envelope_out(&e), plain_out()]);
            assert_eq!(
                extract_active_anchor(&t),
                Some((1, e.clone())),
                "gated extract must accept at h={h} (>= activation)"
            );
            assert_eq!(decode_active_anchor_output(&envelope_out(&e)), Ok(e));
        }
    }

    #[test]
    fn gated_decode_still_enforces_zero_value_and_codec_rules() {
        // The gate layers on top of the existing rules: a nonzero-value output at
        // an active height is still rejected for value, not accepted.
        let active = env(crate::FFG_ACTIVATION_HEIGHT);
        let bad_value = TxOut { value: 1, script_pubkey: active.encode() };
        assert_eq!(
            decode_active_anchor_output(&bad_value),
            Err(EnvelopeError::NonZeroValue(1))
        );
        // Bad magic still short-circuits before the height gate.
        let not_anchor = TxOut { value: 0, script_pubkey: vec![0xEE; 165] };
        assert_eq!(
            decode_active_anchor_output(&not_anchor),
            Err(EnvelopeError::BadMagic)
        );
    }

    // ── canonical-chain linkage ──────────────────────────────────────────

    fn linked_pair() -> (CheckpointEnvelope, [u8; 32], CheckpointEnvelope) {
        let prev = env(100);
        let prev_hash = [0x9A; 32]; // stand-in for the reader's hash(prev.encode())
        let next = CheckpointEnvelope {
            committee_epoch: prev.committee_epoch, // same epoch (monotonic ok)
            finalized_height: 150,                 // strictly advances
            finalized_block_hash: [0x66; 32],
            prev_checkpoint_hash: prev_hash,       // commits to prev
            quorum_commitment: [0x77; 32],
            committee_commitment: prev.committee_commitment, // frozen within epoch
            total_weight: prev.total_weight,                 // frozen within epoch
        };
        (prev, prev_hash, next)
    }

    #[test]
    fn link_accepts_canonical_successor() {
        let (prev, h, next) = linked_pair();
        assert_eq!(link(&prev, &h, &next), Ok(()));
        // and across an epoch rotation (epoch strictly greater): the committee
        // and total_weight MAY change (the hand-off names the incoming set).
        let mut rotated = next.clone();
        rotated.committee_epoch = prev.committee_epoch + 5;
        rotated.committee_commitment = [0xAB; 32]; // incoming committee
        rotated.total_weight = 2_000; // fresh frozen total
        assert_eq!(link(&prev, &h, &rotated), Ok(()));
    }

    #[test]
    fn link_rejects_prev_hash_mismatch() {
        let (prev, h, mut next) = linked_pair();
        next.prev_checkpoint_hash = [0xDE; 32]; // does not commit to prev
        assert_eq!(link(&prev, &h, &next), Err(LinkError::PrevHashMismatch));
    }

    #[test]
    fn link_rejects_epoch_regression() {
        let (mut prev, h, mut next) = linked_pair();
        prev.committee_epoch = 5;
        next.committee_epoch = 4; // regressed
        assert_eq!(
            link(&prev, &h, &next),
            Err(LinkError::EpochRegressed { prev: 5, next: 4 })
        );
    }

    #[test]
    fn link_rejects_non_advancing_height() {
        let (prev, h, mut next) = linked_pair();
        // equal height is not advancing
        next.finalized_height = prev.finalized_height;
        assert_eq!(
            link(&prev, &h, &next),
            Err(LinkError::HeightNotAdvancing { prev: 100, next: 100 })
        );
        // going backwards is not advancing either
        next.finalized_height = 50;
        assert_eq!(
            link(&prev, &h, &next),
            Err(LinkError::HeightNotAdvancing { prev: 100, next: 50 })
        );
    }

    #[test]
    fn link_rejects_intra_epoch_committee_change() {
        // Same epoch, but the committee_commitment changed => rejected (frozen).
        let (prev, h, mut next) = linked_pair();
        next.committee_commitment = [0x99; 32];
        assert_eq!(link(&prev, &h, &next), Err(LinkError::CommitteeChangedWithinEpoch));
    }

    #[test]
    fn link_rejects_intra_epoch_total_weight_renormalization() {
        // Same epoch, committee unchanged, but total_weight shrank => rejected:
        // the > 2/3 denominator is never re-normalized mid-epoch (spec §3.2).
        let (prev, h, mut next) = linked_pair();
        next.total_weight = prev.total_weight - 1;
        assert_eq!(
            link(&prev, &h, &next),
            Err(LinkError::TotalWeightChangedWithinEpoch {
                prev: prev.total_weight,
                next: prev.total_weight - 1,
            })
        );
    }

    #[test]
    fn link_chain_of_three_via_round_trip() {
        // Three checkpoints chained by hand, round-tripped through the wire
        // form, still link. Uses stand-in per-checkpoint hashes.
        let a = env(10);
        let a_hash = [0x0A; 32];
        let b = CheckpointEnvelope {
            committee_epoch: a.committee_epoch,
            finalized_height: 20,
            finalized_block_hash: [0x0B; 32],
            prev_checkpoint_hash: a_hash,
            quorum_commitment: [0xBB; 32],
            committee_commitment: a.committee_commitment, // frozen within epoch
            total_weight: a.total_weight,
        };
        let b_hash = [0x0B; 32];
        let c = CheckpointEnvelope {
            committee_epoch: a.committee_epoch + 1, // rotated committee
            finalized_height: 30,
            finalized_block_hash: [0x0C; 32],
            prev_checkpoint_hash: b_hash,
            quorum_commitment: [0xCC; 32],
            committee_commitment: [0xEE; 32], // incoming committee at the hand-off
            total_weight: 5_000,              // fresh frozen total after rotation
        };
        let decode = |e: &CheckpointEnvelope| CheckpointEnvelope::decode(&e.encode()).unwrap();
        let (a2, b2, c2) = (decode(&a), decode(&b), decode(&c));
        assert_eq!(link(&a2, &a_hash, &b2), Ok(()));
        assert_eq!(link(&b2, &b_hash, &c2), Ok(()));
        // a -> c does not link: c commits to b, not a.
        assert_eq!(link(&a2, &a_hash, &c2), Err(LinkError::PrevHashMismatch));
    }
}
