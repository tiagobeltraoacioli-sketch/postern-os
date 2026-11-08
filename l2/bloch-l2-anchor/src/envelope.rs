//! L2V0 COMMIT anchor wire format: strict encode/decode + extraction rules.
//!
//! Spec: `docs/specs/BLOCH-L2-EVM-DESIGN.md`, §1 "Interfaces / formats"
//! ("L2V0 anchor envelope"). Byte-for-byte in the TKV0 idiom
//! (`crates/bloch-tokens`): little-endian, strict decode, first-envelope-wins,
//! malformed ⇒ layer no-op, value MUST be 0 (TKV0 caveat E.1).
//!
//! An envelope is the `script_pubkey` of a **zero-value** transaction output,
//! laid out as (all multi-byte integers little-endian) — fixed 173 bytes:
//!
//! ```text
//! offset   size  field
//! 0        4     magic ASCII "L2V0"          (4C 32 56 30)
//! 4        1     version u8 = 0x00
//! 5        32    rollup_id       [u8; 32]    (keccak of the L2 genesis header)
//! 37       8     batch_index     u64 LE
//! 45       32    prev_state_root [u8; 32]    (Ethereum state root before batch)
//! 77       32    new_state_root  [u8; 32]    (Ethereum state root after batch)
//! 109      32    da_commitment   [u8; 32]    (hash of the DA batch blob)
//! 141      32    vkey_hash       [u8; 32]    (SP1 program vkey hash)
//! 173 = total
//! ```
//!
//! Decoding is *strict*: exact magic, exact version, exact length (no
//! truncation, no trailing bytes). All offset arithmetic is checked;
//! malformed input always yields a typed [`EnvelopeError`], never a panic.
//!
//! Reminder (see crate docs): this is an OFF-consensus reader convention.
//! Bloch nodes never parse or verify envelopes — a malformed envelope is an
//! anchor-layer no-op and NEVER invalidates the carrying Bloch transaction.
//! The base gains no operator and needs no consensus change.

// ── Mirror types ──────────────────────────────────────────────────────────────
//
// `Tx` / `TxIn` / `TxOut` mirror `bloch_crypto::core::{Transaction, TxInput,
// TxOutput}` at BlochSISPoW rev dd8df3526518ba792057708a6aa0efd5a91d8e40
// (the same mirrors `bloch-tokens` carries). They are copied (not imported
// via a git dependency) so this crate stays zero-dep and offline-buildable;
// only the fields an anchor reader needs are mirrored (`script_sig` /
// signature material omitted — the node already validated the transaction;
// the anchor layer only reads structure).

/// Mirror of `bloch_crypto::core::TxOutput` (rev dd8df35):
/// `{ value: u64, script_pubkey: Vec<u8> }`. In the upstream type
/// `script_pubkey` is a 20-byte pubkey hash for spendable outputs; the anchor
/// convention reuses the same free-form field to carry the envelope bytes in
/// a zero-value output. (Node validation never constrains an *output*
/// script_pubkey — that is what makes this zero consensus change.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

/// Mirror of `bloch_crypto::core::TxInput` (rev dd8df35), reduced to the
/// outpoint fields a reader needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIn {
    pub prev_txid: [u8; 32],
    pub prev_index: u32,
}

/// Mirror of `bloch_crypto::core::Transaction` (rev dd8df35), reduced to the
/// fields an envelope reader needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx {
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub locktime: u32,
}

// ── Wire constants ────────────────────────────────────────────────────────────

/// 4-byte magic prefix identifying an L2V0 anchor envelope (`4C 32 56 30`).
pub const ENVELOPE_MAGIC: [u8; 4] = *b"L2V0";
/// Wire-format version this crate encodes and accepts (L2V0 draft).
pub const ENVELOPE_VERSION: u8 = 0x00;
/// Exact encoded size of a COMMIT anchor envelope:
/// 4 (magic) + 1 (version) + 32 + 8 + 32 + 32 + 32 + 32 = 173 bytes.
pub const ENVELOPE_LEN: usize = 173;

// ── Errors ────────────────────────────────────────────────────────────────────

/// Typed decode/validation failure. Every malformed-input class maps here;
/// decoding never panics. At the anchor layer every one of these means
/// "no-op" — the Bloch transaction itself stays valid regardless.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Payload does not start with [`ENVELOPE_MAGIC`].
    BadMagic,
    /// Magic matched but the version byte is not [`ENVELOPE_VERSION`].
    BadVersion(u8),
    /// Payload ended before a required field was fully read
    /// (i.e. shorter than [`ENVELOPE_LEN`]).
    Truncated,
    /// Bytes remain after a complete, valid envelope
    /// (i.e. longer than [`ENVELOPE_LEN`]).
    TrailingBytes,
    /// The output carrying the envelope has `value != 0`. Envelopes must
    /// ride zero-value outputs so no BLCH is ever locked behind them (TKV0
    /// caveat E.1: the node's own indexer reads `script_pubkey[..20]` as an
    /// address when the script is >= 20 bytes, so BLCH sent to an envelope
    /// is stranded).
    NonZeroValue(u64),
}

impl core::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "l2v0 envelope: bad magic"),
            Self::BadVersion(v) => write!(f, "l2v0 envelope: unsupported version {v}"),
            Self::Truncated => write!(f, "l2v0 envelope: truncated payload"),
            Self::TrailingBytes => write!(f, "l2v0 envelope: trailing bytes after payload"),
            Self::NonZeroValue(v) => {
                write!(f, "l2v0 envelope: output value must be 0, got {v}")
            }
        }
    }
}

impl std::error::Error for EnvelopeError {}

// ── AnchorEnvelope ────────────────────────────────────────────────────────────

/// A decoded L2V0 COMMIT anchor: one L2 batch commitment written to Bloch as
/// an ordinary zero-value output.
///
/// This is the *reader-side* record only. Nothing here is verified against
/// an SP1 proof or the DA layer by this crate — a decoded envelope is a
/// **claim** by whoever paid the Bloch transaction fee, nothing more.
/// Verification (proof against `vkey_hash`, batch bytes against
/// `da_commitment`) belongs to the L2 verifier, which is NOT this crate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorEnvelope {
    /// Rollup identity: keccak-256 of the L2 genesis header. Readers filter
    /// by this so independent rollups can share the L2V0 magic.
    pub rollup_id: [u8; 32],
    /// Strictly increasing batch counter, starting at the rollup's first
    /// anchored batch. Canonical successors satisfy `next = prev + 1`
    /// (see [`link`]).
    pub batch_index: u64,
    /// Ethereum state root before this batch (must equal the previous
    /// anchor's `new_state_root` on the canonical chain).
    pub prev_state_root: [u8; 32],
    /// Ethereum state root after this batch.
    pub new_state_root: [u8; 32],
    /// Commitment (hash) to the batch data blob on the DA layer.
    pub da_commitment: [u8; 32],
    /// Hash of the SP1 program verification key the batch proof targets.
    pub vkey_hash: [u8; 32],
}

impl AnchorEnvelope {
    /// Encode to the canonical 173-byte wire form (always decodable by
    /// [`AnchorEnvelope::decode`]).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENVELOPE_LEN);
        out.extend_from_slice(&ENVELOPE_MAGIC);
        out.push(ENVELOPE_VERSION);
        out.extend_from_slice(&self.rollup_id);
        out.extend_from_slice(&self.batch_index.to_le_bytes());
        out.extend_from_slice(&self.prev_state_root);
        out.extend_from_slice(&self.new_state_root);
        out.extend_from_slice(&self.da_commitment);
        out.extend_from_slice(&self.vkey_hash);
        debug_assert_eq!(out.len(), ENVELOPE_LEN);
        out
    }

    /// Strict decode. Rejects bad magic, bad version, truncation and
    /// trailing bytes — each with a typed [`EnvelopeError`]. Never panics
    /// on any input.
    pub fn decode(bytes: &[u8]) -> Result<AnchorEnvelope, EnvelopeError> {
        let mut cur = Cursor::new(bytes);

        if cur.take(4)? != ENVELOPE_MAGIC {
            return Err(EnvelopeError::BadMagic);
        }
        let version = cur.take_u8()?;
        if version != ENVELOPE_VERSION {
            return Err(EnvelopeError::BadVersion(version));
        }
        let rollup_id = cur.take_32()?;
        let batch_index = cur.take_u64_le()?;
        let prev_state_root = cur.take_32()?;
        let new_state_root = cur.take_32()?;
        let da_commitment = cur.take_32()?;
        let vkey_hash = cur.take_32()?;

        if !cur.is_exhausted() {
            return Err(EnvelopeError::TrailingBytes);
        }
        Ok(AnchorEnvelope {
            rollup_id,
            batch_index,
            prev_state_root,
            new_state_root,
            da_commitment,
            vkey_hash,
        })
    }
}

// ── Extraction from a transaction ─────────────────────────────────────────────

/// Decode the envelope carried by a single output, enforcing the zero-value
/// rule: an output whose `script_pubkey` starts with [`ENVELOPE_MAGIC`] but
/// whose `value != 0` is a typed [`EnvelopeError::NonZeroValue`] error.
pub fn decode_anchor_output(out: &TxOut) -> Result<AnchorEnvelope, EnvelopeError> {
    if !out.script_pubkey.starts_with(&ENVELOPE_MAGIC) {
        return Err(EnvelopeError::BadMagic);
    }
    if out.value != 0 {
        return Err(EnvelopeError::NonZeroValue(out.value));
    }
    AnchorEnvelope::decode(&out.script_pubkey)
}

/// Extract the transaction's anchor envelope, if any, together with the
/// envelope's output index.
///
/// Reader rules (part of the convention, so every independent reader agrees;
/// identical to TKV0's `extract_envelope` rules):
///
/// 1. **One envelope per tx, first wins.** The lowest-index output whose
///    `script_pubkey` starts with [`ENVELOPE_MAGIC`] is *the* envelope
///    candidate; later magic-bearing outputs are ignored, valid or not.
/// 2. **Zero value.** The candidate must have `value == 0` and decode
///    strictly; otherwise the transaction carries **no** anchor (`None`) —
///    a malformed candidate does not fall through to later outputs, which
///    would make anchor state depend on reader order. The Bloch transaction
///    itself remains valid either way.
pub fn extract_anchor(tx: &Tx) -> Option<(usize, AnchorEnvelope)> {
    let (idx, candidate) = tx
        .outputs
        .iter()
        .enumerate()
        .find(|(_, o)| o.script_pubkey.starts_with(&ENVELOPE_MAGIC))?;
    decode_anchor_output(candidate).ok().map(|env| (idx, env))
}

// ── Canonical-chain linkage ───────────────────────────────────────────────────

/// Why `next` is not the canonical successor of `prev` (see [`link`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkError {
    /// The two anchors belong to different rollups.
    RollupIdMismatch,
    /// `next.batch_index != prev.batch_index + 1` (also raised when
    /// `prev.batch_index == u64::MAX`, which can have no successor).
    NonConsecutiveIndex { prev: u64, next: u64 },
    /// `next.prev_state_root != prev.new_state_root`: the state chain does
    /// not connect.
    StateRootMismatch,
}

impl core::fmt::Display for LinkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RollupIdMismatch => write!(f, "l2v0 link: rollup_id mismatch"),
            Self::NonConsecutiveIndex { prev, next } => {
                write!(f, "l2v0 link: batch_index {next} does not follow {prev}")
            }
            Self::StateRootMismatch => {
                write!(f, "l2v0 link: prev_state_root does not equal prior new_state_root")
            }
        }
    }
}

impl std::error::Error for LinkError {}

/// Pure canonical-chain check: is `next` the canonical successor of `prev`?
///
/// Holds iff (a) same `rollup_id`, (b) `next.batch_index` is *strictly*
/// `prev.batch_index + 1` (checked arithmetic — `u64::MAX` has no
/// successor), and (c) `next.prev_state_root == prev.new_state_root`.
///
/// This checks *linkage only*. It says nothing about whether either anchor
/// is proof-backed, DA-available, or confirmed at depth on Bloch — those are
/// the verifier's and the anchor manager's jobs, not this function's.
pub fn link(prev: &AnchorEnvelope, next: &AnchorEnvelope) -> Result<(), LinkError> {
    if prev.rollup_id != next.rollup_id {
        return Err(LinkError::RollupIdMismatch);
    }
    let expected = prev
        .batch_index
        .checked_add(1)
        .ok_or(LinkError::NonConsecutiveIndex { prev: prev.batch_index, next: next.batch_index })?;
    if next.batch_index != expected {
        return Err(LinkError::NonConsecutiveIndex {
            prev: prev.batch_index,
            next: next.batch_index,
        });
    }
    if next.prev_state_root != prev.new_state_root {
        return Err(LinkError::StateRootMismatch);
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

    /// Take exactly `n` bytes; checked offset arithmetic so `pos + n` can
    /// never overflow `usize` even on adversarial lengths.
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

    fn anchor(batch_index: u64) -> AnchorEnvelope {
        AnchorEnvelope {
            rollup_id: [0x11; 32],
            batch_index,
            prev_state_root: [0x22; 32],
            new_state_root: [0x33; 32],
            da_commitment: [0x44; 32],
            vkey_hash: [0x55; 32],
        }
    }

    fn envelope_out(env: &AnchorEnvelope) -> TxOut {
        TxOut { value: 0, script_pubkey: env.encode() }
    }

    fn plain_out() -> TxOut {
        TxOut { value: 5_000, script_pubkey: vec![0xEE; 20] }
    }

    fn tx(outputs: Vec<TxOut>) -> Tx {
        Tx { version: 1, inputs: vec![], outputs, locktime: 0 }
    }

    // ── byte layout is pinned exactly (offsets from the spec) ────────────

    #[test]
    fn byte_layout_matches_spec() {
        let env = AnchorEnvelope {
            rollup_id: [0xA1; 32],
            batch_index: 0x0102_0304_0506_0708,
            prev_state_root: [0xB2; 32],
            new_state_root: [0xC3; 32],
            da_commitment: [0xD4; 32],
            vkey_hash: [0xE5; 32],
        };
        let b = env.encode();
        assert_eq!(b.len(), ENVELOPE_LEN);
        assert_eq!(ENVELOPE_LEN, 173);
        assert_eq!(&b[0..4], b"L2V0"); // magic at 0
        assert_eq!(b[4], 0x00); // version at 4
        assert_eq!(&b[5..37], &[0xA1; 32]); // rollup_id at 5
        assert_eq!(&b[37..45], &0x0102_0304_0506_0708u64.to_le_bytes()); // batch_index LE at 37
        assert_eq!(&b[45..77], &[0xB2; 32]); // prev_state_root at 45
        assert_eq!(&b[77..109], &[0xC3; 32]); // new_state_root at 77
        assert_eq!(&b[109..141], &[0xD4; 32]); // da_commitment at 109
        assert_eq!(&b[141..173], &[0xE5; 32]); // vkey_hash at 141
    }

    // ── round trips ──────────────────────────────────────────────────────

    #[test]
    fn round_trip() {
        for env in [
            anchor(0),
            anchor(1),
            anchor(u64::MAX),
            AnchorEnvelope {
                rollup_id: [0x00; 32],
                batch_index: 0,
                prev_state_root: [0x00; 32],
                new_state_root: [0xFF; 32],
                da_commitment: [0x00; 32],
                vkey_hash: [0xFF; 32],
            },
        ] {
            let bytes = env.encode();
            let decoded = AnchorEnvelope::decode(&bytes).expect("valid envelope must decode");
            assert_eq!(decoded, env);
            // encode(decode(x)) == x for all valid envelopes
            assert_eq!(decoded.encode(), bytes);
        }
    }

    #[test]
    fn round_trip_distinct_field_bytes() {
        // Every 32-byte field distinct, so a swapped-offset bug cannot pass.
        let mut env = anchor(42);
        for (i, byte) in env.rollup_id.iter_mut().enumerate() {
            *byte = i as u8;
        }
        for (i, byte) in env.prev_state_root.iter_mut().enumerate() {
            *byte = 0x40 + i as u8;
        }
        for (i, byte) in env.new_state_root.iter_mut().enumerate() {
            *byte = 0x80 + i as u8;
        }
        for (i, byte) in env.da_commitment.iter_mut().enumerate() {
            *byte = 0xC0 ^ i as u8;
        }
        for (i, byte) in env.vkey_hash.iter_mut().enumerate() {
            *byte = 0xF0 ^ i as u8;
        }
        let bytes = env.encode();
        assert_eq!(AnchorEnvelope::decode(&bytes).unwrap(), env);
    }

    // ── malformed classes → typed errors, never panics ───────────────────

    #[test]
    fn rejects_bad_magic() {
        let mut b = anchor(1).encode();
        b[0] ^= 0xFF;
        assert_eq!(AnchorEnvelope::decode(&b), Err(EnvelopeError::BadMagic));
        // TKV0 magic is NOT an L2V0 envelope.
        let mut tkv0 = anchor(1).encode();
        tkv0[..4].copy_from_slice(b"TKV0");
        assert_eq!(AnchorEnvelope::decode(&tkv0), Err(EnvelopeError::BadMagic));
        assert_eq!(AnchorEnvelope::decode(b"XXXX"), Err(EnvelopeError::BadMagic));
        assert_eq!(AnchorEnvelope::decode(&[]), Err(EnvelopeError::Truncated));
    }

    #[test]
    fn rejects_bad_version() {
        let mut b = anchor(1).encode();
        b[4] = 0x01;
        assert_eq!(AnchorEnvelope::decode(&b), Err(EnvelopeError::BadVersion(0x01)));
        b[4] = 0xFF;
        assert_eq!(AnchorEnvelope::decode(&b), Err(EnvelopeError::BadVersion(0xFF)));
    }

    #[test]
    fn rejects_truncation_at_every_prefix() {
        let full = anchor(7).encode();
        for cut in 0..full.len() {
            let err = AnchorEnvelope::decode(&full[..cut])
                .expect_err("every strict prefix must fail");
            assert!(
                matches!(err, EnvelopeError::Truncated | EnvelopeError::BadMagic),
                "unexpected error at cut {cut}: {err:?}"
            );
        }
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut b = anchor(7).encode();
        b.push(0x00);
        assert_eq!(AnchorEnvelope::decode(&b), Err(EnvelopeError::TrailingBytes));
        // Even a lot of trailing garbage: still the typed error, no panic.
        b.extend_from_slice(&[0xAB; 100]);
        assert_eq!(AnchorEnvelope::decode(&b), Err(EnvelopeError::TrailingBytes));
    }

    #[test]
    fn never_panics_on_random_ish_garbage() {
        // Deterministic pseudo-random byte soup (xorshift), no deps: decode
        // must return, valid or typed-error, for every input.
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        for len in 0..400usize {
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                buf.push(state as u8);
            }
            let _ = AnchorEnvelope::decode(&buf); // must not panic
        }
    }

    // ── extraction rules ─────────────────────────────────────────────────

    #[test]
    fn extract_finds_envelope_among_plain_outputs() {
        let t = tx(vec![plain_out(), envelope_out(&anchor(3)), plain_out()]);
        assert_eq!(extract_anchor(&t), Some((1, anchor(3))));
    }

    #[test]
    fn extract_none_without_envelope() {
        assert_eq!(extract_anchor(&tx(vec![plain_out(), plain_out()])), None);
        assert_eq!(extract_anchor(&tx(vec![])), None);
    }

    #[test]
    fn extract_enforces_zero_value() {
        let bad = TxOut { value: 1, script_pubkey: anchor(3).encode() };
        assert_eq!(extract_anchor(&tx(vec![bad.clone()])), None);
        // and the typed error is exposed at the output level:
        assert_eq!(decode_anchor_output(&bad), Err(EnvelopeError::NonZeroValue(1)));
    }

    #[test]
    fn extract_first_envelope_wins() {
        // Two valid envelopes: the lowest output index wins.
        let t = tx(vec![envelope_out(&anchor(9)), envelope_out(&anchor(10))]);
        assert_eq!(extract_anchor(&t), Some((0, anchor(9))));

        // First candidate malformed (truncated): the tx carries NO anchor —
        // a later valid envelope must NOT be promoted.
        let mut truncated = anchor(9).encode();
        truncated.truncate(truncated.len() - 1);
        let t = tx(vec![
            TxOut { value: 0, script_pubkey: truncated },
            envelope_out(&anchor(10)),
        ]);
        assert_eq!(extract_anchor(&t), None);

        // First candidate has nonzero value: same rule, no fall-through.
        let t = tx(vec![
            TxOut { value: 7, script_pubkey: anchor(9).encode() },
            envelope_out(&anchor(10)),
        ]);
        assert_eq!(extract_anchor(&t), None);
    }

    // ── canonical-chain linkage ──────────────────────────────────────────

    fn linked_pair() -> (AnchorEnvelope, AnchorEnvelope) {
        let prev = anchor(5);
        let next = AnchorEnvelope {
            rollup_id: prev.rollup_id,
            batch_index: 6,
            prev_state_root: prev.new_state_root,
            new_state_root: [0x66; 32],
            da_commitment: [0x77; 32],
            vkey_hash: prev.vkey_hash,
        };
        (prev, next)
    }

    #[test]
    fn link_accepts_canonical_successor() {
        let (prev, next) = linked_pair();
        assert_eq!(link(&prev, &next), Ok(()));
    }

    #[test]
    fn link_rejects_rollup_id_mismatch() {
        let (prev, mut next) = linked_pair();
        next.rollup_id = [0xDE; 32];
        assert_eq!(link(&prev, &next), Err(LinkError::RollupIdMismatch));
    }

    #[test]
    fn link_rejects_non_consecutive_index() {
        let (prev, mut next) = linked_pair();
        for bad in [5u64, 7, 0, u64::MAX] {
            next.batch_index = bad;
            assert_eq!(
                link(&prev, &next),
                Err(LinkError::NonConsecutiveIndex { prev: 5, next: bad })
            );
        }
    }

    #[test]
    fn link_rejects_index_overflow() {
        let (mut prev, mut next) = linked_pair();
        prev.batch_index = u64::MAX;
        next.batch_index = 0; // wrap-around must NOT count as +1
        next.prev_state_root = prev.new_state_root;
        assert_eq!(
            link(&prev, &next),
            Err(LinkError::NonConsecutiveIndex { prev: u64::MAX, next: 0 })
        );
    }

    #[test]
    fn link_rejects_state_root_mismatch() {
        let (prev, mut next) = linked_pair();
        next.prev_state_root = [0xBA; 32];
        assert_eq!(link(&prev, &next), Err(LinkError::StateRootMismatch));
    }

    #[test]
    fn link_chain_of_three_via_round_trip() {
        // Chain-linkage test across encode/decode: a 3-anchor chain built by
        // hand, round-tripped through the wire form, still links.
        let a = anchor(0);
        let b = AnchorEnvelope {
            rollup_id: a.rollup_id,
            batch_index: 1,
            prev_state_root: a.new_state_root,
            new_state_root: [0x99; 32],
            da_commitment: [0x0B; 32],
            vkey_hash: a.vkey_hash,
        };
        let c = AnchorEnvelope {
            rollup_id: b.rollup_id,
            batch_index: 2,
            prev_state_root: b.new_state_root,
            new_state_root: [0xAA; 32],
            da_commitment: [0x0C; 32],
            vkey_hash: b.vkey_hash,
        };
        let decode = |e: &AnchorEnvelope| AnchorEnvelope::decode(&e.encode()).unwrap();
        let (a2, b2, c2) = (decode(&a), decode(&b), decode(&c));
        assert_eq!(link(&a2, &b2), Ok(()));
        assert_eq!(link(&b2, &c2), Ok(()));
        // and NOT transitively: a -> c skips index 1.
        assert_eq!(
            link(&a2, &c2),
            Err(LinkError::NonConsecutiveIndex { prev: 0, next: 2 })
        );
    }
}
