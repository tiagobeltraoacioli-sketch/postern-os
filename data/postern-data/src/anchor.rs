//! DATA0 backup-anchor wire format: strict encode/decode + extraction rules.
//!
//! Spec: `docs/specs/POSTERN-DATA-FILECOIN-DESIGN.md`, §2 ("DATA0 anchor
//! envelope — 177-byte fixed wire format"). Follows the L2V0/TKV0 idiom
//! (`l2/bloch-l2-anchor/src/envelope.rs`, `crates/bloch-tokens`) for the
//! zero-value/first-wins/strict-decode *discipline*, but carries this
//! design's own 177-byte field set: little-endian, strict decode,
//! first-envelope-wins, malformed => layer no-op, value MUST be 0 (TKV0
//! caveat E.1).
//!
//! An envelope is the `script_pubkey` of a **zero-value** transaction output,
//! laid out as (all multi-byte integers little-endian) — fixed 177 bytes:
//!
//! ```text
//! offset   size  field           meaning
//! 0        4     magic "DAT0"    (44 41 54 30)
//! 4        1     version u8=0x00
//! 5        32    namespace_id    SHAKE-256/256(b"postern-backup/ns/v1" ‖ enveloped_signer_pk);
//!                                the vault filter (role of rollup_id) — binds the chain to one signer.
//! 37       8     sequence u64 LE strictly increasing per namespace; 0 = genesis (role of batch_index).
//! 45       32    prev_root       previous anchor's manifest_root; [0;32] at genesis (the chain link).
//! 77       32    manifest_root   SHAKE-256/256 of the PBP0 package's committed prefix. THE commitment.
//! 109      32    signer_commit   SHA3-256(enveloped_signer_pk) — same primitive as the chain's address family.
//! 141      36    manifest_cid    CIDv1 binary (0x01 ‖ codec varint ‖ 0x12 0x20 ‖ sha2-256[32]) —
//!                                a LOCATOR ONLY, UNSIGNED, zero integrity weight (§2, §4, §6).
//! 177 = total
//! ```
//!
//! Decoding is *strict*: exact magic, exact version, exact length (no
//! truncation, no trailing bytes). All offset arithmetic is checked;
//! malformed input always yields a typed [`EnvelopeError`], never a panic.
//!
//! HONESTY (see crate docs): this is an OFF-consensus reader convention.
//! Bloch nodes never parse or verify envelopes — a malformed envelope is an
//! anchor-layer no-op and NEVER invalidates the carrying Bloch transaction.
//! The base gains no operator and needs no consensus change. `manifest_root`
//! and `signer_commit` are commitments produced *elsewhere* (real SHAKE-256 +
//! PQ signing live behind the `postern-backup-net` boundary, NOT in this
//! crate); here they are opaque bytes. `manifest_cid` is a LOCATOR ONLY and is
//! **unsigned by design** (the signature-circularity note, §3.2). A decoded
//! envelope is a **claim** until a reader fetches the manifest package,
//! recomputes `manifest_root`, checks `signer_commit == SHA3-256(pk)`, and
//! verifies the PQ signature — this crate does none of that verification.

// ── Mirror types ──────────────────────────────────────────────────────────────
//
// `Tx` / `TxIn` / `TxOut` mirror `bloch_crypto::core::{Transaction, TxInput,
// TxOutput}` at BlochSISPoW rev dd8df3526518ba792057708a6aa0efd5a91d8e40
// (the same mirrors `bloch-tokens` and `bloch-l2-anchor` carry). They are
// copied (not imported via a git dependency) so this crate stays zero-dep and
// offline-buildable; only the fields an anchor reader needs are mirrored
// (`script_sig` / signature material omitted — the node already validated the
// transaction; the anchor layer only reads structure).

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

/// 4-byte magic prefix identifying a DATA0 backup-anchor envelope
/// (`44 41 54 30`). Reads "DATA0" on the wire as `DAT0` + the `0x00` version
/// byte, mirroring the 3-char+`0` shape of `TKV0` / `L2V0`.
pub const ENVELOPE_MAGIC: [u8; 4] = *b"DAT0";
/// Wire-format version this crate encodes and accepts (DATA0 draft).
pub const ENVELOPE_VERSION: u8 = 0x00;
/// Length of the binary CIDv1 `manifest_cid` field (0x01 ‖ codec ‖ 0x12 0x20 ‖
/// sha2-256 digest[32] = 36 bytes for the sha2-256/32 multihash form).
pub const CID_LEN: usize = 36;
/// Exact encoded size of a DATA0 anchor envelope:
/// 4 (magic) + 1 (version) + 32 + 8 + 32 + 32 + 32 + 36 = 177 bytes.
pub const ENVELOPE_LEN: usize = 177;

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
            Self::BadMagic => write!(f, "data0 envelope: bad magic"),
            Self::BadVersion(v) => write!(f, "data0 envelope: unsupported version {v}"),
            Self::Truncated => write!(f, "data0 envelope: truncated payload"),
            Self::TrailingBytes => write!(f, "data0 envelope: trailing bytes after payload"),
            Self::NonZeroValue(v) => {
                write!(f, "data0 envelope: output value must be 0, got {v}")
            }
        }
    }
}

impl std::error::Error for EnvelopeError {}

// ── AnchorEnvelope ────────────────────────────────────────────────────────────

/// A decoded DATA0 backup anchor: one backup-set commitment written to Bloch
/// as an ordinary zero-value output.
///
/// This is the *reader-side* record only. Nothing here is verified against a
/// PQ signature or the off-chain manifest by this crate — a decoded envelope
/// is a **claim** by whoever paid the Bloch transaction fee, nothing more.
/// Verification (recompute `manifest_root`, check `signer_commit == SHA3-256(pk)`,
/// verify the ML-DSA-65‖Falcon-1024 hybrid signature, re-hash fetched
/// ciphertext) belongs to the reader/verifier in `postern-backup-net`, which
/// is NOT this crate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorEnvelope {
    /// Namespace/vault identity: binds the whole anchor chain to one backup
    /// signer. Readers filter by this so independent vaults can share the
    /// DATA0 magic. (In the full design this is
    /// `SHAKE-256(b"postern-backup/ns/v1" ‖ enveloped_signer_pk)`; this crate
    /// treats it as an opaque 32-byte id.)
    pub namespace_id: [u8; 32],
    /// Strictly increasing manifest counter per namespace, starting at 0.
    /// Canonical successors satisfy `next = prev + 1` (see [`link`]).
    pub sequence: u64,
    /// Previous anchor's `manifest_root` (must equal it on the canonical
    /// chain); `[0u8; 32]` at genesis.
    pub prev_root: [u8; 32],
    /// The signed manifest root: SHAKE-256/256 of the PBP0 package's committed
    /// prefix, produced *outside this crate*. 32 opaque bytes here — this
    /// crate never computes or verifies it.
    pub manifest_root: [u8; 32],
    /// `SHA3-256(enveloped_signer_pk)` — matches bloch-crypto's address
    /// derivation family, so a reader recomputes it with the same primitive
    /// the chain uses. Opaque 32 bytes here; the verify step (outside this
    /// crate) checks `signer_commit == SHA3-256(pk)`.
    pub signer_commit: [u8; 32],
    /// CIDv1 binary locator for the off-chain PBP0 package. A **locator only,
    /// UNSIGNED**, carrying zero integrity weight (a wrong CID simply fails
    /// the `manifest_root` recomputation). Fixed [`CID_LEN`] bytes.
    pub manifest_cid: [u8; CID_LEN],
}

impl AnchorEnvelope {
    /// Encode to the canonical 177-byte wire form (always decodable by
    /// [`AnchorEnvelope::decode`]).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENVELOPE_LEN);
        out.extend_from_slice(&ENVELOPE_MAGIC);
        out.push(ENVELOPE_VERSION);
        out.extend_from_slice(&self.namespace_id);
        out.extend_from_slice(&self.sequence.to_le_bytes());
        out.extend_from_slice(&self.prev_root);
        out.extend_from_slice(&self.manifest_root);
        out.extend_from_slice(&self.signer_commit);
        out.extend_from_slice(&self.manifest_cid);
        debug_assert_eq!(out.len(), ENVELOPE_LEN);
        out
    }

    /// The signed transcript `t` for this anchor — the envelope **minus the
    /// unsigned `manifest_cid` locator** (§3.2). This is the exact byte string
    /// a signer signs and a verifier checks; the signature and its production
    /// live outside this zero-dep crate, but the transcript is a pure function
    /// of the envelope, so it is defined here to keep signer and verifier in
    /// byte-agreement.
    ///
    /// `t = b"postern-backup/anchor/v0" ‖ magic ‖ version ‖ namespace_id ‖
    ///      sequence ‖ prev_root ‖ manifest_root ‖ signer_commit`.
    pub fn signing_transcript(&self) -> Vec<u8> {
        const DOMAIN: &[u8] = b"postern-backup/anchor/v0";
        let mut t = Vec::with_capacity(DOMAIN.len() + ENVELOPE_LEN - CID_LEN);
        t.extend_from_slice(DOMAIN);
        t.extend_from_slice(&ENVELOPE_MAGIC);
        t.push(ENVELOPE_VERSION);
        t.extend_from_slice(&self.namespace_id);
        t.extend_from_slice(&self.sequence.to_le_bytes());
        t.extend_from_slice(&self.prev_root);
        t.extend_from_slice(&self.manifest_root);
        t.extend_from_slice(&self.signer_commit);
        t
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
        let namespace_id = cur.take_32()?;
        let sequence = cur.take_u64_le()?;
        let prev_root = cur.take_32()?;
        let manifest_root = cur.take_32()?;
        let signer_commit = cur.take_32()?;
        let manifest_cid = cur.take_cid()?;

        if !cur.is_exhausted() {
            return Err(EnvelopeError::TrailingBytes);
        }
        Ok(AnchorEnvelope {
            namespace_id,
            sequence,
            prev_root,
            manifest_root,
            signer_commit,
            manifest_cid,
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
/// identical to L2V0/TKV0's extraction rules):
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
    /// The two anchors belong to different namespaces.
    NamespaceMismatch,
    /// `next.sequence != prev.sequence + 1` (also raised when
    /// `prev.sequence == u64::MAX`, which can have no successor).
    NonConsecutiveSequence { prev: u64, next: u64 },
    /// `next.prev_root != prev.manifest_root`: the commitment chain does not
    /// connect.
    RootMismatch,
}

impl core::fmt::Display for LinkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NamespaceMismatch => write!(f, "data0 link: namespace_id mismatch"),
            Self::NonConsecutiveSequence { prev, next } => {
                write!(f, "data0 link: sequence {next} does not follow {prev}")
            }
            Self::RootMismatch => {
                write!(f, "data0 link: prev_root does not equal prior manifest_root")
            }
        }
    }
}

impl std::error::Error for LinkError {}

/// Pure canonical-chain check: is `next` the canonical successor of `prev`?
///
/// Holds iff (a) same `namespace_id`, (b) `next.sequence` is *strictly*
/// `prev.sequence + 1` (checked arithmetic — `u64::MAX` has no successor), and
/// (c) `next.prev_root == prev.manifest_root`.
///
/// This checks *linkage only*. It says nothing about whether either anchor is
/// signature-backed, manifest-available, or confirmed at depth on Bloch —
/// those are the verifier's and the reader's jobs, not this function's.
pub fn link(prev: &AnchorEnvelope, next: &AnchorEnvelope) -> Result<(), LinkError> {
    if prev.namespace_id != next.namespace_id {
        return Err(LinkError::NamespaceMismatch);
    }
    let expected = prev.sequence.checked_add(1).ok_or(LinkError::NonConsecutiveSequence {
        prev: prev.sequence,
        next: next.sequence,
    })?;
    if next.sequence != expected {
        return Err(LinkError::NonConsecutiveSequence { prev: prev.sequence, next: next.sequence });
    }
    if next.prev_root != prev.manifest_root {
        return Err(LinkError::RootMismatch);
    }
    Ok(())
}

// ── Adversarial head selection (reader-side fork choice for one vault) ────────

/// Pick the canonical **head** (chain tip) for a single vault out of an
/// unordered, possibly adversarial bag of anchors.
///
/// This is the reader-side fork-choice for one backup vault. Given every anchor
/// a reader has scraped off Bloch — across *all* vaults, in *any* order, and
/// including replays (two anchors sharing a `sequence`), gaps (a missing
/// `sequence`), and competing forks — it returns the tip of the **longest
/// link-valid chain** rooted at that vault's genesis, or `None` if the vault
/// has no valid chain at all.
///
/// Field mapping to the item's vocabulary: `vault_id` is the [`AnchorEnvelope`]
/// `namespace_id`; the "manifest_index" is `sequence`; the "new_root" of each
/// link is `manifest_root`; and the link predicate `prev_root -> new_root` is
/// exactly [`link`].
///
/// Rules (all pure, all offline — this is the OFF-consensus reader convention of
/// the module docs; it decides **nothing** about Bloch itself):
///
/// 1. **Vault filter.** Only anchors whose `namespace_id == *vault_id` are
///    considered; anchors from every other vault are ignored entirely.
/// 2. **Genesis root.** A chain must start at a genesis anchor: `sequence == 0`
///    **and** `prev_root == [0u8; 32]`. A `sequence == 0` anchor with a
///    non-zero `prev_root`, or any `sequence > 0` anchor with no link-valid
///    predecessor, roots no chain.
/// 3. **Link-valid, strictly-increasing.** Every step `prev -> next` must
///    satisfy [`link`]: same namespace, `next.sequence == prev.sequence + 1`
///    (so a **gap** severs the chain), and `next.prev_root == prev.manifest_root`
///    (so a forged link does not connect). Because a successor needs exactly
///    `prev.sequence + 1`, a **replayed** `sequence` only ever competes as a
///    fork — it can never extend the chain a second time.
/// 4. **Longest wins, deterministically.** The head is the tip of the longest
///    valid chain (equivalently, the reachable anchor of highest `sequence`).
///    Ties between two equally-long forks break by the lexicographically
///    greatest `manifest_root`, then `prev_root`, then `signer_commit`, then
///    `manifest_cid` — a fixed total order so independent readers converge
///    byte-for-byte on the same head. This tiebreak is a *determinism* device,
///    NOT a security claim: a live fork past a confirmed head is an
///    availability/verification problem for the reader, never something this
///    ordering "resolves".
///
/// Returns a reference into `anchors`. Complexity is `O(n log n)` in the number
/// of this vault's anchors (a sort plus one predecessor pass); it never panics
/// and allocates only bookkeeping.
pub fn select_head<'a>(
    anchors: &'a [AnchorEnvelope],
    vault_id: &[u8; 32],
) -> Option<&'a AnchorEnvelope> {
    use std::collections::HashMap;

    // Rule 1 — vault filter: indices of this vault's anchors only.
    let vault: Vec<usize> = anchors
        .iter()
        .enumerate()
        .filter(|(_, a)| &a.namespace_id == vault_id)
        .map(|(i, _)| i)
        .collect();
    if vault.is_empty() {
        return None;
    }

    // Group by sequence for O(1) predecessor lookup at `sequence - 1`.
    let mut by_seq: HashMap<u64, Vec<usize>> = HashMap::new();
    for &i in &vault {
        by_seq.entry(anchors[i].sequence).or_default().push(i);
    }

    // Score every anchor by ascending sequence so each predecessor (at
    // `sequence - 1`) is settled before its successors. `chain_len[i]` is the
    // length of the longest valid chain ending at `i`; absent means `i` roots
    // no chain from genesis (unreachable), which is treated as 0.
    let mut order = vault.clone();
    order.sort_by_key(|&i| anchors[i].sequence);

    let mut chain_len: HashMap<usize, u64> = HashMap::new();
    for &i in &order {
        let a = &anchors[i];
        let len = if a.sequence == 0 {
            // Rule 2 — genesis: sequence 0 with an all-zero prev_root.
            u64::from(a.prev_root == [0u8; 32])
        } else {
            // Rule 3 — extend the best link-valid predecessor at sequence - 1.
            a.sequence
                .checked_sub(1)
                .and_then(|p| by_seq.get(&p))
                .into_iter()
                .flatten()
                .filter(|&&p| chain_len.get(&p).copied().unwrap_or(0) > 0)
                .filter(|&&p| link(&anchors[p], a).is_ok())
                .map(|&p| chain_len[&p])
                .max()
                .map_or(0, |best| best + 1)
        };
        if len > 0 {
            chain_len.insert(i, len);
        }
    }

    // Rule 4 — longest chain wins; a fixed total order breaks any tie.
    vault
        .into_iter()
        .filter(|i| chain_len.contains_key(i))
        .max_by(|&x, &y| {
            chain_len[&x]
                .cmp(&chain_len[&y])
                .then_with(|| anchors[x].manifest_root.cmp(&anchors[y].manifest_root))
                .then_with(|| anchors[x].prev_root.cmp(&anchors[y].prev_root))
                .then_with(|| anchors[x].signer_commit.cmp(&anchors[y].signer_commit))
                .then_with(|| anchors[x].manifest_cid.cmp(&anchors[y].manifest_cid))
        })
        .map(|i| &anchors[i])
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

    fn take_cid(&mut self) -> Result<[u8; CID_LEN], EnvelopeError> {
        let mut b = [0u8; CID_LEN];
        b.copy_from_slice(self.take(CID_LEN)?);
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

    fn anchor(sequence: u64) -> AnchorEnvelope {
        AnchorEnvelope {
            namespace_id: [0x11; 32],
            sequence,
            prev_root: [0x22; 32],
            manifest_root: [0x33; 32],
            signer_commit: [0x44; 32],
            manifest_cid: [0x55; CID_LEN],
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

    // ── byte layout is pinned exactly (offsets from the spec §2 table) ────

    #[test]
    fn byte_layout_matches_spec() {
        let env = AnchorEnvelope {
            namespace_id: [0xA1; 32],
            sequence: 0x0102_0304_0506_0708,
            prev_root: [0xB2; 32],
            manifest_root: [0xC3; 32],
            signer_commit: [0xD4; 32],
            manifest_cid: [0xE5; CID_LEN],
        };
        let b = env.encode();
        assert_eq!(b.len(), ENVELOPE_LEN);
        assert_eq!(ENVELOPE_LEN, 177);
        assert_eq!(&b[0..4], b"DAT0"); // magic at 0
        assert_eq!(&b[0..4], &[0x44, 0x41, 0x54, 0x30]); // 44 41 54 30
        assert_eq!(b[4], 0x00); // version at 4
        assert_eq!(&b[5..37], &[0xA1; 32]); // namespace_id at 5
        assert_eq!(&b[37..45], &0x0102_0304_0506_0708u64.to_le_bytes()); // sequence LE at 37
        assert_eq!(&b[45..77], &[0xB2; 32]); // prev_root at 45
        assert_eq!(&b[77..109], &[0xC3; 32]); // manifest_root at 77
        assert_eq!(&b[109..141], &[0xD4; 32]); // signer_commit at 109
        assert_eq!(&b[141..177], &[0xE5; CID_LEN]); // manifest_cid at 141
    }

    #[test]
    fn signing_transcript_excludes_the_locator() {
        // The transcript is domain ‖ envelope[..141] (everything but manifest_cid),
        // so changing only manifest_cid does NOT change what is signed (§3.2).
        let mut a = anchor(3);
        let t0 = a.signing_transcript();
        a.manifest_cid = [0xFF; CID_LEN];
        assert_eq!(a.signing_transcript(), t0, "manifest_cid must be unsigned");
        // but changing a signed field DOES change the transcript
        a.manifest_root = [0x99; 32];
        assert_ne!(a.signing_transcript(), t0);
        // shape: domain(24) + magic(4) + ver(1) + 32 + 8 + 32 + 32 + 32
        assert_eq!(t0.len(), 24 + 5 + 32 + 8 + 32 + 32 + 32);
        assert_eq!(&t0[0..24], b"postern-backup/anchor/v0");
    }

    // ── round trips ──────────────────────────────────────────────────────

    #[test]
    fn round_trip() {
        for env in [
            anchor(0),
            anchor(1),
            anchor(u64::MAX),
            AnchorEnvelope {
                namespace_id: [0x00; 32],
                sequence: 0,
                prev_root: [0x00; 32],
                manifest_root: [0xFF; 32],
                signer_commit: [0x00; 32],
                manifest_cid: [0xFF; CID_LEN],
            },
        ] {
            let bytes = env.encode();
            let decoded = AnchorEnvelope::decode(&bytes).expect("valid envelope must decode");
            assert_eq!(decoded, env);
            assert_eq!(decoded.encode(), bytes); // encode(decode(x)) == x
        }
    }

    #[test]
    fn round_trip_distinct_field_bytes() {
        // Every field distinct, so a swapped-offset bug cannot pass.
        let mut env = anchor(42);
        for (i, byte) in env.namespace_id.iter_mut().enumerate() {
            *byte = i as u8;
        }
        for (i, byte) in env.prev_root.iter_mut().enumerate() {
            *byte = 0x40 + i as u8;
        }
        for (i, byte) in env.manifest_root.iter_mut().enumerate() {
            *byte = 0x80 + i as u8;
        }
        for (i, byte) in env.signer_commit.iter_mut().enumerate() {
            *byte = 0xC0 ^ i as u8;
        }
        for (i, byte) in env.manifest_cid.iter_mut().enumerate() {
            *byte = 0x10 ^ i as u8;
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
        let mut l2v0 = anchor(1).encode();
        l2v0[..4].copy_from_slice(b"L2V0");
        assert_eq!(AnchorEnvelope::decode(&l2v0), Err(EnvelopeError::BadMagic));
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
        b.extend_from_slice(&[0xAB; 100]);
        assert_eq!(AnchorEnvelope::decode(&b), Err(EnvelopeError::TrailingBytes));
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
        assert_eq!(decode_anchor_output(&bad), Err(EnvelopeError::NonZeroValue(1)));
    }

    #[test]
    fn extract_first_envelope_wins() {
        let t = tx(vec![envelope_out(&anchor(9)), envelope_out(&anchor(10))]);
        assert_eq!(extract_anchor(&t), Some((0, anchor(9))));

        let mut truncated = anchor(9).encode();
        truncated.truncate(truncated.len() - 1);
        let t = tx(vec![
            TxOut { value: 0, script_pubkey: truncated },
            envelope_out(&anchor(10)),
        ]);
        assert_eq!(extract_anchor(&t), None);

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
            namespace_id: prev.namespace_id,
            sequence: 6,
            prev_root: prev.manifest_root,
            manifest_root: [0x66; 32],
            signer_commit: [0x77; 32],
            manifest_cid: [0x88; CID_LEN],
        };
        (prev, next)
    }

    #[test]
    fn link_accepts_canonical_successor() {
        let (prev, next) = linked_pair();
        assert_eq!(link(&prev, &next), Ok(()));
    }

    #[test]
    fn link_rejects_namespace_mismatch() {
        let (prev, mut next) = linked_pair();
        next.namespace_id = [0xDE; 32];
        assert_eq!(link(&prev, &next), Err(LinkError::NamespaceMismatch));
    }

    #[test]
    fn link_rejects_non_consecutive_sequence() {
        let (prev, mut next) = linked_pair();
        for bad in [5u64, 7, 0, u64::MAX] {
            next.sequence = bad;
            assert_eq!(
                link(&prev, &next),
                Err(LinkError::NonConsecutiveSequence { prev: 5, next: bad })
            );
        }
    }

    #[test]
    fn link_rejects_sequence_overflow() {
        let (mut prev, mut next) = linked_pair();
        prev.sequence = u64::MAX;
        next.sequence = 0; // wrap-around must NOT count as +1
        next.prev_root = prev.manifest_root;
        assert_eq!(
            link(&prev, &next),
            Err(LinkError::NonConsecutiveSequence { prev: u64::MAX, next: 0 })
        );
    }

    #[test]
    fn link_rejects_root_mismatch() {
        let (prev, mut next) = linked_pair();
        next.prev_root = [0xBA; 32];
        assert_eq!(link(&prev, &next), Err(LinkError::RootMismatch));
    }

    #[test]
    fn link_chain_of_three_via_round_trip() {
        let a = anchor(0);
        let b = AnchorEnvelope {
            namespace_id: a.namespace_id,
            sequence: 1,
            prev_root: a.manifest_root,
            manifest_root: [0x99; 32],
            signer_commit: [0x0B; 32],
            manifest_cid: [0x1B; CID_LEN],
        };
        let c = AnchorEnvelope {
            namespace_id: b.namespace_id,
            sequence: 2,
            prev_root: b.manifest_root,
            manifest_root: [0xAA; 32],
            signer_commit: [0x0C; 32],
            manifest_cid: [0x1C; CID_LEN],
        };
        let decode = |e: &AnchorEnvelope| AnchorEnvelope::decode(&e.encode()).unwrap();
        let (a2, b2, c2) = (decode(&a), decode(&b), decode(&c));
        assert_eq!(link(&a2, &b2), Ok(()));
        assert_eq!(link(&b2, &c2), Ok(()));
        assert_eq!(
            link(&a2, &c2),
            Err(LinkError::NonConsecutiveSequence { prev: 0, next: 2 })
        );
    }

    // ── adversarial head selection ───────────────────────────────────────

    const VAULT_A: [u8; 32] = [0x11; 32];
    const VAULT_B: [u8; 32] = [0x22; 32];
    const ZERO: [u8; 32] = [0u8; 32];

    /// Build an anchor with an explicit vault, sequence, prev_root and
    /// manifest_root (the fields head-selection actually reads); the rest are
    /// fixed filler.
    fn node(ns: [u8; 32], sequence: u64, prev_root: [u8; 32], manifest_root: [u8; 32]) -> AnchorEnvelope {
        AnchorEnvelope {
            namespace_id: ns,
            sequence,
            prev_root,
            manifest_root,
            signer_commit: [0xCC; 32],
            manifest_cid: [0xDD; CID_LEN],
        }
    }

    fn root(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn select_head_none_on_empty_or_missing_vault() {
        assert_eq!(select_head(&[], &VAULT_A), None);
        // Anchors exist but only for a different vault.
        let other = vec![node(VAULT_B, 0, ZERO, root(1))];
        assert_eq!(select_head(&other, &VAULT_A), None);
    }

    #[test]
    fn select_head_needs_a_genesis_root() {
        // A well-formed 1->2 chain but with no genesis (no seq-0/zero-prev) anchor.
        let anchors = vec![node(VAULT_A, 1, root(0), root(1)), node(VAULT_A, 2, root(1), root(2))];
        assert_eq!(select_head(&anchors, &VAULT_A), None);
        // seq 0 but non-zero prev_root is NOT a genesis.
        let anchors = vec![node(VAULT_A, 0, root(9), root(0))];
        assert_eq!(select_head(&anchors, &VAULT_A), None);
    }

    #[test]
    fn select_head_tiebreak_is_deterministic_and_order_independent() {
        // Two equally-long forks off the same genesis: seq 0 -> {1a, 1b}.
        // No successor to either, so both chains have length 2; the fixed total
        // order (greatest manifest_root) decides, regardless of input order.
        let g = node(VAULT_A, 0, ZERO, root(5));
        let a = node(VAULT_A, 1, root(5), root(0xA0));
        let b = node(VAULT_A, 1, root(5), root(0xB0)); // greater manifest_root wins
        let forward = vec![g.clone(), a.clone(), b.clone()];
        let reversed = vec![b.clone(), a.clone(), g.clone()];
        assert_eq!(select_head(&forward, &VAULT_A), Some(&b));
        assert_eq!(select_head(&reversed, &VAULT_A), Some(&b));
    }
}
