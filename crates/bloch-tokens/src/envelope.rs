//! TKV0 wire format: strict encode/decode + extraction rules.
//!
//! Spec: `docs/specs/BLOCH-PERMISSIONLESS-TOKENS-L2.md`, section
//! "Primitive (a) wire format — TKV0 (draft)".
//!
//! An envelope is the `script_pubkey` of a **zero-value** transaction output,
//! laid out as (all multi-byte integers little-endian):
//!
//! ```text
//! MAGIC (4B "TKV0") | VERSION (1B = 0x00) | OP (1B) | payload
//!
//! OP 0x01  Issue    : decimals u8 (<=18) | flags u8 (bit0 mint-closed, MUST
//!                     be 1 in v0; bits 1-7 MUST be 0) | supply u64-LE (>0)
//!                     | symbol_len u8 (1..=8) | symbol [A-Z0-9]
//!                     | name_len u8 (0..=32) | name UTF-8
//! OP 0x02  Transfer : token_id [u8; 32] | n u8 (1..=16)
//!                     | n x ( vout u32-LE | amount u64-LE (>0) )
//! ```
//!
//! Decoding is *strict*: exact magic, exact version, known op, exact length
//! (no truncation, no trailing bytes), capped and validated strings, non-zero
//! amounts, and no duplicate `vout` in a transfer's assignment list. All
//! offset arithmetic is checked; malformed input always yields a typed
//! [`EnvelopeError`], never a panic.
//!
//! Reminder (see crate docs): this is an off-consensus reader convention.
//! The chain itself never validates envelopes — a malformed envelope is a
//! token-layer no-op and NEVER invalidates the carrying Bloch transaction.

// ── Mirror types ──────────────────────────────────────────────────────────────
//
// `Tx` / `TxIn` / `TxOut` mirror `bloch_crypto::core::{Transaction, TxInput,
// TxOutput}` at BlochSISPoW rev dd8df3526518ba792057708a6aa0efd5a91d8e40. They
// are copied (not imported via a git dependency) so this crate stays zero-dep
// and offline-buildable; only the fields the token standard reads are
// mirrored (`script_sig` / signature material omitted — the node already
// validated the transaction; the token layer only reads structure).

/// Mirror of `bloch_crypto::core::TxOutput` (rev dd8df35):
/// `{ value: u64, script_pubkey: Vec<u8> }`. In the upstream type
/// `script_pubkey` is a 20-byte pubkey hash for spendable outputs; the token
/// standard reuses the same free-form field to carry the envelope bytes in a
/// zero-value output. (Node validation never constrains an *output*
/// script_pubkey — that is what makes this zero consensus change.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

/// Mirror of `bloch_crypto::core::TxInput` (rev dd8df35), reduced to the
/// outpoint fields the token layer needs to follow colored outpoints.
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

/// 4-byte magic prefix identifying a TKV0 token envelope.
pub const ENVELOPE_MAGIC: [u8; 4] = *b"TKV0";
/// Wire-format version this crate encodes and accepts (TKV0 draft).
pub const ENVELOPE_VERSION: u8 = 0x00;
/// Maximum display decimals.
pub const MAX_DECIMALS: u8 = 18;
/// Maximum byte length of a token symbol (ASCII uppercase A–Z / 0–9).
pub const MAX_SYMBOL_LEN: usize = 8;
/// Maximum byte length of a token name (UTF-8; may be empty).
pub const MAX_NAME_LEN: usize = 32;
/// Maximum number of `(vout, amount)` assignments in one transfer.
pub const MAX_ASSIGNMENTS: usize = 16;
/// Issue flags: bit 0 — mint-closed (fixed supply). MUST be set in v0.
pub const FLAG_MINT_CLOSED: u8 = 0b0000_0001;

const OP_ISSUE: u8 = 0x01;
const OP_TRANSFER: u8 = 0x02;

// ── Errors ────────────────────────────────────────────────────────────────────

/// Typed decode/validation failure. Every malformed-input class maps here;
/// decoding never panics. At the token layer every one of these means
/// "no-op" — the Bloch transaction itself stays valid regardless.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Payload does not start with [`ENVELOPE_MAGIC`].
    BadMagic,
    /// Magic matched but the version byte is not [`ENVELOPE_VERSION`].
    BadVersion(u8),
    /// Magic and version matched but the op tag is unknown.
    UnknownOp(u8),
    /// Payload ended before a required field was fully read.
    Truncated,
    /// Bytes remain after a complete, valid envelope.
    TrailingBytes,
    /// Symbol is empty, exceeds [`MAX_SYMBOL_LEN`], or contains a byte
    /// outside ASCII `A-Z0-9`.
    BadSymbol,
    /// Name exceeds [`MAX_NAME_LEN`] or is not valid UTF-8.
    BadName,
    /// Decimals exceed [`MAX_DECIMALS`].
    BadDecimals(u8),
    /// Flags: bit 0 (mint-closed) unset, or a reserved bit (1–7) set.
    BadFlags(u8),
    /// A supply/amount field is zero (the standard requires >= 1) or an
    /// internal checked-arithmetic step overflowed.
    BadAmount,
    /// Transfer assignment count is 0 or exceeds [`MAX_ASSIGNMENTS`].
    BadAssignmentCount(u8),
    /// The same `vout` appears twice in a transfer's assignment list.
    DuplicateVout(u32),
    /// The output carrying the envelope has `value != 0`. Envelopes must
    /// ride zero-value outputs so no BLCH is locked behind them (the node's
    /// own indexer reads `script_pubkey[..20]` as an address when the script
    /// is >= 20 bytes, so BLCH sent to an envelope is stranded).
    NonZeroValue(u64),
}

impl core::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "envelope: bad magic"),
            Self::BadVersion(v) => write!(f, "envelope: unsupported version {v}"),
            Self::UnknownOp(op) => write!(f, "envelope: unknown op 0x{op:02x}"),
            Self::Truncated => write!(f, "envelope: truncated payload"),
            Self::TrailingBytes => write!(f, "envelope: trailing bytes after payload"),
            Self::BadSymbol => write!(f, "envelope: invalid symbol"),
            Self::BadName => write!(f, "envelope: invalid name"),
            Self::BadDecimals(d) => write!(f, "envelope: decimals {d} > {MAX_DECIMALS}"),
            Self::BadFlags(fl) => write!(f, "envelope: invalid flags 0x{fl:02x}"),
            Self::BadAmount => write!(f, "envelope: zero or overflowing amount"),
            Self::BadAssignmentCount(n) => write!(f, "envelope: bad assignment count {n}"),
            Self::DuplicateVout(v) => write!(f, "envelope: duplicate vout {v}"),
            Self::NonZeroValue(v) => write!(f, "envelope: output value must be 0, got {v}"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

// ── TokenOp ───────────────────────────────────────────────────────────────────

/// A decoded TKV0 token operation.
///
/// `Issue` creates a new token; its identity is `token_id := txid` of the
/// issuing transaction (assigned by the indexer — the txid is not repeated
/// inside the envelope). `Transfer` re-assigns token units riding the
/// transaction's *colored input outpoints* to explicit output indices;
/// BLCH values on all outputs are untouched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenOp {
    Issue {
        /// Display decimals, 0..=[`MAX_DECIMALS`] (purely presentational).
        decimals: u8,
        /// Flag byte; in v0 exactly [`FLAG_MINT_CLOSED`] (fixed supply).
        flags: u8,
        /// Total supply in base units, >= 1. Assigned to output 0 of the
        /// issuing transaction.
        supply: u64,
        /// ASCII uppercase `A-Z0-9`, 1..=[`MAX_SYMBOL_LEN`] bytes.
        symbol: String,
        /// UTF-8, 0..=[`MAX_NAME_LEN`] bytes (may be empty).
        name: String,
    },
    Transfer {
        /// Token identifier (txid of the issuing transaction).
        token_id: [u8; 32],
        /// Explicit `(vout, amount)` assignments, 1..=[`MAX_ASSIGNMENTS`],
        /// no duplicate `vout`, every amount >= 1. Unassigned input color
        /// is burned (no implicit change).
        assignments: Vec<(u32, u64)>,
    },
}

impl TokenOp {
    /// Encode to the canonical wire form (always decodable by [`TokenOp::decode`],
    /// provided `self` satisfies the standard's field constraints).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&ENVELOPE_MAGIC);
        out.push(ENVELOPE_VERSION);
        match self {
            TokenOp::Issue { decimals, flags, supply, symbol, name } => {
                out.push(OP_ISSUE);
                out.push(*decimals);
                out.push(*flags);
                out.extend_from_slice(&supply.to_le_bytes());
                out.push(symbol.len() as u8);
                out.extend_from_slice(symbol.as_bytes());
                out.push(name.len() as u8);
                out.extend_from_slice(name.as_bytes());
            }
            TokenOp::Transfer { token_id, assignments } => {
                out.push(OP_TRANSFER);
                out.extend_from_slice(token_id);
                out.push(assignments.len() as u8);
                for (vout, amount) in assignments {
                    out.extend_from_slice(&vout.to_le_bytes());
                    out.extend_from_slice(&amount.to_le_bytes());
                }
            }
        }
        out
    }

    /// Strict decode. Rejects bad magic/version/op, truncation, trailing
    /// bytes, over-cap or invalid strings, bad decimals/flags, zero amounts,
    /// bad assignment counts and duplicate vouts — each with a typed
    /// [`EnvelopeError`]. Never panics on any input.
    pub fn decode(bytes: &[u8]) -> Result<TokenOp, EnvelopeError> {
        let mut cur = Cursor::new(bytes);

        if cur.take(4)? != ENVELOPE_MAGIC {
            return Err(EnvelopeError::BadMagic);
        }
        let version = cur.take_u8()?;
        if version != ENVELOPE_VERSION {
            return Err(EnvelopeError::BadVersion(version));
        }
        let op = match cur.take_u8()? {
            OP_ISSUE => {
                let decimals = cur.take_u8()?;
                if decimals > MAX_DECIMALS {
                    return Err(EnvelopeError::BadDecimals(decimals));
                }
                let flags = cur.take_u8()?;
                if flags != FLAG_MINT_CLOSED {
                    // v0: bit 0 MUST be 1 (fixed supply), bits 1-7 MUST be 0.
                    return Err(EnvelopeError::BadFlags(flags));
                }
                let supply = cur.take_u64_le()?;
                if supply == 0 {
                    return Err(EnvelopeError::BadAmount);
                }

                let sym_len = cur.take_u8()? as usize;
                if sym_len == 0 || sym_len > MAX_SYMBOL_LEN {
                    return Err(EnvelopeError::BadSymbol);
                }
                let sym_bytes = cur.take(sym_len)?;
                if !sym_bytes.iter().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()) {
                    return Err(EnvelopeError::BadSymbol);
                }
                // ASCII-checked above, so from_utf8 cannot fail; still avoid unwrap.
                let symbol =
                    String::from_utf8(sym_bytes.to_vec()).map_err(|_| EnvelopeError::BadSymbol)?;

                let name_len = cur.take_u8()? as usize;
                if name_len > MAX_NAME_LEN {
                    return Err(EnvelopeError::BadName);
                }
                let name = String::from_utf8(cur.take(name_len)?.to_vec())
                    .map_err(|_| EnvelopeError::BadName)?;

                TokenOp::Issue { decimals, flags, supply, symbol, name }
            }
            OP_TRANSFER => {
                let mut token_id = [0u8; 32];
                token_id.copy_from_slice(cur.take(32)?);

                let n = cur.take_u8()?;
                if n == 0 || n as usize > MAX_ASSIGNMENTS {
                    return Err(EnvelopeError::BadAssignmentCount(n));
                }
                let mut assignments = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    let vout = cur.take_u32_le()?;
                    let amount = cur.take_u64_le()?;
                    if amount == 0 {
                        return Err(EnvelopeError::BadAmount);
                    }
                    if assignments.iter().any(|(v, _)| *v == vout) {
                        return Err(EnvelopeError::DuplicateVout(vout));
                    }
                    assignments.push((vout, amount));
                }
                TokenOp::Transfer { token_id, assignments }
            }
            other => return Err(EnvelopeError::UnknownOp(other)),
        };

        if !cur.is_exhausted() {
            return Err(EnvelopeError::TrailingBytes);
        }
        Ok(op)
    }
}

// ── Extraction from a transaction ─────────────────────────────────────────────

/// Decode the envelope carried by a single output, enforcing the zero-value
/// rule: an output whose `script_pubkey` starts with [`ENVELOPE_MAGIC`] but
/// whose `value != 0` is a typed [`EnvelopeError::NonZeroValue`] error.
pub fn decode_envelope_output(out: &TxOut) -> Result<TokenOp, EnvelopeError> {
    if !out.script_pubkey.starts_with(&ENVELOPE_MAGIC) {
        return Err(EnvelopeError::BadMagic);
    }
    if out.value != 0 {
        return Err(EnvelopeError::NonZeroValue(out.value));
    }
    TokenOp::decode(&out.script_pubkey)
}

/// Extract the transaction's token operation, if any, together with the
/// envelope's output index.
///
/// Reader rules (part of the standard, so every independent indexer agrees):
///
/// 1. **First envelope wins.** The lowest-index output whose
///    `script_pubkey` starts with [`ENVELOPE_MAGIC`] is *the* envelope
///    candidate; later magic-bearing outputs are ignored, valid or not.
/// 2. **Zero value.** The candidate must have `value == 0` and decode
///    strictly; otherwise the transaction carries **no** token operation
///    (`None`) — a malformed candidate does not fall through to later
///    outputs, which would make token state depend on reader order. The
///    Bloch transaction itself remains valid either way.
pub fn extract_envelope(tx: &Tx) -> Option<(usize, TokenOp)> {
    let (idx, candidate) = tx
        .outputs
        .iter()
        .enumerate()
        .find(|(_, o)| o.script_pubkey.starts_with(&ENVELOPE_MAGIC))?;
    decode_envelope_output(candidate).ok().map(|op| (idx, op))
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
        let end = self.pos.checked_add(n).ok_or(EnvelopeError::BadAmount)?;
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

    fn take_u32_le(&mut self) -> Result<u32, EnvelopeError> {
        let mut b = [0u8; 4];
        b.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(b))
    }

    fn take_u64_le(&mut self) -> Result<u64, EnvelopeError> {
        let mut b = [0u8; 8];
        b.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(b))
    }

    fn is_exhausted(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn issue() -> TokenOp {
        TokenOp::Issue {
            decimals: 8,
            flags: FLAG_MINT_CLOSED,
            supply: 21_000_000_00000000,
            symbol: "TOK1".into(),
            name: "Example Token".into(),
        }
    }

    fn transfer() -> TokenOp {
        TokenOp::Transfer {
            token_id: [0xAB; 32],
            assignments: vec![(0, 12_000), (2, 345)],
        }
    }

    fn envelope_out(op: &TokenOp) -> TxOut {
        TxOut { value: 0, script_pubkey: op.encode() }
    }

    fn plain_out() -> TxOut {
        TxOut { value: 5_000, script_pubkey: vec![0x11; 20] }
    }

    fn tx(outputs: Vec<TxOut>) -> Tx {
        Tx { version: 1, inputs: vec![], outputs, locktime: 0 }
    }

    // ── byte layout is pinned exactly (offsets from the spec tables) ─────

    #[test]
    fn issue_byte_layout_matches_spec() {
        let op = TokenOp::Issue {
            decimals: 2,
            flags: FLAG_MINT_CLOSED,
            supply: 0x0102_0304_0506_0708,
            symbol: "AB1".into(),
            name: "xy".into(),
        };
        let b = op.encode();
        assert_eq!(&b[0..4], b"TKV0"); // magic
        assert_eq!(b[4], 0x00); // version
        assert_eq!(b[5], 0x01); // op = ISSUE
        assert_eq!(b[6], 2); // decimals
        assert_eq!(b[7], 0b0000_0001); // flags: mint-closed
        assert_eq!(&b[8..16], &0x0102_0304_0506_0708u64.to_le_bytes()); // supply LE
        assert_eq!(b[16], 3); // symbol_len
        assert_eq!(&b[17..20], b"AB1"); // symbol
        assert_eq!(b[20], 2); // name_len at 17+sl
        assert_eq!(&b[21..23], b"xy"); // name at 18+sl
        assert_eq!(b.len(), 18 + 3 + 2); // ends exactly at 18+sl+nl
    }

    #[test]
    fn transfer_byte_layout_matches_spec() {
        let op = TokenOp::Transfer {
            token_id: [0xCD; 32],
            assignments: vec![(7, 0x1111_2222_3333_4444), (9, 1)],
        };
        let b = op.encode();
        assert_eq!(&b[0..4], b"TKV0");
        assert_eq!(b[4], 0x00);
        assert_eq!(b[5], 0x02); // op = TRANSFER
        assert_eq!(&b[6..38], &[0xCD; 32]); // token_id
        assert_eq!(b[38], 2); // n
        assert_eq!(&b[39..43], &7u32.to_le_bytes()); // vout 0 at 39+12*0
        assert_eq!(&b[43..51], &0x1111_2222_3333_4444u64.to_le_bytes()); // amount 0
        assert_eq!(&b[51..55], &9u32.to_le_bytes()); // vout 1 at 39+12*1
        assert_eq!(&b[55..63], &1u64.to_le_bytes()); // amount 1
        assert_eq!(b.len(), 39 + 12 * 2); // ends exactly at 39+12n
    }

    #[test]
    fn max_envelope_sizes_match_spec() {
        let max_issue = TokenOp::Issue {
            decimals: MAX_DECIMALS,
            flags: FLAG_MINT_CLOSED,
            supply: u64::MAX,
            symbol: "A".repeat(MAX_SYMBOL_LEN),
            name: "n".repeat(MAX_NAME_LEN),
        };
        assert_eq!(max_issue.encode().len(), 58);
        let max_transfer = TokenOp::Transfer {
            token_id: [0; 32],
            assignments: (0..MAX_ASSIGNMENTS as u32).map(|v| (v, 1)).collect(),
        };
        assert_eq!(max_transfer.encode().len(), 231);
    }

    // ── round trips ──────────────────────────────────────────────────────

    #[test]
    fn round_trip_issue_and_transfer() {
        for op in [issue(), transfer()] {
            let bytes = op.encode();
            let decoded = TokenOp::decode(&bytes).expect("valid envelope must decode");
            assert_eq!(decoded, op);
            // encode(decode(x)) == x for all valid envelopes
            assert_eq!(decoded.encode(), bytes);
        }
    }

    #[test]
    fn round_trip_boundary_values() {
        let ops = [
            TokenOp::Issue {
                decimals: 0,
                flags: FLAG_MINT_CLOSED,
                supply: 1,
                symbol: "A".into(),
                name: String::new(), // name may be empty
            },
            TokenOp::Issue {
                decimals: MAX_DECIMALS,
                flags: FLAG_MINT_CLOSED,
                supply: u64::MAX,
                symbol: "A".repeat(MAX_SYMBOL_LEN),
                name: "n".repeat(MAX_NAME_LEN),
            },
            TokenOp::Transfer { token_id: [0u8; 32], assignments: vec![(0, 1)] },
            TokenOp::Transfer {
                token_id: [0xFF; 32],
                assignments: (0..MAX_ASSIGNMENTS as u32).map(|v| (v, u64::MAX)).collect(),
            },
        ];
        for op in ops {
            let bytes = op.encode();
            let decoded = TokenOp::decode(&bytes).unwrap();
            assert_eq!(decoded, op);
            assert_eq!(decoded.encode(), bytes);
        }
    }

    #[test]
    fn round_trip_utf8_name() {
        let op = TokenOp::Issue {
            decimals: 2,
            flags: FLAG_MINT_CLOSED,
            supply: 100,
            symbol: "MOEDA".into(),
            name: "moeda de exposição".into(),
        };
        let bytes = op.encode();
        assert_eq!(TokenOp::decode(&bytes).unwrap().encode(), bytes);
    }

    // ── malformed classes → typed errors, never panics ───────────────────

    #[test]
    fn rejects_bad_magic() {
        let mut b = issue().encode();
        b[0] ^= 0xFF;
        assert_eq!(TokenOp::decode(&b), Err(EnvelopeError::BadMagic));
        assert_eq!(TokenOp::decode(b"XXXX"), Err(EnvelopeError::BadMagic));
        assert_eq!(TokenOp::decode(&[]), Err(EnvelopeError::Truncated));
    }

    #[test]
    fn rejects_bad_version() {
        let mut b = issue().encode();
        b[4] = 0x01;
        assert_eq!(TokenOp::decode(&b), Err(EnvelopeError::BadVersion(0x01)));
    }

    #[test]
    fn rejects_unknown_op() {
        let mut b = transfer().encode();
        b[5] = 0x7F;
        assert_eq!(TokenOp::decode(&b), Err(EnvelopeError::UnknownOp(0x7F)));
    }

    #[test]
    fn rejects_truncation_at_every_prefix() {
        for op in [issue(), transfer()] {
            let full = op.encode();
            for cut in 0..full.len() {
                let err = TokenOp::decode(&full[..cut])
                    .expect_err("every strict prefix must fail");
                assert!(
                    matches!(err, EnvelopeError::Truncated | EnvelopeError::BadMagic),
                    "unexpected error at cut {cut}: {err:?}"
                );
            }
        }
    }

    #[test]
    fn rejects_trailing_bytes() {
        for op in [issue(), transfer()] {
            let mut b = op.encode();
            b.push(0x00);
            assert_eq!(TokenOp::decode(&b), Err(EnvelopeError::TrailingBytes));
        }
    }

    #[test]
    fn rejects_bad_symbol() {
        // over cap
        let over = TokenOp::Issue {
            decimals: 0,
            flags: FLAG_MINT_CLOSED,
            supply: 1,
            symbol: "A".repeat(MAX_SYMBOL_LEN + 1),
            name: "n".into(),
        };
        assert_eq!(TokenOp::decode(&over.encode()), Err(EnvelopeError::BadSymbol));
        // empty
        let empty = TokenOp::Issue {
            decimals: 0,
            flags: FLAG_MINT_CLOSED,
            supply: 1,
            symbol: String::new(),
            name: "n".into(),
        };
        assert_eq!(TokenOp::decode(&empty.encode()), Err(EnvelopeError::BadSymbol));
        // lowercase / non-alphanumeric bytes
        for bad in ["tok", "T K", "T-K"] {
            let op = TokenOp::Issue {
                decimals: 0,
                flags: FLAG_MINT_CLOSED,
                supply: 1,
                symbol: bad.into(),
                name: "n".into(),
            };
            assert_eq!(TokenOp::decode(&op.encode()), Err(EnvelopeError::BadSymbol));
        }
    }

    #[test]
    fn rejects_bad_name() {
        let over = TokenOp::Issue {
            decimals: 0,
            flags: FLAG_MINT_CLOSED,
            supply: 1,
            symbol: "T".into(),
            name: "n".repeat(MAX_NAME_LEN + 1),
        };
        assert_eq!(TokenOp::decode(&over.encode()), Err(EnvelopeError::BadName));

        // invalid UTF-8 in the name bytes (hand-built payload)
        let mut b = Vec::new();
        b.extend_from_slice(&ENVELOPE_MAGIC);
        b.push(ENVELOPE_VERSION);
        b.push(0x01); // OP_ISSUE
        b.push(0); // decimals
        b.push(FLAG_MINT_CLOSED); // flags
        b.extend_from_slice(&1u64.to_le_bytes()); // supply
        b.push(1);
        b.push(b'T');
        b.push(2);
        b.extend_from_slice(&[0xFF, 0xFE]); // not UTF-8
        assert_eq!(TokenOp::decode(&b), Err(EnvelopeError::BadName));
    }

    #[test]
    fn rejects_bad_decimals_and_flags() {
        let bad_dec = TokenOp::Issue {
            decimals: MAX_DECIMALS + 1,
            flags: FLAG_MINT_CLOSED,
            supply: 1,
            symbol: "T".into(),
            name: String::new(),
        };
        assert_eq!(
            TokenOp::decode(&bad_dec.encode()),
            Err(EnvelopeError::BadDecimals(MAX_DECIMALS + 1))
        );

        // v0: mint-open (bit 0 unset) and reserved bits are both malformed.
        for bad_flags in [0x00u8, 0x02, 0x03, 0xFF] {
            let op = TokenOp::Issue {
                decimals: 0,
                flags: bad_flags,
                supply: 1,
                symbol: "T".into(),
                name: String::new(),
            };
            assert_eq!(TokenOp::decode(&op.encode()), Err(EnvelopeError::BadFlags(bad_flags)));
        }
    }

    #[test]
    fn rejects_zero_amounts() {
        let zero_supply = TokenOp::Issue {
            decimals: 0,
            flags: FLAG_MINT_CLOSED,
            supply: 0,
            symbol: "T".into(),
            name: "n".into(),
        };
        assert_eq!(TokenOp::decode(&zero_supply.encode()), Err(EnvelopeError::BadAmount));

        let zero_amount =
            TokenOp::Transfer { token_id: [1u8; 32], assignments: vec![(0, 0)] };
        assert_eq!(TokenOp::decode(&zero_amount.encode()), Err(EnvelopeError::BadAmount));
    }

    #[test]
    fn rejects_bad_assignment_count_and_duplicate_vout() {
        let empty = TokenOp::Transfer { token_id: [1u8; 32], assignments: vec![] };
        assert_eq!(
            TokenOp::decode(&empty.encode()),
            Err(EnvelopeError::BadAssignmentCount(0))
        );

        let over = TokenOp::Transfer {
            token_id: [1u8; 32],
            assignments: (0..MAX_ASSIGNMENTS as u32 + 1).map(|v| (v, 1)).collect(),
        };
        assert_eq!(
            TokenOp::decode(&over.encode()),
            Err(EnvelopeError::BadAssignmentCount(MAX_ASSIGNMENTS as u8 + 1))
        );

        let dup = TokenOp::Transfer {
            token_id: [1u8; 32],
            assignments: vec![(3, 1), (3, 2)],
        };
        assert_eq!(TokenOp::decode(&dup.encode()), Err(EnvelopeError::DuplicateVout(3)));
    }

    #[test]
    fn never_panics_on_random_ish_garbage() {
        // Deterministic pseudo-random byte soup (xorshift), no deps: decode
        // must return, valid or typed-error, for every input.
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        for len in 0..250usize {
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                buf.push(state as u8);
            }
            let _ = TokenOp::decode(&buf); // must not panic
        }
    }

    // ── extraction rules ─────────────────────────────────────────────────

    #[test]
    fn extract_finds_envelope_among_plain_outputs() {
        let t = tx(vec![plain_out(), envelope_out(&issue()), plain_out()]);
        assert_eq!(extract_envelope(&t), Some((1, issue())));
    }

    #[test]
    fn extract_none_without_envelope() {
        assert_eq!(extract_envelope(&tx(vec![plain_out(), plain_out()])), None);
        assert_eq!(extract_envelope(&tx(vec![])), None);
    }

    #[test]
    fn extract_enforces_zero_value() {
        let bad = TxOut { value: 1, script_pubkey: issue().encode() };
        assert_eq!(extract_envelope(&tx(vec![bad.clone()])), None);
        // and the typed error is exposed at the output level:
        assert_eq!(
            decode_envelope_output(&bad),
            Err(EnvelopeError::NonZeroValue(1))
        );
    }

    #[test]
    fn extract_first_envelope_wins() {
        // Two valid envelopes: the first wins.
        let t = tx(vec![envelope_out(&transfer()), envelope_out(&issue())]);
        assert_eq!(extract_envelope(&t), Some((0, transfer())));

        // First candidate malformed (truncated): the tx carries NO token op —
        // a later valid envelope must NOT be promoted.
        let mut truncated = issue().encode();
        truncated.truncate(truncated.len() - 1);
        let t = tx(vec![
            TxOut { value: 0, script_pubkey: truncated },
            envelope_out(&issue()),
        ]);
        assert_eq!(extract_envelope(&t), None);

        // First candidate has nonzero value: same rule, no fall-through.
        let t = tx(vec![
            TxOut { value: 7, script_pubkey: transfer().encode() },
            envelope_out(&issue()),
        ]);
        assert_eq!(extract_envelope(&t), None);
    }
}
