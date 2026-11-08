// SPDX-License-Identifier: MIT OR Apache-2.0
//! `L2D0` deposit envelope — byte-exact per BLOCH-L2-EVM-DESIGN §5.
//!
//! One zero-value `TxOutput.script_pubkey` on Bloch L1 (the TKV0 trick:
//! node validation never constrains new-output script_pubkeys, so this is
//! provably zero consensus change). Wire format, all ints little-endian:
//!
//! ```text
//! offset 0:  4B  magic "L2D0"        (0x4C 0x32 0x44 0x30)
//! offset 4:  u8  version = 0x00
//! offset 5:  u8  op      = 0x01 (DEPOSIT)
//! offset 6:  u64 l2_chain_id (LE)   — EVM chain id of the target L2
//! offset 14: 20B l2_recipient       — EVM address to credit
//! offset 34: end — EXACTLY 34 bytes, no trailing bytes tolerated
//! ```
//!
//! Layer rules (inherited from the TKV0 idiom, tested here):
//! * strict decode: any violation is a typed error and a **layer no-op**
//!   (the Bloch tx itself stays valid; per §5 the BLCH still lands in the
//!   vault and is handled by the published refund policy — NOT this crate);
//! * envelopes ride **zero-value** outputs only (TKV0 caveat E.1: the node
//!   address indexer misreads long script_pubkeys as addresses, so no BLCH
//!   ever rides an envelope);
//! * one envelope per tx, **lowest-index-wins** (TKV0 rule C.1).
//!
//! SCAFFOLD, UNAUDITED: this is a codec, not a bridge. Nothing here moves
//! value.

/// The 4-byte ASCII magic, `"L2D0"`.
pub const MAGIC: [u8; 4] = *b"L2D0";
/// Envelope version this codec understands.
pub const VERSION: u8 = 0x00;
/// The only op defined for L2D0 v0: DEPOSIT.
pub const OP_DEPOSIT: u8 = 0x01;
/// Exact encoded length: 4 + 1 + 1 + 8 + 20.
pub const ENVELOPE_LEN: usize = 34;

/// A decoded `L2D0` DEPOSIT envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepositEnvelope {
    /// EVM chain id of the target L2 (e.g. 700771, a PLACEHOLDER pending
    /// ethereum-lists/chains registration).
    pub l2_chain_id: u64,
    /// EVM address on the L2 to credit with the deposit mint.
    pub l2_recipient: [u8; 20],
}

impl DepositEnvelope {
    /// Encode to the exact 34-byte wire form.
    pub fn encode(&self) -> [u8; ENVELOPE_LEN] {
        let mut out = [0u8; ENVELOPE_LEN];
        out[0..4].copy_from_slice(&MAGIC);
        out[4] = VERSION;
        out[5] = OP_DEPOSIT;
        out[6..14].copy_from_slice(&self.l2_chain_id.to_le_bytes());
        out[14..34].copy_from_slice(&self.l2_recipient);
        out
    }

    /// Strict decode. Any deviation from the wire format is a typed error;
    /// callers MUST treat every error as a layer no-op (never a tx
    /// rejection — this layer has no consensus authority).
    pub fn decode(script_pubkey: &[u8]) -> Result<Self, DecodeError> {
        if script_pubkey.len() < 4 {
            return Err(DecodeError::TooShort {
                len: script_pubkey.len(),
            });
        }
        if script_pubkey[0..4] != MAGIC {
            return Err(DecodeError::BadMagic);
        }
        if script_pubkey.len() < 6 {
            return Err(DecodeError::TooShort {
                len: script_pubkey.len(),
            });
        }
        if script_pubkey[4] != VERSION {
            return Err(DecodeError::UnsupportedVersion(script_pubkey[4]));
        }
        if script_pubkey[5] != OP_DEPOSIT {
            return Err(DecodeError::UnsupportedOp(script_pubkey[5]));
        }
        if script_pubkey.len() < ENVELOPE_LEN {
            return Err(DecodeError::TooShort {
                len: script_pubkey.len(),
            });
        }
        if script_pubkey.len() > ENVELOPE_LEN {
            return Err(DecodeError::TrailingBytes {
                len: script_pubkey.len(),
            });
        }
        let mut chain_id = [0u8; 8];
        chain_id.copy_from_slice(&script_pubkey[6..14]);
        let mut recipient = [0u8; 20];
        recipient.copy_from_slice(&script_pubkey[14..34]);
        Ok(DepositEnvelope {
            l2_chain_id: u64::from_le_bytes(chain_id),
            l2_recipient: recipient,
        })
    }
}

/// Typed strict-decode errors. Every variant means "layer no-op".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Fewer bytes than the field being read requires.
    TooShort { len: usize },
    /// First four bytes are not `"L2D0"`.
    BadMagic,
    /// Version byte is not 0x00.
    UnsupportedVersion(u8),
    /// Op byte is not 0x01 (DEPOSIT).
    UnsupportedOp(u8),
    /// Longer than the exact 34-byte form (strict: no trailing bytes).
    TrailingBytes { len: usize },
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DecodeError::TooShort { len } => write!(f, "L2D0: too short ({len} bytes)"),
            DecodeError::BadMagic => write!(f, "L2D0: bad magic"),
            DecodeError::UnsupportedVersion(v) => write!(f, "L2D0: unsupported version {v:#04x}"),
            DecodeError::UnsupportedOp(op) => write!(f, "L2D0: unsupported op {op:#04x}"),
            DecodeError::TrailingBytes { len } => {
                write!(f, "L2D0: trailing bytes ({len} > {ENVELOPE_LEN})")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// A transaction output as this layer sees it (value in L1 atoms/sats plus
/// the raw script_pubkey). Mirrors the shape bloch-tokens reads over RPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutput {
    /// Output value in L1 atoms. Envelopes MUST be zero-value.
    pub value: u64,
    /// Raw script_pubkey bytes.
    pub script_pubkey: Vec<u8>,
}

/// Extract the winning `L2D0` deposit envelope from a transaction's
/// outputs, per the layer rules:
///
/// * only **zero-value** outputs are considered (caveat E.1);
/// * malformed envelopes are no-ops (skipped);
/// * the FIRST (lowest output index) valid envelope wins; later valid
///   envelopes in the same tx are ignored (TKV0 rule C.1).
///
/// Returns `(output_index, envelope)` or `None` if the tx carries no valid
/// envelope. Note: the deposit AMOUNT is not read here — per §5 it is the
/// sum of tx outputs paying disclosed vault addresses, which requires the
/// vault set (see `stubs::L1DepositWatcher`, honestly stubbed).
pub fn extract_deposit_envelope(outputs: &[TxOutput]) -> Option<(u32, DepositEnvelope)> {
    for (index, out) in outputs.iter().enumerate() {
        if out.value != 0 {
            continue; // value-bearing outputs are never envelopes
        }
        if let Ok(envelope) = DepositEnvelope::decode(&out.script_pubkey) {
            return Some((index as u32, envelope));
        }
        // malformed => layer no-op: keep scanning later outputs
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> DepositEnvelope {
        DepositEnvelope {
            l2_chain_id: 700_771,
            l2_recipient: [0x11; 20],
        }
    }

    #[test]
    fn round_trip() {
        let e = sample();
        let bytes = e.encode();
        assert_eq!(bytes.len(), ENVELOPE_LEN);
        assert_eq!(DepositEnvelope::decode(&bytes).unwrap(), e);
    }

    #[test]
    fn round_trip_extremes() {
        for chain_id in [0u64, 1, u64::MAX] {
            for fill in [0x00u8, 0xff] {
                let e = DepositEnvelope {
                    l2_chain_id: chain_id,
                    l2_recipient: [fill; 20],
                };
                assert_eq!(DepositEnvelope::decode(&e.encode()).unwrap(), e);
            }
        }
    }

    #[test]
    fn golden_vector() {
        // chain_id 700771 = 0x000AB163 -> LE: 63 b1 0a 00 00 00 00 00
        let e = DepositEnvelope {
            l2_chain_id: 700_771,
            l2_recipient: [
                0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            ],
        };
        let expected_hex = "4c324430\
                            00\
                            01\
                            63b10a0000000000\
                            deadbeef000102030405060708090a0b0c0d0e0f";
        assert_eq!(crate::hex::encode(&e.encode()), expected_hex);
        // and the golden bytes decode back to the same struct
        let bytes = crate::hex::decode(expected_hex).unwrap();
        assert_eq!(DepositEnvelope::decode(&bytes).unwrap(), e);
    }

    #[test]
    fn malformed_classes_are_typed_no_ops() {
        let good = sample().encode();

        // empty / short-of-magic
        assert_eq!(
            DepositEnvelope::decode(&[]),
            Err(DecodeError::TooShort { len: 0 })
        );
        assert_eq!(
            DepositEnvelope::decode(b"L2D"),
            Err(DecodeError::TooShort { len: 3 })
        );

        // wrong magic (TKV0's magic, and a corrupt byte)
        let mut bad_magic = good;
        bad_magic[0..4].copy_from_slice(b"TKV0");
        assert_eq!(
            DepositEnvelope::decode(&bad_magic),
            Err(DecodeError::BadMagic)
        );

        // magic only, no version/op
        assert_eq!(
            DepositEnvelope::decode(b"L2D0"),
            Err(DecodeError::TooShort { len: 4 })
        );
        assert_eq!(
            DepositEnvelope::decode(b"L2D0\x00"),
            Err(DecodeError::TooShort { len: 5 })
        );

        // unknown version
        let mut bad_version = good;
        bad_version[4] = 0x01;
        assert_eq!(
            DepositEnvelope::decode(&bad_version),
            Err(DecodeError::UnsupportedVersion(0x01))
        );

        // unknown op
        let mut bad_op = good;
        bad_op[5] = 0x02;
        assert_eq!(
            DepositEnvelope::decode(&bad_op),
            Err(DecodeError::UnsupportedOp(0x02))
        );

        // truncated body
        assert_eq!(
            DepositEnvelope::decode(&good[..33]),
            Err(DecodeError::TooShort { len: 33 })
        );

        // trailing byte (strict: exact length only)
        let mut trailing = good.to_vec();
        trailing.push(0x00);
        assert_eq!(
            DepositEnvelope::decode(&trailing),
            Err(DecodeError::TrailingBytes { len: 35 })
        );
    }

    #[test]
    fn extraction_lowest_index_wins() {
        let a = DepositEnvelope {
            l2_chain_id: 700_771,
            l2_recipient: [0xaa; 20],
        };
        let b = DepositEnvelope {
            l2_chain_id: 700_771,
            l2_recipient: [0xbb; 20],
        };
        let outputs = vec![
            TxOutput {
                value: 5_000,
                script_pubkey: vec![0x99; 20], // ordinary payment
            },
            TxOutput {
                value: 0,
                script_pubkey: a.encode().to_vec(),
            },
            TxOutput {
                value: 0,
                script_pubkey: b.encode().to_vec(),
            },
        ];
        assert_eq!(extract_deposit_envelope(&outputs), Some((1, a)));
    }

    #[test]
    fn extraction_skips_malformed_and_value_bearing() {
        let good = sample();
        let mut malformed = good.encode().to_vec();
        malformed[4] = 0xff; // bad version => no-op, not a poison pill
        let outputs = vec![
            // valid bytes but NON-ZERO value: never an envelope (caveat E.1)
            TxOutput {
                value: 1,
                script_pubkey: good.encode().to_vec(),
            },
            // zero-value but malformed: layer no-op, scanning continues
            TxOutput {
                value: 0,
                script_pubkey: malformed,
            },
            // the winner
            TxOutput {
                value: 0,
                script_pubkey: good.encode().to_vec(),
            },
        ];
        assert_eq!(extract_deposit_envelope(&outputs), Some((2, good)));
    }

    #[test]
    fn decode_never_panics_on_arbitrary_bytes() {
        // The strict decoder must be panic-free (no OOB indexing, no
        // slice-length panics) for EVERY input length and content: every
        // deviation is a typed error, never a crash.
        for len in 0..=48usize {
            for fill in [0x00u8, 0x4c, 0x30, 0xff, 0x01] {
                let buf = vec![fill; len];
                let _ = DepositEnvelope::decode(&buf); // must not panic
            }
        }
        // every prefix of a well-formed header (partial magic/version/op)
        let header = *b"L2D0\x00\x01";
        for len in 0..=header.len() {
            let _ = DepositEnvelope::decode(&header[..len]);
        }
        // a valid envelope with growing trailing tails: exactly-34 decodes,
        // anything longer is the typed TrailingBytes error (never a panic).
        let base = DepositEnvelope {
            l2_chain_id: 1,
            l2_recipient: [7; 20],
        }
        .encode();
        for extra in 0..8usize {
            let mut v = base.to_vec();
            v.extend(vec![0xABu8; extra]);
            match DepositEnvelope::decode(&v) {
                Ok(_) => assert_eq!(extra, 0),
                Err(DecodeError::TrailingBytes { len }) => {
                    assert!(extra > 0 && len == ENVELOPE_LEN + extra);
                }
                Err(other) => panic!("unexpected error for +{extra} tail: {other:?}"),
            }
        }
    }

    #[test]
    fn extraction_none_when_no_envelope() {
        let outputs = vec![
            TxOutput {
                value: 42,
                script_pubkey: vec![0x01; 20],
            },
            TxOutput {
                value: 0,
                script_pubkey: b"not an envelope".to_vec(),
            },
        ];
        assert_eq!(extract_deposit_envelope(&outputs), None);
        assert_eq!(extract_deposit_envelope(&[]), None);
    }
}
