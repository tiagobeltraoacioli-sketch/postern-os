// SPDX-License-Identifier: MIT OR Apache-2.0
//! EIP-2718 transaction-type classification of a raw signed tx envelope, and
//! the sequencer-boundary policy on which types the single disclosed operator
//! accepts from user RPC intake.
//!
//! Per `BLOCH-L2-EVM-DESIGN.md` §1, this L2 is byte-for-byte Cancun with an
//! enumerated delta list; one delta is: **type-3 (EIP-4844 blob) transactions
//! are rejected at the sequencer exactly as on OP-Stack L2s** (blob data lives
//! on L1; this L2 has no blob mempool — `BLOBHASH`/blob-basefee opcodes still
//! return spec-correct values for the resulting blobless blocks). The OP-style
//! type-`0x7E` deposit (§5) is a SYSTEM transaction derived from L1; a user can
//! never inject one through the RPC intake either.
//!
//! Classification is a pure, panic-free function of the envelope's leading
//! byte, using the EIP-2718 rule: a leading byte in `0x00..=0x7F` is a typed
//! transaction whose value is the type; a leading byte in `0xC0..=0xFF` is the
//! RLP-list prefix of a legacy transaction. Leading bytes `0x80..=0xBF` are RLP
//! *string* prefixes and are not valid transaction envelopes.
//!
//! SCAFFOLD: this inspects only the leading byte — it does NOT decode or verify
//! the RLP body or the signature (the real Reth intake does). It is exactly
//! enough to enforce the type-admission boundary above, deterministically.

use crate::deposit::DEPOSIT_TX_TYPE;

/// EIP-2718 transaction type as seen at the sequencer boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxType {
    /// Pre-EIP-2718 legacy transaction (leading byte is an RLP list prefix,
    /// `0xC0..=0xFF`).
    Legacy,
    /// EIP-2930 access-list transaction (type `0x01`).
    Eip2930AccessList,
    /// EIP-1559 dynamic-fee transaction (type `0x02`).
    Eip1559DynamicFee,
    /// EIP-4844 blob transaction (type `0x03`) — REJECTED at this sequencer.
    Eip4844Blob,
    /// OP-style deposit transaction (type `0x7E`, §5) — a SYSTEM tx derived
    /// from L1, never user-submittable.
    Deposit,
    /// A reserved/unknown typed envelope (`0x00`, `0x04..=0x7D`, `0x7F`) or an
    /// RLP string prefix (`0x80..=0xBF`) that is not a valid tx envelope. The
    /// wrapped byte is the leading byte for diagnostics.
    Unknown(u8),
}

impl TxType {
    /// Whether the single disclosed sequencer accepts this type from user RPC
    /// intake. Blob (type-3) and deposit (type-`0x7E`) txs are the only named
    /// types refused; unknown/reserved leading bytes are left to the (stubbed)
    /// real RLP decoder and are not gated here.
    pub fn is_user_submittable(self) -> bool {
        !matches!(self, TxType::Eip4844Blob | TxType::Deposit)
    }
}

/// Classify a raw signed-tx envelope by its leading byte (EIP-2718 rule).
///
/// Returns `None` only for an empty slice. Never panics.
pub fn classify(raw: &[u8]) -> Option<TxType> {
    let lead = *raw.first()?;
    Some(match lead {
        // RLP list prefix ⇒ legacy transaction.
        0xC0..=0xFF => TxType::Legacy,
        0x01 => TxType::Eip2930AccessList,
        0x02 => TxType::Eip1559DynamicFee,
        0x03 => TxType::Eip4844Blob,
        DEPOSIT_TX_TYPE => TxType::Deposit, // 0x7E
        other => TxType::Unknown(other),
    })
}

/// True iff `raw` is an EIP-4844 blob transaction (type `0x03`). Convenience
/// wrapper over [`classify`]; an empty slice is not a blob tx.
pub fn is_blob_tx(raw: &[u8]) -> bool {
    matches!(classify(raw), Some(TxType::Eip4844Blob))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_is_unclassifiable() {
        assert_eq!(classify(&[]), None);
        assert!(!is_blob_tx(&[]));
    }

    #[test]
    fn named_types_classify_exactly() {
        assert_eq!(classify(&[0x01, 0xaa]), Some(TxType::Eip2930AccessList));
        assert_eq!(classify(&[0x02, 0xaa]), Some(TxType::Eip1559DynamicFee));
        assert_eq!(classify(&[0x03, 0xaa]), Some(TxType::Eip4844Blob));
        assert_eq!(classify(&[0x7E, 0xaa]), Some(TxType::Deposit));
    }

    #[test]
    fn legacy_is_any_rlp_list_prefix() {
        for lead in 0xC0u8..=0xFF {
            assert_eq!(classify(&[lead, 0x00]), Some(TxType::Legacy), "lead {lead:#x}");
        }
    }

    #[test]
    fn reserved_and_string_prefixes_are_unknown() {
        assert_eq!(classify(&[0x00]), Some(TxType::Unknown(0x00)));
        assert_eq!(classify(&[0x04]), Some(TxType::Unknown(0x04)));
        assert_eq!(classify(&[0x7F]), Some(TxType::Unknown(0x7F)));
        // 0x80..=0xBF are RLP string prefixes, not tx envelopes.
        assert_eq!(classify(&[0x80]), Some(TxType::Unknown(0x80)));
        assert_eq!(classify(&[0xBF]), Some(TxType::Unknown(0xBF)));
    }

    #[test]
    fn only_blob_and_deposit_are_non_submittable() {
        assert!(TxType::Legacy.is_user_submittable());
        assert!(TxType::Eip2930AccessList.is_user_submittable());
        assert!(TxType::Eip1559DynamicFee.is_user_submittable());
        assert!(TxType::Unknown(0x00).is_user_submittable());
        assert!(!TxType::Eip4844Blob.is_user_submittable());
        assert!(!TxType::Deposit.is_user_submittable());
    }

    #[test]
    fn blob_detection_matches_classify() {
        assert!(is_blob_tx(&[0x03, 0x01, 0x02, 0x03]));
        assert!(!is_blob_tx(&[0x02, 0x01]));
        assert!(!is_blob_tx(&[0xC8, 0x01]));
        assert!(!is_blob_tx(&[0x7E, 0x01]));
    }
}
