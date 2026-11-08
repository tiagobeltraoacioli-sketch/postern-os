// SPDX-License-Identifier: MIT OR Apache-2.0

//! Decode a REAL node transaction into the protocol's transfer intent, for
//! WYSIWYS — parsed from the bytes the phone would sign, never from prose.
//!
//! The v1 headline is wallet-login (no tx). This module is the value path: it
//! turns a `bloch_crypto::core::Transaction` (Bitcoin-format hex, exactly what
//! the desktop builds and what `WalletCore::sign_tx_hex` signs) into a
//! [`TransferIntent`](postern_signer_protocol::TransferIntent), so a transfer
//! request flows into the protocol's existing ExplicitReview WYSIWYS path
//! ([`render`](postern_signer_protocol::render)). Recipients are formatted with
//! `bloch_crypto::crypto::address_from_hash` — the same encoder the node uses.
//!
//! ## Honest limits (surfaced, never rounded off)
//!
//! - **Fee is NOT verifiable from the tx bytes alone.** The transaction wire
//!   format carries no input amounts, so `fee = Σinputs − Σoutputs` cannot be
//!   computed here. A requester-declared fee is passed through and **labeled
//!   unverifiable**; it is never presented as ground truth.
//! - **Network** comes from the phone's own wallet (`testnet`), not the request —
//!   the tx format folds chain-id into the sighash, not the visible bytes.
//! - **Single-recipient only, fail-closed.** A [`TransferIntent`] names one
//!   recipient + amount. A multi-output transaction cannot be honestly reduced to
//!   that, so [`to_transfer_intent`] **refuses** it (rather than under-displaying
//!   what would be signed). [`describe_outputs`] still lists every output for the
//!   card.

use bloch_crypto::core::{ChainId, Transaction};
use bloch_crypto::crypto::address_from_hash;
use postern_signer_protocol::message::{Chain, TransferIntent};

/// Why decoding a transaction for display failed. Fail-closed: if the phone
/// cannot honestly show what it would sign, it refuses.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TxDecodeError {
    /// The hex was not valid hex.
    #[error("transaction is not valid hex: {0}")]
    BadHex(String),
    /// The bytes did not decode to a transaction.
    #[error("could not decode the transaction to show what would be signed: {0}")]
    Undecodable(String),
    /// The transaction has no spendable output to display.
    #[error("transaction has no outputs")]
    NoOutputs,
    /// A [`TransferIntent`] cannot honestly represent a multi-output tx.
    #[error("multi-output transaction ({0} outputs) is not representable as a single-recipient transfer; refusing rather than under-displaying")]
    MultiOutput(usize),
}

/// One decoded output line for the approval card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputLine {
    /// The recipient address (formatted with the node's `address_from_hash`), or a
    /// labeled `<non-standard script …>` for a non-20-byte script.
    pub recipient: String,
    /// The value in sats.
    pub value_sats: u64,
}

/// A full, honest description of every output in the tx, for display. Total value
/// + an explicit fee-unverifiable disclosure travel alongside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxDescription {
    /// Every output, in order.
    pub outputs: Vec<OutputLine>,
    /// Sum of all output values (sats).
    pub total_out_sats: u64,
    /// Number of inputs (the count is on the wire; the amounts are not).
    pub input_count: usize,
    /// "testnet"/"mainnet", from the phone's own wallet.
    pub network: &'static str,
    /// The mandatory disclosures to render (fee unverifiability + WYSIWYS).
    pub disclosures: Vec<String>,
}

/// Decode + describe every output of `unsigned_tx_hex`, formatting recipients for
/// `network_is_testnet` (the phone wallet's own network). `declared_fee_sats` is
/// the requester's claim; it is surfaced as unverifiable.
pub fn describe_outputs(
    unsigned_tx_hex: &str,
    network_is_testnet: bool,
    declared_fee_sats: Option<u64>,
) -> Result<TxDescription, TxDecodeError> {
    let tx = decode(unsigned_tx_hex)?;
    if tx.outputs.is_empty() {
        return Err(TxDecodeError::NoOutputs);
    }
    let mut outputs = Vec::with_capacity(tx.outputs.len());
    let mut total: u64 = 0;
    for out in &tx.outputs {
        total = total.saturating_add(out.value);
        outputs.push(OutputLine {
            recipient: format_recipient(&out.script_pubkey, network_is_testnet),
            value_sats: out.value,
        });
    }
    let mut disclosures = vec![
        "You are signing THIS transaction, decoded from the bytes on your phone — \
         not text the other device sent."
            .to_string(),
    ];
    disclosures.push(match declared_fee_sats {
        Some(f) => format!(
            "Requester-declared fee: {f} sats — NOT verifiable from the transaction \
             bytes alone (inputs carry no amounts). Treat as a hint, not a fact."
        ),
        None => "No fee declared; the fee cannot be verified from the transaction \
                 bytes alone."
            .to_string(),
    });
    Ok(TxDescription {
        outputs,
        total_out_sats: total,
        input_count: tx.inputs.len(),
        network: if network_is_testnet { "testnet" } else { "mainnet" },
        disclosures,
    })
}

/// Reduce a **single-recipient** transaction to a protocol [`TransferIntent`], so
/// it can be rendered by the protocol's ExplicitReview WYSIWYS and signed on the
/// same path. Refuses multi-output txs (see [`TxDecodeError::MultiOutput`]).
///
/// The intent `nonce` is bound to the transaction's own `txid`, so a captured
/// intent cannot be re-pointed at a different tx. `chain` comes from the phone's
/// network. `fee` is the requester's declared value (unverifiable — see module
/// docs); pass `0` if unknown.
pub fn to_transfer_intent(
    unsigned_tx_hex: &str,
    network_is_testnet: bool,
    declared_fee_sats: u64,
) -> Result<TransferIntent, TxDecodeError> {
    let tx = decode(unsigned_tx_hex)?;
    match tx.outputs.len() {
        0 => Err(TxDecodeError::NoOutputs),
        1 => {
            let out = &tx.outputs[0];
            Ok(TransferIntent {
                to_address: format_recipient(&out.script_pubkey, network_is_testnet),
                amount: out.value,
                fee: declared_fee_sats,
                chain: if network_is_testnet { Chain::Testnet } else { Chain::Mainnet },
                nonce: tx.txid(),
            })
        }
        n => Err(TxDecodeError::MultiOutput(n)),
    }
}

/// The chain-id the phone's wallet signs under (mainnet ≠ testnet). Kept next to
/// the decoder so a caller can display it; folded into the sighash by
/// `WalletCore::sign_tx_hex`.
pub fn chain_id(network_is_testnet: bool) -> ChainId {
    if network_is_testnet { ChainId::Testnet } else { ChainId::Mainnet }
}

fn decode(unsigned_tx_hex: &str) -> Result<Transaction, TxDecodeError> {
    let bytes = hex::decode(unsigned_tx_hex).map_err(|e| TxDecodeError::BadHex(e.to_string()))?;
    Transaction::from_stratum_bytes(&bytes).map_err(TxDecodeError::Undecodable)
}

fn format_recipient(script_pubkey: &[u8], network_is_testnet: bool) -> String {
    if script_pubkey.len() == 20 {
        let mut h = [0u8; 20];
        h.copy_from_slice(script_pubkey);
        address_from_hash(&h, network_is_testnet)
    } else {
        format!("<non-standard script: 0x{}>", hex::encode(script_pubkey))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloch_crypto::core::{Transaction, TxInput, TxOutput};

    fn tx_hex(values: &[u64]) -> String {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [3u8; 32],
                prev_index: 0,
                script_sig: vec![],
                sequence: 0xffff_ffff,
            }],
            outputs: values
                .iter()
                .map(|v| TxOutput { value: *v, script_pubkey: vec![9u8; 20] })
                .collect(),
            locktime: 0,
        };
        hex::encode(tx.to_stratum_bytes(true))
    }

    #[test]
    fn describe_lists_outputs_with_node_addresses_and_fee_disclosure() {
        let d = describe_outputs(&tx_hex(&[500, 250]), true, Some(21)).unwrap();
        assert_eq!(d.total_out_sats, 750);
        assert_eq!(d.outputs.len(), 2);
        assert!(d.outputs[0].recipient.starts_with("bloch1t"));
        assert_eq!(d.network, "testnet");
        assert!(d.disclosures.iter().any(|s| s.contains("NOT verifiable")));
    }

    #[test]
    fn single_output_becomes_a_transfer_intent_bound_to_the_txid() {
        let hexstr = tx_hex(&[500]);
        let intent = to_transfer_intent(&hexstr, true, 21).unwrap();
        assert_eq!(intent.amount, 500);
        assert_eq!(intent.fee, 21);
        assert_eq!(intent.chain, Chain::Testnet);
        assert!(intent.to_address.starts_with("bloch1t"));
        // Nonce is the tx's own txid (stable), so it re-points to no other tx.
        let again = to_transfer_intent(&hexstr, true, 21).unwrap();
        assert_eq!(intent.nonce, again.nonce);
    }

    #[test]
    fn multi_output_is_refused_not_under_displayed() {
        assert!(matches!(
            to_transfer_intent(&tx_hex(&[500, 250]), true, 0),
            Err(TxDecodeError::MultiOutput(2))
        ));
    }

    #[test]
    fn bad_hex_fails_closed() {
        assert!(matches!(
            describe_outputs("zz", true, None),
            Err(TxDecodeError::BadHex(_))
        ));
    }
}
