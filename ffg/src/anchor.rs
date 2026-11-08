// SPDX-License-Identifier: MIT OR Apache-2.0
//! A light anchoring-client interface to the ownerless Bloch-SIS-PoW base.
//!
//! # SCAFFOLD — not a secure or deployed system
//!
//! Layer 2 (this module's domain) **reads** the base (headers, accumulated
//! work, canonical tip) and **anchors** its certificate hashes back onto the
//! base **as ordinary base transactions/commitments** — the way any user writes
//! data to an ownerless chain (design `§1.1`-`§1.3`, `§10.4`). It never gains
//! privileged write access, never changes base validity, and never becomes a
//! consensus dependency of the base. If the whole Postern signer set vanished,
//! the base continues exactly as before, minus the notarizations.
//!
//! This interface is **defined here, standalone**. It deliberately does **not**
//! depend on any sibling framework crate; it only mirrors the same
//! read-tip / write-commitment anchoring *pattern*. Base gas paid (in BLCH) to
//! anchor is **operational spend only** — paying for computation, never a value
//! claim about the worthless BLCH coin (design `§0.4`).

use crate::checkpoint::BaseAnchorRef;

/// A commitment (e.g. a checkpoint-certificate hash) to be written onto the base
/// as ordinary transaction data. 32 opaque bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorCommitment(pub [u8; 32]);

/// Receipt proving a commitment was accepted into the base as ordinary data.
///
/// SCAFFOLD: a receipt records only that *data was written* — it confers no
/// base-consensus privilege and no settlement guarantee.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorReceipt {
    /// Base transaction id that carried the commitment.
    pub base_txid: [u8; 32],
    /// Base height at which the anchoring transaction was included.
    pub anchored_at_height: u64,
    /// The commitment that was anchored.
    pub commitment: AnchorCommitment,
}

/// The light Bloch anchoring-client interface.
///
/// A real implementation talks to Postern's own fully-validating base nodes.
/// This crate ships only the in-memory [`InMemoryAnchorClient`] scaffold.
pub trait BlochAnchorClient {
    /// Return the canonical tip as seen by Postern's own base nodes (design
    /// `§1.2`). This is an *observation*, not a consensus authority.
    fn canonical_tip(&self) -> Result<BaseAnchorRef, AnchorError>;

    /// Return the base header reference at a given height, if known.
    fn header_at(&self, height: u64) -> Result<BaseAnchorRef, AnchorError>;

    /// Anchor a commitment onto the base as ordinary transaction data.
    ///
    /// Writing ordinary data only — no reserved namespace, no consensus
    /// privilege, no exclusivity (design `§1.5`). Anyone else may anchor their
    /// own (including decentralized) finality gadget to the same base in
    /// parallel.
    fn anchor_commitment(
        &mut self,
        commitment: AnchorCommitment,
    ) -> Result<AnchorReceipt, AnchorError>;
}

/// Errors from the anchoring client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorError {
    /// The requested base height is not known to the client.
    UnknownHeight(u64),
    /// The base view is empty / not yet synced.
    NoCanonicalTip,
    /// The underlying base transport failed (opaque, scaffold-level).
    Transport(String),
}

impl core::fmt::Display for AnchorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AnchorError::UnknownHeight(h) => write!(f, "unknown base height {h}"),
            AnchorError::NoCanonicalTip => write!(f, "no canonical base tip observed yet"),
            AnchorError::Transport(m) => write!(f, "base transport error: {m}"),
        }
    }
}

impl std::error::Error for AnchorError {}

/// An in-memory scaffold implementation of [`BlochAnchorClient`].
///
/// # SCAFFOLD — not a secure or deployed system
///
/// It fakes a base view from a list of headers and records anchored commitments
/// in a `Vec`. It does not connect to any real Bloch node, performs no PoW
/// validation, and provides no durability or guarantees. It exists only to make
/// the anchoring interface exercisable in tests and examples.
#[derive(Debug, Default, Clone)]
pub struct InMemoryAnchorClient {
    headers: Vec<BaseAnchorRef>,
    anchored: Vec<AnchorReceipt>,
    next_fake_txid: u64,
}

impl InMemoryAnchorClient {
    /// Create an empty scaffold client.
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed a fake base header (highest height becomes the canonical tip).
    pub fn push_header(&mut self, header: BaseAnchorRef) {
        self.headers.push(header);
    }

    /// All commitments anchored so far (scaffold introspection).
    pub fn anchored(&self) -> &[AnchorReceipt] {
        &self.anchored
    }

    /// Deterministically simulate a base **reorg**: every header at
    /// `from_height` or above is dropped and the `replacement` headers become
    /// the new view of the base from there on.
    ///
    /// # SCAFFOLD — a test aid, not a chain
    ///
    /// This exists so tests can exercise the honest failure mode the design
    /// insists on: the `k=4`, `51%`-attackable base **can reorg beneath an
    /// already-notarized checkpoint**, and when it does the notary must
    /// *observe and report* it ([`crate::notary::NotaryEvent::BaseReorgObserved`]),
    /// because a checkpoint is a Postern attestation, not settlement finality.
    /// No PoW, fork-choice, or validity rules are simulated — headers are
    /// replaced verbatim, deterministically (no RNG, no time).
    ///
    /// Already-recorded [`AnchorReceipt`]s are intentionally left in place:
    /// on a real base a reorg can also drop the anchoring transactions
    /// themselves, which would only strengthen the "no finality" point.
    pub fn simulate_reorg_from(&mut self, from_height: u64, replacement: Vec<BaseAnchorRef>) {
        self.headers.retain(|h| h.block_height < from_height);
        self.headers.extend(replacement);
    }
}

impl BlochAnchorClient for InMemoryAnchorClient {
    fn canonical_tip(&self) -> Result<BaseAnchorRef, AnchorError> {
        self.headers
            .iter()
            .max_by_key(|h| h.block_height)
            .cloned()
            .ok_or(AnchorError::NoCanonicalTip)
    }

    fn header_at(&self, height: u64) -> Result<BaseAnchorRef, AnchorError> {
        self.headers
            .iter()
            .find(|h| h.block_height == height)
            .cloned()
            .ok_or(AnchorError::UnknownHeight(height))
    }

    fn anchor_commitment(
        &mut self,
        commitment: AnchorCommitment,
    ) -> Result<AnchorReceipt, AnchorError> {
        let tip = self.canonical_tip()?;
        let mut txid = [0u8; 32];
        txid[..8].copy_from_slice(&self.next_fake_txid.to_be_bytes());
        self.next_fake_txid += 1;
        let receipt = AnchorReceipt {
            base_txid: txid,
            anchored_at_height: tip.block_height,
            commitment,
        };
        self.anchored.push(receipt.clone());
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(h: u64) -> BaseAnchorRef {
        BaseAnchorRef {
            block_height: h,
            block_hash: [h as u8; 32],
            accumulated_work: h as u128 * 10,
        }
    }

    #[test]
    fn tip_is_highest_header() {
        let mut c = InMemoryAnchorClient::new();
        assert_eq!(c.canonical_tip(), Err(AnchorError::NoCanonicalTip));
        c.push_header(header(10));
        c.push_header(header(42));
        c.push_header(header(30));
        assert_eq!(c.canonical_tip().unwrap().block_height, 42);
    }

    #[test]
    fn anchoring_records_a_receipt_at_tip() {
        let mut c = InMemoryAnchorClient::new();
        c.push_header(header(7));
        let r = c.anchor_commitment(AnchorCommitment([9u8; 32])).unwrap();
        assert_eq!(r.anchored_at_height, 7);
        assert_eq!(c.anchored().len(), 1);
    }

    #[test]
    fn header_lookup_reports_unknown() {
        let c = InMemoryAnchorClient::new();
        assert_eq!(c.header_at(5), Err(AnchorError::UnknownHeight(5)));
    }

    #[test]
    fn simulated_reorg_replaces_headers_from_height() {
        let mut c = InMemoryAnchorClient::new();
        c.push_header(header(10));
        c.push_header(header(11));
        c.push_header(header(12));

        // Reorg from height 11: heights 11-12 are replaced with different
        // hashes and the chain extends to 13.
        let replaced = |h: u64| BaseAnchorRef {
            block_height: h,
            block_hash: [0xAA; 32],
            accumulated_work: h as u128 * 10 + 1,
        };
        c.simulate_reorg_from(11, vec![replaced(11), replaced(12), replaced(13)]);

        // Below the reorg point: unchanged. At/above: replaced.
        assert_eq!(c.header_at(10).unwrap(), header(10));
        assert_eq!(c.header_at(11).unwrap().block_hash, [0xAA; 32]);
        assert_eq!(c.canonical_tip().unwrap().block_height, 13);
    }
}
