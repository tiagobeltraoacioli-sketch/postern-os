// SPDX-License-Identifier: MIT OR Apache-2.0
//! §4 mempool: two-lane strict-FIFO ordering plus the published admission
//! policy.
//!
//! ORDERING RULE (normative for this scaffold, from §4): transactions whose
//! EIP-1559 effective tip at the current basefee is `>= threshold` form the
//! PRIORITY lane; all other includable transactions form the STANDARD lane.
//! The priority lane is drained before the standard lane; within a lane the
//! order is strict FIFO by sequencer arrival sequence. No bundles, no private
//! orderflow, no auctions.
//!
//! One necessary refinement the spec leaves implicit: a transaction is only
//! *eligible* when its nonce is the sender's next expected nonce (execution
//! would reject it otherwise). Eligibility is applied by repeated FIFO passes
//! until a fixpoint — fully deterministic; a priority-lane tx blocked on a
//! standard-lane predecessor is emitted in the first pass after its
//! predecessor. This is documented behavior, tested below.
//!
//! ADMISSION (published policy, §4): nonce-gap ≤ 16 ahead of the sender's next
//! expected nonce, pending cap 64 txs/sender, replacement needs a ≥10% bump on
//! both fee caps, raw tx ≤ 128 KiB, a min-base-fee floor (a tx whose fee cap
//! can never reach the floor is refused), and the §1 type boundary: EIP-4844
//! blob (type-3) txs are rejected and type-`0x7E` deposits are system-only.
//! No address filtering.

use std::collections::BTreeMap;

use crate::fees::effective_tip;
use crate::params::{
    MAX_TX_BYTES, NONCE_GAP_MAX, REPLACEMENT_BUMP_PERCENT, SENDER_PENDING_CAP,
};
use crate::txtype::{classify, TxType};

/// A signed user transaction as the sequencer's RPC intake sees it.
///
/// `raw` is the opaque canonical signed-tx encoding (RLP in the real system).
/// SCAFFOLD: no signature or RLP validation happens here — the fields are
/// taken at face value; the real intake derives them from the decoded tx.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxSubmission {
    pub hash: [u8; 32],
    pub sender: [u8; 20],
    pub nonce: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub raw: Vec<u8>,
}

/// A pooled transaction with its immutable arrival sequence number.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolEntry {
    pub tx: TxSubmission,
    pub arrival_seq: u64,
}

/// Why an admission was refused (mirrors the published §4 policy).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    /// Below the sender's on-chain account nonce.
    NonceTooLow { account_nonce: u64, got: u64 },
    /// More than [`NONCE_GAP_MAX`] ahead of the sender's next expected nonce.
    NonceGapTooLarge { next_expected: u64, got: u64 },
    /// Sender already has [`SENDER_PENDING_CAP`] pending transactions.
    SenderCapExceeded,
    /// Same (sender, nonce) with less than a 10% bump on both fee caps.
    ReplacementUnderpriced,
    /// Raw tx exceeds [`MAX_TX_BYTES`].
    TxTooLarge { len: usize },
    /// `max_fee_per_gas` is below the pool's min-base-fee floor (§4 published
    /// policy) — the tx could never be includable, so it is never pooled.
    BelowFeeFloor { floor: u128, max_fee_per_gas: u128 },
    /// An EIP-4844 blob transaction (type-3) was submitted. Rejected at the
    /// sequencer boundary per design §1 (as on OP-Stack L2s): this L2 has no
    /// blob mempool and blob data belongs to L1.
    BlobTxRejected,
    /// A type-`0x7E` deposit was submitted through user RPC intake. Deposits
    /// are SYSTEM transactions derived from L1 (§5); a user cannot inject one.
    DepositNotUserSubmittable,
}

/// The sequencer mempool. Deterministic: state is a pure function of the
/// admission call sequence.
#[derive(Debug, Default)]
pub struct Mempool {
    /// Kept ordered by `arrival_seq` (append-only + order-preserving removal).
    entries: Vec<PoolEntry>,
    next_seq: u64,
    /// §4 "min base fee floor": a tx whose `max_fee_per_gas` is below this can
    /// never be included, so it is refused at admission. `0` disables the
    /// check (the default, matching pure Ethereum semantics).
    min_basefee_floor: u128,
}

impl Mempool {
    /// A pool with no fee floor (floor `0`).
    pub fn new() -> Self {
        Self::default()
    }

    /// A pool that refuses any tx whose `max_fee_per_gas` is below `floor`
    /// (§4's published "min base fee floor"). Pass
    /// [`crate::params::MIN_BASEFEE_WEI`] for the scaffold placeholder.
    pub fn with_min_basefee_floor(floor: u128) -> Self {
        Self {
            min_basefee_floor: floor,
            ..Self::default()
        }
    }

    /// The pool's current min-base-fee floor.
    pub fn min_basefee_floor(&self) -> u128 {
        self.min_basefee_floor
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[PoolEntry] {
        &self.entries
    }

    fn position(&self, sender: &[u8; 20], nonce: u64) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| &e.tx.sender == sender && e.tx.nonce == nonce)
    }

    /// The sender's next expected nonce given the on-chain `account_nonce`
    /// and what is already pending: `max(account_nonce, highest_pending + 1)`.
    fn next_expected(&self, sender: &[u8; 20], account_nonce: u64) -> u64 {
        self.entries
            .iter()
            .filter(|e| &e.tx.sender == sender)
            .map(|e| e.tx.nonce.saturating_add(1))
            .max()
            .map_or(account_nonce, |n| n.max(account_nonce))
    }

    /// Admit a transaction under the published §4 policy. Returns the
    /// assigned arrival sequence number. A successful replacement gets a NEW
    /// arrival sequence (it goes to the back of its lane — FIFO is by receipt
    /// time of the accepted bytes, documented).
    pub fn admit(
        &mut self,
        tx: TxSubmission,
        account_nonce: u64,
    ) -> Result<u64, AdmissionError> {
        if tx.raw.len() > MAX_TX_BYTES {
            return Err(AdmissionError::TxTooLarge { len: tx.raw.len() });
        }
        // §1 type-admission boundary: reject blob (type-3) txs and
        // system-only deposit (type-0x7E) txs at the sequencer intake. Unknown
        // / reserved leading bytes are left to the (stubbed) real RLP decoder.
        match classify(&tx.raw) {
            Some(TxType::Eip4844Blob) => return Err(AdmissionError::BlobTxRejected),
            Some(TxType::Deposit) => return Err(AdmissionError::DepositNotUserSubmittable),
            _ => {}
        }
        // §4 min-base-fee floor: a fee cap that can never reach the floor means
        // the tx is never includable, so it is refused rather than pooled.
        if self.min_basefee_floor > 0 && tx.max_fee_per_gas < self.min_basefee_floor {
            return Err(AdmissionError::BelowFeeFloor {
                floor: self.min_basefee_floor,
                max_fee_per_gas: tx.max_fee_per_gas,
            });
        }
        if tx.nonce < account_nonce {
            return Err(AdmissionError::NonceTooLow {
                account_nonce,
                got: tx.nonce,
            });
        }

        // Replacement check for an existing (sender, nonce).
        if let Some(i) = self.position(&tx.sender, tx.nonce) {
            let old = &self.entries[i].tx;
            let bump = |v: u128| v.saturating_add(v / (100 / REPLACEMENT_BUMP_PERCENT));
            if tx.max_fee_per_gas < bump(old.max_fee_per_gas)
                || tx.max_priority_fee_per_gas < bump(old.max_priority_fee_per_gas)
            {
                return Err(AdmissionError::ReplacementUnderpriced);
            }
            self.entries.remove(i); // order-preserving
        } else {
            // Cap and gap apply to genuinely new nonces only.
            let pending = self
                .entries
                .iter()
                .filter(|e| e.tx.sender == tx.sender)
                .count();
            if pending >= SENDER_PENDING_CAP {
                return Err(AdmissionError::SenderCapExceeded);
            }
            let next_expected = self.next_expected(&tx.sender, account_nonce);
            if tx.nonce > next_expected.saturating_add(NONCE_GAP_MAX) {
                return Err(AdmissionError::NonceGapTooLarge {
                    next_expected,
                    got: tx.nonce,
                });
            }
        }

        let seq = self.next_seq;
        self.next_seq += 1;
        self.entries.push(PoolEntry {
            tx,
            arrival_seq: seq,
        });
        Ok(seq)
    }

    /// Compute the deterministic inclusion order (arrival sequence numbers)
    /// at the given basefee and priority-lane threshold. Does not mutate the
    /// pool. `account_nonces` maps sender → on-chain nonce (missing = 0).
    pub fn inclusion_order(
        &self,
        basefee: u128,
        priority_tip_threshold: u128,
        account_nonces: &BTreeMap<[u8; 20], u64>,
    ) -> Vec<u64> {
        // Lane assignment; txs with max_fee < basefee are not includable and
        // simply stay pooled.
        let mut priority: Vec<&PoolEntry> = Vec::new();
        let mut standard: Vec<&PoolEntry> = Vec::new();
        for e in &self.entries {
            match effective_tip(e.tx.max_fee_per_gas, e.tx.max_priority_fee_per_gas, basefee) {
                Some(tip) if tip >= priority_tip_threshold => priority.push(e),
                Some(_) => standard.push(e),
                None => {}
            }
        }
        // `entries` is arrival-ordered, so each lane already is too.
        let ordered: Vec<&PoolEntry> = priority.into_iter().chain(standard).collect();

        let mut expected: BTreeMap<[u8; 20], u64> = account_nonces.clone();
        let mut used = vec![false; ordered.len()];
        let mut out = Vec::with_capacity(ordered.len());
        loop {
            let mut progress = false;
            for (i, e) in ordered.iter().enumerate() {
                if used[i] {
                    continue;
                }
                let exp = expected.get(&e.tx.sender).copied().unwrap_or(0);
                if e.tx.nonce == exp {
                    out.push(e.arrival_seq);
                    expected.insert(e.tx.sender, exp + 1);
                    used[i] = true;
                    progress = true;
                }
            }
            if !progress {
                break;
            }
        }
        out
    }

    /// Remove and return the entries with the given arrival sequences, in the
    /// given order (used by the block builder after selection).
    pub fn take(&mut self, seqs: &[u64]) -> Vec<PoolEntry> {
        let mut out = Vec::with_capacity(seqs.len());
        for &seq in seqs {
            if let Some(i) = self.entries.iter().position(|e| e.arrival_seq == seq) {
                out.push(self.entries.remove(i));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sender(b: u8) -> [u8; 20] {
        [b; 20]
    }

    fn tx(sender_byte: u8, nonce: u64, max_fee: u128, tip: u128) -> TxSubmission {
        let mut hash = [0u8; 32];
        hash[0] = sender_byte;
        hash[8..16].copy_from_slice(&nonce.to_le_bytes());
        TxSubmission {
            hash,
            sender: sender(sender_byte),
            nonce,
            gas_limit: 21_000,
            max_fee_per_gas: max_fee,
            max_priority_fee_per_gas: tip,
            // Leading 0x02 = EIP-1559 dynamic-fee envelope (these txs carry a
            // max_fee/max_priority pair), so it clears the type boundary.
            raw: vec![0x02, sender_byte, nonce as u8],
        }
    }

    /// A raw envelope with an explicit EIP-2718 type-byte prefix.
    fn tx_typed(sender_byte: u8, type_byte: u8) -> TxSubmission {
        let mut t = tx(sender_byte, 0, 200, 1);
        t.raw = vec![type_byte, sender_byte, 0x00];
        t
    }

    const BASEFEE: u128 = 100;
    const THRESHOLD: u128 = 10;

    #[test]
    fn priority_lane_drains_before_standard_fifo_within_lane() {
        let mut pool = Mempool::new();
        // Interleave arrivals: std, prio, std, prio (all distinct senders).
        pool.admit(tx(1, 0, 200, 1), 0).unwrap(); // standard (tip 1)
        pool.admit(tx(2, 0, 200, 50), 0).unwrap(); // priority (tip 50)
        pool.admit(tx(3, 0, 200, 2), 0).unwrap(); // standard
        pool.admit(tx(4, 0, 200, 99), 0).unwrap(); // priority
        let order = pool.inclusion_order(BASEFEE, THRESHOLD, &BTreeMap::new());
        // Priority lane FIFO (seqs 1, 3) then standard lane FIFO (seqs 0, 2).
        assert_eq!(order, vec![1, 3, 0, 2]);
    }

    #[test]
    fn equal_tip_txs_keep_arrival_order_stable() {
        let mut pool = Mempool::new();
        for b in 1..=5u8 {
            pool.admit(tx(b, 0, 200, 50), 0).unwrap();
        }
        let order = pool.inclusion_order(BASEFEE, THRESHOLD, &BTreeMap::new());
        assert_eq!(order, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn ordering_is_deterministic_across_identical_pools() {
        // Property-style: same admission sequence (pseudo-random via LCG)
        // into two pools yields byte-identical inclusion order; and lane
        // partition is correct for every emitted tx.
        let mut a = Mempool::new();
        let mut b = Mempool::new();
        let mut x: u64 = 0x1234_5678_9abc_def0;
        let mut lcg = move || {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            x
        };
        let mut txs = Vec::new();
        for i in 0..64u64 {
            let r = lcg();
            let t = tx(
                (i % 16) as u8 + 1,          // 16 senders
                i / 16,                       // contiguous nonces per sender
                90 + (r % 200) as u128,       // some below basefee → excluded
                (r >> 8) as u128 % 40,        // tips straddle the threshold
            );
            txs.push(t);
        }
        for t in &txs {
            let _ = a.admit(t.clone(), 0);
            let _ = b.admit(t.clone(), 0);
        }
        let oa = a.inclusion_order(BASEFEE, THRESHOLD, &BTreeMap::new());
        let ob = b.inclusion_order(BASEFEE, THRESHOLD, &BTreeMap::new());
        assert_eq!(oa, ob);
        assert!(!oa.is_empty());

        // Lane-correctness: with all senders independent at nonce 0 the
        // emitted order must be exactly [all priority (FIFO)] ++ [all
        // standard (FIFO)] — check monotonicity of lane and seq within lane.
        let lane_of = |seq: u64| -> u8 {
            let e = a.entries().iter().find(|e| e.arrival_seq == seq).unwrap();
            let tip =
                effective_tip(e.tx.max_fee_per_gas, e.tx.max_priority_fee_per_gas, BASEFEE)
                    .expect("emitted tx must be includable");
            u8::from(tip < THRESHOLD) // 0 = priority, 1 = standard
        };
        // Only check the first block's worth: senders have multiple nonces so
        // later nonces interleave by eligibility. Restrict to nonce-0 txs.
        let nonce0: Vec<u64> = oa
            .iter()
            .copied()
            .filter(|&s| {
                a.entries()
                    .iter()
                    .find(|e| e.arrival_seq == s)
                    .map(|e| e.tx.nonce == 0)
                    .unwrap_or(false)
            })
            .collect();
        for w in nonce0.windows(2) {
            let (l0, l1) = (lane_of(w[0]), lane_of(w[1]));
            assert!(l0 <= l1, "priority tx emitted after standard tx among nonce-0 txs");
            if l0 == l1 {
                assert!(w[0] < w[1], "FIFO violated within a lane");
            }
        }
    }

    #[test]
    fn tx_below_basefee_is_not_included() {
        let mut pool = Mempool::new();
        pool.admit(tx(1, 0, 99, 5), 0).unwrap(); // max_fee < basefee 100
        pool.admit(tx(2, 0, 150, 5), 0).unwrap();
        let order = pool.inclusion_order(BASEFEE, THRESHOLD, &BTreeMap::new());
        assert_eq!(order, vec![1]);
        assert_eq!(pool.len(), 2, "excluded tx stays pooled");
    }

    #[test]
    fn nonce_eligibility_holds_fifo_but_never_breaks_sender_order() {
        let mut pool = Mempool::new();
        // Sender 1's nonce-1 tx arrives BEFORE its nonce-0 tx.
        pool.admit(tx(1, 1, 200, 50), 0).unwrap(); // seq 0, not yet eligible
        pool.admit(tx(2, 0, 200, 50), 0).unwrap(); // seq 1
        pool.admit(tx(1, 0, 200, 50), 0).unwrap(); // seq 2, unblocks seq 0
        let order = pool.inclusion_order(BASEFEE, THRESHOLD, &BTreeMap::new());
        // Pass 1: seq0 blocked, seq1 ok, seq2 ok (expected nonce 0);
        // pass 2: seq0 now eligible.
        assert_eq!(order, vec![1, 2, 0]);
    }

    #[test]
    fn cross_lane_nonce_dependency_is_deterministic() {
        let mut pool = Mempool::new();
        // Priority tx (nonce 1) depends on a standard tx (nonce 0).
        pool.admit(tx(1, 1, 200, 50), 0).unwrap(); // seq 0 priority, blocked
        pool.admit(tx(1, 0, 200, 1), 0).unwrap(); // seq 1 standard
        pool.admit(tx(2, 0, 200, 50), 0).unwrap(); // seq 2 priority
        let order = pool.inclusion_order(BASEFEE, THRESHOLD, &BTreeMap::new());
        // Pass 1: seq0 blocked → seq2 (priority) → seq1 (standard);
        // pass 2: seq0. Documented fixpoint behavior.
        assert_eq!(order, vec![2, 1, 0]);
    }

    #[test]
    fn admission_nonce_gap_max_16() {
        let mut pool = Mempool::new();
        // account nonce 0, empty pool: nonce 16 is exactly gap 16 → admitted.
        pool.admit(tx(1, 16, 200, 1), 0).unwrap();
        // nonce 17 relative to next_expected 17 (highest pending 16 + 1) is
        // fine — the gap is measured from max(account_nonce, highest+1).
        pool.admit(tx(1, 17, 200, 1), 0).unwrap();
        // But a fresh sender at nonce 17 with account nonce 0 is gap 17.
        let err = pool.admit(tx(2, 17, 200, 1), 0).unwrap_err();
        assert_eq!(
            err,
            AdmissionError::NonceGapTooLarge {
                next_expected: 0,
                got: 17
            }
        );
        // And jumping 17 past the pending head is rejected too.
        let err = pool.admit(tx(1, 35, 200, 1), 0).unwrap_err();
        assert_eq!(
            err,
            AdmissionError::NonceGapTooLarge {
                next_expected: 18,
                got: 35
            }
        );
    }

    #[test]
    fn admission_nonce_too_low() {
        let mut pool = Mempool::new();
        let err = pool.admit(tx(1, 4, 200, 1), 5).unwrap_err();
        assert_eq!(
            err,
            AdmissionError::NonceTooLow {
                account_nonce: 5,
                got: 4
            }
        );
    }

    #[test]
    fn admission_per_sender_cap_64() {
        let mut pool = Mempool::new();
        for n in 0..64u64 {
            pool.admit(tx(1, n, 200, 1), 0).unwrap();
        }
        let err = pool.admit(tx(1, 64, 200, 1), 0).unwrap_err();
        assert_eq!(err, AdmissionError::SenderCapExceeded);
        // Other senders are unaffected.
        pool.admit(tx(2, 0, 200, 1), 0).unwrap();
    }

    #[test]
    fn replacement_needs_ten_percent_bump_on_both_caps() {
        let mut pool = Mempool::new();
        pool.admit(tx(1, 0, 200, 20), 0).unwrap();
        // 9% bump → refused.
        let mut low = tx(1, 0, 218, 21);
        low.hash[31] = 1;
        assert_eq!(
            pool.admit(low, 0).unwrap_err(),
            AdmissionError::ReplacementUnderpriced
        );
        // ≥10% on both caps → replaces, gets a new (later) arrival seq.
        let mut ok = tx(1, 0, 220, 22);
        ok.hash[31] = 2;
        let seq = pool.admit(ok, 0).unwrap();
        assert_eq!(pool.len(), 1);
        assert_eq!(seq, 1, "replacement gets a fresh, later arrival seq");
        assert_eq!(pool.entries()[0].tx.max_fee_per_gas, 220);
    }

    #[test]
    fn admission_tx_too_large() {
        let mut pool = Mempool::new();
        let mut t = tx(1, 0, 200, 1);
        t.raw = vec![0u8; MAX_TX_BYTES + 1];
        assert!(matches!(
            pool.admit(t, 0).unwrap_err(),
            AdmissionError::TxTooLarge { .. }
        ));
    }

    #[test]
    fn blob_tx_rejected_at_sequencer_boundary() {
        let mut pool = Mempool::new();
        // Type-3 (EIP-4844) blob tx: leading byte 0x03. Rejected per §1.
        let blob = tx_typed(1, 0x03);
        assert_eq!(pool.admit(blob, 0).unwrap_err(), AdmissionError::BlobTxRejected);
        assert!(pool.is_empty(), "blob tx is never pooled");
        // Non-blob typed txs of the same sender still admit fine.
        pool.admit(tx_typed(1, 0x01), 0).unwrap(); // access-list
        pool.admit(tx_typed(2, 0x02), 0).unwrap(); // dynamic-fee
        pool.admit(tx_typed(3, 0xc8), 0).unwrap(); // legacy (RLP list)
        assert_eq!(pool.len(), 3);
    }

    #[test]
    fn deposit_type_tx_not_user_submittable() {
        let mut pool = Mempool::new();
        // Type-0x7E deposit envelope may not enter via user RPC intake.
        let dep = tx_typed(1, 0x7E);
        assert_eq!(
            pool.admit(dep, 0).unwrap_err(),
            AdmissionError::DepositNotUserSubmittable
        );
        assert!(pool.is_empty());
    }

    #[test]
    fn fee_floor_refuses_sub_floor_fee_caps() {
        const FLOOR: u128 = 1_000;
        let mut pool = Mempool::with_min_basefee_floor(FLOOR);
        assert_eq!(pool.min_basefee_floor(), FLOOR);
        // max_fee 999 < floor 1000 → refused, never pooled.
        let err = pool.admit(tx(1, 0, FLOOR - 1, 1), 0).unwrap_err();
        assert_eq!(
            err,
            AdmissionError::BelowFeeFloor {
                floor: FLOOR,
                max_fee_per_gas: FLOOR - 1
            }
        );
        assert!(pool.is_empty());
        // Exactly at the floor is admissible.
        pool.admit(tx(2, 0, FLOOR, 1), 0).unwrap();
        // Above the floor too.
        pool.admit(tx(3, 0, FLOOR + 5_000, 1), 0).unwrap();
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn default_pool_has_no_fee_floor() {
        // The zero-floor default admits any fee cap (pure-Ethereum semantics),
        // preserving the crate's original behavior.
        let mut pool = Mempool::new();
        assert_eq!(pool.min_basefee_floor(), 0);
        pool.admit(tx(1, 0, 1, 0), 0).unwrap();
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn size_check_precedes_type_and_fee_floor_checks() {
        // An oversized blob tx still reports TxTooLarge (size is the first
        // gate), so the ordering of admission checks is stable/documented.
        let mut pool = Mempool::with_min_basefee_floor(1_000_000_000);
        let mut t = tx_typed(1, 0x03); // would otherwise be BlobTxRejected
        t.raw = vec![0x03; MAX_TX_BYTES + 1];
        assert!(matches!(
            pool.admit(t, 0).unwrap_err(),
            AdmissionError::TxTooLarge { .. }
        ));
    }

    #[test]
    fn take_removes_in_requested_order() {
        let mut pool = Mempool::new();
        pool.admit(tx(1, 0, 200, 50), 0).unwrap();
        pool.admit(tx(2, 0, 200, 1), 0).unwrap();
        let order = pool.inclusion_order(BASEFEE, THRESHOLD, &BTreeMap::new());
        let taken = pool.take(&order);
        assert_eq!(taken.len(), 2);
        assert_eq!(taken[0].tx.sender, sender(1));
        assert!(pool.is_empty());
    }
}
