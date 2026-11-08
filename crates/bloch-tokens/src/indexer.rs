//! Reproducible reference indexer: replay, journal, reorg recovery.
//!
//! [`Indexer::sync`] pulls the selected chain from any [`BlockSource`] (a
//! real node's read RPC in a deployment — out of scope here, see
//! [`crate::stream`] — or [`crate::stream::MockChain`] in tests) and derives
//! token state by replaying heights **in order** through
//! [`TokenState::apply_tx`].
//!
//! ## Reorg handling
//!
//! The indexer keeps a per-height **block-hash journal** plus a per-height
//! **state snapshot**. On every sync it walks back from the last common
//! candidate height comparing its journal against `getblockhash`; the first
//! (highest) agreeing height is the fork point. Everything above it is
//! rewound — journal and snapshots truncated, state restored from the last
//! surviving snapshot (or a fresh state when rewound to nothing) — and the
//! new branch is replayed forward. The result is **exactly** the state a
//! fresh indexer computes replaying the new chain from genesis (asserted by
//! equality in the tests below): reorg recovery can never leave residue.
//!
//! Snapshot-per-height is O(state × height) memory — deliberately simple
//! for a reference implementation. A production indexer would checkpoint
//! every N blocks and re-replay the gap from the source (the fork-point
//! detection is identical); interval checkpointing changes nothing about
//! the convergence argument.
//!
//! ## Neutrality (crate docs, restated)
//!
//! Anyone can run this indexer against any node; there is no privileged
//! operator, no registry, no gatekeeper — reproducibility replaces trust.
//! Zero consensus change: this code only READS the chain.

use crate::state::TokenState;
use crate::stream::{BlockHash, BlockSource, SourceError};

/// What one [`Indexer::sync`] call did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncReport {
    /// A hash mismatch was found and blocks were rewound.
    pub reorged: bool,
    /// Height of the highest block that survived the rewind (`None` when
    /// nothing survived, or when no reorg happened and there was no rewind).
    pub rewound_to: Option<u64>,
    /// Blocks applied (replayed) by this call.
    pub applied: u64,
    /// The source's tip height after this sync (`None` = empty chain).
    pub tip: Option<u64>,
}

/// Reference indexer: [`TokenState`] + block-hash journal + per-height
/// snapshots. See module docs for the sync/reorg algorithm.
#[derive(Clone, Debug, Default)]
pub struct Indexer {
    state: TokenState,
    /// `journal[h]` = hash of the block indexed at height `h`.
    journal: Vec<BlockHash>,
    /// `snapshots[h]` = state after applying the block at height `h`.
    snapshots: Vec<TokenState>,
}

impl Indexer {
    pub fn new() -> Self {
        Self::default()
    }

    /// The current derived token state.
    pub fn state(&self) -> &TokenState {
        &self.state
    }

    /// The per-height block-hash journal (read-only).
    pub fn journal(&self) -> &[BlockHash] {
        &self.journal
    }

    /// Height of the last indexed block (`None` when nothing is indexed).
    pub fn indexed_height(&self) -> Option<u64> {
        (self.journal.len() as u64).checked_sub(1)
    }

    /// Synchronize with `src`: detect any reorg via hash mismatch, rewind
    /// to the fork point (journal + snapshots truncated, state restored),
    /// then replay heights in order up to the source tip.
    ///
    /// Idempotent: syncing an already-synced chain applies nothing.
    /// Deterministic: after any sequence of syncs across any reorgs, the
    /// state equals a fresh indexer's replay of the current chain.
    pub fn sync<S: BlockSource>(&mut self, src: &S) -> Result<SyncReport, SourceError> {
        let tip = match src.tip_height() {
            Ok(t) => Some(t),
            // An empty source is a full rewind, not an error: the mock (or
            // a pruned/reset node) simply has nothing for us.
            Err(SourceError::EmptyChain) => None,
            Err(e) => return Err(e),
        };
        // `tip + 1` must be CHECKED: a hostile or buggy source reporting
        // `u64::MAX` would otherwise panic in debug builds or wrap to 0 in
        // release builds — and a wrapped `remote_len == 0` looks exactly like
        // an empty chain, silently rewinding (wiping) the entire indexed
        // state. Fail closed with a transport error instead; state untouched.
        let remote_len: u64 = match tip {
            None => 0,
            Some(t) => t.checked_add(1).ok_or_else(|| {
                SourceError::Transport(format!(
                    "source reported tip height {t}: tip+1 overflows u64 — refusing to sync"
                ))
            })?,
        };
        let local_len = self.journal.len() as u64;

        // Fork-point search: highest height where journal and source agree.
        // For the no-reorg fast path this checks exactly one hash.
        let mut common = local_len.min(remote_len);
        while common > 0 {
            let h = common - 1;
            if src.block_hash(h)? == self.journal[h as usize] {
                break;
            }
            common -= 1;
        }

        // Rewind: drop everything above the fork point.
        let reorged = common < local_len;
        if reorged {
            self.journal.truncate(common as usize);
            self.snapshots.truncate(common as usize);
            self.state = self.snapshots.last().cloned().unwrap_or_default();
        }

        // Replay forward, in height order.
        let mut applied: u64 = 0;
        for h in common..remote_len {
            let block = src.block_by_height(h)?;
            if block.height != h {
                return Err(SourceError::Transport(format!(
                    "source returned height {} for requested height {h}",
                    block.height
                )));
            }
            for tx in &block.transactions {
                self.state.apply_tx(h, tx);
            }
            self.journal.push(block.hash);
            self.snapshots.push(self.state.clone());
            applied += 1;
        }

        Ok(SyncReport {
            reorged,
            rewound_to: if reorged { common.checked_sub(1) } else { None },
            applied,
            tip,
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{ChainTx, OutPoint};
    use crate::envelope::{TokenOp, TxOut, FLAG_MINT_CLOSED};
    use crate::state::TokenEffect;
    use crate::stream::MockChain;

    fn txid(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn spk(n: u8) -> Vec<u8> {
        vec![n; 20]
    }

    fn pay(script: Vec<u8>) -> TxOut {
        TxOut { value: 546, script_pubkey: script }
    }

    fn env_out(op: &TokenOp) -> TxOut {
        TxOut { value: 0, script_pubkey: op.encode() }
    }

    fn issue_tx(n: u8, to: Vec<u8>, supply: u64) -> ChainTx {
        let op = TokenOp::Issue {
            decimals: 0,
            flags: FLAG_MINT_CLOSED,
            supply,
            symbol: "TOK".into(),
            name: String::new(),
        };
        ChainTx { txid: txid(n), inputs: vec![], outputs: vec![pay(to), env_out(&op)] }
    }

    fn transfer_tx(
        n: u8,
        spend: (u8, u32),
        token: [u8; 32],
        assignments: Vec<(u32, u64)>,
        recipients: Vec<Vec<u8>>,
    ) -> ChainTx {
        let mut outputs: Vec<TxOut> = recipients.into_iter().map(pay).collect();
        outputs.push(env_out(&TokenOp::Transfer { token_id: token, assignments }));
        ChainTx {
            txid: txid(n),
            inputs: vec![OutPoint { txid: txid(spend.0), vout: spend.1 }],
            outputs,
        }
    }

    const ALICE: u8 = 0xA1;
    const BOB: u8 = 0xB2;
    const CAROL: u8 = 0xC3;
    const DAVE: u8 = 0xD4;

    /// issue(1000→alice) → transfer(400→bob, 600 change→alice)
    /// → transfer(150→carol, 200 change→bob, 50 burned).
    fn issue_transfer_transfer_chain() -> MockChain {
        let token = txid(1);
        let mut chain = MockChain::new();
        chain.append(vec![issue_tx(1, spk(ALICE), 1000)]);
        chain.append(vec![transfer_tx(
            2,
            (1, 0),
            token,
            vec![(0, 400), (1, 600)],
            vec![spk(BOB), spk(ALICE)],
        )]);
        chain.append(vec![transfer_tx(
            3,
            (2, 0),
            token,
            vec![(0, 150), (1, 200)],
            vec![spk(CAROL), spk(BOB)],
        )]);
        chain
    }

    #[test]
    fn acceptance_issue_transfer_transfer_balances() {
        let chain = issue_transfer_transfer_chain();
        let token = txid(1);

        let mut ix = Indexer::new();
        let report = ix.sync(&chain).unwrap();
        assert_eq!(report, SyncReport { reorged: false, rewound_to: None, applied: 3, tip: Some(2) });

        let st = ix.state();
        assert_eq!(st.balance(&spk(ALICE), &token), 600);
        assert_eq!(st.balance(&spk(BOB), &token), 200);
        assert_eq!(st.balance(&spk(CAROL), &token), 150);
        let info = st.token(&token).unwrap();
        assert_eq!(info.supply, 1000);
        assert_eq!(info.burned, 50, "unassigned remainder of the second transfer");
        assert_eq!(info.circulating(), 950);
        assert_eq!(ix.indexed_height(), Some(2));

        // Idempotent: a second sync applies nothing and changes nothing.
        let again = ix.sync(&chain).unwrap();
        assert_eq!(again, SyncReport { reorged: false, rewound_to: None, applied: 0, tip: Some(2) });
        assert_eq!(ix.state(), &Indexer::new().tap_sync(&chain).state().clone());
    }

    /// Small helper so tests can build a freshly-synced indexer inline.
    trait TapSync {
        fn tap_sync<S: BlockSource>(self, src: &S) -> Self;
    }
    impl TapSync for Indexer {
        fn tap_sync<S: BlockSource>(mut self, src: &S) -> Self {
            self.sync(src).expect("sync must succeed");
            self
        }
    }

    #[test]
    fn incremental_sync_matches_batch_sync() {
        let full = issue_transfer_transfer_chain();

        // Incremental: sync after every block.
        let mut partial = MockChain::new();
        let mut incremental = Indexer::new();
        for h in 0..=2 {
            partial.append(full.block_by_height(h).unwrap().transactions);
            incremental.sync(&partial).unwrap();
        }

        let batch = Indexer::new().tap_sync(&full);
        assert_eq!(incremental.state(), batch.state());
        // Journals differ only if hashes differ (uniq counters advanced the
        // same way here), so both indexed the same number of heights:
        assert_eq!(incremental.indexed_height(), batch.indexed_height());
    }

    #[test]
    fn reorg_replacing_suffix_converges_to_fresh_replay() {
        let token = txid(1);
        let mut chain = issue_transfer_transfer_chain();

        let mut ix = Indexer::new();
        ix.sync(&chain).unwrap();
        assert_eq!(ix.state().balance(&spk(CAROL), &token), 150);

        // Force a reorg: drop heights 1.. and install a LONGER branch where
        // alice instead sends everything to dave, who splits it to carol.
        chain.replace_suffix(
            1,
            vec![
                vec![transfer_tx(12, (1, 0), token, vec![(0, 1000)], vec![spk(DAVE)])],
                vec![transfer_tx(
                    13,
                    (12, 0),
                    token,
                    vec![(0, 700), (1, 300)],
                    vec![spk(CAROL), spk(DAVE)],
                )],
                vec![issue_tx(14, spk(BOB), 5)],
            ],
        );

        let report = ix.sync(&chain).unwrap();
        assert!(report.reorged);
        assert_eq!(report.rewound_to, Some(0), "height 0 survived the fork");
        assert_eq!(report.applied, 3);

        // Convergence: EXACTLY the state of a fresh indexer on the new chain.
        let fresh = Indexer::new().tap_sync(&chain);
        assert_eq!(ix.state(), fresh.state());
        assert_eq!(ix.journal(), fresh.journal());

        // And the new balances are the new chain's, with no residue.
        assert_eq!(ix.state().balance(&spk(ALICE), &token), 0);
        assert_eq!(ix.state().balance(&spk(BOB), &token), 0);
        assert_eq!(ix.state().balance(&spk(CAROL), &token), 700);
        assert_eq!(ix.state().balance(&spk(DAVE), &token), 300);
        assert_eq!(ix.state().balance(&spk(BOB), &txid(14)), 5);
    }

    #[test]
    fn reorg_to_shorter_chain_converges() {
        let token = txid(1);
        let mut chain = issue_transfer_transfer_chain();
        let mut ix = Indexer::new();
        ix.sync(&chain).unwrap();

        // The new branch is SHORTER (drops two blocks, adds one).
        chain.replace_suffix(
            1,
            vec![vec![transfer_tx(12, (1, 0), token, vec![(0, 1000)], vec![spk(DAVE)])]],
        );
        let report = ix.sync(&chain).unwrap();
        assert!(report.reorged);
        assert_eq!(ix.indexed_height(), Some(1));

        let fresh = Indexer::new().tap_sync(&chain);
        assert_eq!(ix.state(), fresh.state());
        assert_eq!(ix.journal(), fresh.journal());
        assert_eq!(ix.state().balance(&spk(DAVE), &token), 1000);
        assert_eq!(ix.state().balance(&spk(CAROL), &token), 0);
    }

    #[test]
    fn reorg_from_genesis_converges() {
        let mut chain = issue_transfer_transfer_chain();
        let mut ix = Indexer::new();
        ix.sync(&chain).unwrap();

        // Replace EVERYTHING (fork below the first block).
        chain.replace_suffix(0, vec![vec![issue_tx(21, spk(DAVE), 42)]]);
        let report = ix.sync(&chain).unwrap();
        assert!(report.reorged);
        assert_eq!(report.rewound_to, None, "nothing survived");
        assert_eq!(ix.indexed_height(), Some(0));

        let fresh = Indexer::new().tap_sync(&chain);
        assert_eq!(ix.state(), fresh.state());
        assert_eq!(ix.state().balance(&spk(DAVE), &txid(21)), 42);
        assert_eq!(ix.state().token(&txid(1)), None, "no residue of the old chain");
    }

    /// Regression (tip+1 overflow): a hostile source reporting
    /// `tip_height() == u64::MAX` used to hit an unchecked `t + 1` — a panic
    /// in debug builds, and in release builds a wrap to `remote_len == 0`
    /// that masquerades as an empty chain and REWINDS (wipes) all indexed
    /// state. It must instead fail closed with a transport error and leave
    /// the indexer untouched.
    #[test]
    fn hostile_tip_at_u64_max_fails_closed_without_touching_state() {
        struct OverflowTipSource;
        impl BlockSource for OverflowTipSource {
            fn tip_height(&self) -> Result<u64, SourceError> {
                Ok(u64::MAX)
            }
            fn block_hash(&self, height: u64) -> Result<crate::stream::BlockHash, SourceError> {
                Err(SourceError::HeightNotFound(height))
            }
            fn block_by_height(&self, height: u64) -> Result<crate::stream::Block, SourceError> {
                Err(SourceError::HeightNotFound(height))
            }
        }

        let chain = issue_transfer_transfer_chain();
        let mut ix = Indexer::new();
        ix.sync(&chain).unwrap();
        let state_before = ix.state().clone();
        let journal_before = ix.journal().to_vec();

        let err = ix.sync(&OverflowTipSource).expect_err("tip+1 overflow must be an error");
        assert!(matches!(err, SourceError::Transport(_)), "got {err:?}");

        // Fail closed means fail UNCHANGED: no rewind, no wipe.
        assert_eq!(ix.state(), &state_before, "a refused sync must not modify state");
        assert_eq!(ix.journal(), journal_before.as_slice());
    }

    #[test]
    fn sync_against_empty_source_rewinds_everything() {
        let chain = issue_transfer_transfer_chain();
        let mut ix = Indexer::new();
        ix.sync(&chain).unwrap();

        let empty = MockChain::new();
        let report = ix.sync(&empty).unwrap();
        assert_eq!(report, SyncReport { reorged: true, rewound_to: None, applied: 0, tip: None });
        assert_eq!(ix.state(), &TokenState::default());
        assert_eq!(ix.indexed_height(), None);
    }

    #[test]
    fn apply_outcomes_surface_through_state() {
        // Sanity: the block-driven path really produces the same effects the
        // state machine documents (spot-check the issue effect).
        let chain = issue_transfer_transfer_chain();
        let mut st = TokenState::new();
        let b0 = chain.block_by_height(0).unwrap();
        let out = st.apply_tx(b0.height, &b0.transactions[0]);
        assert_eq!(out.effect, TokenEffect::Issued { token_id: txid(1), supply: 1000 });
    }

    #[test]
    fn two_indexers_same_history_identical_observables() {
        let chain = issue_transfer_transfer_chain();
        let a = Indexer::new().tap_sync(&chain);
        let b = Indexer::new().tap_sync(&chain);
        assert_eq!(a.state(), b.state());
        assert_eq!(a.journal(), b.journal());
        // BTreeMap-backed Debug is order-stable — no hash-order dependence
        // in any observable output.
        assert_eq!(format!("{:?}", a.state()), format!("{:?}", b.state()));
    }
}
