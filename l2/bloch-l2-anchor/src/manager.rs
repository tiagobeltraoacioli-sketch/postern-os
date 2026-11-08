//! Anchor manager — reorg-aware reader that derives the canonical L2 anchor
//! chain from any [`crate::source::BlockSource`].
//!
//! // SCAFFOLD, UNAUDITED, NOT A WORKING L2. [`AnchorManager::sync`] is the
//! // REAL, offline-testable replay/reorg logic — the same journal +
//! // rewind-and-replay discipline `bloch-tokens`' `indexer::Indexer`
//! // implements for TKV0 — driven by the [`crate::source::BlockSource`]
//! // trait. It derives an anchor chain from **bytes only**: a decoded,
//! // linked anchor is an unverified *claim*, never a checked proof. There is
//! // no SP1 verifier, no DA check, no bridge, and no live node here. Wiring
//! // [`crate::source::BlockSource`] to a real Bloch JSON-RPC endpoint is
//! // deliberately OUT OF SCOPE (zero-dep, offline-buildable), exactly as
//! // `bloch-tokens` states; [`crate::source::MockChain`] stands in so the
//! // reader — reorg handling included — is exercised fully offline.
//!
//! Design source: `docs/specs/BLOCH-L2-EVM-DESIGN.md` §2 — the deterministic
//! rule by which any reader derives the canonical L2 anchor chain from Bloch
//! via the existing JSON-RPC replay/reorg discipline (`getblockcount`,
//! `getblockhash`, `getblockbyheight`), and the confirmation-depth policy
//! that makes the L2's inheritance of Bloch's (currently weak, k=4) finality
//! explicit and machine-handled.

use crate::envelope::{extract_anchor, link, AnchorEnvelope};
use crate::source::{BlockHash, BlockSource, SourceError};

/// Where an anchor stands relative to the reader's current view of Bloch.
///
/// The depth policy makes L2 finality inheritance explicit: an anchor is
/// only as final as the Bloch block that carries it, and Bloch today is
/// k=4 forgeable / 51%-attackable / unaudited (see the design doc's reorg
/// gate). A production reader must treat `Anchored { depth }` as *tentative*
/// until `depth` clears its configured confirmation threshold, and must
/// handle `Orphaned` by rewinding derived L2 state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnchorStatus {
    /// Broadcast (or observed in the mempool) but not yet in any Bloch block
    /// the reader has seen.
    Pending,
    /// In a Bloch block on the reader's current best chain, `depth` blocks
    /// deep (`depth == 0` means "in the tip block").
    Anchored { depth: u64 },
    /// Was in a Bloch block that the reader's best chain no longer contains
    /// (reorged out). The sequencer must re-post orphaned anchors; derived
    /// L2 state anchored to the orphaned block must be rewound with it.
    Orphaned,
}

/// A tracked anchor: the decoded envelope plus where the reader saw it.
///
/// // SCAFFOLD: record type only; nothing populates it yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrackedAnchor {
    /// The decoded L2V0 COMMIT envelope.
    pub envelope: AnchorEnvelope,
    /// Txid of the carrying Bloch transaction.
    pub txid: [u8; 32],
    /// Height of the Bloch block that carried it, if any.
    pub height: Option<u64>,
    /// Current status under the reader's view.
    pub status: AnchorStatus,
}

/// What one [`AnchorManager::sync`] call did. Mirrors `bloch-tokens`'
/// `indexer::SyncReport`, extended with the anchor-layer specifics
/// (`anchors_added`, the `orphaned` anchors dropped by a rewind).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorSyncReport {
    /// A block-hash mismatch was found and blocks were rewound.
    pub reorged: bool,
    /// Height of the highest block that survived the rewind (`None` when
    /// nothing survived, or when no reorg happened and there was no rewind).
    pub rewound_to: Option<u64>,
    /// Blocks applied (replayed) by this call.
    pub applied_blocks: u64,
    /// Anchors appended to the canonical chain by this call.
    pub anchors_added: u64,
    /// Anchors dropped from the chain because their carrying block was
    /// reorged out; each is returned with `status == Orphaned`.
    pub orphaned: Vec<TrackedAnchor>,
    /// The source's tip height after this sync (`None` = empty chain).
    pub tip: Option<u64>,
}

/// Reorg-aware reader that derives the canonical anchor chain for one
/// rollup from Bloch blocks.
///
/// Reuses the journal + rewind-and-replay discipline of `crates/bloch-tokens`
/// (`stream::BlockSource`, `indexer::Indexer`): a per-height block-hash
/// journal detects reorgs (a changed `getblockhash(h)` for an already-seen
/// height), the chain is rewound to the fork point (anchors carried at or
/// above it are marked [`AnchorStatus::Orphaned`] and dropped), and the new
/// branch is replayed forward. The result is **exactly** the chain a fresh
/// manager derives replaying the current source from genesis — reorg
/// recovery can never leave residue.
#[derive(Clone, Debug)]
pub struct AnchorManager {
    /// The rollup this manager tracks (envelopes with any other `rollup_id`
    /// are ignored).
    pub rollup_id: [u8; 32],
    /// Confirmation depth at which an `Anchored` anchor is treated as
    /// settled by this reader (policy, not consensus; the design doc
    /// discusses K around 24 for Bloch's 30s blocks).
    pub confirm_depth: u64,
    /// Canonical anchor chain derived so far, in `batch_index` order; every
    /// adjacent pair satisfies [`crate::envelope::link`].
    pub chain: Vec<TrackedAnchor>,
    /// Per-height block-hash journal: `journal[h]` is the hash of the block
    /// scanned at height `h`. Private — its only role is reorg detection.
    journal: Vec<BlockHash>,
}

impl AnchorManager {
    /// New manager for one rollup with the given settlement depth policy.
    pub fn new(rollup_id: [u8; 32], confirm_depth: u64) -> Self {
        Self { rollup_id, confirm_depth, chain: Vec::new(), journal: Vec::new() }
    }

    /// The per-height block-hash journal (read-only).
    pub fn journal(&self) -> &[BlockHash] {
        &self.journal
    }

    /// Height of the last scanned block (`None` when nothing is scanned).
    pub fn scanned_height(&self) -> Option<u64> {
        (self.journal.len() as u64).checked_sub(1)
    }

    /// Synchronize with `src`: detect any reorg via block-hash mismatch,
    /// rewind to the fork point (journal truncated, anchors carried at or
    /// above it marked [`AnchorStatus::Orphaned`] and dropped), then replay
    /// heights in order up to the source tip — scanning each block's txs with
    /// [`crate::envelope::extract_anchor`] and appending an anchor iff it is
    /// the first for this rollup or [`crate::envelope::link`] extends the
    /// chain head. Finally refresh every tracked anchor to
    /// `Anchored { depth = tip - height }`.
    ///
    /// Idempotent: syncing an already-synced chain applies nothing.
    /// Deterministic: after any sequence of syncs across any reorgs, the
    /// chain equals a fresh manager's replay of the current chain.
    ///
    /// // SCAFFOLD: derives an UNVERIFIED anchor chain from bytes only — no
    /// // proof/DA/finality check (see module docs). A real JSON-RPC
    /// // `BlockSource` is out of scope; [`crate::source::MockChain`] drives
    /// // this offline.
    pub fn sync<S: BlockSource>(&mut self, src: &S) -> Result<AnchorSyncReport, SyncError> {
        let tip = match src.tip_height() {
            Ok(t) => Some(t),
            // An empty source is a full rewind, not an error: the mock (or a
            // pruned/reset node) simply has nothing for us.
            Err(SourceError::EmptyChain) => None,
            Err(e) => return Err(SyncError::Source(e.to_string())),
        };
        // `tip + 1` must be CHECKED: a hostile or buggy source reporting
        // `u64::MAX` would otherwise panic in debug builds or wrap to 0 in
        // release builds — and a wrapped `remote_len == 0` looks exactly like
        // an empty chain, silently rewinding (wiping) the entire tracked
        // chain. Fail closed with a source error instead; state untouched.
        let remote_len: u64 = match tip {
            None => 0,
            Some(t) => t.checked_add(1).ok_or_else(|| {
                SyncError::Source(format!(
                    "source reported tip height {t}: tip+1 overflows u64 — refusing to sync"
                ))
            })?,
        };
        let local_len = self.journal.len() as u64;

        // Fork-point search: highest height where journal and source agree.
        // For the no-reorg fast path this checks exactly one hash. Runs
        // BEFORE any mutation, so a source error here leaves state untouched.
        let mut common = local_len.min(remote_len);
        while common > 0 {
            let h = common - 1;
            let hash = src.block_hash(h).map_err(|e| SyncError::Source(e.to_string()))?;
            if hash == self.journal[h as usize] {
                break;
            }
            common -= 1;
        }

        // Rewind: drop journal + anchors above the fork point.
        let reorged = common < local_len;
        let mut orphaned: Vec<TrackedAnchor> = Vec::new();
        if reorged {
            self.journal.truncate(common as usize);
            let mut kept: Vec<TrackedAnchor> = Vec::with_capacity(self.chain.len());
            for mut anchor in self.chain.drain(..) {
                match anchor.height {
                    Some(h) if h >= common => {
                        anchor.status = AnchorStatus::Orphaned;
                        orphaned.push(anchor);
                    }
                    _ => kept.push(anchor),
                }
            }
            self.chain = kept;
        }

        // Replay forward, in height order.
        let mut applied_blocks: u64 = 0;
        let mut anchors_added: u64 = 0;
        for h in common..remote_len {
            let block = src
                .block_by_height(h)
                .map_err(|e| SyncError::Source(e.to_string()))?;
            if block.height != h {
                return Err(SyncError::Source(format!(
                    "source returned height {} for requested height {h}",
                    block.height
                )));
            }
            for stx in &block.transactions {
                if let Some((_, env)) = extract_anchor(&stx.tx) {
                    let extends = match self.chain.last() {
                        // First anchor for this rollup establishes the head;
                        // wrong-rollup envelopes never become the head.
                        None => env.rollup_id == self.rollup_id,
                        // Otherwise only a canonical successor is appended;
                        // non-linking / wrong-rollup envelopes are ignored.
                        Some(head) => link(&head.envelope, &env).is_ok(),
                    };
                    if extends {
                        self.chain.push(TrackedAnchor {
                            envelope: env,
                            txid: stx.txid,
                            height: Some(h),
                            // Refreshed to Anchored { depth } below.
                            status: AnchorStatus::Pending,
                        });
                        anchors_added += 1;
                    }
                }
            }
            self.journal.push(block.hash);
            applied_blocks += 1;
        }

        // Depth refresh: every tracked anchor sits on the current best chain,
        // so its status is Anchored at (tip - height). All heights are <= tip
        // by construction, so the subtraction never underflows.
        if let Some(t) = tip {
            for anchor in &mut self.chain {
                if let Some(h) = anchor.height {
                    anchor.status = AnchorStatus::Anchored { depth: t - h };
                }
            }
        }

        Ok(AnchorSyncReport {
            reorged,
            rewound_to: if reorged { common.checked_sub(1) } else { None },
            applied_blocks,
            anchors_added,
            orphaned,
            tip,
        })
    }
}

/// Errors [`AnchorManager::sync`] surfaces: any [`crate::source::SourceError`]
/// (transport / height-not-found / self-inconsistent source) folded into a
/// message, plus the fail-closed `tip+1` overflow guard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncError {
    /// The block source could not be reached or returned malformed data.
    Source(String),
}

impl core::fmt::Display for SyncError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Source(msg) => write!(f, "anchor sync: source error: {msg}"),
        }
    }
}

impl std::error::Error for SyncError {}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Tx, TxOut};
    use crate::source::{Block, MockChain, SourceTx};

    const ROLLUP: [u8; 32] = [0x11; 32];
    const OTHER_ROLLUP: [u8; 32] = [0x22; 32];

    fn mgr() -> AnchorManager {
        AnchorManager::new(ROLLUP, 24)
    }

    /// A 32-byte state root derived from `n` with a base tag, so distinct
    /// families of roots never collide.
    fn root(base: u8, n: u64) -> [u8; 32] {
        let mut r = [base; 32];
        r[..8].copy_from_slice(&n.to_le_bytes());
        r
    }

    /// Canonical anchor `batch_index` on the "main" root family: links to its
    /// predecessor from the same family (and, for index 1, to index 0).
    fn anchor(rollup: [u8; 32], batch_index: u64) -> AnchorEnvelope {
        AnchorEnvelope {
            rollup_id: rollup,
            batch_index,
            prev_state_root: root(0x00, batch_index),
            new_state_root: root(0x00, batch_index + 1),
            da_commitment: [0x44; 32],
            vkey_hash: [0x55; 32],
        }
    }

    /// A DIFFERENT internally-linked family that still links onto main-family
    /// anchor 0 (its batch-1 `prev_state_root` == main anchor 0's
    /// `new_state_root`). Used to build a genuinely different reorg branch.
    fn alt_anchor(batch_index: u64) -> AnchorEnvelope {
        AnchorEnvelope {
            rollup_id: ROLLUP,
            batch_index,
            prev_state_root: if batch_index == 1 { root(0x00, 1) } else { root(0xAA, batch_index) },
            new_state_root: root(0xAA, batch_index + 1),
            da_commitment: [0x88; 32],
            vkey_hash: [0x55; 32],
        }
    }

    fn env_stx(txid: u8, env: &AnchorEnvelope) -> SourceTx {
        SourceTx {
            txid: [txid; 32],
            tx: Tx {
                version: 1,
                inputs: vec![],
                outputs: vec![TxOut { value: 0, script_pubkey: env.encode() }],
                locktime: 0,
            },
        }
    }

    fn plain_stx(txid: u8) -> SourceTx {
        SourceTx {
            txid: [txid; 32],
            tx: Tx {
                version: 1,
                inputs: vec![],
                outputs: vec![TxOut { value: 546, script_pubkey: vec![0xEE; 20] }],
                locktime: 0,
            },
        }
    }

    /// Main-family chain: block h carries the anchor with batch_index == h,
    /// for h in 0..n. Every adjacent pair links.
    fn linked_chain(n: u64) -> MockChain {
        let mut c = MockChain::new();
        for h in 0..n {
            c.append(vec![env_stx(h as u8, &anchor(ROLLUP, h))]);
        }
        c
    }

    fn fresh_synced<S: BlockSource>(src: &S) -> AnchorManager {
        let mut m = mgr();
        m.sync(src).expect("sync must succeed");
        m
    }

    fn batch_indices(m: &AnchorManager) -> Vec<u64> {
        m.chain.iter().map(|a| a.envelope.batch_index).collect()
    }

    // ── basic replay / head establishment ────────────────────────────────

    #[test]
    fn first_anchor_for_rollup_establishes_the_head() {
        let chain = linked_chain(3);
        let mut m = mgr();
        let report = m.sync(&chain).unwrap();
        assert_eq!(report.reorged, false);
        assert_eq!(report.rewound_to, None);
        assert_eq!(report.applied_blocks, 3);
        assert_eq!(report.anchors_added, 3);
        assert_eq!(report.orphaned, vec![]);
        assert_eq!(report.tip, Some(2));
        assert_eq!(batch_indices(&m), vec![0, 1, 2]);
        assert_eq!(m.scanned_height(), Some(2));
    }

    #[test]
    fn first_anchor_wrong_rollup_does_not_establish_head() {
        // A wrong-rollup envelope in the genesis block must NOT become the
        // head; the correct-rollup anchor two blocks later is then the first.
        let mut c = MockChain::new();
        c.append(vec![env_stx(1, &anchor(OTHER_ROLLUP, 0))]); // ignored
        c.append(vec![plain_stx(2)]); // no anchor
        c.append(vec![env_stx(3, &anchor(ROLLUP, 0))]); // first for our rollup
        c.append(vec![env_stx(4, &anchor(ROLLUP, 1))]);

        let mut m = mgr();
        let report = m.sync(&c).unwrap();
        assert_eq!(report.anchors_added, 2);
        assert_eq!(batch_indices(&m), vec![0, 1]);
        assert_eq!(m.chain[0].height, Some(2));
        assert_eq!(m.chain[1].height, Some(3));
    }

    #[test]
    fn non_linking_envelope_is_ignored() {
        // Head is anchor 0; a block carrying anchor 2 (skips index 1) and a
        // wrong-rollup anchor must both be ignored; then anchor 1 links.
        let mut c = MockChain::new();
        c.append(vec![env_stx(0, &anchor(ROLLUP, 0))]);
        c.append(vec![env_stx(9, &anchor(ROLLUP, 2))]); // non-consecutive: ignored
        c.append(vec![env_stx(8, &anchor(OTHER_ROLLUP, 1))]); // wrong rollup: ignored
        c.append(vec![env_stx(1, &anchor(ROLLUP, 1))]); // links onto head

        let mut m = mgr();
        m.sync(&c).unwrap();
        assert_eq!(batch_indices(&m), vec![0, 1]);
        // And it equals a fresh replay of the same chain.
        assert_eq!(m.chain, fresh_synced(&c).chain);
    }

    // ── depth refresh ────────────────────────────────────────────────────

    #[test]
    fn depth_refreshes_to_tip_minus_height() {
        let mut c = linked_chain(3); // heights 0,1,2
        let mut m = mgr();
        m.sync(&c).unwrap();
        assert_eq!(
            m.chain.iter().map(|a| a.status.clone()).collect::<Vec<_>>(),
            vec![
                AnchorStatus::Anchored { depth: 2 },
                AnchorStatus::Anchored { depth: 1 },
                AnchorStatus::Anchored { depth: 0 },
            ]
        );

        // Extend the tip by two anchor-free blocks: every depth grows by 2.
        c.append(vec![plain_stx(50)]);
        c.append(vec![plain_stx(51)]);
        let report = m.sync(&c).unwrap();
        assert_eq!(report.anchors_added, 0);
        assert_eq!(report.applied_blocks, 2);
        assert_eq!(
            m.chain.iter().map(|a| a.status.clone()).collect::<Vec<_>>(),
            vec![
                AnchorStatus::Anchored { depth: 4 },
                AnchorStatus::Anchored { depth: 3 },
                AnchorStatus::Anchored { depth: 2 },
            ]
        );
    }

    // ── idempotence ──────────────────────────────────────────────────────

    #[test]
    fn re_sync_is_idempotent() {
        let chain = linked_chain(3);
        let mut m = mgr();
        m.sync(&chain).unwrap();
        let snapshot = m.chain.clone();
        let journal = m.journal().to_vec();

        let again = m.sync(&chain).unwrap();
        assert_eq!(
            again,
            AnchorSyncReport {
                reorged: false,
                rewound_to: None,
                applied_blocks: 0,
                anchors_added: 0,
                orphaned: vec![],
                tip: Some(2),
            }
        );
        assert_eq!(m.chain, snapshot);
        assert_eq!(m.journal(), journal.as_slice());
    }

    // ── empty source ─────────────────────────────────────────────────────

    #[test]
    fn empty_source_rewinds_everything() {
        let chain = linked_chain(3);
        let mut m = mgr();
        m.sync(&chain).unwrap();

        let empty = MockChain::new();
        let report = m.sync(&empty).unwrap();
        assert_eq!(report.reorged, true);
        assert_eq!(report.rewound_to, None);
        assert_eq!(report.applied_blocks, 0);
        assert_eq!(report.anchors_added, 0);
        assert_eq!(report.tip, None);
        assert_eq!(report.orphaned.len(), 3, "all three anchors orphaned");
        assert!(report.orphaned.iter().all(|a| a.status == AnchorStatus::Orphaned));
        assert_eq!(m.chain, vec![]);
        assert_eq!(m.scanned_height(), None);
        // Converges to a fresh manager on the empty chain.
        assert_eq!(m.chain, fresh_synced(&empty).chain);
    }

    // ── hostile tip = u64::MAX fails closed ──────────────────────────────

    #[test]
    fn hostile_tip_u64_max_fails_closed_without_touching_state() {
        struct OverflowTipSource;
        impl BlockSource for OverflowTipSource {
            fn tip_height(&self) -> Result<u64, SourceError> {
                Ok(u64::MAX)
            }
            fn block_hash(&self, height: u64) -> Result<BlockHash, SourceError> {
                Err(SourceError::HeightNotFound(height))
            }
            fn block_by_height(&self, height: u64) -> Result<Block, SourceError> {
                Err(SourceError::HeightNotFound(height))
            }
        }

        let chain = linked_chain(3);
        let mut m = mgr();
        m.sync(&chain).unwrap();
        let chain_before = m.chain.clone();
        let journal_before = m.journal().to_vec();

        let err = m
            .sync(&OverflowTipSource)
            .expect_err("tip+1 overflow must be an error");
        assert!(matches!(err, SyncError::Source(_)), "got {err:?}");

        // Fail closed means fail UNCHANGED: no rewind, no wipe.
        assert_eq!(m.chain, chain_before);
        assert_eq!(m.journal(), journal_before.as_slice());
    }

    // ── KEY INVARIANT: convergence to a fresh replay across reorgs ────────

    #[test]
    fn reorg_replacing_suffix_converges_to_fresh_replay() {
        let mut chain = linked_chain(3); // anchors 0,1,2
        let mut m = mgr();
        m.sync(&chain).unwrap();
        assert_eq!(batch_indices(&m), vec![0, 1, 2]);

        // Force a reorg at height 1: install a LONGER, genuinely different
        // branch (alt family) that still links onto the surviving anchor 0.
        // Embed junk (non-linking + wrong-rollup) to prove it is ignored.
        chain.replace_suffix(
            1,
            vec![
                vec![env_stx(31, &alt_anchor(1)), env_stx(99, &anchor(ROLLUP, 7))],
                vec![env_stx(32, &alt_anchor(2))],
                vec![env_stx(98, &anchor(OTHER_ROLLUP, 3)), env_stx(33, &alt_anchor(3))],
            ],
        );

        let report = m.sync(&chain).unwrap();
        assert!(report.reorged);
        assert_eq!(report.rewound_to, Some(0), "height 0 survived the fork");
        assert_eq!(report.applied_blocks, 3);
        assert_eq!(report.anchors_added, 3);
        // The old anchors 1 and 2 (heights 1,2) were orphaned.
        assert_eq!(report.orphaned.len(), 2);
        assert!(report.orphaned.iter().all(|a| a.status == AnchorStatus::Orphaned));

        // Convergence: EXACTLY the chain + journal of a fresh manager.
        let fresh = fresh_synced(&chain);
        assert_eq!(m.chain, fresh.chain);
        assert_eq!(m.journal(), fresh.journal());
        assert_eq!(batch_indices(&m), vec![0, 1, 2, 3]);
        // Head is now the alt family (different new_state_root than main).
        assert_eq!(m.chain[3].envelope, alt_anchor(3));
    }

    #[test]
    fn reorg_to_shorter_branch_converges() {
        let mut chain = linked_chain(4); // anchors 0..3
        let mut m = mgr();
        m.sync(&chain).unwrap();

        // Shorter branch: one replacement block after the fork.
        chain.replace_suffix(1, vec![vec![env_stx(41, &alt_anchor(1))]]);
        let report = m.sync(&chain).unwrap();
        assert!(report.reorged);
        assert_eq!(report.orphaned.len(), 3);
        assert_eq!(m.scanned_height(), Some(1));

        let fresh = fresh_synced(&chain);
        assert_eq!(m.chain, fresh.chain);
        assert_eq!(m.journal(), fresh.journal());
        assert_eq!(batch_indices(&m), vec![0, 1]);
    }

    #[test]
    fn reorg_from_genesis_converges() {
        let mut chain = linked_chain(3);
        let mut m = mgr();
        m.sync(&chain).unwrap();

        // Replace EVERYTHING (fork below the first block).
        chain.replace_suffix(0, vec![vec![env_stx(60, &anchor(ROLLUP, 0))]]);
        let report = m.sync(&chain).unwrap();
        assert!(report.reorged);
        assert_eq!(report.rewound_to, None, "nothing survived");
        assert_eq!(report.orphaned.len(), 3);
        assert_eq!(m.scanned_height(), Some(0));

        let fresh = fresh_synced(&chain);
        assert_eq!(m.chain, fresh.chain);
        assert_eq!(m.journal(), fresh.journal());
        assert_eq!(batch_indices(&m), vec![0]);
    }

    #[test]
    fn incremental_sync_matches_batch_sync() {
        let full = linked_chain(3);

        // Incremental: sync after every appended block.
        let mut partial = MockChain::new();
        let mut incremental = mgr();
        for h in 0..3 {
            partial.append(full.block_by_height(h).unwrap().transactions);
            incremental.sync(&partial).unwrap();
        }

        let batch = fresh_synced(&full);
        assert_eq!(incremental.chain, batch.chain);
        assert_eq!(incremental.journal(), batch.journal());
    }

    #[test]
    fn two_managers_same_history_are_identical() {
        let chain = linked_chain(3);
        let a = fresh_synced(&chain);
        let b = fresh_synced(&chain);
        assert_eq!(a.chain, b.chain);
        assert_eq!(a.journal(), b.journal());
    }
}
