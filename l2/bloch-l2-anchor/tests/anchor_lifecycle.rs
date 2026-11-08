//! Integration test for the reorg-aware L2 anchor reader
//! (`AnchorManager::sync`), driven end-to-end through the crate's **public
//! API only** over a local/mock Bloch chain.
//!
//! // SCAFFOLD, UNAUDITED, NOT A WORKING L2. This exercises the offline
//! // replay/reorg reader exactly as a real reader would use it: point it at
//! // a `BlockSource` (here [`MockChain`] standing in for the node's
//! // `getblockcount`/`getblockhash`/`getblockbyheight` RPC), call `sync`,
//! // and read back an anchor's [`AnchorStatus`]. A decoded, linked anchor is
//! // still an *unverified claim* — there is no SP1 proof, DA, or finality
//! // check here.
//!
//! Coverage (the item's acceptance):
//!   1. `sync` replays a mock Bloch chain and populates an
//!      [`AnchorStatus`] — `Pending` / `Anchored { depth }` / `Orphaned` —
//!      for every decoded L2V0 COMMIT envelope.
//!   2. A reorg that disconnects the anchoring block flips the affected
//!      anchor's status to `Orphaned`.

use bloch_l2_anchor::{
    AnchorEnvelope, AnchorManager, AnchorStatus, MockChain, SourceTx, Tx, TxOut,
};

const ROLLUP: [u8; 32] = [0x11; 32];
const OTHER_ROLLUP: [u8; 32] = [0x22; 32];
const CONFIRM_DEPTH: u64 = 24;

/// A 32-byte state root tagged by `base` and indexed by `n`, so distinct
/// root families never collide.
fn root(base: u8, n: u64) -> [u8; 32] {
    let mut r = [base; 32];
    r[..8].copy_from_slice(&n.to_le_bytes());
    r
}

/// Canonical anchor on the "main" root family: batch `i`'s `prev_state_root`
/// equals batch `i-1`'s `new_state_root`, so adjacent anchors link.
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

/// An alternative, internally-linked root family that still links onto main
/// anchor 0 (its batch-1 `prev_state_root` equals main anchor 0's
/// `new_state_root`). Used to build a genuinely different reorg branch.
fn alt_anchor(batch_index: u64) -> AnchorEnvelope {
    AnchorEnvelope {
        rollup_id: ROLLUP,
        batch_index,
        prev_state_root: if batch_index == 1 {
            root(0x00, 1)
        } else {
            root(0xAA, batch_index)
        },
        new_state_root: root(0xAA, batch_index + 1),
        da_commitment: [0x88; 32],
        vkey_hash: [0x55; 32],
    }
}

/// A tx carrying `env` in the `script_pubkey` of a zero-value output (the
/// L2V0 COMMIT convention), keyed by a single-byte `txid`.
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

/// A non-anchor tx (ordinary spend), so a replacement block can carry no
/// anchor at all.
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

/// The reader's lifecycle view of the anchor for `batch_index`: its tracked
/// status if it is on the derived canonical chain, else [`AnchorStatus::Pending`]
/// — a batch the sequencer has produced but that the reader has not yet
/// observed in any Bloch block (exactly the `Pending` semantics). This is how
/// a reader answers "where does batch N stand?" from `sync`'s output.
fn status_of(m: &AnchorManager, batch_index: u64) -> AnchorStatus {
    m.chain
        .iter()
        .find(|a| a.envelope.batch_index == batch_index)
        .map(|a| a.status.clone())
        .unwrap_or(AnchorStatus::Pending)
}

/// Full lifecycle over a single mock Bloch chain: a batch is `Pending` before
/// its block is mined, becomes `Anchored { depth = tip - height }` once the
/// reader replays that block, deepens as the tip advances, and flips to
/// `Orphaned` when a reorg disconnects its anchoring block.
#[test]
fn anchor_lifecycle_pending_then_anchored_then_orphaned() {
    let mut chain = MockChain::new();
    let mut mgr = AnchorManager::new(ROLLUP, CONFIRM_DEPTH);

    // ── Phase 1: PENDING ──────────────────────────────────────────────────
    // The sequencer has produced batches 0, 1 and 2, but only 0 and 1 are
    // mined so far (heights 0 and 1). Batch 2 is broadcast-but-unmined.
    chain.append(vec![env_stx(0, &anchor(ROLLUP, 0))]);
    chain.append(vec![env_stx(1, &anchor(ROLLUP, 1))]);

    let r1 = mgr.sync(&chain).expect("sync over 2-block chain");
    assert!(!r1.reorged);
    assert_eq!(r1.applied_blocks, 2);
    assert_eq!(r1.anchors_added, 2);
    assert_eq!(r1.tip, Some(1));

    // Mined batches are Anchored at (tip - height); the unmined batch 2 is
    // Pending (not yet on the reader's chain).
    assert_eq!(status_of(&mgr, 0), AnchorStatus::Anchored { depth: 1 });
    assert_eq!(status_of(&mgr, 1), AnchorStatus::Anchored { depth: 0 });
    assert_eq!(status_of(&mgr, 2), AnchorStatus::Pending);

    // ── Phase 2: ANCHORED for every decoded envelope ──────────────────────
    // Batch 2 is mined at height 2, and two anchor-free blocks extend the tip
    // to height 4 (so every anchor's confirmation depth grows).
    chain.append(vec![env_stx(2, &anchor(ROLLUP, 2))]);
    chain.append(vec![plain_stx(50)]);
    chain.append(vec![plain_stx(51)]);

    let r2 = mgr.sync(&chain).expect("sync after mining batch 2 + 2 fillers");
    assert!(!r2.reorged);
    assert_eq!(r2.applied_blocks, 3);
    assert_eq!(r2.anchors_added, 1, "only batch 2 is a new anchor");
    assert_eq!(r2.tip, Some(4));

    // Every decoded COMMIT envelope now carries an Anchored { depth } status,
    // depth = tip(4) - height.
    assert_eq!(status_of(&mgr, 0), AnchorStatus::Anchored { depth: 4 });
    assert_eq!(status_of(&mgr, 1), AnchorStatus::Anchored { depth: 3 });
    assert_eq!(status_of(&mgr, 2), AnchorStatus::Anchored { depth: 2 });
    // No decoded envelope is left Pending or Orphaned on the best chain.
    assert!(mgr.chain.iter().all(|a| matches!(a.status, AnchorStatus::Anchored { .. })));

    // ── Phase 3: ORPHANED by a reorg that disconnects the anchoring block ──
    // Reorg from height 2: replace batch 2's carrying block with a single
    // anchor-free block. Batch 2's anchoring block is disconnected; batches 0
    // and 1 (heights 0, 1) survive below the fork.
    chain.replace_suffix(2, vec![vec![plain_stx(60)]]);

    let r3 = mgr.sync(&chain).expect("sync across the reorg");
    assert!(r3.reorged, "the disconnected anchoring block must be detected");
    assert_eq!(r3.rewound_to, Some(1), "heights 0 and 1 survived the fork");
    assert_eq!(r3.tip, Some(2));

    // The flip: batch 2's status is now Orphaned, surfaced in the report.
    assert_eq!(r3.orphaned.len(), 1, "exactly batch 2 was orphaned");
    let orphan = &r3.orphaned[0];
    assert_eq!(orphan.envelope, anchor(ROLLUP, 2));
    assert_eq!(orphan.status, AnchorStatus::Orphaned);

    // It is gone from the derived canonical chain (a reader must rewind any
    // L2 state anchored to it); from the reader's lifecycle view it is once
    // again Pending until the sequencer re-posts it.
    assert_eq!(status_of(&mgr, 2), AnchorStatus::Pending);

    // Surviving anchors are re-depth-ed against the new, shorter tip.
    assert_eq!(status_of(&mgr, 0), AnchorStatus::Anchored { depth: 2 });
    assert_eq!(status_of(&mgr, 1), AnchorStatus::Anchored { depth: 1 });

    // The reader converges to exactly what a fresh replay of the reorged
    // chain derives — reorg recovery leaves no residue.
    let mut fresh = AnchorManager::new(ROLLUP, CONFIRM_DEPTH);
    fresh.sync(&chain).unwrap();
    assert_eq!(mgr.chain, fresh.chain);
    assert_eq!(mgr.journal(), fresh.journal());
}

/// A reorg that disconnects the anchoring block while REPLACING it with a
/// different, longer anchor branch: the old anchor flips to `Orphaned` and the
/// new branch's anchor takes its place as `Anchored`.
#[test]
fn reorg_replacing_anchor_branch_orphans_the_old_anchor() {
    // Main chain: anchors 0, 1, 2 at heights 0, 1, 2.
    let mut chain = MockChain::new();
    for h in 0..3u64 {
        chain.append(vec![env_stx(h as u8, &anchor(ROLLUP, h))]);
    }
    let mut mgr = AnchorManager::new(ROLLUP, CONFIRM_DEPTH);
    mgr.sync(&chain).unwrap();
    assert_eq!(status_of(&mgr, 1), AnchorStatus::Anchored { depth: 1 });
    assert_eq!(status_of(&mgr, 2), AnchorStatus::Anchored { depth: 0 });

    // Reorg from height 1 onto the alt family (a genuinely different branch
    // that still links onto surviving anchor 0), with junk embedded to prove
    // non-linking / wrong-rollup envelopes are ignored.
    chain.replace_suffix(
        1,
        vec![
            vec![env_stx(31, &alt_anchor(1)), env_stx(99, &anchor(ROLLUP, 7))],
            vec![env_stx(32, &alt_anchor(2))],
            vec![env_stx(98, &anchor(OTHER_ROLLUP, 3)), env_stx(33, &alt_anchor(3))],
        ],
    );

    let report = mgr.sync(&chain).unwrap();
    assert!(report.reorged);
    assert_eq!(report.rewound_to, Some(0));

    // The two main-family anchors that sat on the disconnected blocks (old
    // batches 1 and 2) are orphaned.
    assert_eq!(report.orphaned.len(), 2);
    assert!(report.orphaned.iter().all(|a| a.status == AnchorStatus::Orphaned));
    let orphaned_roots: Vec<[u8; 32]> =
        report.orphaned.iter().map(|a| a.envelope.new_state_root).collect();
    assert!(orphaned_roots.contains(&anchor(ROLLUP, 1).new_state_root));
    assert!(orphaned_roots.contains(&anchor(ROLLUP, 2).new_state_root));

    // The new alt branch is now Anchored; the head is the alt-family batch 3.
    assert_eq!(status_of(&mgr, 3), AnchorStatus::Anchored { depth: 0 });
    assert_eq!(mgr.chain.last().unwrap().envelope, alt_anchor(3));
    // Batch 0 below the fork was never disturbed.
    assert_eq!(status_of(&mgr, 0), AnchorStatus::Anchored { depth: 3 });

    // Convergence to a fresh replay.
    let mut fresh = AnchorManager::new(ROLLUP, CONFIRM_DEPTH);
    fresh.sync(&chain).unwrap();
    assert_eq!(mgr.chain, fresh.chain);
    assert_eq!(mgr.journal(), fresh.journal());
}
