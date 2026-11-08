//! DATA0 chain scan: a reorg-aware reader that derives the canonical backup
//! anchor chain for one namespace from any [`BlockSource`].
//!
//! Spec: `docs/specs/POSTERN-DATA-FILECOIN-DESIGN.md` §7 (Phase 3 anchor
//! reader) and the reader-plumbing note (line 81): the reader reuses
//! `bloch-tokens`' `BlockSource` (`getblockcount`−1 / `getblockhash(h)` /
//! `getblockbyheight(h, verbose)`) and the height→hash journal with fork-point
//! rewind + forward replay, so two independent readers of the same selected
//! chain reach byte-identical anchor state, reorg-correctly. This module
//! **mirrors `l2/bloch-l2-anchor/src/{source,manager}.rs` wholesale**,
//! retargeted from the L2V0 rollup field set to the DATA0 backup field set
//! ([`crate::anchor`]: `namespace_id`/`sequence`/`prev_root`/`manifest_root`).
//!
//! HONESTY (non-negotiable, see crate docs):
//!
//! * **Bytes only, no verification.** A decoded, linked anchor is an
//!   UNVERIFIED **claim** — never a checked proof. There is no PQ-signature
//!   check, no manifest fetch, no `signer_commit` recomputation here. The
//!   verifier that recomputes `manifest_root` and checks the ML-DSA/Falcon
//!   signature lives outside this zero-dep crate (`postern-backup-net`).
//! * **No live node.** A real JSON-RPC [`BlockSource`] is deliberately OUT OF
//!   SCOPE (zero deps, offline-buildable, exactly as `bloch-tokens` states);
//!   [`MockChain`] stands in so the reader — reorg handling included — is
//!   exercised fully offline and deterministically.
//! * **Inherits the base in full.** The chain is k=4, low-hashrate,
//!   51%-attackable, unaudited. An [`AnchorStatus::Anchored { depth }`] is
//!   *tentative* until `depth` clears the reader's configured
//!   [`ChainScanner::confirm_depth`]; a reorg surfaces as
//!   [`AnchorStatus::Orphaned`] and the derived state anchored above the fork
//!   point is dropped. No finite depth is finality.

use crate::anchor::{extract_anchor, link, AnchorEnvelope, Tx};

/// A block hash, as raw bytes (the node's `Hex32`).
pub type BlockHash = [u8; 32];

/// Read-path failure. `HeightNotFound` mirrors the node's non-standard
/// `result.error` on `getblockhash`/`getblockbyheight`; `EmptyChain` is
/// `getblockcount == 0` (no tip yet); `Transport` is reserved for real
/// clients and for a source that returns malformed / self-inconsistent data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceError {
    /// `getblockcount == 0`: the chain has no blocks yet.
    EmptyChain,
    /// The requested height is absent (node returned a method-level error).
    HeightNotFound(u64),
    /// Network/serialization failure, or a self-inconsistent source.
    Transport(String),
}

impl core::fmt::Display for SourceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyChain => write!(f, "source: chain has no blocks (getblockcount == 0)"),
            Self::HeightNotFound(h) => write!(f, "source: height {h} not found"),
            Self::Transport(msg) => write!(f, "source: transport failure: {msg}"),
        }
    }
}

impl std::error::Error for SourceError {}

/// One selected-chain transaction: its txid plus the structural body the
/// anchor reader inspects via [`crate::anchor::extract_anchor`]. The zero-dep
/// crate never hashes a transaction itself — `txid` comes from the node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceTx {
    /// Transaction id as reported by the node.
    pub txid: [u8; 32],
    /// Structural body an anchor reader inspects.
    pub tx: Tx,
}

/// The selected-chain view of one block: the subset of the node's `Block`
/// schema (`verbose=true`) the anchor layer reads — hash, height, and
/// transactions (txid + body).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// Block hash (`getblockhash(height)`).
    pub hash: BlockHash,
    /// Selected-chain height of this block (heights start at 0).
    pub height: u64,
    /// Transactions in the block, in block order.
    pub transactions: Vec<SourceTx>,
}

/// Read-only access to the selected chain, shaped on the documented node RPC:
/// `tip_height` = `getblockcount` − 1, `block_hash` = `getblockhash(height)`,
/// `block_by_height` = `getblockbyheight(height, verbose=true)`. All three are
/// public **reads** — which is what keeps the anchor layer permissionless:
/// anyone can point a reader at any node with no key and derive the same
/// canonical anchor chain. Implemented by [`MockChain`] here; a real JSON-RPC
/// client is out of scope by design.
pub trait BlockSource {
    /// Current tip height (`getblockcount` − 1). [`SourceError::EmptyChain`]
    /// when the count is 0.
    fn tip_height(&self) -> Result<u64, SourceError>;

    /// Hash of the selected-chain block at `height` (`getblockhash`).
    fn block_hash(&self, height: u64) -> Result<BlockHash, SourceError>;

    /// Full block at `height` (`getblockbyheight(height, verbose=true)`).
    fn block_by_height(&self, height: u64) -> Result<Block, SourceError>;
}

// ── MockChain ─────────────────────────────────────────────────────────────────

/// In-memory stand-in for the node's read RPC: an append-only selected chain
/// (heights start at 0) that can be **forced to reorg** by replacing a suffix
/// of blocks ([`MockChain::replace_suffix`]). Mirrors
/// `l2/bloch-l2-anchor/src/source.rs`'s `MockChain`.
///
/// Block hashes come from a deterministic mixing function (FNV-1a lanes) over
/// `(height, uniq, parent hash, txids)` — **not cryptographic, mock-only**.
/// `uniq` is a monotonic counter, so a replacement block at an already-used
/// height always hashes differently even with identical transactions, which is
/// exactly what a reorged real chain looks like to `getblockhash`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MockChain {
    blocks: Vec<Block>,
    uniq: u64,
}

impl MockChain {
    /// A fresh empty chain (`getblockcount == 0`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of blocks (== `getblockcount`).
    pub fn block_count(&self) -> u64 {
        self.blocks.len() as u64
    }

    /// Append a block at the next height carrying `transactions`; returns its
    /// hash.
    pub fn append(&mut self, transactions: Vec<SourceTx>) -> BlockHash {
        let height = self.blocks.len() as u64;
        let parent = self.blocks.last().map(|b| b.hash).unwrap_or([0u8; 32]);
        self.uniq += 1;
        let hash = mock_block_hash(height, &parent, &transactions, self.uniq);
        self.blocks.push(Block { hash, height, transactions });
        hash
    }

    /// Force a reorg: drop every block at height >= `from_height`, then append
    /// the replacement blocks in order. The `uniq` counter never resets, so
    /// replacement blocks hash differently from the ones they replace — a
    /// reader sees a hash mismatch at `from_height`.
    pub fn replace_suffix(&mut self, from_height: u64, replacement: Vec<Vec<SourceTx>>) {
        self.blocks.truncate(from_height as usize);
        for txs in replacement {
            self.append(txs);
        }
    }
}

impl BlockSource for MockChain {
    fn tip_height(&self) -> Result<u64, SourceError> {
        match self.blocks.len() {
            0 => Err(SourceError::EmptyChain),
            n => Ok(n as u64 - 1),
        }
    }

    fn block_hash(&self, height: u64) -> Result<BlockHash, SourceError> {
        self.blocks
            .get(height as usize)
            .map(|b| b.hash)
            .ok_or(SourceError::HeightNotFound(height))
    }

    fn block_by_height(&self, height: u64) -> Result<Block, SourceError> {
        self.blocks
            .get(height as usize)
            .cloned()
            .ok_or(SourceError::HeightNotFound(height))
    }
}

/// Deterministic 32-byte mixing function (four FNV-1a-64 lanes with distinct
/// seeds). NOT cryptographic — collision-resistance is irrelevant for a test
/// mock; determinism and sensitivity to every input byte are what matter.
fn mock_block_hash(height: u64, parent: &BlockHash, txs: &[SourceTx], uniq: u64) -> BlockHash {
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    let mut lanes = [
        FNV_OFFSET ^ 0x9e37_79b9_7f4a_7c15,
        FNV_OFFSET ^ 0x6a09_e667_f3bc_c908,
        FNV_OFFSET ^ 0xbb67_ae85_84ca_a73b,
        FNV_OFFSET ^ 0x3c6e_f372_fe94_f82b,
    ];
    let mut feed = |bytes: &[u8]| {
        for (i, b) in bytes.iter().enumerate() {
            let lane = &mut lanes[i % 4];
            *lane ^= u64::from(*b);
            *lane = lane.wrapping_mul(FNV_PRIME);
        }
        for lane in &mut lanes {
            *lane ^= 0xff;
            *lane = lane.wrapping_mul(FNV_PRIME);
        }
    };
    feed(&height.to_le_bytes());
    feed(&uniq.to_le_bytes());
    feed(parent);
    for tx in txs {
        feed(&tx.txid);
    }
    let mut out = [0u8; 32];
    for (i, lane) in lanes.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&lane.to_le_bytes());
    }
    out
}

// ── Scanner ─────────────────────────────────────────────────────────────────

/// Where an anchor stands relative to the reader's current view of Bloch.
///
/// The depth policy makes finality inheritance explicit: an anchor is only as
/// final as the Bloch block that carries it, and Bloch today is k=4 /
/// 51%-attackable / unaudited. A reader must treat `Anchored { depth }` as
/// *tentative* until `depth` clears its configured confirmation threshold, and
/// must handle `Orphaned` by rewinding any derived state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnchorStatus {
    /// Broadcast (or in the mempool) but not yet in any block the reader has
    /// seen.
    Pending,
    /// In a block on the reader's current best chain, `depth` blocks deep
    /// (`depth == 0` means "in the tip block").
    Anchored { depth: u64 },
    /// Was in a block that the reader's best chain no longer contains
    /// (reorged out). The writer must re-post orphaned anchors; state anchored
    /// to the orphaned block must be rewound with it.
    Orphaned,
}

/// A tracked DATA0 backup anchor: the decoded envelope plus where the reader
/// saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrackedAnchor {
    /// The decoded DATA0 envelope.
    pub envelope: AnchorEnvelope,
    /// Txid of the carrying Bloch transaction.
    pub txid: [u8; 32],
    /// Height of the Bloch block that carried it, if any.
    pub height: Option<u64>,
    /// Current status under the reader's view.
    pub status: AnchorStatus,
}

/// What one [`ChainScanner::scan`] call did. Mirrors the L2 reader's
/// `AnchorSyncReport`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanReport {
    /// A block-hash mismatch was found and blocks were rewound.
    pub reorged: bool,
    /// Height of the highest block that survived the rewind (`None` when
    /// nothing survived, or when no reorg happened).
    pub rewound_to: Option<u64>,
    /// Blocks applied (replayed) by this call.
    pub applied_blocks: u64,
    /// Anchors appended to the canonical chain by this call.
    pub anchors_added: u64,
    /// Anchors dropped because their carrying block was reorged out; each is
    /// returned with `status == Orphaned`.
    pub orphaned: Vec<TrackedAnchor>,
    /// The source's tip height after this scan (`None` = empty chain).
    pub tip: Option<u64>,
}

/// Reorg-aware reader that derives the canonical DATA0 anchor chain for one
/// backup namespace from Bloch blocks.
///
/// Reuses the journal + rewind-and-replay discipline of the L2 anchor reader:
/// a per-height block-hash journal detects reorgs (a changed
/// `getblockhash(h)`), the chain is rewound to the fork point (anchors carried
/// at or above it are marked [`AnchorStatus::Orphaned`] and dropped), and the
/// new branch is replayed forward. The result is **exactly** the chain a fresh
/// scanner derives replaying the current source from genesis — reorg recovery
/// can never leave residue.
#[derive(Clone, Debug)]
pub struct ChainScanner {
    /// The backup namespace this scanner tracks (envelopes with any other
    /// `namespace_id` are ignored).
    pub namespace_id: [u8; 32],
    /// Confirmation depth at which an `Anchored` anchor is treated as settled
    /// by this reader (policy, not consensus; no depth is finality on a k=4
    /// base).
    pub confirm_depth: u64,
    /// Canonical anchor chain derived so far, in `sequence` order; every
    /// adjacent pair satisfies [`crate::anchor::link`].
    pub chain: Vec<TrackedAnchor>,
    /// Per-height block-hash journal: `journal[h]` is the hash of the block
    /// scanned at height `h`. Private — its only role is reorg detection.
    journal: Vec<BlockHash>,
}

impl ChainScanner {
    /// New scanner for one namespace with the given settlement depth policy.
    pub fn new(namespace_id: [u8; 32], confirm_depth: u64) -> Self {
        Self { namespace_id, confirm_depth, chain: Vec::new(), journal: Vec::new() }
    }

    /// The per-height block-hash journal (read-only).
    pub fn journal(&self) -> &[BlockHash] {
        &self.journal
    }

    /// Height of the last scanned block (`None` when nothing is scanned).
    pub fn scanned_height(&self) -> Option<u64> {
        (self.journal.len() as u64).checked_sub(1)
    }

    /// The latest anchored `sequence` for this namespace, or `None` if the
    /// chain is empty. The design's "report the latest sequence" (§7).
    pub fn latest_sequence(&self) -> Option<u64> {
        self.chain.last().map(|a| a.envelope.sequence)
    }

    /// Whether `anchor` has cleared this reader's [`ChainScanner::confirm_depth`]
    /// policy threshold — i.e. it is [`AnchorStatus::Anchored`] at
    /// `depth >= confirm_depth`. Everything else — a shallower `Anchored`, a
    /// [`AnchorStatus::Pending`], or an [`AnchorStatus::Orphaned`] anchor — is
    /// *tentative*.
    ///
    /// This is the ONE place `confirm_depth` becomes load-bearing: it turns the
    /// stored policy number into a settled/tentative verdict. The boundary is
    /// **inclusive** — `depth == confirm_depth` is settled.
    ///
    /// HONESTY: "settled" here means "cleared the reader's local confirmation
    /// policy", NOT "final". Bloch's DATA0 base is k=4, low-hashrate,
    /// 51%-attackable and unaudited — **no finite depth is finality**. A deeper
    /// reorg can still surface a "settled" anchor as [`AnchorStatus::Orphaned`]
    /// on a later [`ChainScanner::scan`]; `confirm_depth` only trades
    /// reorg-exposure for latency, it never removes it.
    pub fn is_settled(&self, anchor: &TrackedAnchor) -> bool {
        matches!(anchor.status, AnchorStatus::Anchored { depth } if depth >= self.confirm_depth)
    }

    /// The anchors on the canonical chain that have cleared
    /// [`ChainScanner::confirm_depth`] per [`ChainScanner::is_settled`], in
    /// `sequence` order.
    ///
    /// Depth strictly decreases toward the tip (`depth == tip - height`), so the
    /// settled anchors are always a contiguous prefix of [`ChainScanner::chain`]:
    /// the older an anchor, the deeper it is, so once one anchor is settled every
    /// earlier one is too. Same k=4 non-finality caveat as [`ChainScanner::is_settled`]
    /// — a policy view, never a finality guarantee.
    pub fn settled_anchors(&self) -> Vec<&TrackedAnchor> {
        self.chain.iter().filter(|a| self.is_settled(a)).collect()
    }

    /// Scan `src`: detect any reorg via block-hash mismatch, rewind to the
    /// fork point (journal truncated, anchors carried at or above it marked
    /// [`AnchorStatus::Orphaned`] and dropped), then replay heights in order
    /// up to the tip — scanning each block's txs with
    /// [`crate::anchor::extract_anchor`] and appending an anchor iff it is the
    /// first for this namespace or [`crate::anchor::link`] extends the chain
    /// head. Finally refresh every tracked anchor to
    /// `Anchored { depth = tip - height }`.
    ///
    /// Idempotent: scanning an already-scanned chain applies nothing.
    /// Deterministic: after any sequence of scans across any reorgs, the chain
    /// equals a fresh scanner's replay of the current chain.
    ///
    /// // SCAFFOLD: derives an UNVERIFIED anchor chain from bytes only — no
    /// // PQ-signature / manifest / finality check (see module docs).
    pub fn scan<S: BlockSource>(&mut self, src: &S) -> Result<ScanReport, ScanError> {
        let tip = match src.tip_height() {
            Ok(t) => Some(t),
            // An empty source is a full rewind, not an error.
            Err(SourceError::EmptyChain) => None,
            Err(e) => return Err(ScanError::Source(e.to_string())),
        };
        // `tip + 1` must be CHECKED: a hostile source reporting `u64::MAX`
        // would otherwise panic in debug or wrap to 0 in release — and a
        // wrapped `remote_len == 0` looks exactly like an empty chain,
        // silently wiping the tracked chain. Fail closed instead.
        let remote_len: u64 = match tip {
            None => 0,
            Some(t) => t.checked_add(1).ok_or_else(|| {
                ScanError::Source(format!(
                    "source reported tip height {t}: tip+1 overflows u64 — refusing to scan"
                ))
            })?,
        };
        let local_len = self.journal.len() as u64;

        // Fork-point search: highest height where journal and source agree.
        // Runs BEFORE any mutation, so a source error here leaves state
        // untouched.
        let mut common = local_len.min(remote_len);
        while common > 0 {
            let h = common - 1;
            let hash = src.block_hash(h).map_err(|e| ScanError::Source(e.to_string()))?;
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
                .map_err(|e| ScanError::Source(e.to_string()))?;
            if block.height != h {
                return Err(ScanError::Source(format!(
                    "source returned height {} for requested height {h}",
                    block.height
                )));
            }
            for stx in &block.transactions {
                if let Some((_, env)) = extract_anchor(&stx.tx) {
                    let extends = match self.chain.last() {
                        // First anchor for this namespace establishes the head;
                        // wrong-namespace envelopes never become the head.
                        None => env.namespace_id == self.namespace_id,
                        // Otherwise only a canonical successor is appended;
                        // non-linking / wrong-namespace envelopes are ignored.
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

        Ok(ScanReport {
            reorged,
            rewound_to: if reorged { common.checked_sub(1) } else { None },
            applied_blocks,
            anchors_added,
            orphaned,
            tip,
        })
    }
}

/// Errors [`ChainScanner::scan`] surfaces: any [`SourceError`] folded into a
/// message, plus the fail-closed `tip+1` overflow guard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScanError {
    /// The block source could not be reached or returned malformed data.
    Source(String),
}

impl core::fmt::Display for ScanError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Source(msg) => write!(f, "data0 scan: source error: {msg}"),
        }
    }
}

impl std::error::Error for ScanError {}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anchor::{TxOut, CID_LEN};

    const NS: [u8; 32] = [0x11; 32];
    const OTHER_NS: [u8; 32] = [0x22; 32];

    fn scanner() -> ChainScanner {
        ChainScanner::new(NS, 24)
    }

    /// A 32-byte root derived from `n` with a base tag, so distinct families
    /// of roots never collide.
    fn root(base: u8, n: u64) -> [u8; 32] {
        let mut r = [base; 32];
        r[..8].copy_from_slice(&n.to_le_bytes());
        r
    }

    /// Canonical DATA0 anchor at `sequence` on the "main" root family: links
    /// to its predecessor from the same family.
    fn anchor(namespace: [u8; 32], sequence: u64) -> AnchorEnvelope {
        AnchorEnvelope {
            namespace_id: namespace,
            sequence,
            prev_root: root(0x00, sequence),
            manifest_root: root(0x00, sequence + 1),
            signer_commit: [0x55; 32],
            manifest_cid: [0x66; CID_LEN],
        }
    }

    /// A DIFFERENT internally-linked family that still links onto main-family
    /// anchor 0 (its seq-1 `prev_root` == main anchor 0's `manifest_root`).
    fn alt_anchor(sequence: u64) -> AnchorEnvelope {
        AnchorEnvelope {
            namespace_id: NS,
            sequence,
            prev_root: if sequence == 1 { root(0x00, 1) } else { root(0xAA, sequence) },
            manifest_root: root(0xAA, sequence + 1),
            signer_commit: [0x88; 32],
            manifest_cid: [0x99; CID_LEN],
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

    /// Main-family chain: block h carries the anchor with `sequence == h`.
    fn linked_chain(n: u64) -> MockChain {
        let mut c = MockChain::new();
        for h in 0..n {
            c.append(vec![env_stx(h as u8, &anchor(NS, h))]);
        }
        c
    }

    fn fresh_scanned<S: BlockSource>(src: &S) -> ChainScanner {
        let mut m = scanner();
        m.scan(src).expect("scan must succeed");
        m
    }

    fn sequences(m: &ChainScanner) -> Vec<u64> {
        m.chain.iter().map(|a| a.envelope.sequence).collect()
    }

    // ── MockChain basics ─────────────────────────────────────────────────

    #[test]
    fn empty_chain_reports_empty() {
        let c = MockChain::new();
        assert_eq!(c.tip_height(), Err(SourceError::EmptyChain));
        assert_eq!(c.block_hash(0), Err(SourceError::HeightNotFound(0)));
        assert_eq!(c.block_by_height(0), Err(SourceError::HeightNotFound(0)));
    }

    #[test]
    fn append_extends_the_selected_chain() {
        let mut c = MockChain::new();
        let h0 = c.append(vec![plain_stx(1)]);
        let h1 = c.append(vec![plain_stx(2)]);
        assert_eq!(c.tip_height(), Ok(1));
        assert_eq!(c.block_hash(0), Ok(h0));
        assert_eq!(c.block_hash(1), Ok(h1));
        assert_ne!(h0, h1);
        assert_eq!(c.block_hash(2), Err(SourceError::HeightNotFound(2)));
    }

    #[test]
    fn replace_suffix_forces_a_visible_reorg() {
        let mut c = MockChain::new();
        let h0 = c.append(vec![plain_stx(1)]);
        let h1 = c.append(vec![plain_stx(2)]);
        c.replace_suffix(1, vec![vec![plain_stx(4)]]);
        assert_eq!(c.tip_height(), Ok(1));
        assert_eq!(c.block_hash(0), Ok(h0), "prefix untouched");
        assert_ne!(c.block_hash(1), Ok(h1), "replaced height re-hashes");

        // Even IDENTICAL transactions re-hash after a reorg (uniq counter).
        let before = c.block_hash(1).unwrap();
        let txs = c.block_by_height(1).unwrap().transactions;
        c.replace_suffix(1, vec![txs]);
        assert_ne!(c.block_hash(1).unwrap(), before);
    }

    // ── basic replay / head establishment ────────────────────────────────

    #[test]
    fn first_anchor_for_namespace_establishes_the_head() {
        let chain = linked_chain(3);
        let mut m = scanner();
        let report = m.scan(&chain).unwrap();
        assert_eq!(report.reorged, false);
        assert_eq!(report.rewound_to, None);
        assert_eq!(report.applied_blocks, 3);
        assert_eq!(report.anchors_added, 3);
        assert_eq!(report.orphaned, vec![]);
        assert_eq!(report.tip, Some(2));
        assert_eq!(sequences(&m), vec![0, 1, 2]);
        assert_eq!(m.scanned_height(), Some(2));
        assert_eq!(m.latest_sequence(), Some(2));
    }

    #[test]
    fn first_anchor_wrong_namespace_does_not_establish_head() {
        let mut c = MockChain::new();
        c.append(vec![env_stx(1, &anchor(OTHER_NS, 0))]); // ignored
        c.append(vec![plain_stx(2)]); // no anchor
        c.append(vec![env_stx(3, &anchor(NS, 0))]); // first for our namespace
        c.append(vec![env_stx(4, &anchor(NS, 1))]);

        let mut m = scanner();
        let report = m.scan(&c).unwrap();
        assert_eq!(report.anchors_added, 2);
        assert_eq!(sequences(&m), vec![0, 1]);
        assert_eq!(m.chain[0].height, Some(2));
        assert_eq!(m.chain[1].height, Some(3));
    }

    #[test]
    fn non_linking_envelope_is_ignored() {
        let mut c = MockChain::new();
        c.append(vec![env_stx(0, &anchor(NS, 0))]);
        c.append(vec![env_stx(9, &anchor(NS, 2))]); // non-consecutive: ignored
        c.append(vec![env_stx(8, &anchor(OTHER_NS, 1))]); // wrong namespace: ignored
        c.append(vec![env_stx(1, &anchor(NS, 1))]); // links onto head

        let mut m = scanner();
        m.scan(&c).unwrap();
        assert_eq!(sequences(&m), vec![0, 1]);
        assert_eq!(m.chain, fresh_scanned(&c).chain);
    }

    // ── depth refresh ────────────────────────────────────────────────────

    #[test]
    fn depth_refreshes_to_tip_minus_height() {
        let mut c = linked_chain(3);
        let mut m = scanner();
        m.scan(&c).unwrap();
        assert_eq!(
            m.chain.iter().map(|a| a.status.clone()).collect::<Vec<_>>(),
            vec![
                AnchorStatus::Anchored { depth: 2 },
                AnchorStatus::Anchored { depth: 1 },
                AnchorStatus::Anchored { depth: 0 },
            ]
        );

        c.append(vec![plain_stx(50)]);
        c.append(vec![plain_stx(51)]);
        let report = m.scan(&c).unwrap();
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
    fn re_scan_is_idempotent() {
        let chain = linked_chain(3);
        let mut m = scanner();
        m.scan(&chain).unwrap();
        let snapshot = m.chain.clone();
        let journal = m.journal().to_vec();

        let again = m.scan(&chain).unwrap();
        assert_eq!(
            again,
            ScanReport {
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
        let mut m = scanner();
        m.scan(&chain).unwrap();

        let empty = MockChain::new();
        let report = m.scan(&empty).unwrap();
        assert_eq!(report.reorged, true);
        assert_eq!(report.rewound_to, None);
        assert_eq!(report.tip, None);
        assert_eq!(report.orphaned.len(), 3, "all three anchors orphaned");
        assert!(report.orphaned.iter().all(|a| a.status == AnchorStatus::Orphaned));
        assert_eq!(m.chain, vec![]);
        assert_eq!(m.scanned_height(), None);
        assert_eq!(m.latest_sequence(), None);
        assert_eq!(m.chain, fresh_scanned(&empty).chain);
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
        let mut m = scanner();
        m.scan(&chain).unwrap();
        let chain_before = m.chain.clone();
        let journal_before = m.journal().to_vec();

        let err = m.scan(&OverflowTipSource).expect_err("tip+1 overflow must be an error");
        assert!(matches!(err, ScanError::Source(_)), "got {err:?}");

        // Fail closed means fail UNCHANGED: no rewind, no wipe.
        assert_eq!(m.chain, chain_before);
        assert_eq!(m.journal(), journal_before.as_slice());
    }

    // ── KEY INVARIANT: convergence to a fresh replay across reorgs ────────

    #[test]
    fn reorg_replacing_suffix_converges_to_fresh_replay() {
        let mut chain = linked_chain(3); // anchors 0,1,2
        let mut m = scanner();
        m.scan(&chain).unwrap();
        assert_eq!(sequences(&m), vec![0, 1, 2]);

        // Reorg at height 1: a LONGER, genuinely different branch (alt family)
        // linking onto surviving anchor 0. Embed junk to prove it is ignored.
        chain.replace_suffix(
            1,
            vec![
                vec![env_stx(31, &alt_anchor(1)), env_stx(99, &anchor(NS, 7))],
                vec![env_stx(32, &alt_anchor(2))],
                vec![env_stx(98, &anchor(OTHER_NS, 3)), env_stx(33, &alt_anchor(3))],
            ],
        );

        let report = m.scan(&chain).unwrap();
        assert!(report.reorged);
        assert_eq!(report.rewound_to, Some(0), "height 0 survived the fork");
        assert_eq!(report.applied_blocks, 3);
        assert_eq!(report.anchors_added, 3);
        assert_eq!(report.orphaned.len(), 2);
        assert!(report.orphaned.iter().all(|a| a.status == AnchorStatus::Orphaned));

        // Convergence: EXACTLY the chain + journal of a fresh scanner.
        let fresh = fresh_scanned(&chain);
        assert_eq!(m.chain, fresh.chain);
        assert_eq!(m.journal(), fresh.journal());
        assert_eq!(sequences(&m), vec![0, 1, 2, 3]);
        assert_eq!(m.chain[3].envelope, alt_anchor(3));
        assert_eq!(m.latest_sequence(), Some(3));
    }

    #[test]
    fn reorg_to_shorter_branch_converges() {
        let mut chain = linked_chain(4);
        let mut m = scanner();
        m.scan(&chain).unwrap();

        chain.replace_suffix(1, vec![vec![env_stx(41, &alt_anchor(1))]]);
        let report = m.scan(&chain).unwrap();
        assert!(report.reorged);
        assert_eq!(report.orphaned.len(), 3);
        assert_eq!(m.scanned_height(), Some(1));

        let fresh = fresh_scanned(&chain);
        assert_eq!(m.chain, fresh.chain);
        assert_eq!(m.journal(), fresh.journal());
        assert_eq!(sequences(&m), vec![0, 1]);
    }

    #[test]
    fn reorg_from_genesis_converges() {
        let mut chain = linked_chain(3);
        let mut m = scanner();
        m.scan(&chain).unwrap();

        chain.replace_suffix(0, vec![vec![env_stx(60, &anchor(NS, 0))]]);
        let report = m.scan(&chain).unwrap();
        assert!(report.reorged);
        assert_eq!(report.rewound_to, None, "nothing survived");
        assert_eq!(report.orphaned.len(), 3);
        assert_eq!(m.scanned_height(), Some(0));

        let fresh = fresh_scanned(&chain);
        assert_eq!(m.chain, fresh.chain);
        assert_eq!(m.journal(), fresh.journal());
        assert_eq!(sequences(&m), vec![0]);
    }

    #[test]
    fn incremental_scan_matches_batch_scan() {
        let full = linked_chain(3);

        let mut partial = MockChain::new();
        let mut incremental = scanner();
        for h in 0..3 {
            partial.append(full.block_by_height(h).unwrap().transactions);
            incremental.scan(&partial).unwrap();
        }

        let batch = fresh_scanned(&full);
        assert_eq!(incremental.chain, batch.chain);
        assert_eq!(incremental.journal(), batch.journal());
    }

    #[test]
    fn two_scanners_same_history_are_identical() {
        let chain = linked_chain(3);
        let a = fresh_scanned(&chain);
        let b = fresh_scanned(&chain);
        assert_eq!(a.chain, b.chain);
        assert_eq!(a.journal(), b.journal());
    }

    // ── settled / tentative status from confirm_depth ────────────────────

    /// A scanner whose `confirm_depth == k` over a `depth+1`-block chain, so
    /// the deepest anchor sits at exactly `depth == k` (the boundary) and each
    /// shallower anchor is one below. Returns the scanner ready to inspect.
    fn scanner_with_depths(confirm_depth: u64, blocks: u64) -> ChainScanner {
        let chain = linked_chain(blocks);
        let mut m = ChainScanner::new(NS, confirm_depth);
        m.scan(&chain).unwrap();
        m
    }

    #[test]
    fn is_settled_is_true_at_and_above_confirm_depth_false_below() {
        // 5 blocks (heights 0..4), tip = 4 → depths 4,3,2,1,0 for seq 0..4.
        let m = scanner_with_depths(2, 5);
        let depths: Vec<u64> = m
            .chain
            .iter()
            .map(|a| match a.status {
                AnchorStatus::Anchored { depth } => depth,
                _ => panic!("all anchored"),
            })
            .collect();
        assert_eq!(depths, vec![4, 3, 2, 1, 0]);

        // confirm_depth == 2: depths 4,3,2 settled; 1,0 tentative.
        let verdicts: Vec<bool> = m.chain.iter().map(|a| m.is_settled(a)).collect();
        assert_eq!(verdicts, vec![true, true, true, false, false]);
    }

    #[test]
    fn boundary_exactly_confirm_depth_is_settled() {
        // 4 blocks, tip = 3 → the seq-0 anchor sits at depth 3.
        let m = scanner_with_depths(3, 4);
        // Its depth is EXACTLY confirm_depth.
        assert_eq!(m.chain[0].status, AnchorStatus::Anchored { depth: 3 });
        assert!(m.is_settled(&m.chain[0]), "depth == confirm_depth must be settled");
        // One shallower (depth 2) is just below the threshold → tentative.
        assert_eq!(m.chain[1].status, AnchorStatus::Anchored { depth: 2 });
        assert!(!m.is_settled(&m.chain[1]), "depth == confirm_depth - 1 is tentative");
    }

    #[test]
    fn settled_anchors_is_the_deep_contiguous_prefix() {
        // 5 blocks, tip 4, depths 4,3,2,1,0; confirm_depth 3 → seq {0,1} settled.
        let m = scanner_with_depths(3, 5);
        let settled: Vec<u64> = m.settled_anchors().iter().map(|a| a.envelope.sequence).collect();
        assert_eq!(settled, vec![0, 1]);
    }

    #[test]
    fn confirm_depth_zero_settles_all_anchored_pending_and_orphaned_never() {
        // depth >= 0 is always true for Anchored, so every tracked anchor is
        // settled — but Pending / Orphaned are never Anchored, so never settled.
        let m = scanner_with_depths(0, 3);
        assert_eq!(m.settled_anchors().len(), 3);
        assert!(m.chain.iter().all(|a| m.is_settled(a)));

        // A hand-built Pending / Orphaned anchor is tentative even at depth 0.
        let pending = TrackedAnchor {
            envelope: anchor(NS, 9),
            txid: [0; 32],
            height: None,
            status: AnchorStatus::Pending,
        };
        let orphaned = TrackedAnchor { status: AnchorStatus::Orphaned, ..pending.clone() };
        assert!(!m.is_settled(&pending));
        assert!(!m.is_settled(&orphaned));
    }

    #[test]
    fn high_confirm_depth_settles_nothing_until_chain_grows() {
        // confirm_depth 24 (the module's default), only 3 blocks: deepest anchor
        // is at depth 2, far below threshold → nothing settled yet.
        let m = scanner_with_depths(24, 3);
        assert!(m.settled_anchors().is_empty(), "no anchor is 24-deep on a 3-block chain");
        assert!(m.chain.iter().all(|a| !m.is_settled(a)));
    }

    #[test]
    fn orphaned_anchor_after_reorg_is_never_settled() {
        // Deep chain, low confirm_depth: everything settled...
        let mut chain = linked_chain(4);
        let mut m = ChainScanner::new(NS, 1);
        m.scan(&chain).unwrap();
        assert_eq!(m.settled_anchors().len(), 3, "seq 0,1,2 at depth >=1");

        // ...then a reorg orphans the suffix. Orphaned anchors leave the chain;
        // whatever remains is re-depth-stamped and only settled if it clears
        // confirm_depth. This asserts settled status tracks reorgs, not history.
        chain.replace_suffix(1, vec![vec![env_stx(41, &alt_anchor(1))]]);
        m.scan(&chain).unwrap();
        // Now tip = 1: seq 0 at depth 1 (settled), seq 1 (alt) at depth 0 (tentative).
        let settled: Vec<u64> = m.settled_anchors().iter().map(|a| a.envelope.sequence).collect();
        assert_eq!(settled, vec![0]);
    }
}
