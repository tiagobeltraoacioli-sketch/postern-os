// SPDX-License-Identifier: MIT OR Apache-2.0
//! Batch sealing (§4 batcher): every 300 s OR when pending canonical bytes
//! reach 256 KiB OR when a cadence window's worth of blocks (150 at 2 s) has
//! accumulated — whichever first.
//!
//! # Cross-crate correspondence (documentation only, no code dependency)
//!
//! [`Batch`]'s fields line up one-to-one with the `L2V0` BATCH envelope
//! (op `0x02`, §4 wire format) that the sibling standalone crate
//! `bloch-l2-anchor` encodes and posts to Bloch:
//!
//! | this crate (`Batch`) | `L2V0` BATCH envelope field |
//! |---|---|
//! | `batch_index`        | `batch_no` (u64 LE) |
//! | `l2_block_first`     | `l2_block_first` (u64 LE) |
//! | `l2_block_last`      | `l2_block_last` (u64 LE) |
//! | `batch_data_hash`    | `batch_data_hash` ([u8;32]) |
//! | `compressed` (zstd)  | the DA payload the hash commits to |
//!
//! `rollup_id`, `prev_batch_hash`, `post_state_root`, `withdrawal_root`,
//! `da_mode` and the mirror pointers belong to anchoring/execution and are
//! NOT produced here (execution and anchor posting are stubbed — see
//! [`crate::stubs`]). The crates stay disjoint on purpose (standalone-crate
//! pattern, like `crates/bloch-tokens`).
//!
//! # Compression (§4)
//!
//! §4 defines `batch_data_hash = SHA3-256(zstd-compressed batch bytes)` and
//! the DA payload posted to Bloch is the compressed bytes, not the raw list.
//! This crate compresses the canonical tx-list with deterministic zstd
//! (level [`ZSTD_LEVEL`], single-threaded, no dictionary) and hashes the
//! COMPRESSED output, matching the L2V0 BATCH envelope. [`Batch::tx_list`]
//! retains the pre-compression canonical bytes (inspectable / re-compressible)
//! and [`Batch::compressed`] is the DA payload; the two are reversible
//! ([`decompress_batch`] round-trips `compressed` back to `tx_list`).
//!
//! Determinism note: the hash is taken over encoder output, so it is bound to
//! the pinned libzstd version (see `Cargo.toml`). zstd guarantees
//! DEcompression across versions, but exact compressed bytes only within an
//! encoder version — a production sequencer/verifier pair MUST pin the
//! encoder. The §4 "dictionary trained on EVM calldata" is a ratio
//! optimization layered on the same construction (embed + version a fixed
//! dictionary); it is deferred and does not change the hash definition.
//! The §4 256 KiB seal bound is measured on the raw canonical bytes here
//! (pre-compression), an intentionally conservative over-estimate of the
//! compressed DA size.

use crate::block::{BlockTx, L2Block};
use crate::hash::sha3_256;
use crate::params::{BATCH_CADENCE_SECS, BATCH_MAX_BLOCKS, BATCH_TARGET_BYTES};

/// zstd compression level for batch DA payloads (§4: "zstd -19").
pub const ZSTD_LEVEL: i32 = 19;

/// Deterministically zstd-compress the canonical tx-list bytes into the DA
/// payload the §4 `batch_data_hash` commits to. Single-threaded, no
/// dictionary, fixed level ([`ZSTD_LEVEL`]) ⇒ byte-identical output for
/// identical input under a fixed libzstd (see `Cargo.toml` pin).
pub fn compress_batch(tx_list: &[u8]) -> Vec<u8> {
    zstd::stream::encode_all(tx_list, ZSTD_LEVEL)
        .expect("in-memory zstd compression is infallible")
}

/// Inverse of [`compress_batch`]: recover the canonical tx-list bytes from a
/// zstd DA payload. Returns `Err` on a malformed/truncated frame (a verifier
/// rejecting bad DA).
pub fn decompress_batch(compressed: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    zstd::stream::decode_all(compressed)
}

/// A sealed batch — the fields the `L2V0` BATCH envelope commits to (see
/// module docs for the correspondence table).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    pub batch_index: u64,
    pub l2_block_first: u64,
    pub l2_block_last: u64,
    /// Canonical tx-list bytes (the DA payload): per block,
    /// `block_number u64 LE | tx_count u32 LE |` then per tx
    /// `len u32 LE | canonical tx bytes` (deposit = its canonical `0x7E`
    /// encoding, user tx = its raw signed bytes).
    pub tx_list: Vec<u8>,
    pub tx_count: u64,
    /// §4 `batch_data_hash`: SHA3-256 of the zstd-COMPRESSED DA payload
    /// ([`Batch::compressed`]), matching the L2V0 BATCH envelope.
    pub batch_data_hash: [u8; 32],
    /// The zstd DA payload the hash commits to (what gets posted to Bloch /
    /// the mirror). Deterministic output of [`compress_batch`] over
    /// [`Batch::tx_list`]; reversible via [`decompress_batch`].
    pub compressed: Vec<u8>,
}

/// Why a batch was sealed (surfaced for tests/telemetry).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealReason {
    /// Pending bytes reached [`BATCH_TARGET_BYTES`].
    Size,
    /// [`BATCH_MAX_BLOCKS`] blocks accumulated.
    BlockCount,
    /// [`BATCH_CADENCE_SECS`] elapsed since the window opened.
    Cadence,
}

/// Accumulates sealed L2 blocks and seals batches on the §4 bounds.
/// Deterministic: output is a pure function of the (block, timestamp) call
/// sequence. Time is caller-supplied (no clocks in this crate).
#[derive(Debug, Default)]
pub struct BatchSealer {
    next_index: u64,
    pending: Vec<u8>,
    pending_blocks: usize,
    pending_txs: u64,
    first_block: Option<u64>,
    last_block: u64,
    opened_at: Option<u64>,
}

/// Canonical per-block byte encoding folded into a batch (see [`Batch::tx_list`]).
pub fn canonical_block_bytes(block: &L2Block) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&block.number.to_le_bytes());
    out.extend_from_slice(&(block.txs.len() as u32).to_le_bytes());
    for tx in &block.txs {
        let bytes: Vec<u8> = match tx {
            BlockTx::Deposit(d) => d.encode(),
            BlockTx::User(u) => u.raw.clone(),
        };
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&bytes);
    }
    out
}

impl BatchSealer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pending_bytes(&self) -> usize {
        self.pending.len()
    }

    pub fn pending_blocks(&self) -> usize {
        self.pending_blocks
    }

    /// Fold a sealed L2 block into the open window (`now` = wall-clock
    /// seconds, caller-supplied). Returns a sealed batch (and why) if this
    /// push crossed the size or block-count bound.
    pub fn push_block(&mut self, block: &L2Block, now: u64) -> Option<(Batch, SealReason)> {
        if self.first_block.is_none() {
            self.first_block = Some(block.number);
            self.opened_at = Some(now);
        }
        self.last_block = block.number;
        self.pending_blocks += 1;
        self.pending_txs += block.txs.len() as u64;
        self.pending.extend_from_slice(&canonical_block_bytes(block));

        if self.pending.len() >= BATCH_TARGET_BYTES {
            return Some((self.seal(), SealReason::Size));
        }
        if self.pending_blocks >= BATCH_MAX_BLOCKS {
            return Some((self.seal(), SealReason::BlockCount));
        }
        None
    }

    /// Cadence check (§4: seal every 300 s regardless of size). Returns a
    /// batch iff the window is non-empty and 300 s have elapsed since it
    /// opened. Empty windows never seal (no empty batches).
    pub fn tick(&mut self, now: u64) -> Option<(Batch, SealReason)> {
        let opened = self.opened_at?;
        if now.saturating_sub(opened) >= BATCH_CADENCE_SECS && self.pending_blocks > 0 {
            return Some((self.seal(), SealReason::Cadence));
        }
        None
    }

    fn seal(&mut self) -> Batch {
        let tx_list = std::mem::take(&mut self.pending);
        // §4: DA payload is the zstd-compressed bytes; batch_data_hash commits
        // to those compressed bytes (not the raw list).
        let compressed = compress_batch(&tx_list);
        let batch = Batch {
            batch_index: self.next_index,
            l2_block_first: self.first_block.expect("non-empty window"),
            l2_block_last: self.last_block,
            batch_data_hash: sha3_256(&compressed),
            tx_count: self.pending_txs,
            compressed,
            tx_list,
        };
        self.next_index += 1;
        self.pending_blocks = 0;
        self.pending_txs = 0;
        self.first_block = None;
        self.opened_at = None;
        batch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mempool::TxSubmission;

    fn block_with_raw_tx(number: u64, raw_len: usize) -> L2Block {
        let tx = TxSubmission {
            hash: [number as u8; 32],
            sender: [1; 20],
            nonce: number,
            gas_limit: 21_000,
            max_fee_per_gas: 1_000,
            max_priority_fee_per_gas: 1,
            raw: vec![0xcc; raw_len],
        };
        L2Block {
            number,
            timestamp: number * 2,
            basefee: 1_000_000_000,
            gas_limit: 30_000_000,
            txs: vec![BlockTx::User(tx)],
        }
    }

    #[test]
    fn seals_on_size_bound() {
        let mut sealer = BatchSealer::new();
        // Each block ≈ 64 KiB of raw tx bytes → 4th push crosses 256 KiB.
        let mut sealed = None;
        for n in 0..10 {
            if let Some(s) = sealer.push_block(&block_with_raw_tx(n, 64 * 1024), 100 + n) {
                sealed = Some(s);
                break;
            }
        }
        let (batch, reason) = sealed.expect("must seal on size");
        assert_eq!(reason, SealReason::Size);
        assert_eq!(batch.batch_index, 0);
        assert_eq!(batch.l2_block_first, 0);
        assert_eq!(batch.l2_block_last, 3);
        assert!(batch.tx_list.len() >= BATCH_TARGET_BYTES);
        // §4: hash commits to the COMPRESSED DA payload, not the raw list.
        assert_eq!(batch.batch_data_hash, sha3_256(&batch.compressed));
        assert_ne!(
            batch.batch_data_hash,
            sha3_256(&batch.tx_list),
            "must not be the raw-bytes hash"
        );
        // Highly compressible fixture (repeated 0xcc) ⇒ payload shrinks.
        assert!(batch.compressed.len() < batch.tx_list.len());
        // Window reset.
        assert_eq!(sealer.pending_bytes(), 0);
    }

    #[test]
    fn seals_on_cadence_not_before() {
        let mut sealer = BatchSealer::new();
        assert!(sealer.push_block(&block_with_raw_tx(5, 10), 1_000).is_none());
        assert!(sealer.tick(1_000 + BATCH_CADENCE_SECS - 1).is_none());
        let (batch, reason) = sealer.tick(1_000 + BATCH_CADENCE_SECS).expect("cadence seal");
        assert_eq!(reason, SealReason::Cadence);
        assert_eq!(batch.l2_block_first, 5);
        assert_eq!(batch.l2_block_last, 5);
        assert_eq!(batch.tx_count, 1);
        // No empty batches: tick with nothing pending yields nothing.
        assert!(sealer.tick(10_000).is_none());
    }

    #[test]
    fn seals_on_block_count_bound() {
        let mut sealer = BatchSealer::new();
        let mut sealed = None;
        for n in 0..(BATCH_MAX_BLOCKS as u64 + 10) {
            if let Some(s) = sealer.push_block(&block_with_raw_tx(n, 1), n * 2) {
                sealed = Some(s);
                break;
            }
        }
        let (batch, reason) = sealed.expect("must seal on block count");
        assert_eq!(reason, SealReason::BlockCount);
        assert_eq!(
            (batch.l2_block_last - batch.l2_block_first + 1) as usize,
            BATCH_MAX_BLOCKS
        );
    }

    #[test]
    fn batch_index_increments_and_hash_is_deterministic() {
        let mut a = BatchSealer::new();
        let mut b = BatchSealer::new();
        let mk = |sealer: &mut BatchSealer, base: u64| -> Vec<Batch> {
            let mut out = Vec::new();
            for n in 0..3u64 {
                sealer.push_block(&block_with_raw_tx(base + n, 100), base + n);
            }
            out.extend(sealer.tick(base + 10_000).map(|(b, _)| b));
            out
        };
        let a1 = mk(&mut a, 0);
        let a2 = mk(&mut a, 100);
        let b1 = mk(&mut b, 0);
        assert_eq!(a1[0].batch_index, 0);
        assert_eq!(a2[0].batch_index, 1);
        // Same input blocks → byte-identical tx_list and hash.
        assert_eq!(a1[0].tx_list, b1[0].tx_list);
        assert_eq!(a1[0].batch_data_hash, b1[0].batch_data_hash);
        // Different blocks → different hash.
        assert_ne!(a1[0].batch_data_hash, a2[0].batch_data_hash);
    }

    #[test]
    fn canonical_bytes_include_deposits_in_0x7e_encoding() {
        use crate::deposit::{DepositId, DepositTx};
        let d = DepositTx::from_l1(
            &DepositId {
                l1_txid: [7; 32],
                vout: 1,
            },
            &[8; 32],
            [1; 20],
            [2; 20],
            10,
            10,
            21_000,
            vec![],
        );
        let block = L2Block {
            number: 9,
            timestamp: 18,
            basefee: 1,
            gas_limit: 30_000_000,
            txs: vec![BlockTx::Deposit(d.clone())],
        };
        let bytes = canonical_block_bytes(&block);
        // block_number(8) + tx_count(4) + len(4) + encoded deposit
        let enc = d.encode();
        assert_eq!(bytes.len(), 8 + 4 + 4 + enc.len());
        assert_eq!(&bytes[16..], &enc[..]);
        assert_eq!(bytes[16], 0x7E);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn compress_hash_decompress_round_trip() {
        // Mixed-entropy payload: incompressible prefix + compressible run, so
        // the round-trip exercises real zstd framing (not a degenerate case).
        let mut raw = Vec::new();
        for i in 0..4096u32 {
            raw.extend_from_slice(&i.to_le_bytes());
        }
        raw.extend(std::iter::repeat_n(0xab, 8192));

        let compressed = compress_batch(&raw);
        let hash = sha3_256(&compressed);

        // Deterministic: recompressing yields byte-identical output + hash.
        assert_eq!(compressed, compress_batch(&raw));
        assert_eq!(hash, sha3_256(&compress_batch(&raw)));

        // decompress(compress(x)) == x, and the hash is over the compressed
        // form (the §4 batch_data_hash), distinct from the raw-bytes hash.
        let restored = decompress_batch(&compressed).expect("valid zstd frame");
        assert_eq!(restored, raw);
        assert_ne!(hash, sha3_256(&raw));
    }

    #[test]
    fn seal_round_trips_through_da_payload() {
        // A sealed batch's compressed DA payload decompresses back to exactly
        // its canonical tx_list, and its batch_data_hash matches.
        let mut sealer = BatchSealer::new();
        for n in 0..3u64 {
            sealer.push_block(&block_with_raw_tx(n, 500), n);
        }
        let (batch, _) = sealer.tick(BATCH_CADENCE_SECS + 1).expect("cadence seal");
        assert_eq!(
            decompress_batch(&batch.compressed).expect("valid frame"),
            batch.tx_list
        );
        assert_eq!(batch.batch_data_hash, sha3_256(&batch.compressed));
    }

    #[test]
    fn decompress_rejects_garbage() {
        assert!(decompress_batch(b"not a zstd frame at all").is_err());
    }

    /// Golden vector — pins the exact §4 construction end to end so a
    /// regression (level change, dictionary drift, hashing the wrong bytes,
    /// or a libzstd bump) is caught. Bound to the pinned zstd = "=0.13.3"
    /// (bundles libzstd 1.5.7); a version bump that changes encoder output
    /// intentionally requires regenerating these constants.
    #[test]
    fn golden_vector_compressed_batch_hash() {
        // Fixed 256-byte canonical payload: bytes 0..=255.
        let raw: Vec<u8> = (0..=255u16).map(|b| b as u8).collect();

        let compressed = compress_batch(&raw);
        // Golden compressed bytes (zstd -19, no dictionary, single-threaded).
        assert_eq!(
            hex(&compressed),
            "28b52ffd0068010800\
             000102030405060708090a0b0c0d0e0f\
             101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f\
             303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f\
             505152535455565758595a5b5c5d5e5f\
             606162636465666768696a6b6c6d6e6f\
             707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f\
             909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf\
             b0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
             c0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
             d0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
             e0e1e2e3e4e5e6e7e8e9eaebecedeeef\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "golden compressed bytes drifted"
        );
        // Golden §4 batch_data_hash = SHA3-256(compressed).
        assert_eq!(
            hex(&sha3_256(&compressed)),
            "ece46917d336f874c2a4f074588e78b2b6d264300dbd2cc80e9c985b3f886598",
            "golden batch_data_hash drifted"
        );
        // Sanity: the frame decompresses back to the exact input.
        assert_eq!(decompress_batch(&compressed).unwrap(), raw);
    }
}
