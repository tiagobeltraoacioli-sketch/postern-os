// SPDX-License-Identifier: MIT OR Apache-2.0
//! # bloch-l2-sequencer — SCAFFOLD, UNAUDITED, not a working L2
//!
//! Pure, deterministic ordering/fee logic for the (designed, unbuilt) Bloch
//! EVM L2 sequencer — a **single disclosed operator** product per
//! `docs/specs/BLOCH-L2-EVM-DESIGN.md` §4. This crate contains **no network,
//! no EVM execution, no proving, no anchoring, no DA** — those are honestly
//! stubbed (see [`stubs`]). It DOES now carry real disclosed-operator receipt
//! signing (post-quantum ML-DSA-65 behind a trait; see [`receipt`]). Nothing here is audited
//! or safe; the L2 it belongs to is DESIGN ONLY and gated to testnet / zero
//! value.
//!
//! Real + tested (all pure functions):
//! * [`fees`] — EIP-1559 basefee update with the §1 parameters
//!   (initial 1 gwei, gas limit 30M, elasticity 2, denominator 250, 2 s blocks)
//!   and EIP-1559 effective-tip semantics.
//! * [`mempool`] — §4 two-lane FIFO ordering (priority lane drained before the
//!   standard lane, strict FIFO by arrival sequence within a lane) plus the
//!   published admission policy (nonce-gap ≤ 16, per-sender cap 64, ≥10%
//!   replacement bump, tx ≤ 128 KiB, min-base-fee floor, and the type-admission
//!   boundary below).
//! * [`txtype`] — EIP-2718 tx-type classification of a raw envelope and the
//!   §1 sequencer-boundary rule: **type-3 (EIP-4844) blob txs are rejected**
//!   (as on OP-Stack L2s), and type-`0x7E` deposits are system-only.
//! * [`deposit`] — OP-style type-`0x7E` deposit transaction (§5) with
//!   `source_hash = keccak256(deposit_id ‖ l1_block_hash)` and a canonical,
//!   strictly-decoded byte encoding.
//! * [`block`] — block assembly: deposits execute FIRST in a block and cannot
//!   be dropped once derived.
//! * [`batch`] — batch sealing on the §4 bounds (300 s cadence OR 256 KiB,
//!   whichever first), producing the fields the `L2V0` BATCH envelope commits
//!   to (see [`batch`] docs for the cross-crate correspondence with
//!   `bloch-l2-anchor` — documentation only, no code dependency).
//! * [`receipt`] — the signed inclusion-receipt (§4): a REAL post-quantum
//!   ML-DSA-65 (FIPS 204) disclosed-sequencer-key signature over the
//!   domain-separated payload, behind the `ReceiptSigScheme` trait (the SAME
//!   PQ primitive the BFT/FFG crates use — NO BLS, NO classical curve);
//!   sign/verify round-trips and any field mutation is rejected. UNAUDITED
//!   integration of the UNAUDITED (pre-1.0) RustCrypto `ml-dsa` primitive.
//! * [`hash`] — self-contained Keccak-f[1600] (keccak-256 / SHA3-256), zero-dep;
//!   checked against known vectors.

pub mod batch;
pub mod block;
pub mod deposit;
pub mod fees;
pub mod hash;
pub mod mempool;
pub mod params;
pub mod receipt;
pub mod stubs;
pub mod txtype;
