// SPDX-License-Identifier: MIT OR Apache-2.0
//! # bloch-l2-evm — **SCAFFOLD, UNAUDITED, not a working L2.**
//!
//! Execution-layer state-transition scaffold for the Bloch EVM L2 described in
//! `docs/specs/BLOCH-L2-EVM-DESIGN.md` §1. It is a first-iteration, compiling
//! skeleton — real, tested code where feasible, honest labelled stubs where a
//! multi-month integration (Reth node, SP1 guest)
//! belongs. **Nothing here is audited, safe, or a working Layer-2.** No claim
//! of ethereum/tests or EEST conformance is made anywhere in this crate.
//!
//! > **The reorg gate (from the design, read first).** An L2 inherits its
//! > L1's finality. Bloch today is k=4 forgeable, 51%-attackable, unaudited —
//! > a Bloch reorg can unwind L2 state anchored to reorged blocks. Real value
//! > is gated on Bloch mainnet security (k=8 ramp, WAN hashrate, checkpoint
//! > finality) + a third-party audit + legal review. Everything below is
//! > **testnet / zero-value** until then.
//!
//! ## What is REAL and tested here
//! * [`chainspec::ChainSpec`] — the design's genesis knobs (chain_id 700771,
//!   30M gas limit, EIP-1559 elasticity 2 / denominator 250, block reward 0,
//!   COINBASE = fee-vault address) plus a tested EIP-1559 next-base-fee
//!   calculation with those knobs.
//! * [`scale`] — the exact u64-sats (8 decimals, L1 BLCH) ⇄ U256-wei
//!   (18 decimals, L2) helpers with `ATOM_SCALE = 10^10`.
//! * [`state::L2State`] — an account/state layer over revm's
//!   `CacheDB`/`InMemoryDB` with deposit-mint (credits **exactly** the
//!   escrow-derived wei; provenance is bridged BLCH **only** — the L2 never
//!   issues) and total-supply accounting.
//! * [`executor::execute_block`] — runs **UNMODIFIED** revm at
//!   `SpecId::CANCUN`, applies deposit mints at block start, routes the
//!   basefee to the `BaseFeeVault` and the priority fee to the
//!   `SequencerFeeVault` — bridged BLCH is **never burned**, so the L1 escrow
//!   always balances. Blob (type-3) transactions are rejected at the
//!   sequencer boundary exactly as on OP-Stack L2s.
//! * [`stateroot::compute_keccak_mpt_state_root`] — the **real** keccak-256
//!   hexary Merkle-Patricia state root (account trie + per-account storage
//!   tries, empty accounts excluded per EIP-161) via `alloy-trie`, wired into
//!   [`executor::ExecutionOutcome::state_root`]. Empty state → the canonical
//!   `EMPTY_ROOT_HASH`; deterministic and insertion-order independent.
//!
//! ## What is honestly STUBBED (`todo!()` / `unimplemented!()`, `// SCAFFOLD:`)
//! * the `eth_*` JSON-RPC surface, the txpool, and the Reth-SDK node
//!   embedding ([`stubs`]).
//! * the SP1 guest (riscv32im) build target and witness plumbing
//!   ([`stubs::sp1_guest`]).
//!
//! The L2 is an **owned Postern product** that anchors to the ownerless Bloch
//! base as ordinary transactions; the base gains no operator and needs no
//! consensus change. BLCH is never sold and the L2 never issues new BLCH.

// Design determinism rule (§1): integer-only arithmetic in the execution path.
#![deny(clippy::float_arithmetic)]
#![warn(missing_docs)]

pub mod chainspec;
pub mod executor;
pub mod scale;
pub mod state;
pub mod stateroot;
pub mod stubs;

pub use chainspec::ChainSpec;
pub use executor::{execute_block, BlockContext, BlockInput, ExecutionOutcome};
pub use scale::{sats_to_wei, wei_to_sats, ATOM_SCALE};
pub use state::{DepositMint, DepositProvenance, L2Account, L2State};
pub use stateroot::compute_keccak_mpt_state_root;

/// The exact revm version this scaffold is pinned to (also pinned as `=41.0.0`
/// in `Cargo.toml` and recorded in `README.md`). Any bump is a documented
/// program upgrade per the design's determinism contract.
pub const REVM_PIN: &str = "41.0.0";
