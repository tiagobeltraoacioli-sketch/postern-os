//! # bloch-l2-prover — SP1-guest RSP-pattern SKELETON
//!
//! **SCAFFOLD, UNAUDITED, not a working L2, NOT a zk prover — the
//! [`MockProver`](mock::MockProver) proves nothing cryptographically.**
//!
//! This crate is the *shape* of the Bloch EVM L2 proving pipeline described in
//! `docs/specs/BLOCH-L2-EVM-DESIGN.md` §3 (the zk-validity rollup on SP1,
//! following Succinct's RSP pattern), with the genuinely large integrations
//! honestly stubbed:
//!
//! ## Real and tested here
//! * [`public_values::BatchPublicValues`] — the guest-committed public values
//!   struct exactly as the design §3 specifies, with a canonical fixed-width
//!   little-endian byte encoding, decoding, and a SHAKE-256 domain-separated
//!   commitment hash (the `prev_batch_hash` chain link).
//! * [`witness::ExecutionWitness`] — the RSP-shaped host→guest private input
//!   (pre-state root, raw txs, state-witness nodes, bytecodes, ≤256 ancestor
//!   headers, deposits) with a canonical length-prefixed ser/de round-trip.
//! * [`stf::stf`] — the guest entry point signature, wired to a deliberately
//!   **SIMPLIFIED account-map re-execution** (documented placeholder: NOT
//!   revm, NOT MPT-verified, NOT Ethereum semantics) so the whole pipeline is
//!   exercisable end-to-end in tests.
//! * [`mock::MockProver`] — plumbing that re-runs the STF and binds the
//!   public values by hash. **Zero soundness**: anyone can forge a
//!   `MockProof`; it only checks that two parties agree on bytes.
//!
//! ## Honestly stubbed (`// SCAFFOLD:` markers, [`sp1_stub`])
//! * The real SP1 program/script/service triple (pattern:
//!   `crates/coherence-prover` in the Bloch node repo).
//! * riscv32im guest builds (`cargo prove build --docker`).
//! * keccak-256 MPT witness verification against `prev_state_root`.
//! * revm-in-guest re-execution at a pinned hardfork.
//! * FRI proof handling (raw SP1 core/compressed STARK, never Groth16/Plonk —
//!   the repo's post-quantum rule).
//! * vkey pinning / upgrade envelopes.
//!
//! ## Determinism contract (from the design, enforced where possible)
//! * `#![deny(clippy::float_arithmetic)]` (via `[lints]`) — integer-only.
//! * `BTreeMap` only in state-affecting paths (deterministic iteration).
//! * `no_std` + `alloc` capable (`--no-default-features`), the shape an SP1
//!   guest requires.
//!
//! Never interpret anything in this crate as a "proof of validity": the mock
//! proof is a hash equality check with **no cryptographic soundness**.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod hash;
pub mod mock;
pub mod public_values;
pub mod sp1_stub;
pub mod stf;
pub mod witness;

pub use mock::{MockProof, MockProver, MockVerifyError};
pub use public_values::{BatchPublicValues, DecodeError};
pub use stf::{stf, StfError};
pub use witness::{
    AncestorHeader, BatchContext, DepositEvent, ExecutionWitness, WitnessDecodeError,
};
