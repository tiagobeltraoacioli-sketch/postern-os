//! Honest stubs for every genuinely large integration this scaffold does NOT
//! deliver. Each function is `// SCAFFOLD:`-marked and `todo!()`s with a
//! pointer to what the real implementation is.
//!
//! Real-implementation template: `crates/coherence-prover` in the Bloch node
//! repo — the SP1 `program/` (guest) + `script/` (host) + `service/` (GPU
//! HTTP prover) triple, deployed per `deploy/sp1-prover/`. The L2 prover is
//! designed (`BLOCH-L2-EVM-DESIGN.md` §3) as the same triple with the RSP
//! revm-in-SP1 pattern inside the guest.
//!
//! None of these can be feature-flag-enabled into working: they require the
//! SP1 toolchain (`sp1up`, `cargo prove build --docker` for reproducible
//! riscv32im guest ELFs), revm pinned to `SpecId::CANCUN`, alloy-trie MPT
//! verification, and an audited witness generator. Multi-month work; claimed
//! nowhere as done.

#![allow(unreachable_code)]

use crate::hash::Hash32;
use crate::public_values::BatchPublicValues;
use crate::witness::ExecutionWitness;

/// A real SP1 FRI proof blob (raw core/compressed STARK — Groth16/Plonk curve
/// wrappers are forbidden by the repo's post-quantum rule, COHERENCE-C1 §3).
///
/// SCAFFOLD: type alias only; no SP1 types are linked in this crate.
pub type FriProofBytes = alloc::vec::Vec<u8>;

/// Error placeholder for the unimplemented SP1 integrations.
///
/// SCAFFOLD: the real host code returns sp1-sdk error types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotImplemented;

impl core::fmt::Display for NotImplemented {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SCAFFOLD: SP1 integration not implemented")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NotImplemented {}

/// SCAFFOLD: the real SP1 guest program entry.
///
/// Real shape (design §3, RSP pattern; analog of `coherence-prover/program`):
/// `sp1_zkvm::entrypoint!` main that reads the witness via `sp1_zkvm::io`,
/// (a) verifies keccak-256 MPT witness proofs against `prev_state_root`,
/// (b) applies deposit mints, (c) executes every tx through pinned revm
/// (SpecId::CANCUN, sp1-patches accelerated keccak/k256/sha256),
/// (d) accumulates the withdrawal SMT root, (e) computes the new MPT root,
/// (f) `sp1_zkvm::io::commit(&BatchPublicValues)`.
/// Built for riscv32im with `cargo prove build --docker` (reproducible ELF).
pub fn guest_main_riscv32im() -> ! {
    // SCAFFOLD: requires the SP1 toolchain + revm + alloy-trie in a separate
    // `program/` crate compiled to riscv32im — cannot live in this host crate.
    todo!("SP1 guest program: see crates/coherence-prover/program for the pattern")
}

/// SCAFFOLD: verify MPT state-witness proofs against `prev_state_root`.
///
/// Real shape: alloy-trie keccak-256 hexary MPT proof verification for every
/// touched account/storage slot; reject the batch if any node fails its
/// keccak path. The placeholder STF's flat-commitment check in
/// [`crate::stf::stf`] stands in for this in the scaffold pipeline.
pub fn verify_mpt_witness(_witness: &ExecutionWitness, _pre_state_root: &Hash32) -> bool {
    // SCAFFOLD:
    todo!("keccak-256 MPT witness verification (alloy-trie) — not implemented")
}

/// SCAFFOLD: re-execute the batch with revm inside the guest.
///
/// Real shape: unmodified revm pinned to one exact version and
/// `SpecId::CANCUN`, RSP-style stateless DB backed by the verified witness,
/// deposit system-txs (type 0x7E) first, EIP-1559 fees to the vault
/// predeploys. The placeholder account-map STF is NOT this.
pub fn revm_execute_batch(_witness: &ExecutionWitness) -> Result<BatchPublicValues, NotImplemented> {
    // SCAFFOLD:
    todo!("revm-in-guest re-execution — not implemented")
}

/// SCAFFOLD: the host/prover side ("script" + "service" of the triple).
///
/// Real shape: `sp1_sdk::ProverClient` loading the pinned guest ELF, proving
/// in core (or, pending a COHERENCE-C1 §3 amendment, compressed) FRI mode —
/// NEVER `.groth16()`/`.plonk()` — exposed as the bearer-auth GPU service
/// (`POST /prove-batch`, `GET /jobs/{id}`, `POST /verify`, `GET /vkey`)
/// extending `coherence-prover/service` on the existing L40S deploy.
pub fn sp1_prove_batch(_witness: &ExecutionWitness) -> Result<FriProofBytes, NotImplemented> {
    // SCAFFOLD:
    todo!("SP1 host proving (sp1-sdk, FRI core proofs) — not implemented")
}

/// SCAFFOLD: verify a real FRI proof against pinned vkey + public values.
///
/// Real shape: `sp1_sdk` verification against a vkey recomputed from source
/// (reproducible `cargo prove build --docker` ELF), with the
/// `{vkey_hash → activation batch_index}` pin set from the repo, consumed by
/// the open `l2-verifier` binary. The [`crate::mock::MockProver`] hash check
/// is NOT this and proves nothing.
pub fn sp1_verify_fri(
    _proof: &FriProofBytes,
    _publics: &BatchPublicValues,
    _vkey_hash: &Hash32,
) -> bool {
    // SCAFFOLD:
    todo!("SP1 FRI verification + vkey pinning — not implemented")
}
