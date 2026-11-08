// SPDX-License-Identifier: MIT OR Apache-2.0
//! A generic deterministic state kernel for the OWNED layer.
//!
//! # REFERENCE SCAFFOLD — not a secure or deployed system
//!
//! This is the whole trick of the owned layer, in one type: **state lives ONLY
//! here, in the owned layer.** The ownerless Bloch-SIS-PoW base never sees a
//! kernel's state, ops, or even that a kernel exists — only opaque 32-byte
//! roots land on the base, written as **ordinary transactions** via the
//! existing [`crate::anchor::BlochAnchorClient`]. If the operator (Postern)
//! vanished, the base would continue exactly as before; the kernels merely
//! stop anchoring (that property is asserted in code — see the
//! `postern_vanishes_*` test in `lib.rs`).
//!
//! A kernel is:
//!
//! - an **append-only operation log**,
//! - a **pure** transition `apply(state, op) -> Result<state>` (no I/O, no
//!   clock, no randomness — same log in, same state out), and
//! - a **chained state commitment**:
//!   `root_{i+1} = SHAKE-256(prev_root || canonical op encoding)`.
//!   Replaying the same op log from the same genesis always yields the same
//!   root; reordering or tampering with any op yields a different root.
//!
//! ## The chained root is NOT a Merkle tree — no proof claims
//!
//! **Explicitly:** the chained commitment root is a plain hash chain over the
//! op log. It is **NOT** a Merkle tree and supports **no inclusion proofs**,
//! no exclusion proofs, no fraud proofs, and no validity proofs. Nothing about
//! a root can be *proven* to a third party except by replaying the entire log.
//! No proof claim of any kind is made here. Likewise there is **no data
//! availability**: the base stores 32 bytes, not the log — if the operator
//! withholds the log, the root is unverifiable. An anchored root proves only
//! "a signer asserted this root" — never that the state behind it is correct,
//! complete, or backed by anything.

use crate::hash::{shake256_32, Hash32};

/// Domain for a kernel's genesis root.
const KERNEL_GENESIS_DOMAIN: &str = "postern-ffg/kernel-genesis/v0";
/// Domain for each chained-root step.
const KERNEL_CHAIN_DOMAIN: &str = "postern-ffg/kernel-chain/v0";

/// An operation a deterministic kernel can apply.
///
/// Implementations MUST keep [`KernelOp::apply`] **pure**: a function of the
/// given state and the op's own fields only — no I/O, no clock, no randomness,
/// no global state. That purity is what makes replay determinism (and thus the
/// chained root) meaningful. [`KernelOp::canonical_bytes`] must be a
/// deterministic, unambiguous encoding of the op (two ops encode equal iff
/// they are the same op).
pub trait KernelOp<S>: Sized {
    /// Rejection type for invalid ops.
    type Error;

    /// Pure transition: produce the next state or reject the op. MUST NOT
    /// mutate anything; rejected ops leave the kernel (state, log, root)
    /// entirely untouched.
    fn apply(&self, state: &S) -> Result<S, Self::Error>;

    /// Canonical, deterministic byte encoding of this op — the bytes that are
    /// folded into the chained commitment root.
    fn canonical_bytes(&self) -> Vec<u8>;
}

/// A deterministic state kernel: append-only op log, pure `apply`, chained
/// SHAKE-256 commitment root. See the module docs for the honest limits (the
/// root is a hash chain, NOT a Merkle tree — no proofs of any kind).
#[derive(Clone, Debug)]
pub struct StateKernel<S, O> {
    state: S,
    log: Vec<O>,
    root: Hash32,
}

impl<S, O: KernelOp<S>> StateKernel<S, O> {
    /// Create a kernel at genesis. The `kernel_id` names this kernel instance
    /// (e.g. a tenant id or product name) and is bound into the genesis root,
    /// so two kernels with different ids never share a root chain even over
    /// identical logs.
    pub fn new(kernel_id: &[u8], genesis_state: S) -> Self {
        Self {
            state: genesis_state,
            log: Vec::new(),
            root: shake256_32(KERNEL_GENESIS_DOMAIN, kernel_id),
        }
    }

    /// Apply one op: run the pure transition, and on success append the op to
    /// the log and advance the chained root
    /// (`root = SHAKE-256(prev_root || canonical op encoding)`, with the op
    /// encoding length-prefixed so the fold is unambiguous). A rejected op
    /// changes nothing.
    pub fn apply(&mut self, op: O) -> Result<(), O::Error> {
        let next_state = op.apply(&self.state)?;
        let op_bytes = op.canonical_bytes();
        let mut buf = Vec::with_capacity(32 + 8 + op_bytes.len());
        buf.extend_from_slice(&self.root);
        buf.extend_from_slice(&(op_bytes.len() as u64).to_le_bytes());
        buf.extend_from_slice(&op_bytes);
        self.root = shake256_32(KERNEL_CHAIN_DOMAIN, &buf);
        self.state = next_state;
        self.log.push(op);
        Ok(())
    }

    /// Rebuild a kernel by replaying an op log from genesis. Determinism is
    /// the point: the same `(kernel_id, genesis_state, ops)` always yields the
    /// same final root; any reordering or tampering yields a different one.
    pub fn replay(
        kernel_id: &[u8],
        genesis_state: S,
        ops: impl IntoIterator<Item = O>,
    ) -> Result<Self, O::Error> {
        let mut kernel = Self::new(kernel_id, genesis_state);
        for op in ops {
            kernel.apply(op)?;
        }
        Ok(kernel)
    }

    /// The current owned-layer state. Lives ONLY here; the base never sees it.
    pub fn state(&self) -> &S {
        &self.state
    }

    /// The append-only op log applied so far.
    pub fn log(&self) -> &[O] {
        &self.log
    }

    /// The current chained commitment root. 32 opaque bytes — this is ALL the
    /// base ever sees of a kernel, and only if the operator chooses to anchor
    /// it. NOT a Merkle root; supports no inclusion proofs.
    pub fn root(&self) -> Hash32 {
        self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny test kernel: a saturating counter that rejects overflow.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Add(u64);

    impl KernelOp<u64> for Add {
        type Error = &'static str;

        fn apply(&self, state: &u64) -> Result<u64, Self::Error> {
            state.checked_add(self.0).ok_or("counter overflow")
        }

        fn canonical_bytes(&self) -> Vec<u8> {
            self.0.to_le_bytes().to_vec()
        }
    }

    #[test]
    fn replay_same_log_yields_identical_root() {
        let ops = vec![Add(1), Add(2), Add(3)];
        let a = StateKernel::replay(b"test", 0u64, ops.clone()).unwrap();
        let b = StateKernel::replay(b"test", 0u64, ops).unwrap();
        assert_eq!(a.root(), b.root());
        assert_eq!(a.state(), b.state());
        assert_eq!(*a.state(), 6);
    }

    #[test]
    fn reordering_ops_changes_the_root_even_when_state_agrees() {
        // Addition commutes, so the *state* agrees — the root must still
        // differ because it commits to the ordered log, not the state.
        let a = StateKernel::replay(b"test", 0u64, vec![Add(1), Add(2)]).unwrap();
        let b = StateKernel::replay(b"test", 0u64, vec![Add(2), Add(1)]).unwrap();
        assert_eq!(a.state(), b.state());
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn tampering_one_op_changes_the_root() {
        let a = StateKernel::replay(b"test", 0u64, vec![Add(1), Add(2), Add(3)]).unwrap();
        let b = StateKernel::replay(b"test", 0u64, vec![Add(1), Add(99), Add(3)]).unwrap();
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn kernel_id_is_bound_into_the_chain() {
        let a = StateKernel::replay(b"tenant-a", 0u64, vec![Add(1)]).unwrap();
        let b = StateKernel::replay(b"tenant-b", 0u64, vec![Add(1)]).unwrap();
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn rejected_op_leaves_state_log_and_root_untouched() {
        let mut k = StateKernel::new(b"test", u64::MAX);
        let root_before = k.root();
        assert!(k.apply(Add(1)).is_err());
        assert_eq!(k.root(), root_before);
        assert_eq!(k.log().len(), 0);
        assert_eq!(*k.state(), u64::MAX);
    }
}
