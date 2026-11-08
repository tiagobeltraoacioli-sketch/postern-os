// SPDX-License-Identifier: MIT OR Apache-2.0
//! A multi-tenant BaaS **reference host**: N isolated kernels, one anchor.
//!
//! # REFERENCE SCAFFOLD — not a secure or deployed system
//!
//! This module takes the BaaS row of the Postern roadmap from "design" to a
//! **reference state kernel host**: N isolated [`crate::kernel::StateKernel`]
//! instances keyed by tenant id, each with its own chained root. **Tenants
//! share nothing** — no state, no log, no root chain; an op applied to tenant
//! A can never change tenant B's root (asserted in tests). **No multi-tenant
//! service is operated, offered, or planned to be offered by this code**;
//! operating one would be a regulated activity in many jurisdictions and stays
//! `blocked-on-infra/legal-review` in the spec.
//!
//! ## One batch anchor, one ordinary transaction
//!
//! Per batch, the host computes ONE commitment:
//! `SHAKE-256` over the **sorted** `(tenant_id, root)` pairs (canonical,
//! length-framed — see [`BaasHost::batch_commitment`]) and writes it to the
//! base as **ONE ordinary transaction** via the existing
//! [`crate::anchor::BlochAnchorClient`]. The base sees 32 bytes; it never
//! sees tenants, kernels, or state. The commitment proves only "a signer
//! asserted these roots" — it is NOT a Merkle tree, supports no per-tenant
//! inclusion proofs, and provides no data availability.
//!
//! ## One L2 builder among many, on an open rail
//!
//! The base is an ownerless, permissionless commons: **anyone** may anchor
//! their own L2, token layer, or finality gadget to it in exactly the same
//! way — see `docs/specs/BLOCH-PERMISSIONLESS-TOKENS-L2.md` (the open-rail
//! precedent: no reserved namespace, no consensus privilege, no gatekeeper;
//! Postern is one builder among many). The sibling `l2/bloch-l2-anchor` crate
//! shows the same anchoring idiom with a structured wire format (the `L2V0`
//! zero-value-output envelope); this reference deliberately does **not**
//! duplicate that wire format — it stays **commitment-only** (opaque 32
//! bytes), the lightest honest shape.

use std::collections::BTreeMap;

use crate::anchor::{AnchorCommitment, AnchorError, AnchorReceipt, BlochAnchorClient};
use crate::hash::{shake256_32, Hash32};
use crate::kernel::{KernelOp, StateKernel};

/// A 32-byte tenant identifier (opaque in this reference).
pub type TenantId = [u8; 32];

/// Domain for the multi-tenant batch commitment.
const BAAS_BATCH_DOMAIN: &str = "postern-ffg/baas-batch/v0";

/// Errors from the multi-tenant host (kernel-level rejections are returned
/// as the op's own error type, not this one).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BaasError {
    /// The tenant id is already registered on this host.
    TenantAlreadyExists(TenantId),
    /// The tenant id is not registered on this host.
    UnknownTenant(TenantId),
}

impl core::fmt::Display for BaasError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BaasError::TenantAlreadyExists(_) => write!(f, "tenant already exists"),
            BaasError::UnknownTenant(_) => write!(f, "unknown tenant"),
        }
    }
}

impl std::error::Error for BaasError {}

/// A multi-tenant reference host: isolated kernels keyed by tenant id.
///
/// Isolation is structural: each tenant's [`StateKernel`] owns its state, log,
/// and root chain outright, and the tenant id is bound into each kernel's
/// genesis root, so identical logs under different tenants still produce
/// different roots. The host itself holds no cross-tenant state beyond the map.
#[derive(Clone, Debug)]
pub struct BaasHost<S, O> {
    tenants: BTreeMap<TenantId, StateKernel<S, O>>,
}

impl<S, O: KernelOp<S>> BaasHost<S, O> {
    /// Create an empty host (no tenants).
    pub fn new() -> Self {
        Self { tenants: BTreeMap::new() }
    }

    /// Register a new tenant with its genesis state. The tenant id is bound
    /// into the kernel's genesis root.
    pub fn create_tenant(&mut self, tenant_id: TenantId, genesis_state: S) -> Result<(), BaasError> {
        if self.tenants.contains_key(&tenant_id) {
            return Err(BaasError::TenantAlreadyExists(tenant_id));
        }
        self.tenants.insert(tenant_id, StateKernel::new(&tenant_id, genesis_state));
        Ok(())
    }

    /// Apply one op to ONE tenant's kernel. Ops never cross tenants: this can
    /// only ever touch `tenant_id`'s kernel.
    pub fn apply(&mut self, tenant_id: &TenantId, op: O) -> Result<Result<(), O::Error>, BaasError> {
        let kernel = self.tenants.get_mut(tenant_id).ok_or(BaasError::UnknownTenant(*tenant_id))?;
        Ok(kernel.apply(op))
    }

    /// A tenant's kernel (state, log, root), if registered.
    pub fn tenant(&self, tenant_id: &TenantId) -> Option<&StateKernel<S, O>> {
        self.tenants.get(tenant_id)
    }

    /// A tenant's current root, if registered.
    pub fn tenant_root(&self, tenant_id: &TenantId) -> Option<Hash32> {
        self.tenants.get(tenant_id).map(StateKernel::root)
    }

    /// Number of registered tenants.
    pub fn tenant_count(&self) -> usize {
        self.tenants.len()
    }

    /// The batch commitment: `SHAKE-256` over the sorted `(tenant_id, root)`
    /// pairs (`BTreeMap` iteration is already tenant-id-sorted), framed as
    /// `count u64-LE || (tenant_id[32] || root[32])*` under a fixed domain.
    /// It changes iff some tenant's root changed (or a tenant was added or
    /// removed) — and it is NOT a Merkle root: no per-tenant inclusion proofs.
    pub fn batch_commitment(&self) -> Hash32 {
        let mut buf = Vec::with_capacity(8 + self.tenants.len() * 64);
        buf.extend_from_slice(&(self.tenants.len() as u64).to_le_bytes());
        for (tenant_id, kernel) in &self.tenants {
            buf.extend_from_slice(tenant_id);
            buf.extend_from_slice(&kernel.root());
        }
        shake256_32(BAAS_BATCH_DOMAIN, &buf)
    }

    /// Anchor the batch commitment for ALL tenants as ONE ordinary base
    /// transaction — exactly one [`AnchorReceipt`] regardless of N.
    ///
    /// The receipt proves only "a signer asserted this commitment": no tenant
    /// state exists on the base, no data availability, no settlement meaning,
    /// and the base itself is a `k=4`-forgeable mainnet-beta.
    pub fn anchor_batch(
        &self,
        client: &mut dyn BlochAnchorClient,
    ) -> Result<AnchorReceipt, AnchorError> {
        client.anchor_commitment(AnchorCommitment(self.batch_commitment()))
    }
}

impl<S, O: KernelOp<S>> Default for BaasHost<S, O> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anchor::InMemoryAnchorClient;
    use crate::checkpoint::BaseAnchorRef;
    use crate::rwa::{LegalGate, RwaOp, RwaState};

    fn id(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn register_op(asset: u8) -> RwaOp {
        RwaOp::RegisterAsset {
            asset_id: id(asset),
            issuer: id(100),
            supply: 50,
            legal_review: LegalGate::NotObtained,
        }
    }

    fn host_with_tenants(n: u8) -> BaasHost<RwaState, RwaOp> {
        let mut host = BaasHost::new();
        for t in 1..=n {
            host.create_tenant(id(t), RwaState::default()).unwrap();
        }
        host
    }

    #[test]
    fn ops_in_tenant_a_never_change_tenant_b_root() {
        let mut host = host_with_tenants(2);
        let a_before = host.tenant_root(&id(1)).unwrap();
        let b_before = host.tenant_root(&id(2)).unwrap();
        // Distinct genesis roots even over identical (empty) logs.
        assert_ne!(a_before, b_before);
        host.apply(&id(1), register_op(7)).unwrap().unwrap();
        assert_ne!(host.tenant_root(&id(1)).unwrap(), a_before);
        assert_eq!(host.tenant_root(&id(2)).unwrap(), b_before);
        // And tenant B's state is untouched too.
        assert_eq!(host.tenant(&id(2)).unwrap().state(), &RwaState::default());
    }

    #[test]
    fn batch_commitment_changes_iff_some_tenant_root_changed() {
        let mut host = host_with_tenants(3);
        let c0 = host.batch_commitment();
        // No root changed => commitment identical.
        assert_eq!(host.batch_commitment(), c0);
        // A rejected op changes no root => commitment identical.
        let rejected = host
            .apply(&id(2), RwaOp::Transfer { asset_id: id(9), from: id(1), to: id(2), amount: 1 })
            .unwrap();
        assert!(rejected.is_err());
        assert_eq!(host.batch_commitment(), c0);
        // One tenant root changed => commitment changed.
        host.apply(&id(2), register_op(7)).unwrap().unwrap();
        let c1 = host.batch_commitment();
        assert_ne!(c1, c0);
        // Adding a tenant also changes it.
        host.create_tenant(id(9), RwaState::default()).unwrap();
        assert_ne!(host.batch_commitment(), c1);
    }

    #[test]
    fn anchoring_n_tenants_produces_exactly_one_receipt() {
        let mut host = host_with_tenants(5);
        host.apply(&id(3), register_op(1)).unwrap().unwrap();
        let mut client = InMemoryAnchorClient::new();
        client.push_header(BaseAnchorRef {
            block_height: 42,
            block_hash: [1u8; 32],
            accumulated_work: 420,
        });
        let receipt = host.anchor_batch(&mut client).unwrap();
        assert_eq!(receipt.commitment.0, host.batch_commitment());
        assert_eq!(client.anchored().len(), 1);
    }

    #[test]
    fn unknown_and_duplicate_tenants_are_rejected() {
        let mut host = host_with_tenants(1);
        assert_eq!(
            host.create_tenant(id(1), RwaState::default()),
            Err(BaasError::TenantAlreadyExists(id(1)))
        );
        assert_eq!(
            host.apply(&id(9), register_op(1)).unwrap_err(),
            BaasError::UnknownTenant(id(9))
        );
    }
}
