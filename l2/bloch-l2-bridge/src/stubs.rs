// SPDX-License-Identifier: MIT OR Apache-2.0
//! Honest stubs — the large integrations this scaffold does NOT contain.
//!
//! Every item here is a `// SCAFFOLD:` marker with just enough type
//! surface to name the missing component. Nothing in this module is
//! callable into useful behavior; every method returns
//! [`NotImplemented`]. This is deliberate: claiming any of these worked
//! would violate the project's honesty rule.

/// The single error every stub returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotImplemented(pub &'static str);

impl core::fmt::Display for NotImplemented {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SCAFFOLD: {} is not implemented — this is not a working L2", self.0)
    }
}

impl std::error::Error for NotImplemented {}

// SCAFFOLD: vault keyholder / release-agent logic (§5 release checklist:
// FRI-verify proof, own-node anchor depth, Merkle proof, nullifier log,
// reorg-freeze, proof-of-reserves, rate limit, then quorum co-sign).
// The v1 L1 vault is CUSTODY, full stop — a disclosed operator-held key
// set, NOT cryptographic M-of-N (no production threshold ML-DSA exists).
// Nothing here holds keys or signs anything.
#[derive(Debug, Default)]
pub struct ReleaseAgent;

impl ReleaseAgent {
    /// SCAFFOLD: would run the seven-item §5 checklist before co-signing.
    pub fn evaluate_release(
        &self,
        _withdrawal: &crate::withdrawal::WithdrawalMessage,
        _proof_branch: &[[u8; 32]; crate::merkle::TREE_DEPTH],
    ) -> Result<(), NotImplemented> {
        Err(NotImplemented("ReleaseAgent::evaluate_release"))
    }
}

// SCAFFOLD: the L1 deposit watcher — would reuse the replay/reorg
// algorithm of crates/bloch-tokens (getblockcount / getblockhash /
// getblockbyheight, height->hash journal, rewind-on-mismatch) verbatim
// over the node JSON-RPC, scanning for vault payments + L2D0 envelopes.
// No RPC client exists in this crate.
#[derive(Debug, Default)]
pub struct L1DepositWatcher;

impl L1DepositWatcher {
    /// SCAFFOLD: would sync the chain and emit `DepositEvent`s at depth
    /// >= K(amount).
    pub fn poll(&mut self) -> Result<Vec<crate::status::DepositEvent>, NotImplemented> {
        Err(NotImplemented("L1DepositWatcher::poll"))
    }
}

// SCAFFOLD: FederatedGateway / outside assets (wBTC, wUSDT, wETH) are
// EXPLICITLY OUT OF SCOPE for v1 — the bridge does ONLY WBLCH, per
// contracts/wblch/WBLCH.sol's scope note and §5(B). The type exists only
// so the exclusion is visible in the API surface.
#[derive(Debug, Default)]
pub struct FederatedGatewayOutOfScope;

impl FederatedGatewayOutOfScope {
    pub fn mint(&self) -> Result<(), NotImplemented> {
        Err(NotImplemented(
            "FederatedGateway (outside assets) — out of scope: v1 is WBLCH only",
        ))
    }
}

// SCAFFOLD: contract compilation / deployment / any chain interaction.
// The harness module only VALIDATES a JSON description; it never invokes
// solc, never crafts a transaction, never connects anywhere.
#[derive(Debug, Default)]
pub struct Deployer;

impl Deployer {
    pub fn deploy(&self, _config: &crate::harness::DeployConfig) -> Result<(), NotImplemented> {
        Err(NotImplemented("Deployer::deploy — config-only harness, no live deploys"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stubs_refuse_honestly() {
        // Every stub returns NotImplemented instead of pretending.
        assert!(L1DepositWatcher.poll().is_err());
        assert!(FederatedGatewayOutOfScope.mint().is_err());
        let msg = crate::withdrawal::WithdrawalMessage {
            nonce: 0,
            l2_sender: [0; 20],
            l1_recipient: [0; 20],
            amount_atoms: 0,
            epoch_number: 0,
        };
        let branch = [[0u8; 32]; crate::merkle::TREE_DEPTH];
        let err = ReleaseAgent.evaluate_release(&msg, &branch).unwrap_err();
        assert!(err.to_string().contains("SCAFFOLD"));
        assert!(err.to_string().contains("not a working L2"));
    }
}
