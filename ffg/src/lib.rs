// SPDX-License-Identifier: MIT OR Apache-2.0
//! # Postern FFG — permissioned-notary module (design scaffold)
//!
//! ## ⚠️ SCAFFOLD — not a secure or deployed system
//!
//! This crate is a **conceptual design scaffold**. **Nothing here is built,
//! audited, attested, secure, offered, or operational.** It contains no security
//! claim of any kind. It exists to give the design in
//! `Postern-FFG-RWA-Design.md` a compiling type skeleton — not a working
//! finality/settlement system. Do **not** settle, custody, or rely on anything
//! of value using this code.
//!
//! ## What this is
//!
//! Type-level scaffold for **Layer 2** of the Postern stack: a **permissioned,
//! Postern-OPERATED notary checkpoint** service that *anchors to* the ownerless
//! Bloch-SIS-PoW base. It reads the base (headers, accumulated work, canonical
//! tip) and writes certificate hashes back onto the base as **ordinary
//! transactions/commitments**. It does not fork, modify, or become a consensus
//! dependency of the base. RWA/settlement state lives **only** in this owned
//! layer; the base has no knowledge of any RWA.
//!
//! ## Binding rails (carry these wherever this crate's concepts appear)
//!
//! - **Conceptual scaffold, unaudited — nothing built, secure, attested, or
//!   deployed.** No security claim anywhere.
//! - **Finality is only as strong as the base beneath it.** The base is a
//!   mainnet-beta: `k=4` **trivially-forgeable** and **`51%`-attackable**,
//!   **unaudited**. A notary checkpoint over a forgeable base gives **no real
//!   settlement guarantee today.** Irreversibility here is a Postern promise,
//!   not a protocol property.
//! - **Trust model = "trust Postern."** This is a **centralized, permissioned,
//!   Postern-operated** service. It is **NOT** BFT, **NOT** decentralized,
//!   **NOT** trustless, **NOT** permissionless. A `14-of-21` quorum is `14-of-21`
//!   facets of one actor; slashing/bonding would be self-referential and are
//!   dropped from all security claims this phase (no economic security).
//! - **The finality primitive is ML-DSA-65 (FIPS 204), post-quantum — NOT BLS.**
//!   DKG/threshold-BLS aggregation was deliberately shelved this phase to stay
//!   Shor-safe. The lattice verify goes through a **trait**
//!   ([`signature::MlDsa65Verifier`]) whose **DEFAULT** impl is now
//!   [`signature::RustCryptoMlDsa65Verifier`] — a **real FIPS-204 verify** via
//!   the **unaudited, pre-1.0** RustCrypto `ml-dsa` crate (the `real-mldsa65`
//!   feature is ON by default), so a default `cargo test` accepts genuine
//!   ML-DSA-65 signatures and rejects tampered ones. The
//!   [`signature::NonVerifyingStubVerifier`] (which **verifies nothing**) is the
//!   `--no-default-features` zero-dependency offline stand-in. Real crypto is
//!   **NOT** a claim that this system is secure, operational, audited, or
//!   deployed — every rail on this page still holds.
//! - **The coin (BLCH) is worthless and is not a security.** No sale, no
//!   listing, no price. Nothing here gives BLCH value or routes value into it.
//!   BLCH is the **neutral native gas** of the ownerless base (a protocol fact,
//!   "like ETH" only as a mechanic — never a Postern pitch); paying base gas to
//!   anchor is operational spend only.
//! - **RWA = a separate, regulated, legally-gated instrument.** Tokenizing a
//!   real-world asset creates a regulated financial instrument in most
//!   jurisdictions and operating this layer likely makes Postern a regulated
//!   intermediary. **Independent legal review of BOTH is a HARD GATE before
//!   anything is built or offered.** This is not legal, financial, or investment
//!   advice, and not an offer or solicitation.
//! - **Postern owns only its own instance.** The base is everyone's ownerless
//!   commons; **anyone may build their own finality gadget or RWA rails on it,
//!   including trust-minimized / decentralized alternatives.** Postern claims no
//!   reserved namespace, no consensus privilege, no exclusivity.
//! - **Naming:** never the mark "BABA YAGA" (use *Yagabona* / *Izbushka* if a
//!   scheduler is referenced); the community edition is never called "Postern
//!   OS" (that name is the Nix-built family only).
//!
//! > **Honest one-liner (design `§0`, safety review `§6`):** *"Postern FFG is a
//! > design. It provides no finality guarantee: the base beneath it is forgeable
//! > (`k=4` / `51%`-attackable, unaudited), and its committee is entirely
//! > operated by Postern — so it is a centralized attestation, not Byzantine
//! > fault tolerance. Do not settle anything of value on it."*
//!
//! ## Module map
//!
//! - [`signature`] — the ML-DSA-65 operator-signature interfaces: verify
//!   ([`signature::MlDsa65Verifier`], stubbed by default) and sign
//!   ([`signature::CheckpointSigner`], stub emits junk by default).
//! - [`operator`] — the [`operator::PermissionedOperatorSet`] and era rotation.
//! - [`checkpoint`] — the [`checkpoint::PosternNotaryCheckpoint`] type.
//! - [`anchor`] — the light [`anchor::BlochAnchorClient`] interface to the base
//!   (the in-memory mock includes deterministic reorg simulation).
//! - [`shake`] / [`hash`] — in-crate SHAKE-256 (FIPS 202): **unaudited
//!   reimplementations, reference only**, so the crate pulls in no hashing crate
//!   (its only default dependency is the ML-DSA-65 signature primitive).
//! - [`certificate`] — canonical certificate encoding + its SHAKE-256-32 hash
//!   (the anchored commitment).
//! - [`notary`] — the in-process reference pipeline: read the mock base, sign,
//!   check quorum, anchor, promote, observe reorgs. Nothing operational.
//! - [`follower`] — independent re-verification of anchored certificates; no
//!   privileged reader.
//! - [`kernel`] — the generic deterministic state kernel (owned-layer state,
//!   append-only op log, chained SHAKE-256 root; NOT a Merkle tree, no proofs).
//! - [`rwa`] — the RWA asset-registry reference kernel, with the legal HARD
//!   GATE encoded in the type system ([`rwa::LegalGate`] — only `NotObtained`
//!   is constructible; no offer/sell/list op exists).
//! - [`baas`] — the multi-tenant reference host (N isolated kernels, ONE batch
//!   anchor as ONE ordinary base tx).
//!
//! The `kernel`/`rwa`/`baas` trio are **reference state kernels** — the
//! spec is `docs/specs/POSTERN-FFG-RWA-BAAS-REFERENCE.md`. State lives ONLY in
//! this owned layer; the base sees nothing but opaque 32-byte roots written as
//! ordinary transactions. Nothing is operational or offered; independent legal
//! review remains a HARD GATE that no code can satisfy.
//!
//! Licensed under **MIT OR Apache-2.0**.

// Scaffold-appropriate lint posture: keep the design honest and warnings loud,
// but do not block the build on missing docs while the design is in flux.
#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod anchor;
pub mod baas;
pub mod certificate;
pub mod checkpoint;
pub mod follower;
pub mod hash;
pub mod kernel;
pub mod notary;
pub mod operator;
pub mod rwa;
pub mod shake;
pub mod signature;

// Convenience re-exports of the primary design types.
pub use anchor::{AnchorCommitment, AnchorError, AnchorReceipt, BlochAnchorClient, InMemoryAnchorClient};
pub use certificate::{CheckpointCertificate, CERTIFICATE_DOMAIN_TAG};
pub use baas::{BaasError, BaasHost, TenantId};
pub use hash::{shake256_32, shake256_list, Hash32};
pub use kernel::{KernelOp, StateKernel};
pub use rwa::{
    anchor_rwa_root, new_rwa_kernel, AccountId, AssetId, AssetRecord, LegalGate, RwaError,
    RwaKernel, RwaOp, RwaState,
};
pub use checkpoint::{
    BaseAnchorRef, CheckpointError, ConfidenceLevel, HeightRange, OperatorSignature,
    PosternNotaryCheckpoint, QuorumOutcome,
};
pub use follower::{reverify_anchored_certificate, FollowerError};
pub use notary::{NotarizedRecord, NotaryError, NotaryEvent, NotaryService, SignerSeat};
pub use operator::{
    Era, Operator, OperatorIdentity, OperatorSetError, PermissionedOperatorSet, RotationEvent,
    RotationTrigger, COMMITTEE_SIZE, EPOCHS_PER_ERA, QUORUM_THRESHOLD,
};
// `shake256_32` is intentionally NOT re-exported here: the crate root already
// exposes the domain-separated `hash::shake256_32(domain, data)`; the raw
// single-arg `shake::shake256_32(input)` stays reachable via its module path
// (used by `certificate`), so the two redundant SHAKE-256 helpers don't collide.
pub use shake::shake256;
pub use signature::{
    CheckpointSigner, MlDsa65PublicKey, MlDsa65Signature, MlDsa65Verifier, NonSigningStubSigner,
    NonVerifyingStubVerifier, SignatureError, ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SIGNATURE_LEN,
};

/// A single honest disclaimer string suitable to attach to any surface derived
/// from this scaffold. Mirrors design `§0.6`.
pub const SCAFFOLD_DISCLAIMER: &str = "\
Conceptual design scaffold — not an offer, not advice. Nothing here is built, \
audited, secure, attested, or deployed. Postern FFG is a trusted, CENTRALIZED, \
permissioned settlement/finality service operated by Postern — it is NOT \
decentralized, trustless, permissionless, or BFT; its trust model is 'trust \
Postern.' Finality is not final yet: the base is a mainnet-beta (k=4 \
trivially-forgeable, 51%-attackable, unaudited), so no settlement or \
irreversibility can be relied upon today. The finality signature primitive is \
ML-DSA-65 (post-quantum), not BLS; the verify is stubbed in this scaffold. The \
BLCH coin is worthless and is not a security, and nothing here gives it value; \
BLCH is only the neutral native gas of the ownerless base. Tokenizing a \
real-world asset creates a regulated instrument and operating this layer likely \
makes Postern a regulated intermediary — independent legal review of BOTH is a \
HARD GATE before anything is built or offered. The base is an ownerless commons \
anyone may build on, including decentralized alternatives; Postern owns only its \
own instance.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_to_end_scaffold_wiring_compiles_and_runs() {
        // Build a small permissioned (single-trust-domain) operator set.
        let ops: Vec<Operator> = (1u8..=3)
            .map(|s| {
                let mut uid = [0u8; 32];
                uid[0] = s;
                Operator {
                    identity: OperatorIdentity {
                        uid,
                        jurisdiction: *b"US",
                        client_version: "scaffold-0".into(),
                        registered_at_block: 1,
                    },
                    public_key: MlDsa65PublicKey::from_bytes(vec![s; ML_DSA_65_PUBLIC_KEY_LEN])
                        .unwrap(),
                }
            })
            .collect();
        let set = PermissionedOperatorSet::new(ops, 2).unwrap();

        // Observe a (fake) base tip and anchor a commitment onto the base.
        let mut client = InMemoryAnchorClient::new();
        client.push_header(BaseAnchorRef {
            block_height: 210,
            block_hash: [3u8; 32],
            accumulated_work: 2100,
        });
        let tip = client.canonical_tip().unwrap();

        // Assemble a notary checkpoint over the observed base checkpoint.
        let checkpoint = PosternNotaryCheckpoint {
            height_range: HeightRange::new(205, 210).unwrap(),
            base_anchor: tip.clone(),
            era: Era::genesis(),
            confidence: ConfidenceLevel::SoftJustified,
            signatures: (1u8..=2)
                .map(|s| {
                    let mut uid = [0u8; 32];
                    uid[0] = s;
                    OperatorSignature {
                        operator_uid: uid,
                        signature: MlDsa65Signature::from_bytes(vec![s; ML_DSA_65_SIGNATURE_LEN])
                            .unwrap(),
                    }
                })
                .collect(),
        };

        // The stub verifier asserts nothing => never reaches quorum (by design).
        let outcome = checkpoint.verify_quorum(&set, &NonVerifyingStubVerifier);
        assert!(matches!(outcome, QuorumOutcome::BelowThreshold { valid: 0, .. }));

        // Anchoring writes ordinary base data; the receipt is not a guarantee.
        // The commitment is the certificate hash: SHAKE-256-32 (in-crate,
        // unaudited reference implementation) of the canonical certificate
        // encoding (checkpoint + signatures).
        let certificate = CheckpointCertificate::new(checkpoint);
        let receipt = client.anchor_commitment(certificate.certificate_hash()).unwrap();
        assert_eq!(receipt.anchored_at_height, 210);
        assert_eq!(receipt.commitment, certificate.certificate_hash());

        // Independent re-verification is open to anyone — but with the stub
        // verifier (the `--no-default-features` offline posture) validity is
        // never asserted, so even the follower can never "confirm" a quorum.
        // (The default build verifies real ML-DSA-65; see the integration and
        // signature tests for the genuine-quorum path.)
        assert_eq!(
            follower::reverify_anchored_certificate(&receipt, &certificate, &set, &NonVerifyingStubVerifier),
            Err(FollowerError::QuorumNotReproduced { valid: 0, threshold: 2 })
        );

        // The disclaimer must keep the honest rails present.
        assert!(SCAFFOLD_DISCLAIMER.contains("trust Postern"));
        assert!(SCAFFOLD_DISCLAIMER.contains("ML-DSA-65"));
    }

    /// The ownerless-base test, in code (roadmap §5: "If Postern's entire
    /// signer set vanished, the base would continue unchanged — that is the
    /// test that keeps the base ownerless").
    ///
    /// Postern vanishes — the anchor client is dropped — and the mock base's
    /// headers/state are byte-identical to before: the base never depended on
    /// the owned layer. The kernels keep applying ops (owned-layer state keeps
    /// evolving, roots keep advancing); they merely stop anchoring.
    #[test]
    fn postern_vanishes_and_the_base_is_untouched() {
        use crate::rwa::{LegalGate, RwaOp, RwaState};

        // The mock base: a header chain that exists independently of Postern.
        let base_headers: Vec<BaseAnchorRef> = (1..=5)
            .map(|h| BaseAnchorRef {
                block_height: h,
                block_hash: [h as u8; 32],
                accumulated_work: u128::from(h) * 10,
            })
            .collect();

        // Postern's owned layer: a BaaS host with two tenants, anchoring
        // through a client that merely *views* the base.
        let mut host: BaasHost<RwaState, RwaOp> = BaasHost::new();
        host.create_tenant([1u8; 32], RwaState::default()).unwrap();
        host.create_tenant([2u8; 32], RwaState::default()).unwrap();
        host.apply(
            &[1u8; 32],
            RwaOp::RegisterAsset {
                asset_id: [9u8; 32],
                issuer: [7u8; 32],
                supply: 10,
                legal_review: LegalGate::NotObtained,
            },
        )
        .unwrap()
        .unwrap();

        let mut client = InMemoryAnchorClient::new();
        for h in &base_headers {
            client.push_header(h.clone());
        }
        let receipt = host.anchor_batch(&mut client).unwrap();
        assert_eq!(receipt.anchored_at_height, 5);

        // Postern vanishes: the entire anchoring path is dropped.
        drop(client);

        // The base's headers/state are exactly what they were — the base
        // never knew the owned layer existed. (Anchored commitments were
        // ordinary tx data on the base, not consensus state; the base's
        // header chain, heights, hashes, and accumulated work are untouched.)
        for (i, h) in base_headers.iter().enumerate() {
            assert_eq!(h.block_height, (i + 1) as u64);
            assert_eq!(h.block_hash, [(i + 1) as u8; 32]);
            assert_eq!(h.accumulated_work, u128::from(i as u64 + 1) * 10);
        }

        // The kernels keep working — they merely stop anchoring.
        let root_before = host.tenant_root(&[1u8; 32]).unwrap();
        host.apply(
            &[1u8; 32],
            RwaOp::Transfer {
                asset_id: [9u8; 32],
                from: [7u8; 32],
                to: [8u8; 32],
                amount: 3,
            },
        )
        .unwrap()
        .unwrap();
        assert_ne!(host.tenant_root(&[1u8; 32]).unwrap(), root_before);
        // There is simply no anchor client left to write to — no new receipt
        // exists anywhere, and nothing in the owned layer can affect the base.
    }
}
