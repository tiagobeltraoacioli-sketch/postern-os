// SPDX-License-Identifier: MIT OR Apache-2.0
//! # Postern FFG-BFT finality overlay — hashrate-weighted (design scaffold)
//!
//! ## ⚠️ SCAFFOLD — UNAUDITED — designed != built != booted
//!
//! This crate is a **conceptual design scaffold**. **Nothing here is built,
//! audited, attested, secure, offered, or operational.** It exists to give the
//! design in `docs/specs/POSTERN-FFG-BFT-FINALITY.md` a compiling, tested type
//! skeleton — not a working finality/settlement system. Do **not** settle,
//! custody, or rely on anything of value using this code. This is a testnet-
//! zero-value artifact.
//!
//! ## Why BFT is back (and what unlocked it)
//!
//! Postern **rejected** a BFT finality gadget on 2026-07-12. The blocker then
//! was singular: **BLS/DKG aggregation is not post-quantum** — BLS12-381 is
//! Shor-breakable, so any BLS-aggregated finality certificate is forgeable by a
//! quantum adversary. That rejection stands *for BLS*.
//!
//! What unlocks BFT here is doing it with **individual ML-DSA-65 (FIPS 204)
//! signatures — no aggregation, no DKG, and NO BLS anywhere**. Each seat emits
//! one full ML-DSA-65 signature; a quorum certificate is simply a set of them.
//! This is PQ-coherent end to end, which is the entire point.
//! **BLS / threshold-BLS / DKG / signature aggregation are BANNED** in this
//! crate and its design. (The cost is size: ML-DSA has no aggregation, so a
//! quorum cert is tens-to-hundreds of KB — see spec `§7`. The FFG *checkpoint*
//! overlay is what makes that affordable: one expensive cert amortized over a
//! whole epoch, instead of per block.)
//!
//! ## Why WEIGHTED, not count-based `2f+1` (the locked 2026-07-16 decision)
//!
//! An earlier draft used a **count-based** Byzantine committee: `N` seats,
//! quorum `2f+1`, safety from `N >= 3f+1`. **A review proved that unsafe
//! whenever `N != 3f+1`** — the `2(2f+1) - (3f+1) = f+1` overlap bound holds
//! only at the exact `N = 3f+1` boundary. **The count-based path is deleted.**
//!
//! The committee is now the **miners, weighted by hashrate** — where hashrate
//! is proxied by **block-share in a trailing look-back window** (pure
//! block-share, no per-miner cap). Finality is a strict **`> 2/3` of the
//! epoch's frozen `total_weight`** rule ([`committee::weighted_quorum_reached`]:
//! `covered * 3 > total * 2`, integer-only, overflow-safe). The
//! quorum-intersection guarantee then holds for **any** weight distribution:
//! two `> 2/3`-weight quorums overlap in `> 1/3` of the weight, so `>= 1`
//! attributable seat signed both — **no `N = 3f+1` precondition** (spec `§5.2`).
//!
//! ## Rotation & replacement (safety-first, halt-not-fork)
//!
//! - **Rotation** ([`committee::RotationMeta`]): each epoch (a fixed block
//!   interval, ~120 blocks) re-snapshots membership+weights from a trailing
//!   window; eligible iff a registered ML-DSA key is bound to the coinbase
//!   address **and** block-share `>= min_share` (drops dust). Deterministic and
//!   on-chain-re-derivable; the weight-derivation itself is an out-of-scope seam
//!   (like the anchor reader).
//! - **Replacement / freeze**: the committee and `total_weight` are **FIXED for
//!   the whole epoch — never re-normalized mid-epoch** (shrinking the
//!   denominator would break quorum-intersection). A member that leaves just
//!   stops voting; if departed weight exceeds `1/3`, finality **halts, never
//!   forks**. Replacement is the *next* rotation (departed miners auto-drop);
//!   an emergency early rotation restores liveness after `R` blocks without a
//!   finalization. [`anchor::link`] enforces the intra-epoch frozen-committee /
//!   frozen-total invariant on-chain.
//! - **Hand-off**: at each epoch boundary the outgoing committee's `> 2/3`
//!   quorum signs a checkpoint whose `committee_commitment` names the *incoming*
//!   committee (a weak-subjectivity anchor for continuous finality, spec `§3.3`).
//!
//! ## Binding rails (carry these wherever this crate's concepts appear)
//!
//! - **Scaffold, unaudited — nothing built, secure, attested, or deployed.**
//!   No security claim anywhere.
//! - **The base stays ownerless (Bitcoin model).** This gadget is a **finality
//!   *overlay***, not a base-consensus change. It anchors checkpoints to the
//!   ownerless Bloch base as **ordinary zero-value transactions** (the
//!   L2V0/TKV0/DATA0 idiom; see [`anchor`]). **Coins do NOT vote; hashrate
//!   does** — and hashrate is the same Sybil-resistance already securing the
//!   base, so the overlay introduces no new ownership. If the whole committee
//!   vanished, the base continues exactly as before.
//! - **ML-DSA-65 only, NO BLS.** The finality primitive is individual,
//!   non-aggregated ML-DSA-65. The lattice verify goes through a **seam**
//!   ([`quorum::CheckpointVerifier`]) whose **default** impl,
//!   [`quorum::RustCryptoMlDsa65Verifier`], is a **real FIPS-204 verify** (the
//!   `real-mldsa65` feature is ON by default) — so a **default `cargo test`
//!   finalizes a genuine `> 2/3` quorum and rejects tampered signatures**. The
//!   backing `ml-dsa` crate is **UNAUDITED, pre-1.0**, so this is real crypto
//!   but not a production security claim; the offline [`quorum::MockVerifier`]
//!   (scripted oracle) and [`quorum::RejectingStubVerifier`] (accepts nothing,
//!   the `--no-default-features` posture) remain for crate-free builds. A real,
//!   audited FIPS-204 verifier (e.g. the repo's wired
//!   `bloch_crypto::crypto::verify`) is supplied *outside* this crate.
//! - **Accountable safety, honest liveness.** Finality = signatures covering
//!   `> 2/3` of the frozen epoch weight. A block finalized under a checkpoint
//!   cannot be reorged past *within the committee's view* — this raises the
//!   deep-reorg bar and adds no-deep-reorg finality below each checkpoint. Two
//!   conflicting `> 2/3`-weight quorums overlap in seats holding `> 1/3` of the
//!   weight, so any safety violation is **detectable and attributable**
//!   (accountable safety). **v1 has NO slashing** — detection, reputation, and
//!   exclusion-at-next-rotation only. Liveness halts if `> 1/3` of the weight is
//!   offline/departed; that trade is disclosed (spec `§3.2`, `§6`).
//! - **Honest concentration caveat (spec `§9`).** *Hashrate-weighted finality
//!   is only as decentralized as the hashrate; today concentrated ⇒ effectively
//!   Postern-controlled until miners decentralize; a `> 2/3`-hashrate entity
//!   still breaks it. It MITIGATES 51% (raises the safety bar 51% → 67% +
//!   no-deep-reorg finality below), does not eliminate it.* Because the
//!   committee *is* the miners weighted by block-share, a `> 2/3`-weight quorum
//!   *is* a `> 2/3`-hashrate entity. **No decentralization theater.**
//! - **Finality is capped by the base.** Overall security is
//!   `min(base security, committee security)`. The Bloch base is a mainnet-beta
//!   (`k`-forgeable, `51%`-attackable, unaudited today), so a "finalized"
//!   checkpoint over it is **not settlement finality**. The overlay cannot fix
//!   the base; that hardening is a separate, gating track (spec reorg gate).
//! - **The coin (BLCH) is worthless and is not a security.** Paying base gas to
//!   anchor a checkpoint is operational spend only — never a value claim.
//!
//! > **Honest one-liner:** *"A post-quantum (ML-DSA-65, no BLS) FFG-style BFT
//! > finality overlay whose committee is the miners weighted by hashrate
//! > (block-share). It anchors checkpoints — finalized by signatures covering
//! > `> 2/3` of the epoch's frozen weight — to the ownerless Bloch base as
//! > zero-value transactions. It is a design scaffold: the weighted quorum
//! > arithmetic, checkpoint codec, and base-anchor codec are real and tested;
//! > the real ML-DSA verify, the weight-derivation, and the live committee
//! > round are honest stubs behind seams. It provides no settlement finality —
//! > the base beneath it is forgeable, and finality is only as decentralized as
//! > the hashrate. Do not settle anything of value on it."*
//!
//! ## What is real vs stubbed
//!
//! - **REAL + TESTED (default build; the deterministic core needs no network):**
//!   - [`committee`] — the hashrate-weighted validator set (per-seat `weight`,
//!     frozen `total_weight`) and the strict `> 2/3`
//!     [`committee::weighted_quorum_reached`] predicate, plus membership /
//!     dup-coinbase / dup-pubkey / min_share invariants.
//!   - [`checkpoint`] — strict codecs for the checkpoint transcript (now
//!     including `committee_commitment` + `total_weight`) and the validator
//!     co-signature set, plus the domain-separated signing payload.
//!   - [`quorum`] — distinct-valid-signature **weight summation** against the
//!     `> 2/3` threshold, over the [`quorum::CheckpointVerifier`] seam.
//!   - [`anchor`] — the fixed 165-byte `BFT0` v`0x01` zero-value base-anchor
//!     envelope: strict encode/decode, zero-value extraction (first-wins), and
//!     the canonical-chain linkage check with the intra-epoch frozen-committee /
//!     frozen-total invariant.
//! - **REAL BY DEFAULT / OUT OF SCOPE (behind seams):**
//!   - ML-DSA-65 (FIPS 204) verification runs through the real, default
//!     [`quorum::RustCryptoMlDsa65Verifier`] (UNAUDITED pre-1.0 `ml-dsa`); an
//!     independently **audited** verifier is still supplied *outside* this crate.
//!     The offline [`quorum::MockVerifier`] / [`quorum::RejectingStubVerifier`]
//!     remain for `--no-default-features` builds.
//!   - Weight **derivation** from base blocks (trailing-window block-share,
//!     eligibility, on-chain re-derivation) — a documented seam; this crate
//!     consumes an already-snapshotted weighted set.
//!   - The **live committee round** (propose / weighted co-sign / gossip /
//!     timers / transport) — an intrinsically live-networking object,
//!     deliberately not in this offline crate.
//!
//! Licensed under **MIT OR Apache-2.0**.

// Scaffold-appropriate lint posture: no unsafe anywhere; keep warnings loud
// without blocking the build while the design is in flux.
#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod anchor;
pub mod checkpoint;
pub mod committee;
pub mod quorum;

// Convenience re-exports of the primary design types.
pub use anchor::{
    decode_active_anchor_output, decode_anchor_output, extract_active_anchor, extract_anchor, link,
    CheckpointEnvelope, EnvelopeError, LinkError, Tx, TxIn, TxOut, ENVELOPE_LEN, ENVELOPE_MAGIC,
    ENVELOPE_VERSION,
};
pub use checkpoint::{
    decode_votes, encode_votes, Checkpoint, CheckpointCodecError, Vote, CHECKPOINT_LEN,
    CHECKPOINT_SIGNING_DOMAIN,
};
pub use committee::{
    weighted_quorum_reached, CommitteeError, RotationMeta, Validator, ValidatorId, ValidatorSet,
};
pub use quorum::{
    verify_finalized, verify_finalized_gated, CheckpointVerifier, FinalityOutcome, MockVerifier,
    RejectingStubVerifier,
};
// Real (UNAUDITED, pre-1.0) FIPS-204 ML-DSA-65 verify/sign pair for the
// `CheckpointVerifier` seam — the DEFAULT posture (`real-mldsa65` is ON by
// default). Compiled out only under `--no-default-features`, where the offline
// stub/mock take over.
#[cfg(feature = "real-mldsa65")]
pub use quorum::{RustCryptoMlDsa65Signer, RustCryptoMlDsa65Verifier};

/// **Declared target activation height for FFG-BFT adoption on the Bloch base:
/// block `1_000_000`** — a coordinated, height-gated soft-fork activation
/// (~6.8 months out from ~404k at 30 s blocks). This is a DECLARED TARGET, not a
/// live gate: this crate is still a scaffold, so **nothing runs at this height
/// yet**. Before it can mean anything the overlay must be, in order:
/// (1) **INTEGRATED** into the node — committee gossip, ML-DSA-65 quorum
///     aggregation, BFT0 checkpoint anchoring, wired into consensus + RPC;
/// (2) **AUDITED** (it is a finality/settlement overlay — safety-critical);
/// (3) **DEPLOYED** to a super-majority of hashrate ahead of the height, so the
///     activation is fork-safe (like the reachability upgrade).
/// The public **site announcement happens ONLY once it is coded, tested, and
/// verified OK — never before.** Work on it is **sequenced AFTER the base
/// (sync/convergence) is stable**; it is not started concurrently with node
/// stabilization. See `docs/specs/POSTERN-FFG-BFT-FINALITY.md` and the FFG
/// integration plan.
pub const FFG_ACTIVATION_HEIGHT: u64 = 1_000_000;

/// The single, explicit activation predicate for the FFG-BFT overlay: is the
/// overlay **active** at base `height`?
///
/// It is `true` **iff** `height >= `[`FFG_ACTIVATION_HEIGHT`] — so the overlay is
/// **provably inert for every height `< 1_000_000`** and acceptance begins at
/// **exactly** block `1_000_000`. This is the one place the activation height is
/// enforced: [`FFG_ACTIVATION_HEIGHT`] itself stays a bare constant, and the
/// activation-gated entry points ([`quorum::verify_finalized_gated`] and
/// [`anchor::extract_active_anchor`]) route all their gating through this
/// function, so the boundary is defined once.
///
/// This does not change the scaffold posture: nothing is deployed, and below the
/// height the gated entry points are guaranteed to accept **no** checkpoint,
/// certificate, or anchor whatsoever — the overlay contributes exactly nothing
/// to a node that consults the gated surface for pre-activation heights.
#[inline]
pub const fn is_active(height: u64) -> bool {
    height >= FFG_ACTIVATION_HEIGHT
}

/// A single honest disclaimer string suitable to attach to any surface derived
/// from this scaffold. Covers the scaffold status, the ML-DSA-only / no-BLS
/// commitment, the hashrate-weighted committee model, and the ownerless-base
/// overlay.
pub const SCAFFOLD_DISCLAIMER: &str = "\
Conceptual design scaffold — not an offer, not advice. Nothing here is built, \
audited, secure, attested, or deployed. This is a post-quantum (ML-DSA-65 \
FIPS 204, NO BLS/DKG/aggregation) FFG-style BFT finality OVERLAY whose committee \
is the miners WEIGHTED BY HASHRATE (block-share). Finality = signatures covering \
> 2/3 of the epoch's frozen total weight; the checkpoints anchor to the \
ownerless Bloch-SIS-PoW base as ordinary zero-value transactions. It is NOT a \
base-consensus change; coins do NOT vote, hashrate does; the base gains no \
operator. The weighted quorum arithmetic and codecs are real and tested; the \
real ML-DSA verify, the weight-derivation, and the live committee round are \
stubbed behind seams. Finality is capped at min(base, committee) security: the \
base is a mainnet-beta (k-forgeable, 51%-attackable, unaudited), so no \
settlement or irreversibility can be relied upon today. The BLCH coin is \
worthless and is not a security; anchoring gas is operational spend only.";

/// A second disclaimer naming the **trust surface** explicitly, per the design's
/// no-decentralization-theater rail, including the honest hashrate-concentration
/// caveat (spec `§9`).
pub const TRUST_SURFACE_DISCLAIMER: &str = "\
Trust surface (be honest about it): finality here is the individual ML-DSA-65 \
signatures of the mining committee, WEIGHTED BY HASHRATE, covering > 2/3 of the \
epoch's frozen total weight. HASHRATE-WEIGHTED FINALITY IS ONLY AS DECENTRALIZED \
AS THE HASHRATE; today concentrated ⇒ effectively Postern-controlled until \
miners decentralize; a > 2/3-hashrate entity still breaks it. It MITIGATES 51% \
(raises the safety bar 51% → 67% + no-deep-reorg finality below), does not \
eliminate it. A dishonest quorum (seats covering > 2/3 of the weight, colluding) \
CAN finalize a checkpoint the honest set rejects; it CANNOT do so without leaving \
attributable equivocation evidence (two conflicting > 2/3-weight quorums overlap \
in seats holding > 1/3 of the weight). The committee and its total_weight are \
FROZEN within an epoch and NEVER re-normalized mid-epoch; a departure over 1/3 \
weight HALTS finality (never forks). A 51%-miner on the forgeable base CAN \
reorg/forge the base beneath a finalized checkpoint (finality is capped by the \
base); it CANNOT forge committee signatures. There is NO slashing this phase — \
detection, reputation, and exclusion-at-next-rotation only.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_to_end_scaffold_wiring_compiles_and_runs() {
        // 1) Build a hashrate-weighted committee: total_weight = 100.
        let weights = [40u64, 30, 20, 10];
        let validators: Vec<Validator> = weights
            .iter()
            .enumerate()
            .map(|(i, &w)| {
                let s = (i as u8) + 1;
                let mut id = [0u8; 32];
                id[0] = s;
                let mut coinbase = [0u8; 20];
                coinbase[0] = s;
                Validator { id: ValidatorId(id), coinbase_addr: coinbase, pubkey: vec![s; 8], weight: w }
            })
            .collect();
        let set = ValidatorSet::new(
            validators,
            RotationMeta { epoch: 0, window_blocks: 120, min_share: 1 },
        )
        .unwrap();
        assert_eq!(set.total_weight(), 100);

        // 2) Assemble a checkpoint over a finalized base height.
        let checkpoint = Checkpoint {
            committee_epoch: set.epoch(),
            finalized_height: 210,
            finalized_block_hash: [3u8; 32],
            prev_checkpoint_hash: [0u8; 32],
            committee_commitment: [0x11; 32],
            total_weight: set.total_weight(),
        };
        let message = checkpoint.canonical_signing_payload();

        // 3) Seats covering weight 70 (40 + 30) co-sign — that is > 2/3 of 100.
        let mut verifier = MockVerifier::new();
        let mut votes: Vec<Vote> = Vec::new();
        for seat in 0u32..2 {
            let pubkey = &set.validator_at(seat).unwrap().pubkey;
            let sig = vec![0x80 | seat as u8; 3309];
            verifier.accept(pubkey, &message, &sig);
            votes.push(Vote { validator_index: seat, sig });
        }

        // 4) The weighted quorum (> 2/3 of total_weight) is reached.
        let outcome = verify_finalized(&checkpoint, &votes, &set, &verifier);
        assert_eq!(
            outcome,
            FinalityOutcome::Finalized { covered_weight: 70, total_weight: 100 }
        );
        assert!(weighted_quorum_reached(70, 100));

        // 4b) The rejecting stub (the `--no-default-features` offline posture)
        //     never reaches quorum, whatever the votes.
        let stubbed = verify_finalized(&checkpoint, &votes, &set, &RejectingStubVerifier);
        assert!(!stubbed.is_finalized());

        // 5) Anchor the finalized checkpoint to the base as a zero-value BFT0
        //    v0x01 envelope, and round-trip it through the wire form.
        let envelope = CheckpointEnvelope {
            committee_epoch: checkpoint.committee_epoch,
            finalized_height: checkpoint.finalized_height,
            finalized_block_hash: checkpoint.finalized_block_hash,
            prev_checkpoint_hash: checkpoint.prev_checkpoint_hash,
            quorum_commitment: [0xC0; 32], // reader-side commitment to the votes
            committee_commitment: checkpoint.committee_commitment,
            total_weight: checkpoint.total_weight,
        };
        let out = TxOut { value: 0, script_pubkey: envelope.encode() };
        let tx = Tx { version: 1, inputs: vec![], outputs: vec![out], locktime: 0 };
        assert_eq!(extract_anchor(&tx), Some((0, envelope)));

        // 6) The honest rails are present in the disclaimers.
        assert!(SCAFFOLD_DISCLAIMER.contains("ML-DSA-65"));
        assert!(SCAFFOLD_DISCLAIMER.contains("NO BLS"));
        assert!(SCAFFOLD_DISCLAIMER.contains("WEIGHTED BY HASHRATE"));
        assert!(SCAFFOLD_DISCLAIMER.contains("coins do NOT vote"));
        assert!(TRUST_SURFACE_DISCLAIMER.contains("ONLY AS DECENTRALIZED"));
        assert!(TRUST_SURFACE_DISCLAIMER.contains("51% → 67%"));
        assert!(TRUST_SURFACE_DISCLAIMER.contains("NO slashing"));
    }

    // ── activation gate ───────────────────────────────────────────────────

    #[test]
    fn ffg_activation_height_is_the_bare_declared_const() {
        // The height stays a bare constant; enforcement lives only in is_active.
        assert_eq!(FFG_ACTIVATION_HEIGHT, 1_000_000);
    }

    #[test]
    fn is_active_boundary_is_exact() {
        // Provably inert strictly below the height...
        assert!(!is_active(0));
        assert!(!is_active(1));
        assert!(!is_active(404_000)); // ~ today's tip
        assert!(!is_active(FFG_ACTIVATION_HEIGHT - 1)); // 999_999
        // ...active at EXACTLY the height and everywhere above.
        assert!(is_active(FFG_ACTIVATION_HEIGHT)); // 1_000_000
        assert!(is_active(FFG_ACTIVATION_HEIGHT + 1));
        assert!(is_active(u64::MAX));
    }

    /// End-to-end: a genuine `> 2/3` quorum + a well-formed anchor are BOTH
    /// inert below the activation height and BOTH accepted at exactly the height,
    /// through the gated entry points.
    #[test]
    fn overlay_is_provably_inert_below_height_and_accepts_at_the_height() {
        let weights = [40u64, 30, 20, 10];
        let validators: Vec<Validator> = weights
            .iter()
            .enumerate()
            .map(|(i, &w)| {
                let s = (i as u8) + 1;
                let mut id = [0u8; 32];
                id[0] = s;
                let mut coinbase = [0u8; 20];
                coinbase[0] = s;
                Validator { id: ValidatorId(id), coinbase_addr: coinbase, pubkey: vec![s; 8], weight: w }
            })
            .collect();
        let set = ValidatorSet::new(
            validators,
            RotationMeta { epoch: 0, window_blocks: 120, min_share: 1 },
        )
        .unwrap();

        // Helper: build a checkpoint at a height with a genuine 70-of-100 quorum.
        let finalize_at = |height: u64| {
            let checkpoint = Checkpoint {
                committee_epoch: set.epoch(),
                finalized_height: height,
                finalized_block_hash: [3u8; 32],
                prev_checkpoint_hash: [0u8; 32],
                committee_commitment: [0x11; 32],
                total_weight: set.total_weight(),
            };
            let message = checkpoint.canonical_signing_payload();
            let mut verifier = MockVerifier::new();
            let mut votes: Vec<Vote> = Vec::new();
            for seat in 0u32..2 {
                let pubkey = &set.validator_at(seat).unwrap().pubkey;
                let sig = vec![0x80 | seat as u8; 3309];
                verifier.accept(pubkey, &message, &sig);
                votes.push(Vote { validator_index: seat, sig });
            }
            verify_finalized_gated(&checkpoint, &votes, &set, &verifier)
        };

        // Helper: build an anchor tx at a height and read it through the gate.
        let extract_at = |height: u64| {
            let envelope = CheckpointEnvelope {
                committee_epoch: 0,
                finalized_height: height,
                finalized_block_hash: [3u8; 32],
                prev_checkpoint_hash: [0u8; 32],
                quorum_commitment: [0xC0; 32],
                committee_commitment: [0x11; 32],
                total_weight: set.total_weight(),
            };
            let out = TxOut { value: 0, script_pubkey: envelope.encode() };
            let tx = Tx { version: 1, inputs: vec![], outputs: vec![out], locktime: 0 };
            extract_active_anchor(&tx).map(|(_, e)| e)
        };

        // Below the height: no cert accepted, no anchor accepted.
        assert!(finalize_at(FFG_ACTIVATION_HEIGHT - 1).is_inert());
        assert!(!finalize_at(FFG_ACTIVATION_HEIGHT - 1).is_finalized());
        assert_eq!(extract_at(FFG_ACTIVATION_HEIGHT - 1), None);

        // Exactly at the height: the cert finalizes and the anchor extracts.
        assert_eq!(
            finalize_at(FFG_ACTIVATION_HEIGHT),
            FinalityOutcome::Finalized { covered_weight: 70, total_weight: 100 }
        );
        assert!(extract_at(FFG_ACTIVATION_HEIGHT).is_some());
    }

    #[test]
    fn adding_the_gate_left_the_disclaimers_unchanged() {
        // The gate must not touch the honest disclaimer text.
        assert!(SCAFFOLD_DISCLAIMER.starts_with("Conceptual design scaffold"));
        assert!(SCAFFOLD_DISCLAIMER.ends_with("anchoring gas is operational spend only."));
        assert_eq!(SCAFFOLD_DISCLAIMER.len(), 990);
        assert!(TRUST_SURFACE_DISCLAIMER.starts_with("Trust surface (be honest about it):"));
        assert_eq!(TRUST_SURFACE_DISCLAIMER.len(), 1167);
    }
}
