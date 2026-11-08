//! TPM2 PCR-extend comparison logic — **prep only, offline, no hardware**.
//! This is bucket-B/Dev-C's HOST-doable prep for Platform 4 in
//! `docs/bucketB/RUNBOOK.md`: PCR-extend / measured-boot-replay *verifier
//! logic*, tested against a REAL fixture captured from `swtpm` (a SOFTWARE
//! TPM emulator), the same way `tests/snp_vectors.rs` tests the SEV-SNP chain
//! logic against a captured real Milan report.
//!
//! # HARD HONESTY LABEL — READ BEFORE USING ANYTHING IN THIS MODULE
//!
//! **`swtpm` is a software TPM emulator. It is NOT a hardware TPM, has NO
//! hardware root of trust, and a green test in this module is NEVER
//! evidence of a real measured-boot chain.** Every test and fixture here is
//! named `swtpm_*` / carries a `swtpm — software TPM, NOT hardware evidence`
//! comment for exactly this reason: so nobody mistakes a passing
//! `cargo test` here for a hardware attestation result. See
//! `docs/bucketB/RUNBOOK.md` Platform 4 for the full picture — this crate's
//! TPM2 work is additionally gated behind a **separate, prior** Nix/VM build
//! gate (`nix build .#attested-image` has never been run; `os_roothash` is a
//! design-reference placeholder, not a verified value) before hardware is
//! even the next blocker. This module does not change that sequencing.
//!
//! ## What this module proves (and what it does NOT)
//!
//! [`pcr_extend_sha256`] and [`pcr_replay_sha256`] are the TCG TPM2 Part 1
//! §19.3 PCR-extend algorithm (`PCR_new = SHA-256(PCR_old ‖ event_digest)`)
//! implemented in pure Rust, independent of any TPM binary. `tests/
//! tpm2_pcr_vectors.rs` checks this pure-Rust implementation against TWO REAL
//! fixtures captured from a genuine `swtpm` 0.10.1 process (see
//! `tpm2/fixtures/*.txt` and `tpm2/README.md` for exactly how — raw TPM2
//! command bytes over swtpm's data socket, since `tpm2-tools` is not
//! packaged for Homebrew on macOS and was not used). This proves the
//! hash-chaining math this crate would need for a measured-boot verifier
//! matches what a real TPM (software OR hardware — the algorithm is
//! silicon-independent, defined by the TCG spec) actually computes.
//!
//! What this does **NOT** prove:
//! - that any measurement was made by trustworthy firmware/bootloader code
//!   (that is what a HARDWARE TPM's root of trust for measurement gives you
//!   — a software emulator has none);
//! - a `TPM2_Quote` (a TPM-signed attestation over PCR values plus a
//!   verifier-chosen nonce) — **not implemented this bucket**. Building one
//!   requires creating and loading an attestation key inside the TPM
//!   (`TPM2_CreatePrimary` / `TPM2_Create` / `TPM2_Load`) and marshalling
//!   `TPM2_Quote`'s request/response, which is materially more raw-protocol
//!   surface than PCR-extend/read; attempting it without `tpm2-tools` to
//!   cross-check against risked shipping an unverified, hand-rolled
//!   `TPMS_ATTEST` parser with no real output to validate it against. Scoped
//!   OUT and documented as a gap (`tpm2/README.md` "Scoped out this bucket"),
//!   the same honesty standard as `tdx.rs`'s stated PCK-chain-expiry gap —
//!   not silently missing.
//! - the `os_roothash` binding: `os/ATTESTATION.md` (outside this crate's
//!   write scope) diagrams how a real PCR quote would bind to
//!   `AttestationReport`; this module supplies the PCR-math primitive that
//!   binding would need, nothing more.

use sha2::{Digest, Sha256};

/// TCG TPM2 PCR-extend for the SHA-256 bank (TPM2 Part 1 §19.3):
/// `PCR_new = SHA-256(PCR_old ‖ event_digest)`. Pure math, no TPM involved —
/// this is the function ANY genuine TPM2 (software emulator or real silicon)
/// must satisfy for its SHA-256 PCR bank, and what `tests/tpm2_pcr_vectors.rs`
/// checks against a REAL `swtpm`-produced fixture (see module docs).
pub fn pcr_extend_sha256(old: &[u8; 32], event_digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(old);
    hasher.update(event_digest);
    let out = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

/// Replay a full measured-boot event log (in event order) from a PCR reset
/// value, returning the resulting PCR value. This is what a verifier does to
/// INDEPENDENTLY recompute the expected PCR from a claimed event log, rather
/// than trusting the log's own "final value" field — mirroring how this
/// crate's other verifiers (snp/tdx/mobile) never trust a caller-asserted
/// result, only recomputed/re-verified ones.
pub fn pcr_replay_sha256(reset_value: [u8; 32], events: &[[u8; 32]]) -> [u8; 32] {
    events.iter().fold(reset_value, |pcr, event| pcr_extend_sha256(&pcr, event))
}

/// SHA-256 PCR reset value at `TPM2_Startup(CLEAR)` for the STATIC PCRs
/// (0-15, and 16/23 which are additionally software-resettable at any time):
/// all-zero. **Not universal** — the DRTM PCRs (17-22) reset to all-`0xFF`
/// instead (TCG PC Client Platform Firmware Profile); a real verifier must
/// know which bank/PCR it is comparing before assuming this reset value.
pub const PCR_RESET_ZERO_SHA256: [u8; 32] = [0u8; 32];

/// SHA-256 reset value for the DRTM PCRs 17-22 at `_TPM_Hash_Start` (the
/// dynamic root-of-trust for measurement launch): all-`0xFF`, per the TCG PC
/// Client Platform Firmware Profile. This is the *exact hazard*
/// [`PCR_RESET_ZERO_SHA256`]'s doc-comment warns about: a verifier that
/// replays a DRTM (17-22) event log from the wrong all-zero static-PCR reset
/// value computes a PCR that does **not** match what the chip actually holds.
/// Replaying the *same* events from `0xFF..` vs `0x00..` yields two different
/// PCRs — the reset value is a security-relevant input, not a cosmetic
/// default. Provided so a verifier can pick the correct reset value per PCR
/// index instead of hard-coding zero.
pub const PCR_RESET_DRTM_SHA256: [u8; 32] = [0xFFu8; 32];

/// Verify a claimed final PCR value against an independently-recomputed
/// replay of the claimed event log — the fail-closed comparison a
/// measured-boot verifier performs. Returns `Ok(())` only if the recomputed
/// value equals the claim; otherwise a named `Err` (never silently accepts a
/// log whose own stated final value doesn't match what replaying it produces).
pub fn verify_pcr_replay(
    reset_value: [u8; 32],
    events: &[[u8; 32]],
    claimed_final: &[u8; 32],
) -> Result<(), &'static str> {
    let recomputed = pcr_replay_sha256(reset_value, events);
    if &recomputed != claimed_final {
        return Err("pcr replay — recomputed PCR value does not match the claimed final value");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extend_from_zero_matches_known_sha256_chaining() {
        let old = [0u8; 32];
        let event = [0x11u8; 32];
        let got = pcr_extend_sha256(&old, &event);
        let mut hasher = Sha256::new();
        hasher.update(old);
        hasher.update(event);
        let want: [u8; 32] = hasher.finalize().into();
        assert_eq!(got, want);
    }

    #[test]
    fn empty_event_log_leaves_pcr_at_reset_value() {
        // Boundary: replaying zero events must be the identity — the PCR
        // stays exactly at its reset value.
        let reset = [0x42u8; 32]; // arbitrary, exercises non-zero reset too
        assert_eq!(pcr_replay_sha256(reset, &[]), reset);
    }

    #[test]
    fn replay_is_order_sensitive() {
        // A measured-boot log with the same two events in a DIFFERENT order
        // must produce a DIFFERENT PCR — order is part of what's measured
        // (this is exactly what a compromised bootloader reordering
        // measurements to hide an unexpected component would try to exploit,
        // and the check must reject it).
        let reset = PCR_RESET_ZERO_SHA256;
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        let forward = pcr_replay_sha256(reset, &[a, b]);
        let reversed = pcr_replay_sha256(reset, &[b, a]);
        assert_ne!(forward, reversed);
    }

    #[test]
    fn verify_pcr_replay_accepts_matching_log() {
        let reset = PCR_RESET_ZERO_SHA256;
        let events = [[0xAAu8; 32], [0xBBu8; 32]];
        let claimed = pcr_replay_sha256(reset, &events);
        assert_eq!(verify_pcr_replay(reset, &events, &claimed), Ok(()));
    }

    #[test]
    fn verify_pcr_replay_rejects_tampered_final_value() {
        // Adversarial vector: the event log is genuine, but the "final PCR"
        // claim attached to it has been tampered with (e.g. a compromised
        // measured-boot agent lying about its own PCR state) — must fail
        // closed, not silently trust the claim.
        let reset = PCR_RESET_ZERO_SHA256;
        let events = [[0xAAu8; 32], [0xBBu8; 32]];
        let mut tampered = pcr_replay_sha256(reset, &events);
        tampered[0] ^= 0xFF;
        assert_eq!(
            verify_pcr_replay(reset, &events, &tampered),
            Err("pcr replay — recomputed PCR value does not match the claimed final value")
        );
    }

    #[test]
    fn drtm_and_zero_reset_diverge_for_same_log() {
        // Wrong-reset-value hazard (pure-math form of the fixture test's case
        // (d)): replaying the SAME events from the DRTM 0xFF reset must yield a
        // DIFFERENT PCR than from the all-zero static reset. A verifier that
        // hard-codes the zero reset for a DRTM (17-22) PCR would recompute a
        // value the chip never held — exactly what PCR_RESET_ZERO_SHA256's doc
        // warns against.
        let events = [[0xAAu8; 32], [0x55u8; 32]];
        let from_zero = pcr_replay_sha256(PCR_RESET_ZERO_SHA256, &events);
        let from_drtm = pcr_replay_sha256(PCR_RESET_DRTM_SHA256, &events);
        assert_ne!(from_zero, from_drtm);

        // And the reset consts are what the profile says (documentation-as-test).
        assert_eq!(PCR_RESET_ZERO_SHA256, [0x00u8; 32]);
        assert_eq!(PCR_RESET_DRTM_SHA256, [0xFFu8; 32]);

        // A claim recomputed under one reset must fail-closed under the other.
        assert_eq!(
            verify_pcr_replay(PCR_RESET_DRTM_SHA256, &events, &from_zero),
            Err("pcr replay — recomputed PCR value does not match the claimed final value")
        );
    }

    #[test]
    fn verify_pcr_replay_rejects_dropped_event() {
        // Adversarial vector: an attacker drops one event from the log
        // presented to the verifier (hiding a measurement) while keeping the
        // ORIGINAL final-PCR claim from the full log — the recomputed value
        // from the truncated log must not match, catching the omission.
        let reset = PCR_RESET_ZERO_SHA256;
        let full_events = [[0xAAu8; 32], [0xBBu8; 32], [0xCCu8; 32]];
        let claimed_final = pcr_replay_sha256(reset, &full_events);
        let truncated_events = [full_events[0], full_events[2]]; // middle event dropped
        assert_eq!(
            verify_pcr_replay(reset, &truncated_events, &claimed_final),
            Err("pcr replay — recomputed PCR value does not match the claimed final value")
        );
    }
}
