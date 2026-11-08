//! TPM2 PCR-extend vectors — offline, against REAL fixtures captured from
//! `swtpm` (a SOFTWARE TPM emulator — see `../tpm2/README.md` and
//! `crate::tpm2`'s module docs for the full honest label; **swtpm is NOT
//! hardware evidence**, and a pass here is NEVER a hardware attestation
//! result).
//!
//! What these vectors DO prove: `postern_seal_companion::tpm2`'s pure-Rust
//! PCR-extend/replay implementation reproduces EXACTLY what a real (software)
//! TPM2 computed for its SHA-256 PCR bank, across both a single extend and a
//! three-event replay — mirroring how `tests/snp_vectors.rs` checks the SNP
//! chain logic against a captured real Milan report, and `tests/
//! tdx_collateral.rs` checks the DCAP chain logic against a synthetic anchor.
//!
//! Honest limits of this offline testing (same shape as the crate's other
//! vector tests):
//! - the fixtures are captured from a SOFTWARE TPM emulator, not real
//!   silicon — the PCR-extend *algorithm* is silicon-independent (TCG spec),
//!   but "swtpm computed this" is not "a hardware root of trust measured
//!   this";
//! - no TPM2_Quote (signed attestation) fixture exists — see `crate::tpm2`
//!   module docs, "What this module proves (and what it does NOT)";
//! - `os_roothash` binding (the node-side `bloch::attestation` chain,
//!   `os/ATTESTATION.md`) is out of this crate's scope and unbuilt
//!   (`docs/gap/os-platform-gaps.md` #4) — this test proves the PCR-math
//!   PRIMITIVE that binding would need, nothing about the binding itself.
//!
//! Run: cargo test -p postern-seal-companion --test tpm2_pcr_vectors
//! (default build — no feature flag needed; `tpm2` is unconditional).

use postern_seal_companion::tpm2::{
    pcr_extend_sha256, pcr_replay_sha256, verify_pcr_replay, PCR_RESET_DRTM_SHA256,
    PCR_RESET_ZERO_SHA256,
};

const REPLAY_MISMATCH_ERR: &str =
    "pcr replay — recomputed PCR value does not match the claimed final value";

/// Load the three REAL swtpm event digests + the REAL swtpm-computed final PCR
/// from the three-event fixture. Every adversarial vector below builds on
/// THIS genuine, captured data (not synthetic events) — swtpm is a SOFTWARE
/// TPM emulator, so a pass here is swtpm-not-hardware evidence, never a
/// hardware measured-boot result (see module docs / ../tpm2/README.md).
fn real_three_event_log() -> ([u8; 32], [[u8; 32]; 3], [u8; 32]) {
    let initial = hex32(field(THREE_EVENT_FIXTURE, "initial_pcr"));
    let e1 = hex32(field(THREE_EVENT_FIXTURE, "event_digest_1"));
    let e2 = hex32(field(THREE_EVENT_FIXTURE, "event_digest_2"));
    let e3 = hex32(field(THREE_EVENT_FIXTURE, "event_digest_3"));
    let want_final = hex32(field(THREE_EVENT_FIXTURE, "final_pcr"));
    (initial, [e1, e2, e3], want_final)
}

const SINGLE_EXTEND_FIXTURE: &str = include_str!("../tpm2/fixtures/pcr16_swtpm_single_extend.txt");
const THREE_EVENT_FIXTURE: &str = include_str!("../tpm2/fixtures/pcr15_swtpm_three_event_replay.txt");

/// Tiny `key=value` fixture parser (mirrors `snp_vectors.rs`'s `hex32`/`hex64`
/// helpers, generalized so this crate doesn't need a JSON/serde dependency
/// just for two small text fixtures).
fn field<'a>(fixture: &'a str, key: &str) -> &'a str {
    for line in fixture.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k == key {
                return v;
            }
        }
    }
    panic!("fixture missing field {key:?}");
}

fn hex32(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64, "expected a 32-byte hex field, got {} chars", s.len());
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

#[test]
fn single_extend_matches_real_swtpm_output() {
    let initial = hex32(field(SINGLE_EXTEND_FIXTURE, "initial_pcr"));
    let event = hex32(field(SINGLE_EXTEND_FIXTURE, "event_digest"));
    let want_final = hex32(field(SINGLE_EXTEND_FIXTURE, "final_pcr"));

    // Sanity: swtpm's PCR16 reset value at capture time was all-zero, as
    // documented (TCG static-PCR reset convention).
    assert_eq!(initial, [0u8; 32]);

    let got = pcr_extend_sha256(&initial, &event);
    assert_eq!(
        got, want_final,
        "our pure-Rust pcr_extend_sha256 must reproduce the REAL swtpm-computed PCR value"
    );
}

#[test]
fn three_event_replay_matches_real_swtpm_output() {
    let initial = hex32(field(THREE_EVENT_FIXTURE, "initial_pcr"));
    let e1 = hex32(field(THREE_EVENT_FIXTURE, "event_digest_1"));
    let e2 = hex32(field(THREE_EVENT_FIXTURE, "event_digest_2"));
    let e3 = hex32(field(THREE_EVENT_FIXTURE, "event_digest_3"));
    let want_final = hex32(field(THREE_EVENT_FIXTURE, "final_pcr"));

    let got = pcr_replay_sha256(initial, &[e1, e2, e3]);
    assert_eq!(
        got, want_final,
        "replaying all 3 real swtpm-extended events must reproduce swtpm's actual final PCR"
    );

    // The verifier-facing entry point: accepts the genuine (log, claim) pair...
    assert_eq!(verify_pcr_replay(initial, &[e1, e2, e3], &want_final), Ok(()));

    // ...and fails closed on a truncated log presented against the ORIGINAL
    // (real, swtpm-produced) final-PCR claim — the same "dropped event"
    // adversarial shape as the pure-math unit tests in src/tpm2.rs, but here
    // proven against REAL captured swtpm data rather than synthetic events.
    assert_eq!(
        verify_pcr_replay(initial, &[e1, e3], &want_final),
        Err(REPLAY_MISMATCH_ERR)
    );
}

// ===========================================================================
// Adversarial event-log / replay vectors against the REAL swtpm three-event
// fixture. These go beyond the happy-path + two negatives already covered:
// they exercise the classic measured-boot log attacks (reorder, bit-flip,
// spurious-append, wrong-reset-value, empty-vs-nonzero) directly against the
// genuine captured swtpm digests, so a green result here proves the verifier
// FAILS CLOSED on each — swtpm-not-hardware (SOFTWARE TPM emulator; NEVER a
// hardware attestation result — see module docs / ../tpm2/README.md).
// ===========================================================================

/// (a) LOG-REORDERING ATTACK, swtpm-not-hardware. The three REAL event
/// digests are genuine, but presented to the verifier in a permuted order (a
/// compromised bootloader reordering measurements to hide an unexpected
/// component). Every non-identity permutation must recompute to a PCR that
/// does NOT equal swtpm's real captured final_pcr, and must fail verify.
#[test]
fn swtpm_reordered_real_event_log_does_not_reproduce_real_final_pcr() {
    let (initial, [e1, e2, e3], want_final) = real_three_event_log();

    // Sanity: the genuine order DOES reproduce swtpm's real final PCR — the
    // baseline the reordering attack is measured against.
    assert_eq!(pcr_replay_sha256(initial, &[e1, e2, e3]), want_final);

    // All 5 non-identity permutations of the 3 real digests.
    let permutations: [[[u8; 32]; 3]; 5] = [
        [e1, e3, e2],
        [e2, e1, e3],
        [e2, e3, e1],
        [e3, e1, e2],
        [e3, e2, e1],
    ];
    for perm in permutations {
        let recomputed = pcr_replay_sha256(initial, &perm);
        assert_ne!(
            recomputed, want_final,
            "reordered REAL swtpm log must NOT reproduce the genuine final PCR"
        );
        assert_eq!(
            verify_pcr_replay(initial, &perm, &want_final),
            Err(REPLAY_MISMATCH_ERR),
            "verifier must fail closed on a reordered real log claiming the genuine final PCR"
        );
    }
}

/// (b) SINGLE-BIT-FLIP in any REAL event digest, swtpm-not-hardware. Flip one
/// bit of each of the three genuine digests (every byte position, low bit) and
/// confirm verify_pcr_replay rejects the corrupted log against swtpm's real
/// final_pcr — the avalanche property means even one bit must break the chain.
#[test]
fn swtpm_single_bit_flip_in_any_real_event_digest_fails_verify() {
    let (initial, events, want_final) = real_three_event_log();

    for idx in 0..events.len() {
        for byte in 0..32 {
            let mut tampered = events;
            tampered[idx][byte] ^= 0x01; // single-bit flip
            assert_eq!(
                verify_pcr_replay(initial, &tampered, &want_final),
                Err(REPLAY_MISMATCH_ERR),
                "a 1-bit flip in real event {idx} byte {byte} must fail verify against the genuine final PCR"
            );
        }
    }
}

/// (c) SPURIOUS-APPEND attack, swtpm-not-hardware. The genuine 3-event log is
/// presented with an EXTRA event appended (an attacker adding a measurement
/// after the fact) while still claiming swtpm's ORIGINAL real final_pcr. Any
/// appended event must break the match — appending can never leave the PCR
/// unchanged (that would require SHA-256(final ‖ x) == final, a preimage).
#[test]
fn swtpm_spurious_extra_event_appended_fails_against_original_claim() {
    let (initial, [e1, e2, e3], want_final) = real_three_event_log();

    // A few different spurious events, including one equal to a real digest
    // (replayed) and the all-zero / all-0xFF edge digests.
    let spurious: [[u8; 32]; 4] = [[0x00u8; 32], [0xFFu8; 32], e1, e2];
    for extra in spurious {
        let appended = [e1, e2, e3, extra];
        assert_ne!(
            pcr_replay_sha256(initial, &appended),
            want_final,
            "appending any event to the genuine log must change the PCR"
        );
        assert_eq!(
            verify_pcr_replay(initial, &appended, &want_final),
            Err(REPLAY_MISMATCH_ERR),
            "verifier must fail closed on the genuine log + a spurious appended event"
        );
    }
}

/// (d) WRONG-RESET-VALUE rejection, swtpm-not-hardware. Replaying the SAME
/// genuine event log from the DRTM reset value (all-0xFF, PCRs 17-22) yields a
/// DIFFERENT PCR than from the static-PCR reset (all-zero) — the exact hazard
/// `PCR_RESET_ZERO_SHA256`'s own doc-comment warns about. A verifier that
/// used the wrong reset value would recompute a value the chip never held; the
/// genuine final_pcr (captured from swtpm's zero-reset PCR15) must NOT be
/// reproducible from the 0xFF reset, and verify must fail closed there.
#[test]
fn swtpm_wrong_reset_value_yields_different_pcr_and_fails_verify() {
    let (initial, events, want_final) = real_three_event_log();

    // The fixture was captured from PCR15, a static PCR whose reset value is
    // all-zero — assert that ground truth explicitly.
    assert_eq!(initial, PCR_RESET_ZERO_SHA256);

    let from_zero = pcr_replay_sha256(PCR_RESET_ZERO_SHA256, &events);
    let from_drtm = pcr_replay_sha256(PCR_RESET_DRTM_SHA256, &events);

    assert_eq!(
        from_zero, want_final,
        "zero-reset replay reproduces swtpm's genuine captured final PCR (baseline)"
    );
    assert_ne!(
        from_drtm, want_final,
        "replaying the genuine log from the WRONG (0xFF DRTM) reset value must NOT reproduce the real final PCR"
    );
    assert_ne!(
        from_zero, from_drtm,
        "the reset value is a security-relevant input: 0x00.. vs 0xFF.. must diverge"
    );
    assert_eq!(
        verify_pcr_replay(PCR_RESET_DRTM_SHA256, &events, &want_final),
        Err(REPLAY_MISMATCH_ERR),
        "verifier must fail closed when replaying from the wrong reset value"
    );
}

/// (e) EMPTY-LOG vs NON-ZERO CLAIM, fail closed (swtpm-not-hardware). An empty
/// event log leaves the PCR at its reset value; presenting an empty log while
/// claiming swtpm's non-zero real final_pcr (an attacker asserting a boot
/// state with no measurements to back it) must be rejected — the verifier must
/// never accept an unbacked non-reset claim.
#[test]
fn swtpm_empty_log_against_nonzero_real_claim_fails_closed() {
    let (initial, _events, want_final) = real_three_event_log();

    // The genuine final PCR is provably non-zero (it is a real SHA-256 chain
    // output), so an empty log can never legitimately produce it.
    assert_ne!(want_final, PCR_RESET_ZERO_SHA256);

    assert_eq!(
        verify_pcr_replay(initial, &[], &want_final),
        Err(REPLAY_MISMATCH_ERR),
        "empty log claiming a non-zero final PCR must fail closed"
    );

    // And the honest boundary: an empty log against the reset value itself DOES
    // verify (identity) — fail-closed, not fail-always.
    assert_eq!(verify_pcr_replay(initial, &[], &initial), Ok(()));
}

/// Single-extend fixture, adversarial: a 1-bit flip in the REAL single event
/// digest must not reproduce swtpm's real final_pcr (swtpm-not-hardware).
/// Complements (b) on the second genuine fixture.
#[test]
fn swtpm_single_extend_bit_flip_does_not_reproduce_real_final() {
    let initial = hex32(field(SINGLE_EXTEND_FIXTURE, "initial_pcr"));
    let event = hex32(field(SINGLE_EXTEND_FIXTURE, "event_digest"));
    let want_final = hex32(field(SINGLE_EXTEND_FIXTURE, "final_pcr"));

    assert_eq!(pcr_extend_sha256(&initial, &event), want_final); // baseline

    let mut tampered = event;
    tampered[0] ^= 0x01;
    assert_ne!(
        pcr_extend_sha256(&initial, &tampered),
        want_final,
        "a 1-bit flip in the real single-extend event must not reproduce swtpm's final PCR"
    );
    assert_eq!(
        verify_pcr_replay(initial, &[tampered], &want_final),
        Err(REPLAY_MISMATCH_ERR)
    );
}
