//! SEV-SNP verification vectors — offline, against a REAL Milan attestation
//! report + VCEK (vendored from virtee/sev's Apache-2.0 test fixtures,
//! `testdata/report_milan.hex` + `testdata/vcek_milan.der`) and the pinned
//! AMD ARK/ASK compiled into the `sev` crate from AMD's published certs.
//!
//! What these vectors DO prove: the full chain check (ARK self-signed →
//! ARK signs ASK → ASK signs VCEK → VCEK signs this exact report body) runs
//! and rejects on every tamper, and every expected-field comparison
//! (measurement, HOSTDATA, report_data, TCB floor, generation) enforces.
//!
//! Honest limits of offline testing:
//! - The Genuine case's expected values are the fixture's own (they are what
//!   AMD's silicon signed) — the field COMPARISONS are proven by the mismatch
//!   vectors, not by the happy path.
//! - A Genuine verdict with OUR channel binding in report_data cannot be
//!   minted offline: report_data sits in the silicon-signed region. The
//!   binding math has its own vectors (src/binding.rs); the end-to-end
//!   "gate handshake → Genuine" needs a real SEV-SNP VM — see
//!   docs/specs/POSTERN-CLOUD-CONFIDENTIAL.md.
//!
//! Run: cargo test -p postern-seal-companion --features sev-snp

use postern_seal_companion::binding;
use postern_seal_companion::gate::GateEvidence;
use postern_seal_companion::snp::{
    verify_gate_evidence, verify_snp_report_without_revocation, AmdGeneration, MinTcb,
    RevocationPolicy, SnpExpected, SnpVerdict,
};

// These vectors exercise the chain + field core (the mismatch cases prove each
// comparison enforces); revocation has its own offline vectors in
// `tests/snp_crl.rs`. Using the loudly-named `*_without_revocation` entry keeps
// that split explicit — a real AMD-KDS CRL cannot be minted offline.

const REPORT_HEX: &str = include_str!("../testdata/report_milan.hex");
const VCEK_DER: &[u8] = include_bytes!("../testdata/vcek_milan.der");

fn report_bytes() -> Vec<u8> {
    let s: String = REPORT_HEX.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    assert_eq!(s.len() % 2, 0, "fixture must be whole bytes");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex48(s: &str) -> [u8; 48] {
    let mut out = [0u8; 48];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn hex64(s: &str) -> [u8; 64] {
    let mut out = [0u8; 64];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

/// The fixture report's silicon-signed values (parsed at the SNP v2 offsets,
/// cross-checked against `sev`'s own parser by the genuine vector passing).
const FIXTURE_MEASUREMENT: &str = "7a1e5c266c0108dbc9bb94fa926951320940915d0aafb42464bd88b579ea158d3e1a0dc39b2c60bd95b9c480cd81841f";
const FIXTURE_REPORT_DATA: &str = "d447b55d197491bfe15cf298f9de9986b7a7c4be2468b4f6e2d53b71d7c645810b0f2cdfca0040433be063fc1a8293f0f3f8dae7b79fecb3d1cd82bd6a93ebfd";

/// A verifier clock inside the fixture VCEK's real X.509 validity window
/// (`openssl x509 -in testdata/vcek_milan.der -inform der -noout -dates`:
/// notBefore 2023-04-03T19:23:43Z, notAfter 2030-04-03T19:23:43Z — well
/// inside the pinned Milan ARK/ASK's much wider 2020..2045 window too), used
/// by every test that is not specifically exercising the temporal-validity
/// check itself.
const NOW: i64 = 1_750_000_000; // 2025-06-15T18:13:20Z

/// Before the fixture VCEK's `notBefore` (2023-04-03T19:23:43Z) but AFTER the
/// pinned Milan ARK/ASK's own `notBefore` (2020-10-22T17:23:05Z /
/// 2020-10-22T18:24:20Z) — isolates the VCEK-specific rejection from the
/// (correctly stricter, checked first) ARK/ASK window.
const NOW_BEFORE_VCEK_NOT_BEFORE: i64 = 1_650_000_000; // 2022-04-15T05:20:00Z

/// After the fixture VCEK's `notAfter` (2030-04-03T19:23:43Z).
const NOW_AFTER_VCEK_NOT_AFTER: i64 = 1_920_000_000; // 2030-11-04T05:20:00Z

/// Expected values matching the fixture exactly (the genuine case).
fn fixture_expected() -> SnpExpected {
    SnpExpected {
        generation: AmdGeneration::Milan,
        measurement: hex48(FIXTURE_MEASUREMENT),
        host_data: Some([0u8; 32]), // fixture guest launched with zero HOSTDATA
        report_data: hex64(FIXTURE_REPORT_DATA),
        // The fixture's reported TCB: bootloader 3, tee 0, snp 8, microcode 115.
        min_reported_tcb: Some(MinTcb { bootloader: 3, tee: 0, snp: 8, microcode: 115 }),
        vmpl: Some(0),
    }
}

// ── (a) valid report → Genuine ──────────────────────────────────────────────

#[test]
fn genuine_milan_report_chains_to_amd_root() {
    assert_eq!(
        verify_snp_report_without_revocation(&report_bytes(), VCEK_DER, &fixture_expected(), NOW),
        SnpVerdict::Genuine
    );
}

// ── (b) wrong root / tampered signatures → rejected ─────────────────────────

#[test]
fn wrong_amd_root_generation_is_rejected() {
    // Chain a Milan VCEK to the pinned Genoa (and Turin) roots: the "wrong
    // root" case — an attacker cannot pick which AMD key we trust.
    for wrong in [AmdGeneration::Genoa, AmdGeneration::Turin] {
        let exp = SnpExpected { generation: wrong, ..fixture_expected() };
        assert_eq!(
            verify_snp_report_without_revocation(&report_bytes(), VCEK_DER, &exp, NOW),
            SnpVerdict::Rejected(
                "vcek chain — endorsement certificate does not chain to the pinned AMD root"
            )
        );
    }
}

#[test]
fn tampered_vcek_is_rejected() {
    let mut vcek = VCEK_DER.to_vec();
    vcek[40] ^= 0xFF; // corrupt inside the TBS certificate
    assert_eq!(
        verify_snp_report_without_revocation(&report_bytes(), &vcek, &fixture_expected(), NOW),
        SnpVerdict::Rejected(
            "vcek chain — endorsement certificate does not chain to the pinned AMD root"
        )
    );
}

#[test]
fn tampered_report_body_is_rejected() {
    // Flip a bit in the signed region (byte offset 21, inside `family_id` per
    // the AttestationReport / AMD SNP ABI layout — version:u32(0..4) +
    // guest_svn:u32(4..8) + policy:u64(8..16) + family_id:[u8;16](16..32); the
    // same tamper offset virtee's own vector uses): VCEK signature over bytes
    // 0..0x2A0 must fail regardless of which signed field is touched. (A
    // dedicated tamper of the `policy` field's debug bit specifically —
    // offset 10 — lives in `snp.rs`'s own test module, next to the private
    // `policy_forbids_debug` helper it needs for a self-verifying sanity check.)
    let mut report = report_bytes();
    report[21] ^= 0x80;
    assert_eq!(
        verify_snp_report_without_revocation(&report, VCEK_DER, &fixture_expected(), NOW),
        SnpVerdict::Rejected("report signature — report is not signed by the chained VCEK")
    );
}

#[test]
fn tampered_report_signature_is_rejected() {
    // Corrupt the signature itself (it starts at 0x2A0).
    let mut report = report_bytes();
    let sig_at = 0x2A0;
    report[sig_at] ^= 0xFF;
    assert_eq!(
        verify_snp_report_without_revocation(&report, VCEK_DER, &fixture_expected(), NOW),
        SnpVerdict::Rejected("report signature — report is not signed by the chained VCEK")
    );
}

#[test]
fn garbage_inputs_fail_closed() {
    assert!(matches!(
        verify_snp_report_without_revocation(&[0u8; 16], VCEK_DER, &fixture_expected(), NOW),
        SnpVerdict::Rejected(_)
    ));
    assert!(matches!(
        verify_snp_report_without_revocation(&report_bytes(), &[0u8; 16], &fixture_expected(), NOW),
        SnpVerdict::Rejected(_)
    ));
}

// ── (c) measurement / hostdata mismatch → rejected ──────────────────────────

#[test]
fn measurement_mismatch_is_rejected() {
    let mut exp = fixture_expected();
    exp.measurement[0] ^= 0x01;
    assert_eq!(
        verify_snp_report_without_revocation(&report_bytes(), VCEK_DER, &exp, NOW),
        SnpVerdict::Rejected("measurement — not the expected genuine image/boot chain")
    );
}

#[test]
fn hostdata_mismatch_is_rejected() {
    let mut exp = fixture_expected();
    exp.host_data = Some([0x11; 32]); // expect a policy hash the launch didn't pin
    assert_eq!(
        verify_snp_report_without_revocation(&report_bytes(), VCEK_DER, &exp, NOW),
        SnpVerdict::Rejected("hostdata — launch policy binding does not match the audited image")
    );
}

// ── (d) report_data / nonce mismatch → rejected ──────────────────────────────

#[test]
fn report_data_nonce_mismatch_is_rejected() {
    // The verifier expects OUR fresh channel binding; the (real, validly
    // signed) fixture report was bound to something else → replay/relay is
    // refused even though every signature verifies.
    let mut exp = fixture_expected();
    exp.report_data = binding::report_data(&[0x42; 32], &[0x99; 32]);
    assert_eq!(
        verify_snp_report_without_revocation(&report_bytes(), VCEK_DER, &exp, NOW),
        SnpVerdict::Rejected(
            "report_data — nonce/channel binding mismatch (stale, replayed, or relayed report)"
        )
    );
}

#[test]
fn gate_evidence_with_foreign_binding_is_rejected_end_to_end() {
    // Full §4.1 step 3 over the wire format: a MITM presents a REAL report +
    // REAL VCEK but its own pubkey — recomputed binding can't match.
    let evidence = GateEvidence {
        report: report_bytes(),
        vcek_der: VCEK_DER.to_vec(),
        guest_pubkey: vec![0x99; 32], // attacker's key, not what the silicon bound
    };
    let verdict = verify_gate_evidence(
        &evidence,
        &[0x42; 32],
        fixture_expected(),
        &RevocationPolicy::SkipRevocationCheckDangerously,
        NOW,
    );
    assert_eq!(
        verdict,
        SnpVerdict::Rejected(
            "report_data — nonce/channel binding mismatch (stale, replayed, or relayed report)"
        )
    );
}

// ── TCB rollback floor ───────────────────────────────────────────────────────

#[test]
fn stale_tcb_is_rejected() {
    let mut exp = fixture_expected();
    // Demand one component above what the fixture platform reported.
    exp.min_reported_tcb = Some(MinTcb { bootloader: 3, tee: 0, snp: 9, microcode: 115 });
    assert_eq!(
        verify_snp_report_without_revocation(&report_bytes(), VCEK_DER, &exp, NOW),
        SnpVerdict::Rejected("reported tcb — platform firmware below the accepted minimum")
    );
}

#[test]
fn vmpl_mismatch_is_rejected() {
    let mut exp = fixture_expected();
    exp.vmpl = Some(1); // fixture report was requested at VMPL 0
    assert_eq!(
        verify_snp_report_without_revocation(&report_bytes(), VCEK_DER, &exp, NOW),
        SnpVerdict::Rejected("vmpl — report requested from an unexpected privilege level")
    );
}

// ── certificate temporal validity (notBefore/notAfter) ──────────────────────
//
// Closes the gap `snp.rs`'s module docs used to describe: a VCEK past its own
// expiry, or presented before its validity start, must never chain and sign
// successfully unnoticed. All three vectors run the REAL fixture VCEK (whose
// actual X.509 validity is 2023-04-03T19:23:43Z .. 2030-04-03T19:23:43Z)
// through the full entry point at a `now_unix` chosen to land outside (or
// inside) that window — no synthetic cert needed, the fixture's own dates do
// the work.

#[test]
fn expired_vcek_is_rejected() {
    // now_unix is AFTER the fixture VCEK's real notAfter: an otherwise
    // perfectly genuine, chain-valid, field-matching report must still be
    // rejected — a VCEK past its own expiry proves nothing about current
    // silicon state.
    assert_eq!(
        verify_snp_report_without_revocation(
            &report_bytes(),
            VCEK_DER,
            &fixture_expected(),
            NOW_AFTER_VCEK_NOT_AFTER,
        ),
        SnpVerdict::Rejected("vcek validity — endorsement certificate is expired or not yet valid (notBefore/notAfter)")
    );
}

#[test]
fn not_yet_valid_vcek_is_rejected() {
    // now_unix is BEFORE the fixture VCEK's real notBefore: presenting a
    // certificate before its own validity start is symmetric with presenting
    // one after its expiry — both must fail closed.
    assert_eq!(
        verify_snp_report_without_revocation(
            &report_bytes(),
            VCEK_DER,
            &fixture_expected(),
            NOW_BEFORE_VCEK_NOT_BEFORE,
        ),
        SnpVerdict::Rejected("vcek validity — endorsement certificate is expired or not yet valid (notBefore/notAfter)")
    );
}

#[test]
fn in_window_vcek_passes_the_temporal_check() {
    // The positive control: `NOW` (already used by every other vector in this
    // file) sits inside the fixture VCEK's real validity window, so the new
    // check does not regress the existing Genuine vector — restated here,
    // explicitly, as the temporal-validity happy path.
    assert_eq!(
        verify_snp_report_without_revocation(&report_bytes(), VCEK_DER, &fixture_expected(), NOW),
        SnpVerdict::Genuine
    );
}
