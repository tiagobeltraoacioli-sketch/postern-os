//! REAL AWS SEV-SNP report verification — the VLEK endorsement path, proven end
//! to end against a genuine captured report.
//!
//! Unlike `tests/snp_vectors.rs` (a VCEK fixture from virtee/sev), the artifacts
//! here were captured **this session from a genuine AWS c6a.large SEV-SNP guest**
//! (AMD Milan, us-east-2, 2026-07-18) via configfs-tsm, with `report_data` bound
//! to our own 64-byte channel-binding nonce:
//!   * `testdata/aws_snp_report_milan.bin` — the 1184-byte SNP attestation report
//!     (report version 5, VMPL 0, `signing_key = VLEK`).
//!   * `testdata/aws_vlek_milan.der` — the endorsement certificate AWS provided.
//!     It is a **VLEK**, not a VCEK: subject CN `SEV-VLEK`, issuer
//!     `SEV-VLEK-Milan` (the AMD ASVK). This is exactly why the VCEK-only
//!     verifier used to reject a real AWS report at the chain step.
//!   * `testdata/aws_snp_nonce_milan.hex` — our 64-byte nonce, which the silicon
//!     placed verbatim into the report's `report_data`.
//!
//! What this proves that the VCEK vectors cannot: the VLEK → ASVK → ARK chain
//! actually validates against the **pinned** AMD SEV-VLEK ASVK (vendored from
//! AMD KDS, see `src/snp.rs`), the VLEK signs this exact report body, and the
//! report's `report_data` equals *our* nonce — a genuine Genuine, produced by a
//! real signature chain, on hardware we did not launch but whose endorsement AMD
//! rooted. The tamper vector below flips a VLEK signature byte and shows the
//! path fails closed, so the VLEK chain is adversarially covered like the VCEK.
//!
//! Run: cargo test -p postern-seal-companion --features sev-snp

use postern_seal_companion::snp::{
    verify_snp_report_without_revocation, AmdGeneration, MinTcb, SnpExpected, SnpVerdict,
};

const REPORT: &[u8] = include_bytes!("../testdata/aws_snp_report_milan.bin");
const VLEK_DER: &[u8] = include_bytes!("../testdata/aws_vlek_milan.der");
/// Our channel-binding nonce (hex) — the exact value the guest bound into the
/// report's `report_data` when we requested it over the bound channel.
const NONCE_HEX: &str = include_str!("../testdata/aws_snp_nonce_milan.hex");

/// The report's own launch measurement, read verbatim from the captured report
/// (offset 0x90, 48 bytes) — the boot chain AWS launched this guest under. As
/// with the VCEK fixture, the Genuine case's expected values are the silicon's
/// own; the field COMPARISONS are proven by the mismatch vectors below.
const REPORT_MEASUREMENT: &str =
    "507e82d27ea5b951dd765a3eb31ba5f582673b301d6983ded482d3feb066cb68979f1f11fede97687374d3a25002a15f";

/// A verifier clock INSIDE the captured VLEK's real X.509 validity window
/// (notBefore 2026-03-09T19:30:05Z, notAfter 2027-03-09T19:30:05Z — from
/// `openssl x509 -in testdata/aws_vlek_milan.der -inform der -noout -dates`),
/// and also inside the pinned ARK/ASVK windows. 2026-07-18T00:00:00Z.
const NOW_IN_WINDOW: i64 = 1_784_332_800;

/// Before the captured VLEK's notBefore (2026-03-09T19:30:05Z ≈ 1_773_084_605).
const NOW_BEFORE_VLEK: i64 = 1_760_000_000; // 2025-10-09
/// After the captured VLEK's notAfter (2027-03-09T19:30:05Z ≈ 1_804_620_605).
const NOW_AFTER_VLEK: i64 = 1_820_000_000; // 2027-09-01

fn hex_to_vec(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    assert_eq!(s.len() % 2, 0, "hex must be whole bytes");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex48(s: &str) -> [u8; 48] {
    let v = hex_to_vec(s);
    let mut out = [0u8; 48];
    out.copy_from_slice(&v);
    out
}

fn nonce64() -> [u8; 64] {
    let v = hex_to_vec(NONCE_HEX);
    assert_eq!(v.len(), 64, "channel-binding nonce must be exactly 64 bytes");
    let mut out = [0u8; 64];
    out.copy_from_slice(&v);
    out
}

/// The expected values for the genuine AWS guest: the VLEK generation is Milan,
/// the measurement is the report's own boot chain, `report_data` is OUR nonce
/// (channel binding), HOSTDATA is what the AWS launch pinned (zero), the TCB
/// floor is at the platform's reported baseline, and the report is requested at
/// VMPL 0.
fn aws_expected() -> SnpExpected {
    SnpExpected {
        generation: AmdGeneration::Milan,
        measurement: hex48(REPORT_MEASUREMENT),
        host_data: Some([0u8; 32]), // this AWS guest launched with zero HOSTDATA
        report_data: nonce64(),     // the silicon bound our nonce verbatim
        // The captured platform's reported TCB: bootloader 4, tee 0, snp 29,
        // microcode 222 — floor set at (not above) the observed baseline.
        min_reported_tcb: Some(MinTcb { bootloader: 4, tee: 0, snp: 29, microcode: 222 }),
        vmpl: Some(0),
    }
}

// ── the headline: a REAL AWS VLEK report verifies Genuine ───────────────────

#[test]
fn verify_real_aws_sev_snp_report() {
    // Revocation is waived here (the loudly-named entry) exactly as the VCEK
    // offline vectors do — a real AMD-KDS VLEK CRL cannot be minted offline, and
    // its own crypto is exercised in tests/snp_crl.rs. Everything else — the
    // full VLEK → ASVK → ARK chain to the PINNED AMD root, the VLEK signature
    // over this exact report body, report_data == our nonce, measurement, VMPL,
    // TCB floor, temporal validity — must actually validate to reach Genuine.
    let verdict =
        verify_snp_report_without_revocation(REPORT, VLEK_DER, &aws_expected(), NOW_IN_WINDOW);
    assert_eq!(
        verdict,
        SnpVerdict::Genuine,
        "the real AWS SEV-SNP VLEK report must verify Genuine (got {verdict:?})"
    );
}

// ── adversarial coverage of the VLEK path (mirrors the VCEK vectors) ─────────

#[test]
fn tampered_vlek_signature_is_rejected() {
    // Flip a byte of the report's SIGNATURE (starts at 0x2A0) — the VLEK no
    // longer signs this body, so the path must fail closed at the signature
    // check. This covers the VLEK signature path adversarially, as
    // `tests/snp_vectors.rs` does for the VCEK.
    let mut report = REPORT.to_vec();
    report[0x2A0] ^= 0xFF;
    assert_eq!(
        verify_snp_report_without_revocation(&report, VLEK_DER, &aws_expected(), NOW_IN_WINDOW),
        SnpVerdict::Rejected("report signature — report is not signed by the chained VLEK")
    );
}

#[test]
fn tampered_vlek_cert_breaks_the_chain() {
    // Corrupt the TBS of the VLEK cert itself: it no longer chains through the
    // pinned ASVK to the AMD root.
    let mut vlek = VLEK_DER.to_vec();
    vlek[40] ^= 0xFF;
    assert_eq!(
        verify_snp_report_without_revocation(REPORT, &vlek, &aws_expected(), NOW_IN_WINDOW),
        SnpVerdict::Rejected(
            "vlek chain — endorsement certificate does not chain to the pinned AMD root"
        )
    );
}

#[test]
fn real_report_bound_to_a_different_nonce_is_rejected() {
    // Replay/relay defense on the real report: demand a nonce the silicon did
    // NOT bind → report_data mismatch, even though every signature verifies.
    let mut exp = aws_expected();
    exp.report_data = [0x5A; 64];
    assert_eq!(
        verify_snp_report_without_revocation(REPORT, VLEK_DER, &exp, NOW_IN_WINDOW),
        SnpVerdict::Rejected(
            "report_data — nonce/channel binding mismatch (stale, replayed, or relayed report)"
        )
    );
}

#[test]
fn wrong_measurement_is_rejected() {
    let mut exp = aws_expected();
    exp.measurement[0] ^= 0x01;
    assert_eq!(
        verify_snp_report_without_revocation(REPORT, VLEK_DER, &exp, NOW_IN_WINDOW),
        SnpVerdict::Rejected("measurement — not the expected genuine image/boot chain")
    );
}

#[test]
fn vlek_outside_its_validity_window_is_rejected() {
    // The VLEK's real validity is 2026-03-09 .. 2027-03-09. Before and after
    // both fail closed — a VLEK past its window proves nothing about current
    // silicon state, exactly like the VCEK temporal check.
    for now in [NOW_BEFORE_VLEK, NOW_AFTER_VLEK] {
        assert_eq!(
            verify_snp_report_without_revocation(REPORT, VLEK_DER, &aws_expected(), now),
            SnpVerdict::Rejected(
                "vcek validity — endorsement certificate is expired or not yet valid (notBefore/notAfter)"
            ),
            "now={now} is outside the VLEK window and must be rejected"
        );
    }
}

#[test]
fn vlek_chained_to_the_wrong_generation_root_is_rejected() {
    // A Milan VLEK presented against the pinned Genoa/Turin ASVK+ARK must not
    // chain — an attacker cannot pick which AMD generation root we trust.
    for wrong in [AmdGeneration::Genoa, AmdGeneration::Turin] {
        let exp = SnpExpected { generation: wrong, ..aws_expected() };
        assert_eq!(
            verify_snp_report_without_revocation(REPORT, VLEK_DER, &exp, NOW_IN_WINDOW),
            SnpVerdict::Rejected(
                "vlek chain — endorsement certificate does not chain to the pinned AMD root"
            )
        );
    }
}
