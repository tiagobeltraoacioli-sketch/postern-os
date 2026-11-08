// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs

//! AMD-KDS CRL freshness / revocation vectors for the SEV-SNP verifier — the
//! step that closes the earlier "no CRL refresh" gap (`snp.rs` header).
//!
//! Three layers are proven, offline, with NO AMD hardware or secrets:
//!
//!  1. **The CRL crypto is real** (`check_crl_against_issuer`): against a
//!     SYNTHETIC issuer we control, a well-formed CRL that is signed by the
//!     issuer, fresh, and does not list the VCEK → `Ok`; and each of the four
//!     failure modes — a listed (revoked) serial, an elapsed `nextUpdate`, a
//!     wrong-issuer signature, and malformed DER — is caught. The signature and
//!     revocation checks are genuine `x509-parser`/ring verification, not stubs.
//!  2. **The pinned path fails closed** (`verify_snp_report_with_crl`): an
//!     otherwise-`Genuine` real Milan report is rejected once a CRL that cannot
//!     be authenticated by AMD's *pinned* ASK is supplied — we cannot forge a
//!     CRL under AMD's key, which is exactly the honest guarantee. `Genuine`
//!     under the pinned ASK needs a real AMD-KDS CRL, fetched out of band.
//!  3. **The DEFAULT entry is safe-by-construction** (`verify_snp_report` with a
//!     `RevocationPolicy`): using `EnforceWithIssuer` against a synthetic issuer
//!     and the REAL fixture VCEK, a revoked serial → `Rejected(revoked)`, an
//!     unrevoked serial → `Genuine`, a stale CRL → `Rejected(stale)`, and a
//!     revocation-required-but-absent policy → fail closed. This pins the
//!     footgun fix: a revoked VCEK cannot pass by omission.
//!
//! Run: cargo test -p postern-seal-companion --features sev-snp

use postern_seal_companion::snp::{
    check_crl_against_issuer, verify_snp_report, verify_snp_report_with_crl,
    verify_snp_report_without_revocation, AmdGeneration, CrlError, KdsCrl, MinTcb, RevocationPolicy,
    SnpExpected, SnpVerdict,
};

use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, IsCa, KeyIdMethod,
    KeyPair, KeyUsagePurpose, RevokedCertParams, SerialNumber, PKCS_ECDSA_P256_SHA256,
};
use time::OffsetDateTime;

// Fixed instants for the freshness comparison (seconds since the Unix epoch).
const THIS_UPDATE: i64 = 1_700_000_000;
const NEXT_UPDATE: i64 = 1_800_000_000;
const NOW_FRESH: i64 = 1_750_000_000; // between this/next update
const NOW_STALE: i64 = 1_900_000_000; // past nextUpdate

// A VCEK serial with a clear high bit (< 0x80) so DER encodes it without a
// sign-padding byte — keeps the raw-serial byte comparison unambiguous.
const VCEK_SERIAL: &[u8] = &[0x0A, 0x11, 0x22, 0x33];

fn dt(ts: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(ts).unwrap()
}

/// A synthetic issuer CA (the ASK analogue) with a P-256 key.
fn issuer_ca(cn: &str) -> (rcgen::Certificate, KeyPair) {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(vec![cn.to_string()]).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let cert = p.self_signed(&key).unwrap();
    (cert, key)
}

/// A VCEK-analogue leaf cert with `serial`, signed by `issuer`.
fn vcek_cert(serial: &[u8], issuer: &rcgen::Certificate, issuer_key: &KeyPair) -> Vec<u8> {
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(vec!["vcek.example".to_string()]).unwrap();
    p.serial_number = Some(SerialNumber::from_slice(serial));
    let cert = p.signed_by(&leaf_key, issuer, issuer_key).unwrap();
    cert.der().as_ref().to_vec()
}

/// A CRL signed by `issuer`, valid [THIS_UPDATE, next_update], optionally
/// listing `revoked` serials.
fn crl(issuer: &rcgen::Certificate, issuer_key: &KeyPair, next_update: i64, revoked: &[&[u8]]) -> Vec<u8> {
    let params = CertificateRevocationListParams {
        this_update: dt(THIS_UPDATE),
        next_update: dt(next_update),
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: revoked
            .iter()
            .map(|s| RevokedCertParams {
                serial_number: SerialNumber::from_slice(s),
                revocation_time: dt(THIS_UPDATE),
                reason_code: None,
                invalidity_date: None,
            })
            .collect(),
        key_identifier_method: KeyIdMethod::Sha256,
    };
    params.signed_by(issuer, issuer_key).unwrap().der().as_ref().to_vec()
}

// ── (1) the CRL crypto, against a synthetic issuer we control ────────────────

#[test]
fn fresh_crl_without_the_vcek_is_accepted() {
    let (ca, ca_key) = issuer_ca("Postern Test ASK");
    let vcek = vcek_cert(VCEK_SERIAL, &ca, &ca_key);
    let crl = crl(&ca, &ca_key, NEXT_UPDATE, &[]);
    assert_eq!(
        check_crl_against_issuer(&crl, ca.der(), &vcek, NOW_FRESH),
        Ok(())
    );
}

#[test]
fn revoked_vcek_serial_is_caught() {
    let (ca, ca_key) = issuer_ca("Postern Test ASK");
    let vcek = vcek_cert(VCEK_SERIAL, &ca, &ca_key);
    // The same serial now appears on the CRL.
    let crl = crl(&ca, &ca_key, NEXT_UPDATE, &[VCEK_SERIAL]);
    assert_eq!(
        check_crl_against_issuer(&crl, ca.der(), &vcek, NOW_FRESH),
        Err(CrlError::Revoked)
    );
}

#[test]
fn a_different_revoked_serial_does_not_false_positive() {
    let (ca, ca_key) = issuer_ca("Postern Test ASK");
    let vcek = vcek_cert(VCEK_SERIAL, &ca, &ca_key);
    let crl = crl(&ca, &ca_key, NEXT_UPDATE, &[&[0x44, 0x55, 0x66]]);
    assert_eq!(check_crl_against_issuer(&crl, ca.der(), &vcek, NOW_FRESH), Ok(()));
}

#[test]
fn stale_crl_is_rejected() {
    let (ca, ca_key) = issuer_ca("Postern Test ASK");
    let vcek = vcek_cert(VCEK_SERIAL, &ca, &ca_key);
    let crl = crl(&ca, &ca_key, NEXT_UPDATE, &[]);
    // now is PAST the CRL's nextUpdate — a stale CRL must not be honoured.
    assert_eq!(
        check_crl_against_issuer(&crl, ca.der(), &vcek, NOW_STALE),
        Err(CrlError::Stale)
    );
}

#[test]
fn crl_signed_by_a_foreign_issuer_is_rejected() {
    let (ca, ca_key) = issuer_ca("Postern Test ASK");
    let (foreign, foreign_key) = issuer_ca("Impostor ASK");
    let vcek = vcek_cert(VCEK_SERIAL, &ca, &ca_key);
    // CRL is signed by `foreign`, but we anchor to the real `ca` → bad signature.
    let crl = crl(&foreign, &foreign_key, NEXT_UPDATE, &[]);
    assert_eq!(
        check_crl_against_issuer(&crl, ca.der(), &vcek, NOW_FRESH),
        Err(CrlError::BadSignature)
    );
}

#[test]
fn malformed_crl_der_fails_closed() {
    let (ca, ca_key) = issuer_ca("Postern Test ASK");
    let vcek = vcek_cert(VCEK_SERIAL, &ca, &ca_key);
    assert!(matches!(
        check_crl_against_issuer(&[0xDE, 0xAD, 0xBE, 0xEF], ca.der(), &vcek, NOW_FRESH),
        Err(CrlError::Malformed(_))
    ));
}

#[test]
fn crl_error_reasons_are_named() {
    for e in [
        CrlError::PinnedIssuerUnavailable,
        CrlError::Malformed("crl"),
        CrlError::BadSignature,
        CrlError::Stale,
        CrlError::Revoked,
    ] {
        assert!(!e.to_string().is_empty());
    }
}

// ── (2) the pinned path fails closed on an unauthenticatable CRL ─────────────

const REPORT_HEX: &str = include_str!("../testdata/report_milan.hex");
const VCEK_DER: &[u8] = include_bytes!("../testdata/vcek_milan.der");

fn report_bytes() -> Vec<u8> {
    let s: String = REPORT_HEX.chars().filter(|c| c.is_ascii_hexdigit()).collect();
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

fn fixture_expected() -> SnpExpected {
    SnpExpected {
        generation: AmdGeneration::Milan,
        measurement: hex48("7a1e5c266c0108dbc9bb94fa926951320940915d0aafb42464bd88b579ea158d3e1a0dc39b2c60bd95b9c480cd81841f"),
        host_data: Some([0u8; 32]),
        report_data: hex64("d447b55d197491bfe15cf298f9de9986b7a7c4be2468b4f6e2d53b71d7c645810b0f2cdfca0040433be063fc1a8293f0f3f8dae7b79fecb3d1cd82bd6a93ebfd"),
        min_reported_tcb: Some(MinTcb { bootloader: 3, tee: 0, snp: 8, microcode: 115 }),
        vmpl: Some(0),
    }
}

#[test]
fn genuine_report_with_unauthenticatable_crl_fails_closed() {
    // A synthetic CRL cannot be signed by AMD's PINNED ASK (AMD holds that key),
    // so the CRL step of the pinned path must reject the otherwise-Genuine
    // report. This is the honest guarantee: we cannot mint a passing CRL offline.
    let (ca, ca_key) = issuer_ca("Not the AMD ASK");
    let synthetic_crl = crl(&ca, &ca_key, NEXT_UPDATE, &[]);
    let kds = KdsCrl { crl_der: synthetic_crl, now_unix: NOW_FRESH };

    let verdict = verify_snp_report_with_crl(&report_bytes(), VCEK_DER, &fixture_expected(), &kds);
    assert_eq!(
        verdict,
        SnpVerdict::Rejected("kds crl — CRL is not signed by the pinned AMD ASK")
    );
}

#[test]
fn crl_step_only_runs_after_the_report_is_otherwise_genuine() {
    // If the report itself is rejected (wrong measurement), the CRL never
    // masks or changes that reason — the report verdict wins.
    let (ca, ca_key) = issuer_ca("Not the AMD ASK");
    let kds = KdsCrl { crl_der: crl(&ca, &ca_key, NEXT_UPDATE, &[]), now_unix: NOW_FRESH };
    let mut exp = fixture_expected();
    exp.measurement[0] ^= 0x01;
    assert_eq!(
        verify_snp_report_with_crl(&report_bytes(), VCEK_DER, &exp, &kds),
        SnpVerdict::Rejected("measurement — not the expected genuine image/boot chain")
    );
}

// ── (3) the DEFAULT entry is safe-by-construction ────────────────────────────
//
// These pin the footgun fix itself: the primary `verify_snp_report` takes a
// `RevocationPolicy`, so a revoked VCEK cannot pass by omission. `EnforceWithIssuer`
// lets us drive the *real* revocation crypto end-to-end against a synthetic
// issuer while still using the REAL fixture VCEK (which chains to AMD's pinned
// root, so chain+fields pass and revocation actually runs).

/// The fixture Milan VCEK's serial, exactly as `x509-parser` reads it — the same
/// `raw_serial()` the verifier compares against the CRL entries.
fn fixture_vcek_serial() -> Vec<u8> {
    use x509_parser::prelude::FromDer;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(VCEK_DER).unwrap();
    cert.raw_serial().to_vec()
}

#[test]
fn default_entry_rejects_a_revoked_fixture_vcek() {
    // The default verify entry, handed a (synthetic-issuer) CRL that lists the
    // fixture VCEK's own serial, must return the named revoked verdict — not
    // Genuine. This is the whole point: revocation is on the default path.
    let (ca, ca_key) = issuer_ca("Synthetic Test ASK");
    let serial = fixture_vcek_serial();
    let crl_der = crl(&ca, &ca_key, NEXT_UPDATE, &[&serial]);
    let kds = KdsCrl { crl_der, now_unix: NOW_FRESH };

    let verdict = verify_snp_report(
        &report_bytes(),
        VCEK_DER,
        &fixture_expected(),
        &RevocationPolicy::EnforceWithIssuer { crl: &kds, issuer_der: ca.der() },
        NOW_FRESH,
    );
    assert_eq!(verdict, SnpVerdict::Rejected("kds crl — VCEK is revoked by AMD KDS"));
}

#[test]
fn default_entry_accepts_an_unrevoked_fixture_vcek() {
    // The mirror: a fresh CRL under the same issuer that does NOT list the
    // fixture serial lets the otherwise-Genuine report through. valid → Genuine.
    let (ca, ca_key) = issuer_ca("Synthetic Test ASK");
    let crl_der = crl(&ca, &ca_key, NEXT_UPDATE, &[&[0x44, 0x55, 0x66]]);
    let kds = KdsCrl { crl_der, now_unix: NOW_FRESH };

    let verdict = verify_snp_report(
        &report_bytes(),
        VCEK_DER,
        &fixture_expected(),
        &RevocationPolicy::EnforceWithIssuer { crl: &kds, issuer_der: ca.der() },
        NOW_FRESH,
    );
    assert_eq!(verdict, SnpVerdict::Genuine);
}

#[test]
fn default_entry_with_revocation_required_but_no_crl_fails_closed() {
    // "Given no CRL, the default must refuse rather than silently accept."
    // A caller that wants revocation but has no CRL in hand gets a fail-closed
    // verdict — never Genuine.
    let verdict = verify_snp_report(
        &report_bytes(),
        VCEK_DER,
        &fixture_expected(),
        &RevocationPolicy::RequireButMissing,
        NOW_FRESH,
    );
    assert_eq!(
        verdict,
        SnpVerdict::Rejected(
            "revocation — required but no AMD-KDS CRL supplied; fetch it out of band (fail closed)"
        )
    );
    // There is no CRL-less way to reach Genuine except the loudly-named opt-out.
    assert_eq!(
        verify_snp_report_without_revocation(&report_bytes(), VCEK_DER, &fixture_expected(), NOW_FRESH),
        SnpVerdict::Genuine
    );
}

#[test]
fn default_entry_fails_closed_on_a_stale_revocation_crl() {
    // Freshness is enforced on the default path too: a stale CRL (nextUpdate
    // elapsed) cannot be replayed to hide a later revocation.
    let (ca, ca_key) = issuer_ca("Synthetic Test ASK");
    let crl_der = crl(&ca, &ca_key, NEXT_UPDATE, &[]);
    let kds = KdsCrl { crl_der, now_unix: NOW_STALE };
    let verdict = verify_snp_report(
        &report_bytes(),
        VCEK_DER,
        &fixture_expected(),
        &RevocationPolicy::EnforceWithIssuer { crl: &kds, issuer_der: ca.der() },
        NOW_STALE,
    );
    assert_eq!(
        verdict,
        SnpVerdict::Rejected("kds crl — CRL is stale (nextUpdate elapsed); refresh from AMD KDS")
    );
}
