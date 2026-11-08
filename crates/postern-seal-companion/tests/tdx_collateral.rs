// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs

//! Intel PCS/DCAP collateral-chain vectors for the TDX verifier — offline,
//! against a SYNTHETIC but self-consistent DCAP v4 quote (real ECDSA
//! signatures, a real PCK X.509 chain, real CRLs) that we mint here.
//!
//! What these DO prove (with genuine `x509-parser`/ring + `p256` verification,
//! never a stub): given collateral, [`verify_collateral_anchored`] returns `Ok`
//! for a well-formed quote whose PCK chain terminates at the supplied anchor,
//! whose QE-report binding + QE-report signature + quote signature all check
//! out, and whose CRLs are fresh and clean — and it fails closed on a tampered
//! quote signature, a tampered QE-report signature, a broken QE binding, a
//! non-anchored root, a revoked PCK, a stale CRL, and an expired PCK leaf cert
//! (the `notBefore`/`notAfter` window check, independent of CRL freshness).
//!
//! What they DELIBERATELY do NOT prove (the rails): a `Genuine` verdict on real
//! Intel silicon. The PUBLIC pinned entry `verify_td_quote_with_collateral`
//! anchors to Intel's genuine, now-populated SGX Root CA
//! (`PINNED_INTEL_SGX_ROOT_CA_DER`) — but our synthetic quote chains to OUR test
//! root, so against the pinned entry it fails closed at `RootNotAnchored` (no
//! longer `PinnedRootUnset`). Reaching `Genuine` needs a genuine Intel TDX quote
//! from silicon we launched (hardware-gated); this code has never run against a
//! quote from TEE hardware we control. Two tests below assert the pinned root
//! now parses as a self-signed Intel X.509 root and that a synthetic quote hits
//! `RootNotAnchored` — proving the placeholder no longer swallows the path.
//!
//! Run: cargo test -p postern-seal-companion --features tdx-verify

use postern_seal_companion::tdx::{
    check_bound_fields, parse_td_quote, verify_collateral_anchored, verify_collateral_dcap,
    verify_td_quote_with_collateral, TdxCollateral, TdxCollateralError, TdxExpected,
    TdxJsonCollateral, PINNED_INTEL_SGX_ROOT_CA_DER,
};

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CustomExtension, IsCa,
    KeyIdMethod, KeyPair, KeyUsagePurpose, RevokedCertParams, SerialNumber, PKCS_ECDSA_P256_SHA256,
};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

// Quote layout (must match tdx.rs).
const HEADER_LEN: usize = 48;
const TD_BODY_LEN: usize = 584;
const QUOTE_VERSION_V4: u16 = 4;
const TEE_TYPE_TDX: u32 = 0x0000_0081;
const QE_REPORT_LEN: usize = 384;
const QE_REPORT_DATA_OFF: usize = 320;

// CRL freshness clock.
const THIS_UPDATE: i64 = 1_700_000_000;
const NEXT_UPDATE: i64 = 1_800_000_000;
const NOW_FRESH: i64 = 1_750_000_000;
const NOW_STALE: i64 = 1_900_000_000;

const INTER_SERIAL: &[u8] = &[0x0B, 0x01];
const LEAF_SERIAL: &[u8] = &[0x0C, 0x02];

fn dt(ts: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(ts).unwrap()
}

/// A rcgen CA (or leaf) + a p256 SigningKey derived from the SAME key, so the
/// cert's subject public key matches what we raw-sign with.
struct Node {
    cert: rcgen::Certificate,
    key: KeyPair,
    signer: SigningKey,
}

fn p256_signer(key: &KeyPair) -> SigningKey {
    SigningKey::from_pkcs8_der(&key.serialize_der()).unwrap()
}

fn ca(cn: &str, serial: Option<&[u8]>, issuer: Option<&Node>, not_after: Option<i64>) -> Node {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(vec![cn.to_string()]).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    if let Some(s) = serial {
        p.serial_number = Some(SerialNumber::from_slice(s));
    }
    // `not_after`, when supplied, overrides rcgen's far-future default expiry —
    // how the expired-intermediate / expired-root vectors mint a CA cert that is
    // genuinely, structurally expired at the verifier's `now_unix`.
    if let Some(na) = not_after {
        p.not_after = dt(na);
    }
    let cert = match issuer {
        None => p.self_signed(&key).unwrap(),
        Some(iss) => p.signed_by(&key, &iss.cert, &iss.key).unwrap(),
    };
    let signer = p256_signer(&key);
    Node { cert, key, signer }
}

/// `not_after`, when supplied, overrides rcgen's (very permissive, ~2096) default
/// expiry — how the `expired_pck_leaf_is_rejected` vector below mints a PCK leaf
/// that is genuinely, structurally expired at the verifier's `now_unix`.
fn leaf(cn: &str, serial: &[u8], issuer: &Node, not_after: Option<i64>) -> Node {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(vec![cn.to_string()]).unwrap();
    p.serial_number = Some(SerialNumber::from_slice(serial));
    if let Some(na) = not_after {
        p.not_after = dt(na);
    }
    let cert = p.signed_by(&key, &issuer.cert, &issuer.key).unwrap();
    let signer = p256_signer(&key);
    Node { cert, key, signer }
}

fn crl(issuer: &Node, next_update: i64, revoked: &[&[u8]]) -> Vec<u8> {
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
    params.signed_by(&issuer.cert, &issuer.key).unwrap().der().as_ref().to_vec()
}

/// Raw 64-byte r‖s ECDSA-P256 signature over `msg` (SHA-256, deterministic).
fn sign(signer: &SigningKey, msg: &[u8]) -> [u8; 64] {
    let sig: Signature = signer.sign(msg);
    let mut out = [0u8; 64];
    out.copy_from_slice(&sig.to_bytes());
    out
}

fn att_pub_raw(signer: &SigningKey) -> [u8; 64] {
    let ep = signer.verifying_key().to_encoded_point(false);
    let bytes = ep.as_bytes(); // 0x04 ‖ x ‖ y (65)
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes[1..]);
    out
}

/// Base64-wrap a DER certificate back into a PEM block. Used only by the
/// tampered-intermediate vector, which flips a byte of a cert's DER signature
/// and must re-emit it as the PEM the verifier consumes (rcgen only PEM-encodes
/// certs it minted, so a hand-tampered DER needs its own encoder).
fn der_to_pem(der: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::new();
    for chunk in der.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        b64.push(A[((n >> 18) & 63) as usize] as char);
        b64.push(A[((n >> 12) & 63) as usize] as char);
        b64.push(if chunk.len() > 1 { A[((n >> 6) & 63) as usize] as char } else { '=' });
        b64.push(if chunk.len() > 2 { A[(n & 63) as usize] as char } else { '=' });
    }
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// A whole synthetic DCAP v4 TDX quote + matching collateral, all knobs open so
/// individual tamper tests can perturb one thing.
struct Built {
    quote: Vec<u8>,
    collateral: TdxCollateral,
    root_der: Vec<u8>,
}

struct Knobs {
    tee_tcb_svn: [u8; 16],
    root_crl_next: i64,
    pck_crl_next: i64,
    revoke_leaf: bool,
    now: i64,
    tcb_floor: Option<[u8; 16]>,
    /// `Some(ts)` mints the PCK leaf with `not_after = ts` instead of rcgen's
    /// default far-future expiry — the expired-PCK-cert adversarial vector.
    pck_not_after: Option<i64>,
    /// `Some(ts)` mints the PCK **intermediate** CA with `not_after = ts` — the
    /// expired-intermediate adversarial vector (only the leaf was covered before).
    inter_not_after: Option<i64>,
    /// `Some(ts)` mints the PCK **root** CA with `not_after = ts` — the
    /// expired-root adversarial vector.
    root_not_after: Option<i64>,
}
impl Default for Knobs {
    fn default() -> Self {
        Knobs {
            tee_tcb_svn: [0u8; 16],
            root_crl_next: NEXT_UPDATE,
            pck_crl_next: NEXT_UPDATE,
            revoke_leaf: false,
            now: NOW_FRESH,
            tcb_floor: None,
            pck_not_after: None,
            inter_not_after: None,
            root_not_after: None,
        }
    }
}

fn build(k: &Knobs) -> Built {
    let root = ca("Test SGX Root CA", None, None, k.root_not_after);
    let inter = ca("Test SGX PCK Processor CA", Some(INTER_SERIAL), Some(&root), k.inter_not_after);
    let pck = leaf("Test PCK Leaf", LEAF_SERIAL, &inter, k.pck_not_after);

    // Default embedded PCK PEM chain: leaf ‖ intermediate ‖ root. The structural
    // adversarial vectors (2-cert chain, tampered intermediate) call `assemble`
    // directly with a perturbed chain instead of this.
    let mut pck_pem = pck.cert.pem();
    pck_pem.push_str(&inter.cert.pem());
    pck_pem.push_str(&root.cert.pem());
    assemble(k, &root, &inter, &pck, pck_pem.into_bytes())
}

/// Assemble a full synthetic DCAP v4 quote + collateral from already-minted
/// cert nodes and an explicit embedded PCK PEM chain. Split out of [`build`] so
/// the chain-structure adversarial vectors can pass a truncated or tampered PEM
/// while every signature (AK over header‖body, PCK over the QE report) stays
/// self-consistent with the supplied nodes.
fn assemble(k: &Knobs, root: &Node, inter: &Node, pck: &Node, pck_pem: Vec<u8>) -> Built {
    let att = SigningKey::from_pkcs8_der(
        &KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap().serialize_der(),
    )
    .unwrap();

    // Header.
    let mut header = vec![0u8; HEADER_LEN];
    header[0..2].copy_from_slice(&QUOTE_VERSION_V4.to_le_bytes());
    header[4..8].copy_from_slice(&TEE_TYPE_TDX.to_le_bytes());

    // TD body (TEE_TCB_SVN at [0..16]).
    let mut td_body = vec![0u8; TD_BODY_LEN];
    td_body[0..16].copy_from_slice(&k.tee_tcb_svn);

    // Attestation key signs header ‖ td_body.
    let mut signed_region = header.clone();
    signed_region.extend_from_slice(&td_body);
    let ak_raw = att_pub_raw(&att);
    let quote_sig = sign(&att, &signed_region);

    // QE report: report_data = SHA-256(att_pub ‖ qe_auth).
    let qe_auth: Vec<u8> = vec![0xA5; 8];
    let mut qe_report = vec![0u8; QE_REPORT_LEN];
    let mut h = Sha256::new();
    h.update(ak_raw);
    h.update(&qe_auth);
    qe_report[QE_REPORT_DATA_OFF..QE_REPORT_DATA_OFF + 32].copy_from_slice(&h.finalize());
    // PCK signs the QE report.
    let qe_report_sig = sign(&pck.signer, &qe_report);

    // outer cert data (type 6): qe_report ‖ qe_report_sig ‖ qe_auth ‖ pck cert(5)
    let mut outer = Vec::new();
    outer.extend_from_slice(&qe_report);
    outer.extend_from_slice(&qe_report_sig);
    outer.extend_from_slice(&(qe_auth.len() as u16).to_le_bytes());
    outer.extend_from_slice(&qe_auth);
    outer.extend_from_slice(&5u16.to_le_bytes()); // PCK_CERT_CHAIN
    outer.extend_from_slice(&(pck_pem.len() as u32).to_le_bytes());
    outer.extend_from_slice(&pck_pem);

    // sig_data: sig ‖ att_pub ‖ outer{type 6, size, data}
    let mut sig_data = Vec::new();
    sig_data.extend_from_slice(&quote_sig);
    sig_data.extend_from_slice(&ak_raw);
    sig_data.extend_from_slice(&6u16.to_le_bytes()); // QE_REPORT_CERTIFICATION_DATA
    sig_data.extend_from_slice(&(outer.len() as u32).to_le_bytes());
    sig_data.extend_from_slice(&outer);

    // Full quote: header ‖ td_body ‖ sig_data_len ‖ sig_data
    let mut quote = signed_region;
    quote.extend_from_slice(&(sig_data.len() as u32).to_le_bytes());
    quote.extend_from_slice(&sig_data);

    let revoked_leaf: Vec<&[u8]> = if k.revoke_leaf { vec![LEAF_SERIAL] } else { vec![] };
    let collateral = TdxCollateral {
        root_ca_crl_der: Some(crl(&root, k.root_crl_next, &[])),
        pck_crl_der: Some(crl(&inter, k.pck_crl_next, &revoked_leaf)),
        now_unix: k.now,
        tcb_svn_floor: k.tcb_floor,
        // The TCB-Info/QE-Identity JSON checks have their own self-contained
        // scene builder + vector block at the bottom of this file; the chain /
        // CRL / signature vectors above run with JSON collateral waived (None).
        json: None,
    };

    Built { quote, collateral, root_der: root.cert.der().as_ref().to_vec() }
}

// ── happy path ──────────────────────────────────────────────────────────────

#[test]
fn well_formed_quote_verifies_against_the_synthetic_anchor() {
    let b = build(&Knobs::default());
    assert_eq!(
        verify_collateral_anchored(&b.quote, &b.collateral, &b.root_der),
        Ok(())
    );
}

// ── tamper / fail-closed matrix ──────────────────────────────────────────────

#[test]
fn tampered_quote_signature_is_rejected() {
    let b = build(&Knobs::default());
    let mut q = b.quote.clone();
    // Flip a byte of the TD body so the AK signature over header‖body breaks.
    q[HEADER_LEN + 200] ^= 0xFF;
    assert_eq!(
        verify_collateral_anchored(&q, &b.collateral, &b.root_der),
        Err(TdxCollateralError::QuoteSignature)
    );
}

#[test]
fn tampered_qe_report_signature_is_rejected() {
    // Rebuild and flip a byte inside the qe_report_signature only. Locate it:
    // sig_data starts at 632+4; qe_report_sig is at offset 64+64+6 + 384 within
    // sig_data.
    let b = build(&Knobs::default());
    let mut q = b.quote.clone();
    let sig_data_start = HEADER_LEN + TD_BODY_LEN + 4;
    let qe_report_sig_at = sig_data_start + 64 + 64 + 6 + QE_REPORT_LEN;
    q[qe_report_sig_at] ^= 0xFF;
    assert_eq!(
        verify_collateral_anchored(&q, &b.collateral, &b.root_der),
        Err(TdxCollateralError::QeReportSignature)
    );
}

#[test]
fn broken_qe_binding_is_rejected() {
    // Flip a byte of the qe_report's report_data so it no longer equals
    // SHA-256(att_pub ‖ qe_auth). That is checked before the QE signature.
    let b = build(&Knobs::default());
    let mut q = b.quote.clone();
    let sig_data_start = HEADER_LEN + TD_BODY_LEN + 4;
    let qe_report_data_at = sig_data_start + 64 + 64 + 6 + QE_REPORT_DATA_OFF;
    q[qe_report_data_at] ^= 0xFF;
    assert_eq!(
        verify_collateral_anchored(&q, &b.collateral, &b.root_der),
        Err(TdxCollateralError::QeBindingMismatch)
    );
}

#[test]
fn non_anchored_root_is_rejected() {
    let b = build(&Knobs::default());
    // A different, unrelated root — the chain no longer terminates at our anchor.
    let other = ca("Some Other Root", None, None, None);
    assert_eq!(
        verify_collateral_anchored(&b.quote, &b.collateral, other.cert.der().as_ref()),
        Err(TdxCollateralError::RootNotAnchored)
    );
}

#[test]
fn revoked_pck_leaf_is_rejected() {
    let b = build(&Knobs { revoke_leaf: true, ..Knobs::default() });
    assert_eq!(
        verify_collateral_anchored(&b.quote, &b.collateral, &b.root_der),
        Err(TdxCollateralError::Revoked)
    );
}

#[test]
fn stale_pck_crl_is_rejected() {
    let b = build(&Knobs { pck_crl_next: NEXT_UPDATE, now: NOW_STALE, ..Knobs::default() });
    assert!(matches!(
        verify_collateral_anchored(&b.quote, &b.collateral, &b.root_der),
        Err(TdxCollateralError::CrlInvalid(_))
    ));
}

#[test]
fn tcb_below_floor_is_rejected() {
    // Quote reports TEE_TCB_SVN all-zero; floor demands byte 0 >= 5.
    let mut floor = [0u8; 16];
    floor[0] = 5;
    let b = build(&Knobs { tcb_floor: Some(floor), ..Knobs::default() });
    assert_eq!(
        verify_collateral_anchored(&b.quote, &b.collateral, &b.root_der),
        Err(TdxCollateralError::TcbTooLow)
    );
}

#[test]
fn tcb_at_or_above_floor_passes() {
    let mut svn = [0u8; 16];
    svn[0] = 9;
    let mut floor = [0u8; 16];
    floor[0] = 5;
    let b = build(&Knobs { tee_tcb_svn: svn, tcb_floor: Some(floor), ..Knobs::default() });
    assert_eq!(verify_collateral_anchored(&b.quote, &b.collateral, &b.root_der), Ok(()));
}

#[test]
fn expired_pck_leaf_is_rejected() {
    // The PCK leaf's own X.509 notAfter is BEFORE the verifier's now_unix — a
    // fresh, clean CRL (nextUpdate still in the future, serial not listed) is
    // not enough; the cert-expiry check (crate::tdx's mirror of mobile.rs's
    // `certificate validity` check) must catch this independently of CRL state.
    let expired_before_now = NOW_FRESH - 100;
    let b = build(&Knobs { pck_not_after: Some(expired_before_now), ..Knobs::default() });
    assert_eq!(
        verify_collateral_anchored(&b.quote, &b.collateral, &b.root_der),
        Err(TdxCollateralError::CertExpired("pck leaf")),
        "an expired PCK leaf must fail closed even with a fresh, non-revoking CRL",
    );
}

#[test]
fn expired_pck_intermediate_is_rejected() {
    // The PCK INTERMEDIATE CA's own X.509 notAfter is BEFORE the verifier's
    // now_unix, while the leaf stays inside its (far-future) window. The chain
    // signatures still verify (expiry does not break a signature), so this must
    // be caught by the per-link validity check, NAMED as the intermediate — the
    // expired-leaf case tested this only for the leaf before.
    let expired_before_now = NOW_FRESH - 100;
    let b = build(&Knobs { inter_not_after: Some(expired_before_now), ..Knobs::default() });
    assert_eq!(
        verify_collateral_anchored(&b.quote, &b.collateral, &b.root_der),
        Err(TdxCollateralError::CertExpired("pck intermediate CA")),
        "an expired PCK intermediate CA must fail closed even with a fresh CRL",
    );
}

#[test]
fn expired_pck_root_is_rejected() {
    // The PCK ROOT CA's own X.509 notAfter is BEFORE the verifier's now_unix,
    // while leaf and intermediate stay valid. The root's self-signature still
    // verifies and it is still the anchored root — expiry is independent of both,
    // so it must be caught by the per-link validity check, NAMED as the root.
    let expired_before_now = NOW_FRESH - 100;
    let b = build(&Knobs { root_not_after: Some(expired_before_now), ..Knobs::default() });
    assert_eq!(
        verify_collateral_anchored(&b.quote, &b.collateral, &b.root_der),
        Err(TdxCollateralError::CertExpired("pck root CA")),
        "an expired PCK root CA must fail closed even when it is the pinned anchor",
    );
}

#[test]
fn two_cert_pck_chain_missing_root_is_rejected() {
    // The embedded PCK PEM carries only leaf ‖ intermediate — the root is
    // dropped. The verifier requires at least leaf ‖ intermediate ‖ root, so a
    // truncated 2-cert chain is a hard, named BadPckChain (never silently
    // treating the intermediate as its own anchor).
    let root = ca("Test SGX Root CA", None, None, None);
    let inter = ca("Test SGX PCK Processor CA", Some(INTER_SERIAL), Some(&root), None);
    let pck = leaf("Test PCK Leaf", LEAF_SERIAL, &inter, None);
    let mut pem = pck.cert.pem();
    pem.push_str(&inter.cert.pem()); // NO root appended
    let b = assemble(&Knobs::default(), &root, &inter, &pck, pem.into_bytes());
    assert_eq!(
        verify_collateral_anchored(&b.quote, &b.collateral, &b.root_der),
        Err(TdxCollateralError::BadPckChain),
        "a 2-cert PCK chain missing the root must fail closed as BadPckChain",
    );
}

#[test]
fn tampered_intermediate_signature_is_rejected() {
    // Flip the trailing byte of the intermediate cert's DER (the tail of its
    // ECDSA signature value) and re-embed it. The intermediate's SUBJECT public
    // key is untouched, so the leaf still verifies against it; but the
    // intermediate's own signature no longer verifies under the (correct,
    // anchored) root's key. That link break is a hard, named ChainInvalid.
    let root = ca("Test SGX Root CA", None, None, None);
    let inter = ca("Test SGX PCK Processor CA", Some(INTER_SERIAL), Some(&root), None);
    let pck = leaf("Test PCK Leaf", LEAF_SERIAL, &inter, None);

    let mut inter_der = inter.cert.der().as_ref().to_vec();
    let n = inter_der.len();
    inter_der[n - 1] ^= 0xFF; // corrupt the last byte of the signature value

    let mut pem = pck.cert.pem();
    pem.push_str(&der_to_pem(&inter_der)); // tampered intermediate
    pem.push_str(&root.cert.pem());
    let b = assemble(&Knobs::default(), &root, &inter, &pck, pem.into_bytes());
    assert_eq!(
        verify_collateral_anchored(&b.quote, &b.collateral, &b.root_der),
        Err(TdxCollateralError::ChainInvalid),
        "an intermediate whose signature was tampered must fail closed as ChainInvalid",
    );
}

// ── malformed / truncated / oversized signature-section vectors ──────────────
// The ECDSA sig-section is a nest of length-prefixed fields; a caller-controlled
// length that under- or over-runs its buffer must be a named MalformedSig(_),
// never an out-of-bounds read or a silently-accepted short section.

#[test]
fn short_sig_data_len_is_malformed() {
    // Shrink the outer sig_data_len (u32 at HEADER‖BODY) so the quote signature
    // itself cannot be read out of the truncated section.
    let b = build(&Knobs::default());
    let mut q = b.quote.clone();
    let sig_data_len_off = HEADER_LEN + TD_BODY_LEN; // 632
    q[sig_data_len_off..sig_data_len_off + 4].copy_from_slice(&10u32.to_le_bytes());
    assert!(
        matches!(
            verify_collateral_anchored(&q, &b.collateral, &b.root_der),
            Err(TdxCollateralError::MalformedSig(_))
        ),
        "a too-short sig_data_len must fail closed as MalformedSig",
    );
}

#[test]
fn oversized_outer_cert_size_is_malformed() {
    // The outer (QE-report certification) size u32 claims far more bytes than the
    // section holds; the bounds-checked take must reject it.
    let b = build(&Knobs::default());
    let mut q = b.quote.clone();
    // sig_data starts at HEADER‖BODY+4; outer_size u32 = sig(64)‖att_pub(64)‖type(2).
    let outer_size_at = HEADER_LEN + TD_BODY_LEN + 4 + 64 + 64 + 2;
    q[outer_size_at..outer_size_at + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    assert!(
        matches!(
            verify_collateral_anchored(&q, &b.collateral, &b.root_der),
            Err(TdxCollateralError::MalformedSig(_))
        ),
        "an oversized outer cert size must fail closed as MalformedSig",
    );
}

#[test]
fn oversized_pck_cert_size_is_malformed() {
    // The inner PCK-chain size u32 claims far more bytes than the outer holds.
    let b = build(&Knobs::default());
    let mut q = b.quote.clone();
    // outer starts at sig_start + sig(64)‖att_pub(64)‖type(2)‖size(4) = +134.
    let outer_start = HEADER_LEN + TD_BODY_LEN + 4 + 64 + 64 + 6;
    // Inside outer: qe_report(384)‖qe_report_sig(64)‖qe_auth_size(2)‖qe_auth(8)
    // ‖pck_type(2) → then the pck_size u32.
    const QE_AUTH_LEN: usize = 8; // build() writes vec![0xA5; 8]
    let pck_size_at = outer_start + QE_REPORT_LEN + 64 + 2 + QE_AUTH_LEN + 2;
    q[pck_size_at..pck_size_at + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    assert!(
        matches!(
            verify_collateral_anchored(&q, &b.collateral, &b.root_der),
            Err(TdxCollateralError::MalformedSig(_))
        ),
        "an oversized PCK cert size must fail closed as MalformedSig",
    );
}

#[test]
fn missing_collateral_crls_are_waived_but_chain_still_checked() {
    // No CRLs supplied: freshness/revocation is consciously waived, but the
    // chain + signature + binding checks still run and pass.
    let b = build(&Knobs::default());
    let no_crl = TdxCollateral { now_unix: NOW_FRESH, ..TdxCollateral::default() };
    assert_eq!(verify_collateral_anchored(&b.quote, &no_crl, &b.root_der), Ok(()));
}

// ── the pinned public entry never mints Genuine on this host ─────────────────

#[test]
fn pinned_entry_fails_closed_against_a_non_intel_rooted_quote() {
    // verify_td_quote_with_collateral pins Intel's real, now-populated root. Our
    // synthetic quote chains to OUR test root, so it fails closed at
    // RootNotAnchored → Unverified. TDX still never says Genuine on this host —
    // that needs a genuine Intel-rooted quote (hardware-gated).
    let b = build(&Knobs::default());
    let expected = TdxExpected {
        mrtd: [0u8; 48],
        mr_config_id: None,
        rtmr: None,
        report_data: [0u8; 64],
    };
    assert!(matches!(
        verify_td_quote_with_collateral(&b.quote, &expected, &b.collateral),
        postern_seal_companion::Verdict::Unverified(_)
    ));
}

#[test]
fn the_only_gap_to_genuine_is_the_pinned_root() {
    // Everything BUT the pinned Intel root lines up: the chain authenticates
    // against our synthetic anchor AND the bound fields match. This shows the
    // sole thing standing between "verified" and Genuine on this host is that
    // we will not fabricate Intel's root.
    let b = build(&Knobs::default());
    assert_eq!(verify_collateral_anchored(&b.quote, &b.collateral, &b.root_der), Ok(()));
    let body = parse_td_quote(&b.quote).unwrap();
    let expected = TdxExpected {
        mrtd: body.mrtd,
        mr_config_id: Some(body.mr_config_id),
        rtmr: Some(body.rtmr),
        report_data: body.report_data,
    };
    assert!(check_bound_fields(&body, &expected).is_ok());
}

// ── the pinned Intel root is now real ────────────────────────────────────────

#[test]
fn pinned_intel_root_is_a_real_self_signed_x509_root() {
    use x509_parser::prelude::{FromDer, X509Certificate};

    // No longer the empty placeholder that short-circuited to PinnedRootUnset.
    assert!(
        !PINNED_INTEL_SGX_ROOT_CA_DER.is_empty(),
        "pinned Intel SGX Root CA DER must be populated"
    );

    // Parses as a well-formed DER X.509 certificate…
    let (rest, cert) = X509Certificate::from_der(PINNED_INTEL_SGX_ROOT_CA_DER)
        .expect("pinned Intel root must parse as DER X.509");
    assert!(rest.is_empty(), "no trailing bytes after the pinned root DER");

    // …that is self-signed: subject == issuer AND the signature verifies under
    // the cert's own public key (a genuine root, not just a name match).
    assert_eq!(
        cert.subject(),
        cert.issuer(),
        "an Intel *root* CA is self-issued (subject == issuer)"
    );
    cert.verify_signature(None)
        .expect("pinned Intel root must be validly self-signed");

    // Identity check against Intel's published SGX Root CA (guards against a
    // wrong/typo'd paste): the subject CN is exactly "Intel SGX Root CA".
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .unwrap_or("");
    assert_eq!(cn, "Intel SGX Root CA", "unexpected pinned-root subject CN");
    assert!(cert.is_ca(), "the pinned Intel root must assert CA:TRUE");
}

#[test]
fn synthetic_quote_now_hits_root_not_anchored_not_pinned_unset() {
    // The whole point of pasting the root: verify_collateral_dcap now pins
    // Intel's real root. Our synthetic quote chains to OUR test root, so it is
    // rejected at the anchor-equality gate with RootNotAnchored — NOT the old
    // PinnedRootUnset early return that used to swallow the entire path.
    let b = build(&Knobs::default());
    let got = verify_collateral_dcap(&b.quote, &b.collateral);
    assert_eq!(
        got,
        Err(TdxCollateralError::RootNotAnchored),
        "synthetic (non-Intel-rooted) quote must reach the anchor gate, not PinnedRootUnset"
    );
    assert_ne!(
        got,
        Err(TdxCollateralError::PinnedRootUnset),
        "the empty-root placeholder must no longer short-circuit verify_collateral_dcap"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// Intel TCB-Info + QE-Identity JSON collateral vectors (self-contained)
// ─────────────────────────────────────────────────────────────────────────────
// Everything below builds a SYNTHETIC-but-self-consistent scene: a real PCK leaf
// carrying a real Intel-shaped SGX TCB extension, a real Intel-shaped TCB signing
// cert chained to our test root, and TCB-Info / QE-Identity JSON whose `tcbInfo`
// / `enclaveIdentity` bodies are signed (raw P-256 ECDSA over the exact served
// bytes) by that signing key. The verifier re-slices the signed span, checks the
// signature under the signing cert (chained to the anchored root), enforces
// `nextUpdate` freshness + `tcbStatus`, and cross-checks FMSPC + the SGX/TDX TCB
// components + the QE report's identity against the quote. Each vector flips ONE
// thing to prove that specific check bites. SYNTHETIC — never Intel's real root.

const FMSPC: [u8; 6] = [0x00, 0x90, 0x6e, 0xa1, 0x00, 0x00];
const PCK_COMPS: [u8; 16] = [4; 16];
const PCK_PCESVN: u16 = 11;
const QUOTE_TEE_TCB_SVN: [u8; 16] = [6; 16];
const QE_MRSIGNER: [u8; 32] = [0x77; 32];
const QE_ISVPRODID: u16 = 2;
const QE_MISCSELECT: [u8; 4] = [0; 4];
const QE_ATTRIBUTES: [u8; 16] = [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const QE_ISVSVN: u16 = 5;
const FUTURE: &str = "2099-01-01T00:00:00Z";
const PAST: &str = "2000-01-01T00:00:00Z";
const SIGNING_SERIAL: &[u8] = &[0x0D, 0x03];

fn hexs(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

// ── minimal DER builders (for the PCK Intel SGX extension) ────────────────────

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 128 {
        out.push(len as u8);
    } else {
        let mut lb = Vec::new();
        let mut l = len;
        while l > 0 {
            lb.insert(0, (l & 0xff) as u8);
            l >>= 8;
        }
        out.push(0x80 | lb.len() as u8);
        out.extend(lb);
    }
    out.extend_from_slice(content);
    out
}
fn der_seq(items: &[Vec<u8>]) -> Vec<u8> {
    let mut c = Vec::new();
    for i in items {
        c.extend_from_slice(i);
    }
    der_tlv(0x30, &c)
}
fn enc_oid(arcs: &[u64]) -> Vec<u8> {
    let mut out = vec![(40 * arcs[0] + arcs[1]) as u8];
    for &a in &arcs[2..] {
        let mut stack = vec![(a & 0x7f) as u8];
        let mut x = a >> 7;
        while x > 0 {
            stack.push(0x80 | (x & 0x7f) as u8);
            x >>= 7;
        }
        stack.reverse();
        out.extend(stack);
    }
    out
}
fn der_oid(arcs: &[u64]) -> Vec<u8> {
    der_tlv(0x06, &enc_oid(arcs))
}
fn der_octet(b: &[u8]) -> Vec<u8> {
    der_tlv(0x04, b)
}
fn der_int(v: u64) -> Vec<u8> {
    if v == 0 {
        return der_tlv(0x02, &[0]);
    }
    let mut b = Vec::new();
    let mut x = v;
    while x > 0 {
        b.insert(0, (x & 0xff) as u8);
        x >>= 8;
    }
    if b[0] & 0x80 != 0 {
        b.insert(0, 0);
    }
    der_tlv(0x02, &b)
}

/// Build the Intel SGX PCK-extension content (the SEQUENCE that lands verbatim in
/// the cert's extnValue): PPID, TCB{16 comps ‖ pcesvn ‖ cpusvn}, PCEID, FMSPC,
/// SGX Type — the exact shape `crate::tdx`'s `parse_pck_sgx_tcb` reads.
fn sgx_ext_content(fmspc: &[u8; 6], pcesvn: u16, comps: &[u8; 16]) -> Vec<u8> {
    let base = [1u64, 2, 840, 113741, 1, 13, 1];
    let child = |suffix: &[u64]| -> Vec<u64> {
        let mut v = base.to_vec();
        v.extend_from_slice(suffix);
        v
    };
    let mut tcb_items = Vec::new();
    for (i, c) in comps.iter().enumerate() {
        tcb_items.push(der_seq(&[der_oid(&child(&[2, (i + 1) as u64])), der_int(*c as u64)]));
    }
    tcb_items.push(der_seq(&[der_oid(&child(&[2, 17])), der_int(pcesvn as u64)])); // pcesvn
    tcb_items.push(der_seq(&[der_oid(&child(&[2, 18])), der_octet(&[0u8; 16])])); // cpusvn
    let tcb_seq = der_seq(&tcb_items);

    let ppid = der_seq(&[der_oid(&child(&[1])), der_octet(&[0u8; 16])]);
    let tcb = der_seq(&[der_oid(&child(&[2])), tcb_seq]);
    let pceid = der_seq(&[der_oid(&child(&[3])), der_octet(&[0u8; 2])]);
    let fmspc_e = der_seq(&[der_oid(&child(&[4])), der_octet(fmspc)]);
    let sgxtype = der_seq(&[der_oid(&child(&[5])), der_tlv(0x0a, &[0])]); // ENUMERATED 0
    der_seq(&[ppid, tcb, pceid, fmspc_e, sgxtype])
}

/// A PCK leaf carrying the Intel SGX TCB extension, signed by `issuer`.
fn pck_leaf_with_sgx(serial: &[u8], issuer: &Node, ext_content: Vec<u8>) -> Node {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(vec!["Test PCK Leaf".to_string()]).unwrap();
    p.serial_number = Some(SerialNumber::from_slice(serial));
    p.custom_extensions
        .push(CustomExtension::from_oid_content(&[1, 2, 840, 113741, 1, 13, 1], ext_content));
    let cert = p.signed_by(&key, &issuer.cert, &issuer.key).unwrap();
    let signer = p256_signer(&key);
    Node { cert, key, signer }
}

/// A self-consistent DCAP v4 quote whose QE report carries the given identity
/// fields (mrsigner/isvprodid/miscselect/attributes/isvsvn) and whose embedded
/// PCK PEM chain is `pck_pem`. Mirrors `assemble`, plus the QE identity injection.
#[allow(clippy::too_many_arguments)]
fn assemble_json_quote(
    pck: &Node,
    pck_pem: &[u8],
    tee_tcb_svn: &[u8; 16],
    qe_mrsigner: &[u8; 32],
    qe_isvprodid: u16,
    qe_misc: &[u8; 4],
    qe_attr: &[u8; 16],
    qe_isvsvn: u16,
) -> Vec<u8> {
    let att = SigningKey::from_pkcs8_der(
        &KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap().serialize_der(),
    )
    .unwrap();

    let mut header = vec![0u8; HEADER_LEN];
    header[0..2].copy_from_slice(&QUOTE_VERSION_V4.to_le_bytes());
    header[4..8].copy_from_slice(&TEE_TYPE_TDX.to_le_bytes());

    let mut td_body = vec![0u8; TD_BODY_LEN];
    td_body[0..16].copy_from_slice(tee_tcb_svn);

    let mut signed_region = header.clone();
    signed_region.extend_from_slice(&td_body);
    let ak_raw = att_pub_raw(&att);
    let quote_sig = sign(&att, &signed_region);

    let qe_auth: Vec<u8> = vec![0xA5; 8];
    let mut qe_report = vec![0u8; QE_REPORT_LEN];
    // sgx_report_body_t identity fields (offsets: miscselect 16, attributes 48,
    // mr_signer 128, isv_prod_id 256, isv_svn 258).
    qe_report[16..20].copy_from_slice(qe_misc);
    qe_report[48..64].copy_from_slice(qe_attr);
    qe_report[128..160].copy_from_slice(qe_mrsigner);
    qe_report[256..258].copy_from_slice(&qe_isvprodid.to_le_bytes());
    qe_report[258..260].copy_from_slice(&qe_isvsvn.to_le_bytes());
    // QE binding: report_data = SHA-256(att_pub ‖ qe_auth).
    let mut h = Sha256::new();
    h.update(ak_raw);
    h.update(&qe_auth);
    qe_report[QE_REPORT_DATA_OFF..QE_REPORT_DATA_OFF + 32].copy_from_slice(&h.finalize());
    let qe_report_sig = sign(&pck.signer, &qe_report);

    let mut outer = Vec::new();
    outer.extend_from_slice(&qe_report);
    outer.extend_from_slice(&qe_report_sig);
    outer.extend_from_slice(&(qe_auth.len() as u16).to_le_bytes());
    outer.extend_from_slice(&qe_auth);
    outer.extend_from_slice(&5u16.to_le_bytes());
    outer.extend_from_slice(&(pck_pem.len() as u32).to_le_bytes());
    outer.extend_from_slice(pck_pem);

    let mut sig_data = Vec::new();
    sig_data.extend_from_slice(&quote_sig);
    sig_data.extend_from_slice(&ak_raw);
    sig_data.extend_from_slice(&6u16.to_le_bytes());
    sig_data.extend_from_slice(&(outer.len() as u32).to_le_bytes());
    sig_data.extend_from_slice(&outer);

    let mut quote = signed_region;
    quote.extend_from_slice(&(sig_data.len() as u32).to_le_bytes());
    quote.extend_from_slice(&sig_data);
    quote
}

/// The fixed happy scene: root, PCK-with-SGX-ext, TCB signing cert, and a quote
/// whose QE identity matches the happy QE-Identity JSON below.
struct Scene {
    quote: Vec<u8>,
    root: Node,
    signing: Node,
}

fn scene() -> Scene {
    let root = ca("Test SGX Root CA", None, None, None);
    let inter = ca("Test SGX PCK Processor CA", Some(INTER_SERIAL), Some(&root), None);
    let pck = pck_leaf_with_sgx(LEAF_SERIAL, &inter, sgx_ext_content(&FMSPC, PCK_PCESVN, &PCK_COMPS));
    let signing = leaf("Intel SGX TCB Signing", SIGNING_SERIAL, &root, None);

    let mut pck_pem = pck.cert.pem();
    pck_pem.push_str(&inter.cert.pem());
    pck_pem.push_str(&root.cert.pem());

    let quote = assemble_json_quote(
        &pck,
        pck_pem.as_bytes(),
        &QUOTE_TEE_TCB_SVN,
        &QE_MRSIGNER,
        QE_ISVPRODID,
        &QE_MISCSELECT,
        &QE_ATTRIBUTES,
        QE_ISVSVN,
    );
    Scene { quote, root, signing }
}

fn comps_json(svn: u8) -> String {
    let one = format!("{{\"svn\":{svn}}}");
    format!("[{}]", vec![one; 16].join(","))
}

/// Sign `{ "<key>": <body>, "signature": "<hex>" }`. `tamper_sig` flips a byte of
/// the signature so it no longer verifies over the (untouched) body.
fn sign_doc(signing: &Node, key: &str, body: &str, tamper_sig: bool) -> Vec<u8> {
    let mut sig = sign(&signing.signer, body.as_bytes());
    if tamper_sig {
        sig[10] ^= 0xFF;
    }
    format!("{{\"{key}\":{body},\"signature\":\"{}\"}}", hexs(&sig)).into_bytes()
}

#[allow(clippy::too_many_arguments)]
fn tcb_info_doc(
    signing: &Node,
    fmspc_hex: &str,
    next_update: &str,
    lvl_sgx: u8,
    lvl_tdx: u8,
    lvl_pcesvn: u64,
    status: &str,
    tamper_sig: bool,
) -> Vec<u8> {
    let body = format!(
        "{{\"id\":\"TDX\",\"version\":3,\"issueDate\":\"2020-01-01T00:00:00Z\",\
         \"nextUpdate\":\"{next_update}\",\"fmspc\":\"{fmspc_hex}\",\"pceId\":\"0000\",\
         \"tcbType\":0,\"tcbEvaluationDataNumber\":1,\"tcbLevels\":[{{\"tcb\":{{\
         \"sgxtcbcomponents\":{sgx},\"pcesvn\":{lvl_pcesvn},\"tdxtcbcomponents\":{tdx}}},\
         \"tcbDate\":\"2020-01-01T00:00:00Z\",\"tcbStatus\":\"{status}\"}}]}}",
        sgx = comps_json(lvl_sgx),
        tdx = comps_json(lvl_tdx),
    );
    sign_doc(signing, "tcbInfo", &body, tamper_sig)
}

#[allow(clippy::too_many_arguments)]
fn qe_identity_doc(
    signing: &Node,
    mrsigner_hex: &str,
    isvprodid: u64,
    attr_hex: &str,
    next_update: &str,
    lvl_isvsvn: u64,
    status: &str,
    tamper_sig: bool,
) -> Vec<u8> {
    let body = format!(
        "{{\"id\":\"TD_QE\",\"version\":2,\"issueDate\":\"2020-01-01T00:00:00Z\",\
         \"nextUpdate\":\"{next_update}\",\"tcbEvaluationDataNumber\":1,\
         \"miscselect\":\"00000000\",\"miscselectMask\":\"ffffffff\",\
         \"attributes\":\"{attr_hex}\",\"attributesMask\":\"ff000000000000000000000000000000\",\
         \"mrsigner\":\"{mrsigner_hex}\",\"isvprodid\":{isvprodid},\"tcbLevels\":[{{\"tcb\":{{\
         \"isvsvn\":{lvl_isvsvn}}},\"tcbDate\":\"2020-01-01T00:00:00Z\",\"tcbStatus\":\"{status}\"}}]}}",
    );
    sign_doc(signing, "enclaveIdentity", &body, tamper_sig)
}

/// Happy TCB-Info: fmspc matches the PCK, fresh, level satisfied, UpToDate.
fn happy_tcb_info(signing: &Node) -> Vec<u8> {
    tcb_info_doc(signing, &hexs(&FMSPC), FUTURE, 0, 0, 0, "UpToDate", false)
}
/// Happy QE-Identity: identity matches the QE report, fresh, level met, UpToDate.
fn happy_qe_identity(signing: &Node) -> Vec<u8> {
    qe_identity_doc(signing, &hexs(&QE_MRSIGNER), QE_ISVPRODID as u64, &hexs(&QE_ATTRIBUTES), FUTURE, 3, "UpToDate", false)
}

fn issuer_chain(signing: &Node, root: &Node) -> Vec<u8> {
    let mut pem = signing.cert.pem();
    pem.push_str(&root.cert.pem());
    pem.into_bytes()
}

fn json_collateral(tcb_info: Vec<u8>, qe_identity: Vec<u8>, chain: Vec<u8>) -> TdxCollateral {
    TdxCollateral {
        now_unix: NOW_FRESH,
        json: Some(TdxJsonCollateral {
            tcb_info_json: tcb_info,
            qe_identity_json: qe_identity,
            issuer_chain_pem: chain,
        }),
        ..TdxCollateral::default()
    }
}

/// Run the anchored verifier over the happy scene with a caller-tweaked pair of
/// JSON docs, anchoring at the scene's own test root. `make` returns
/// (tcb_info_json, qe_identity_json).
fn run_json<F>(make: F) -> Result<(), TdxCollateralError>
where
    F: FnOnce(&Node) -> (Vec<u8>, Vec<u8>),
{
    let s = scene();
    let (tcb, qe) = make(&s.signing);
    let coll = json_collateral(tcb, qe, issuer_chain(&s.signing, &s.root));
    verify_collateral_anchored(&s.quote, &coll, s.root.cert.der().as_ref())
}

// ── happy path ───────────────────────────────────────────────────────────────

#[test]
fn json_collateral_happy_path_verifies() {
    assert_eq!(
        run_json(|sg| (happy_tcb_info(sg), happy_qe_identity(sg))),
        Ok(()),
        "a fully-consistent TCB-Info + QE-Identity scene must verify against its anchor",
    );
}

// ── signature vectors ────────────────────────────────────────────────────────

#[test]
fn tampered_tcb_info_signature_is_rejected() {
    let got = run_json(|sg| {
        (tcb_info_doc(sg, &hexs(&FMSPC), FUTURE, 0, 0, 0, "UpToDate", true), happy_qe_identity(sg))
    });
    assert_eq!(got, Err(TdxCollateralError::TcbInfoSignature));
}

#[test]
fn tampered_qe_identity_signature_is_rejected() {
    let got = run_json(|sg| {
        (happy_tcb_info(sg), qe_identity_doc(sg, &hexs(&QE_MRSIGNER), QE_ISVPRODID as u64, &hexs(&QE_ATTRIBUTES), FUTURE, 3, "UpToDate", true))
    });
    assert_eq!(got, Err(TdxCollateralError::QeIdentitySignature));
}

#[test]
fn tcb_signing_cert_not_chained_to_anchor_is_rejected() {
    // The issuer chain (signing + root) is an entirely rogue pair; the anchor is
    // the scene's real root, so the chain root != anchor → fail closed.
    let s = scene();
    let rogue_root = ca("Rogue Root", None, None, None);
    let rogue_signing = leaf("Rogue Signing", SIGNING_SERIAL, &rogue_root, None);
    let coll = json_collateral(
        happy_tcb_info(&rogue_signing),
        happy_qe_identity(&rogue_signing),
        issuer_chain(&rogue_signing, &rogue_root),
    );
    assert!(matches!(
        verify_collateral_anchored(&s.quote, &coll, s.root.cert.der().as_ref()),
        Err(TdxCollateralError::TcbSigningChainInvalid(_)),
    ));
}

// ── freshness vectors ────────────────────────────────────────────────────────

#[test]
fn stale_tcb_info_is_rejected() {
    let got = run_json(|sg| {
        (tcb_info_doc(sg, &hexs(&FMSPC), PAST, 0, 0, 0, "UpToDate", false), happy_qe_identity(sg))
    });
    assert_eq!(got, Err(TdxCollateralError::CollateralExpired("tcbInfo")));
}

#[test]
fn stale_qe_identity_is_rejected() {
    let got = run_json(|sg| {
        (happy_tcb_info(sg), qe_identity_doc(sg, &hexs(&QE_MRSIGNER), QE_ISVPRODID as u64, &hexs(&QE_ATTRIBUTES), PAST, 3, "UpToDate", false))
    });
    assert_eq!(got, Err(TdxCollateralError::CollateralExpired("enclaveIdentity")));
}

// ── TCB status / level vectors ───────────────────────────────────────────────

#[test]
fn tcb_info_out_of_date_status_is_rejected() {
    let got = run_json(|sg| {
        (tcb_info_doc(sg, &hexs(&FMSPC), FUTURE, 0, 0, 0, "OutOfDate", false), happy_qe_identity(sg))
    });
    assert_eq!(got, Err(TdxCollateralError::TcbStatusUnacceptable));
}

#[test]
fn tcb_level_not_satisfied_by_sgx_components_is_rejected() {
    // The single level demands SGX component svn 200; the PCK reports 4 → no
    // level matches → fail closed. Proves the SGX-side (PCK) cross-check bites.
    let got = run_json(|sg| {
        (tcb_info_doc(sg, &hexs(&FMSPC), FUTURE, 200, 0, 0, "UpToDate", false), happy_qe_identity(sg))
    });
    assert_eq!(got, Err(TdxCollateralError::TcbLevelNotFound));
}

#[test]
fn tcb_level_not_satisfied_by_tdx_components_is_rejected() {
    // The level demands TDX component svn 200; the quote's TEE_TCB_SVN is 6 → no
    // level matches → fail closed. Proves the TDX-side (quote) cross-check bites.
    let got = run_json(|sg| {
        (tcb_info_doc(sg, &hexs(&FMSPC), FUTURE, 0, 200, 0, "UpToDate", false), happy_qe_identity(sg))
    });
    assert_eq!(got, Err(TdxCollateralError::TcbLevelNotFound));
}

#[test]
fn fmspc_mismatch_is_rejected() {
    // TCB-Info fmspc differs from the PCK certificate's FMSPC extension.
    let got = run_json(|sg| {
        (tcb_info_doc(sg, "0011223344ff", FUTURE, 0, 0, 0, "UpToDate", false), happy_qe_identity(sg))
    });
    assert_eq!(got, Err(TdxCollateralError::FmspcMismatch));
}

// ── QE-Identity cross-check vectors ──────────────────────────────────────────

#[test]
fn qe_mrsigner_mismatch_is_rejected() {
    let got = run_json(|sg| {
        (happy_tcb_info(sg), qe_identity_doc(sg, &hexs(&[0x88; 32]), QE_ISVPRODID as u64, &hexs(&QE_ATTRIBUTES), FUTURE, 3, "UpToDate", false))
    });
    assert_eq!(got, Err(TdxCollateralError::QeIdentityMismatch("mrsigner")));
}

#[test]
fn qe_isvprodid_mismatch_is_rejected() {
    let got = run_json(|sg| {
        (happy_tcb_info(sg), qe_identity_doc(sg, &hexs(&QE_MRSIGNER), 9, &hexs(&QE_ATTRIBUTES), FUTURE, 3, "UpToDate", false))
    });
    assert_eq!(got, Err(TdxCollateralError::QeIdentityMismatch("isvprodid")));
}

#[test]
fn qe_attributes_masked_mismatch_is_rejected() {
    // The QE report's attributes[0] is 0x03; the identity claims 0x05 under a
    // 0xFF mask on byte 0 → masked mismatch. Proves the masked-attributes check.
    let mut wrong_attr = QE_ATTRIBUTES;
    wrong_attr[0] = 0x05;
    let got = run_json(|sg| {
        (happy_tcb_info(sg), qe_identity_doc(sg, &hexs(&QE_MRSIGNER), QE_ISVPRODID as u64, &hexs(&wrong_attr), FUTURE, 3, "UpToDate", false))
    });
    assert_eq!(got, Err(TdxCollateralError::QeIdentityMismatch("attributes")));
}

#[test]
fn qe_isvsvn_below_level_is_rejected() {
    // The only QE-Identity level demands isvsvn 9; the QE report has 5 → no
    // level met → fail closed.
    let got = run_json(|sg| {
        (happy_tcb_info(sg), qe_identity_doc(sg, &hexs(&QE_MRSIGNER), QE_ISVPRODID as u64, &hexs(&QE_ATTRIBUTES), FUTURE, 9, "UpToDate", false))
    });
    assert_eq!(got, Err(TdxCollateralError::QeTcbStatusUnacceptable));
}

#[test]
fn qe_identity_out_of_date_status_is_rejected() {
    let got = run_json(|sg| {
        (happy_tcb_info(sg), qe_identity_doc(sg, &hexs(&QE_MRSIGNER), QE_ISVPRODID as u64, &hexs(&QE_ATTRIBUTES), FUTURE, 3, "OutOfDate", false))
    });
    assert_eq!(got, Err(TdxCollateralError::QeTcbStatusUnacceptable));
}

// ── waiver + the pinned-entry rail ───────────────────────────────────────────

#[test]
fn absent_json_collateral_is_waived() {
    // json = None: the JSON checks are consciously skipped (documented, like a
    // None CRL). The chain/QE-binding/signature checks still run and pass.
    let s = scene();
    let coll = TdxCollateral { now_unix: NOW_FRESH, json: None, ..TdxCollateral::default() };
    assert_eq!(verify_collateral_anchored(&s.quote, &coll, s.root.cert.der().as_ref()), Ok(()));
}

#[test]
fn pinned_entry_with_json_still_fails_closed() {
    // Even with a fully-consistent JSON collateral, the PUBLIC pinned entry
    // anchors at Intel's real root; our scene chains to a test root, so it fails
    // closed at the anchor gate long before (and regardless of) the JSON step.
    // TDX still never says Genuine on this host.
    let s = scene();
    let coll = json_collateral(happy_tcb_info(&s.signing), happy_qe_identity(&s.signing), issuer_chain(&s.signing, &s.root));
    let got = verify_collateral_dcap(&s.quote, &coll);
    assert_eq!(got, Err(TdxCollateralError::RootNotAnchored));
    let expected = TdxExpected { mrtd: [0u8; 48], mr_config_id: None, rtmr: None, report_data: [0u8; 64] };
    assert!(matches!(
        verify_td_quote_with_collateral(&s.quote, &expected, &coll),
        postern_seal_companion::Verdict::Unverified(_),
    ));
}

// ── the ISO-8601 nextUpdate parser + raw-span signer are load-bearing ─────────

#[test]
fn nextupdate_exactly_at_now_is_stale() {
    // Freshness is `now < nextUpdate`; equality must fail closed. nextUpdate is
    // parsed to a Unix instant, and NOW_FRESH (1_750_000_000) is set to exactly
    // that instant: 2025-06-15T15:06:40Z. This also proves the civil-days ISO
    // parser lands on the right second.
    let got = run_json(|sg| {
        (tcb_info_doc(sg, &hexs(&FMSPC), "2025-06-15T15:06:40Z", 0, 0, 0, "UpToDate", false), happy_qe_identity(sg))
    });
    assert_eq!(got, Err(TdxCollateralError::CollateralExpired("tcbInfo")));
}
