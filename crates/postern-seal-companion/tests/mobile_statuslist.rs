// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
#![cfg(feature = "mobile-attest")]

//! Google Android Key-Attestation **status-list (revocation) + freshness**
//! vectors for the `mobile` verifier — the public-API analogue of `snp_crl.rs`
//! for the SEV-SNP AMD-KDS CRL check. Everything here is **offline** and
//! **synthetic**: no network is touched at verify time, and no real StrongBox
//! device produced any chain (`vector-tested ≠ attested`; UNAUDITED, no
//! hardware security claim — same honesty standard as `mobile.rs`'s header).
//!
//! Three layers are proven through the crate's **public** surface:
//!
//!  1. **The isolated policy helper is correct** (`mobile::check_status_list`):
//!     with a caller-fetched [`GoogleStatusList`], a fresh clean list → `Ok`
//!     (passes), a fresh list that revokes the serial → `Verdict::Mismatch`
//!     (Rejected), a stale / future-dated list → `Verdict::Unverified`
//!     (Rejected, fail-closed), and the loudly-named
//!     `SkipRevocationCheckDangerously` opt-out ignores the list entirely.
//!  2. **The freshness gate matches snp's `nextUpdate` discipline**
//!     (`GoogleStatusList::check_freshness`): inclusive upper bound, negative
//!     age (clock skew) rejected.
//!  3. **The gate is reachable through the real entry point**
//!     (`verify_key_attestation_with_revocation`): a genuine, well-anchored
//!     rcgen leaf←inter←root chain is Genuine under a fresh clean list, but
//!     fails **closed** — Mismatch on a revoked leaf serial, Unverified on a
//!     stale list — and the dangerous opt-out keeps it Genuine even then. The
//!     status list is fed in already-parsed: the crate does NO verify-time
//!     network I/O and carries no JSON dependency in this path.
//!
//! Run: cargo test -p postern-seal-companion --features mobile-attest

use postern_seal_companion::mobile::{
    check_status_list, verify_key_attestation, verify_key_attestation_with_revocation, AppIdentity,
    GoogleStatusList, MobileExpected, MobileRevocationPolicy, SecurityLevel,
};
use postern_seal_companion::Verdict;

use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

// ── context-tag numbers inside an AuthorizationList (KeyMint/Keymaster) ──────
const TAG_ROOT_OF_TRUST: u32 = 704;
const TAG_OS_PATCH_LEVEL: u32 = 706;
const TAG_ATTESTATION_APPLICATION_ID: u32 = 709;

/// DER OID arcs of `1.3.6.1.4.1.11129.2.1.17` (Android Key Attestation).
const ATT_OID_ARCS: &[u64] = &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17];

// ── tiny DER encoders (build a KeyDescription vector by hand, mirroring the
//    in-crate unit-test encoders — kept here so this is a fully self-contained
//    black-box test of the PUBLIC API) ───────────────────────────────────────

fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else {
        let mut b = Vec::new();
        let mut v = n;
        while v > 0 {
            b.insert(0, (v & 0xFF) as u8);
            v >>= 8;
        }
        let mut out = vec![0x80 | b.len() as u8];
        out.extend(b);
        out
    }
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn int(v: u64) -> Vec<u8> {
    if v == 0 {
        return tlv(0x02, &[0x00]);
    }
    let mut b = Vec::new();
    let mut x = v;
    while x > 0 {
        b.insert(0, (x & 0xFF) as u8);
        x >>= 8;
    }
    if b[0] & 0x80 != 0 {
        b.insert(0, 0x00);
    }
    tlv(0x02, &b)
}

fn enumerated(v: u8) -> Vec<u8> {
    tlv(0x0A, &[v])
}
fn octet(v: &[u8]) -> Vec<u8> {
    tlv(0x04, v)
}
fn boolean(b: bool) -> Vec<u8> {
    tlv(0x01, &[if b { 0xFF } else { 0x00 }])
}
fn sequence(inner: &[u8]) -> Vec<u8> {
    tlv(0x30, inner)
}
fn set(inner: &[u8]) -> Vec<u8> {
    tlv(0x31, inner)
}

/// Context-specific constructed [tagnum] EXPLICIT wrapper (long-form tag for
/// tagnum > 30 — exercises the real high-tag encoding the parser reads back).
fn ctx(tagnum: u32, inner: &[u8]) -> Vec<u8> {
    let mut tagbytes = Vec::new();
    if tagnum <= 30 {
        tagbytes.push(0xA0 | tagnum as u8);
    } else {
        tagbytes.push(0xBF); // context, constructed, high-tag form
        let mut base128 = Vec::new();
        let mut v = tagnum;
        base128.insert(0, (v & 0x7F) as u8);
        v >>= 7;
        while v > 0 {
            base128.insert(0, ((v & 0x7F) as u8) | 0x80);
            v >>= 7;
        }
        tagbytes.extend(base128);
    }
    let mut out = tagbytes;
    out.extend(der_len(inner.len()));
    out.extend_from_slice(inner);
    out
}

fn app_id(package: &str, digest: &[u8]) -> Vec<u8> {
    let pkg_info = sequence(&[octet(package.as_bytes()), int(1)].concat());
    let pkg_set = set(&pkg_info);
    let dig_set = set(&octet(digest));
    sequence(&[pkg_set, dig_set].concat())
}

fn root_of_trust(locked: bool, vbstate: u8) -> Vec<u8> {
    sequence(
        &[
            octet(&[0u8; 32]), // verifiedBootKey
            boolean(locked),
            enumerated(vbstate),
            octet(&[0u8; 32]), // verifiedBootHash
        ]
        .concat(),
    )
}

/// A StrongBox(2) / Verified(0) / locked KeyDescription bound to `challenge`,
/// with our pinned package + signing digest, patch level 202401.
fn strongbox_key_description(challenge: &[u8]) -> Vec<u8> {
    let software = sequence(&ctx(
        TAG_ATTESTATION_APPLICATION_ID,
        &octet(&app_id("labs.postern.wallet", &[0xAB; 32])),
    ));
    let tee = sequence(
        &[
            ctx(TAG_ROOT_OF_TRUST, &root_of_trust(true, 0)),
            ctx(TAG_OS_PATCH_LEVEL, &int(202401)),
        ]
        .concat(),
    );
    sequence(
        &[
            int(200),      // attestationVersion
            enumerated(2), // attestationSecurityLevel = StrongBox
            int(4),        // keymasterVersion
            enumerated(2), // keymasterSecurityLevel
            octet(challenge),
            octet(&[]), // uniqueId
            software,
            tee,
        ]
        .concat(),
    )
}

// ── a real (rcgen, ECDSA-P256) leaf←inter←root chain, leaf-first ─────────────

struct RealChain {
    leaf: Vec<u8>,
    inter: Vec<u8>,
    root: Vec<u8>,
}

fn real_attested_chain(kd_der: &[u8]) -> RealChain {
    let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut rp = CertificateParams::new(vec!["Postern Test Attestation Root".into()]).unwrap();
    rp.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    rp.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let root = rp.self_signed(&root_key).unwrap();

    let inter_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ip =
        CertificateParams::new(vec!["Postern Test Attestation Intermediate".into()]).unwrap();
    ip.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ip.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let inter = ip.signed_by(&inter_key, &root, &root_key).unwrap();

    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut lp = CertificateParams::new(vec!["Android Keystore Attested Key".into()]).unwrap();
    lp.custom_extensions
        .push(CustomExtension::from_oid_content(ATT_OID_ARCS, kd_der.to_vec()));
    let leaf = lp.signed_by(&leaf_key, &inter, &inter_key).unwrap();

    RealChain {
        leaf: leaf.der().as_ref().to_vec(),
        inter: inter.der().as_ref().to_vec(),
        root: root.der().as_ref().to_vec(),
    }
}

fn expected_pinning(root_der: Vec<u8>, challenge: &[u8]) -> MobileExpected {
    MobileExpected {
        roots: vec![root_der],
        challenge: challenge.to_vec(),
        require_device_locked: true,
        require_verified_boot: true,
        min_security_level: SecurityLevel::StrongBox,
        min_os_patch_level: Some(202401),
        expected_app: Some(AppIdentity {
            package_names: vec!["labs.postern.wallet".into()],
            signature_digests: vec![vec![0xAB; 32]],
        }),
        now_unix: None,
    }
}

fn leaf_serial(leaf_der: &[u8]) -> Vec<u8> {
    let (_, leaf) = X509Certificate::from_der(leaf_der).unwrap();
    leaf.raw_serial().to_vec()
}

/// A list fetched at t=1000, trusted for 3600s (so [1000, 4600] is fresh).
fn list(revoked: Vec<Vec<u8>>) -> GoogleStatusList {
    GoogleStatusList { revoked_serials: revoked, fetched_at_unix: 1000, max_age_secs: 3600 }
}
const NOW_FRESH: i64 = 2000; // inside [1000, 4600]
const NOW_STALE: i64 = 9_999; // past 4600
const NOW_FUTURE: i64 = 500; // before the fetch instant

// ── layer 1: the isolated public policy helper ───────────────────────────────

#[test]
fn isolated_fresh_clean_list_passes() {
    let l = list(vec![]);
    let policy = MobileRevocationPolicy::Enforce(&l);
    assert_eq!(check_status_list(&policy, &[0x11, 0x22, 0x33], NOW_FRESH), Ok(()));
}

#[test]
fn isolated_revoked_serial_is_rejected_mismatch() {
    let serial = vec![0x0A, 0x0B, 0x0C];
    let l = list(vec![serial.clone()]);
    let policy = MobileRevocationPolicy::Enforce(&l);
    match check_status_list(&policy, &serial, NOW_FRESH) {
        Err(Verdict::Mismatch(reason)) => {
            assert!(reason.contains("revoked"), "expected a revoked-serial mismatch, got: {reason}")
        }
        other => panic!("expected Mismatch(revoked …), got {other:?}"),
    }
}

#[test]
fn isolated_stale_list_is_rejected_unverified() {
    // Even a clean list is refused once aged out: a fresh revocation could have
    // landed since the snapshot, so the gate fails CLOSED (never Genuine).
    let l = list(vec![]);
    let policy = MobileRevocationPolicy::Enforce(&l);
    assert!(matches!(
        check_status_list(&policy, &[0x11, 0x22, 0x33], NOW_STALE),
        Err(Verdict::Unverified(_))
    ));
}

#[test]
fn isolated_future_dated_list_is_rejected_unverified() {
    // now BEFORE the recorded fetch instant is bogus clock skew — not evidence
    // of current revocation state. Fail closed.
    let l = list(vec![]);
    let policy = MobileRevocationPolicy::Enforce(&l);
    assert!(matches!(
        check_status_list(&policy, &[0x11, 0x22, 0x33], NOW_FUTURE),
        Err(Verdict::Unverified(_))
    ));
}

#[test]
fn isolated_freshness_wins_over_contents_on_a_stale_revoking_list() {
    // A stale list that ALSO revokes the serial must still surface Unverified
    // (staleness), not Mismatch: freshness is checked before contents, so a
    // caller cannot even trust a stale list to say "revoked".
    let serial = vec![0x0A, 0x0B, 0x0C];
    let l = list(vec![serial.clone()]);
    let policy = MobileRevocationPolicy::Enforce(&l);
    assert!(matches!(
        check_status_list(&policy, &serial, NOW_STALE),
        Err(Verdict::Unverified(_))
    ));
}

#[test]
fn isolated_skip_dangerously_ignores_the_list_entirely() {
    // The loud opt-out never consults any list — the serial that a stale list
    // would revoke passes unexamined. That is the whole (dangerous) point,
    // and it must be asked for by name.
    let serial = vec![0x0A, 0x0B, 0x0C];
    assert_eq!(
        check_status_list(
            &MobileRevocationPolicy::SkipRevocationCheckDangerously,
            &serial,
            NOW_STALE,
        ),
        Ok(())
    );
}

// ── layer 2: the freshness gate boundary (mirrors snp's nextUpdate) ──────────

#[test]
fn freshness_boundary_is_inclusive_upper_bound() {
    let l = list(vec![]);
    // fetched_at + max_age = 4600 is the LAST fresh instant.
    assert_eq!(l.check_freshness(4600), Ok(()));
    assert!(matches!(l.check_freshness(4601), Err(Verdict::Unverified(_))));
    // fetched_at itself is fresh; one second before is clock skew.
    assert_eq!(l.check_freshness(1000), Ok(()));
    assert!(matches!(l.check_freshness(999), Err(Verdict::Unverified(_))));
}

// ── layer 3: reachable through the real verify entry point ───────────────────

#[test]
fn full_path_genuine_baseline_without_revocation() {
    // Sanity anchor: the exact chain the revocation tests reuse is Genuine on
    // its own, so any non-Genuine below is attributable to the status list.
    let challenge = [1u8, 2, 3, 4];
    let kd = strongbox_key_description(&challenge);
    let c = real_attested_chain(&kd);
    let exp = expected_pinning(c.root.clone(), &challenge);
    let chain: Vec<&[u8]> = vec![&c.leaf, &c.inter, &c.root];
    assert_eq!(verify_key_attestation(&chain, &exp), Verdict::Genuine);
}

#[test]
fn full_path_fresh_clean_list_stays_genuine() {
    let challenge = [1u8, 2, 3, 4];
    let kd = strongbox_key_description(&challenge);
    let c = real_attested_chain(&kd);
    let exp = expected_pinning(c.root.clone(), &challenge);
    let chain: Vec<&[u8]> = vec![&c.leaf, &c.inter, &c.root];
    let l = list(vec![]);
    let policy = MobileRevocationPolicy::Enforce(&l);
    assert_eq!(
        verify_key_attestation_with_revocation(&chain, &exp, &policy, NOW_FRESH),
        Verdict::Genuine
    );
}

#[test]
fn full_path_revoked_leaf_serial_is_rejected() {
    let challenge = [1u8, 2, 3, 4];
    let kd = strongbox_key_description(&challenge);
    let c = real_attested_chain(&kd);
    let exp = expected_pinning(c.root.clone(), &challenge);
    let chain: Vec<&[u8]> = vec![&c.leaf, &c.inter, &c.root];
    // A FRESH list (passes the freshness gate) listing the leaf's own serial.
    let l = list(vec![leaf_serial(&c.leaf)]);
    let policy = MobileRevocationPolicy::Enforce(&l);
    match verify_key_attestation_with_revocation(&chain, &exp, &policy, NOW_FRESH) {
        Verdict::Mismatch(reason) => {
            assert!(reason.contains("revoked"), "expected a revoked-serial mismatch, got: {reason}")
        }
        other => panic!("expected Mismatch(revoked …), got {other:?}"),
    }
}

#[test]
fn full_path_stale_list_fails_closed_unverified() {
    let challenge = [1u8, 2, 3, 4];
    let kd = strongbox_key_description(&challenge);
    let c = real_attested_chain(&kd);
    let exp = expected_pinning(c.root.clone(), &challenge);
    let chain: Vec<&[u8]> = vec![&c.leaf, &c.inter, &c.root];
    // Even an empty (nothing-revoked) list is refused once stale: fail closed.
    let l = list(vec![]);
    let policy = MobileRevocationPolicy::Enforce(&l);
    assert!(matches!(
        verify_key_attestation_with_revocation(&chain, &exp, &policy, NOW_STALE),
        Verdict::Unverified(_)
    ));
}

#[test]
fn full_path_skip_dangerously_stays_genuine_even_when_stale_and_revoked() {
    let challenge = [1u8, 2, 3, 4];
    let kd = strongbox_key_description(&challenge);
    let c = real_attested_chain(&kd);
    let exp = expected_pinning(c.root.clone(), &challenge);
    let chain: Vec<&[u8]> = vec![&c.leaf, &c.inter, &c.root];
    // The opt-out ignores even a stale list that revokes this very leaf.
    assert_eq!(
        verify_key_attestation_with_revocation(
            &chain,
            &exp,
            &MobileRevocationPolicy::SkipRevocationCheckDangerously,
            NOW_STALE,
        ),
        Verdict::Genuine
    );
}
