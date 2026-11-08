// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs

//! Offline verification of the **vendored Google Android hardware-attestation
//! root certificates** — the trust anchors an operator pins into
//! `mobile::MobileExpected::roots`.
//!
//! The `.der` roots under `testdata/mobile/google_attest_roots/` are Google's
//! CURRENT Android Key-Attestation roots, fetched 2026-07-18 from Google's
//! authoritative endpoint `https://android.googleapis.com/attestation/root`
//! (a JSON array of PEM roots) and embedded verbatim as DER. Full provenance —
//! URL, HTTP metadata, fetch note, per-root facts and SHA-256 fingerprints — is
//! recorded in `testdata/mobile/google_attest_roots/PROVENANCE.md`.
//!
//! These tests do **NO** network I/O. They prove, offline:
//!   1. each pinned root parses as a well-formed self-signed X.509v3 CA whose
//!      own signature verifies under its own public key (a genuine root, not a
//!      name match), and whose SHA-256 DER fingerprint equals the pinned value;
//!   2. `mobile.rs` verify **fails closed** ([`Verdict::Unverified`]) with no
//!      root pinned — the anchorless case;
//!   3. the pinned REAL roots are actually **consulted** as the trust anchor: a
//!      chain that does NOT terminate at a pinned Google root is refused at the
//!      trust-anchor gate, while a chain whose terminal cert IS a pinned Google
//!      root gets PAST that gate (proving the real root was accepted as an
//!      anchor) and only then fails for a downstream reason.
//!
//! HONESTY (`vendored real root != attested device`): these tests deliberately
//! do NOT reach [`Verdict::Genuine`] against Google's real root. That needs a
//! real Key-Attestation leaf chain minted by a genuine StrongBox/TEE device and
//! signed by Google's private key (hardware-gated — no such chain exists in this
//! repo). Pinning the genuine roots makes such a chain *authenticatable*; it is
//! not itself an attestation. UNAUDITED.
//!
//! Run: cargo test -p postern-seal-companion --features mobile-attest \
//!         --test mobile_google_roots

// The entire file is gated on `mobile-attest` (the feature that compiles
// `crate::mobile` and pulls in `x509-parser`). On the default feature set this
// integration test compiles to an empty binary — same lean-default discipline
// as the `tdx_collateral` / `snp_*` vector tests.
#![cfg(feature = "mobile-attest")]

use postern_seal_companion::mobile::{
    root_fingerprint_sha256, verify_key_attestation, AppIdentity, MobileExpected, SecurityLevel,
};
use postern_seal_companion::Verdict;
use x509_parser::prelude::{FromDer, X509Certificate};

// The vendored real Google roots (DER), embedded from testdata.
const GOOGLE_ROOT_RSA4096: &[u8] =
    include_bytes!("../testdata/mobile/google_attest_roots/google_hw_attestation_root_rsa4096.der");
const GOOGLE_ROOT_CA1_P384: &[u8] = include_bytes!(
    "../testdata/mobile/google_attest_roots/google_key_attestation_ca1_ecdsa_p384.der"
);

// The recorded SHA-256 DER fingerprints (see PROVENANCE.md / SHA256SUMS). If a
// re-fetch ever changes the vendored bytes, these MUST be updated in lockstep —
// the fingerprint is the out-of-band cross-check the pin depends on.
const FP_RSA4096_HEX: &str =
    "cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc";
const FP_CA1_P384_HEX: &str =
    "6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0";

fn hex32(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64, "fingerprint hex must be 32 bytes");
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("valid hex");
    }
    out
}

/// A `MobileExpected` with the given pinned roots; every other field is set so
/// that the trust-anchor gate (step 4 of `verify_key_attestation_detailed`) is
/// what decides the anchor-related assertions. `now_unix = None` skips the
/// validity-window check so the assertions isolate the anchor behavior.
fn expected_with_roots(roots: Vec<Vec<u8>>) -> MobileExpected {
    MobileExpected {
        roots,
        challenge: vec![0xA1, 0xB2, 0xC3, 0xD4],
        require_device_locked: true,
        require_verified_boot: true,
        min_security_level: SecurityLevel::StrongBox,
        min_os_patch_level: Some(202401),
        expected_app: Some(AppIdentity {
            package_names: vec!["labs.postern.wallet".into()],
            signature_digests: vec![vec![0x11; 32]],
        }),
        now_unix: None,
    }
}

/// (1) Each vendored root is a genuine self-signed X.509v3 CA with the pinned
/// SHA-256 fingerprint — the "real root, not a name match" assertion.
#[test]
fn vendored_google_roots_are_real_self_signed_x509_with_pinned_fingerprints() {
    for (der, fp_hex, label) in [
        (GOOGLE_ROOT_RSA4096, FP_RSA4096_HEX, "RSA-4096 hardware attestation root"),
        (GOOGLE_ROOT_CA1_P384, FP_CA1_P384_HEX, "ECDSA P-384 Key Attestation CA1"),
    ] {
        assert!(!der.is_empty(), "{label}: vendored root DER must be populated");

        // Parses as a well-formed DER X.509 certificate with no trailing bytes.
        let (rest, cert) =
            X509Certificate::from_der(der).unwrap_or_else(|e| panic!("{label}: parse DER: {e:?}"));
        assert!(rest.is_empty(), "{label}: no trailing bytes after the root DER");

        // Self-signed: subject == issuer AND the signature verifies under the
        // cert's own public key (a genuine root, not just a matching name).
        assert_eq!(cert.subject(), cert.issuer(), "{label}: a root is self-issued");
        cert.verify_signature(None)
            .unwrap_or_else(|e| panic!("{label}: root must be validly self-signed: {e:?}"));

        // A trust anchor must assert CA:TRUE.
        assert!(cert.is_ca(), "{label}: pinned root must assert CA:TRUE");

        // SHA-256 DER fingerprint equals the recorded pin (via the crate's own
        // `root_fingerprint_sha256` primitive — same function an operator uses).
        assert_eq!(
            root_fingerprint_sha256(der),
            hex32(fp_hex),
            "{label}: DER fingerprint does not match the recorded pin"
        );
    }
}

/// The RSA root and the ECDSA root are distinct certificates (guards against a
/// copy/paste that vendored the same file twice).
#[test]
fn the_two_vendored_roots_are_distinct() {
    assert_ne!(
        GOOGLE_ROOT_RSA4096, GOOGLE_ROOT_CA1_P384,
        "the two pinned roots must be different certificates"
    );
    assert_ne!(root_fingerprint_sha256(GOOGLE_ROOT_RSA4096), root_fingerprint_sha256(GOOGLE_ROOT_CA1_P384));
}

/// (2) Fail closed with NO root pinned: an Android Key-Attestation chain can
/// only be trusted against a caller-pinned Google root, so an empty root set is
/// [`Verdict::Unverified`] — never `Genuine`. This is the honest offline
/// acceptance alternative to "verify accepts a chain under it".
#[test]
fn no_pinned_root_fails_closed_unverified() {
    // Present a real Google root AS the chain — even so, with nothing pinned the
    // verifier must refuse to trust the chain's own terminal cert.
    let chain: [&[u8]; 1] = [GOOGLE_ROOT_RSA4096];
    let verdict = verify_key_attestation(&chain, &expected_with_roots(vec![]));
    assert!(
        matches!(verdict, Verdict::Unverified(_)),
        "empty root set must fail closed Unverified, got {verdict:?}"
    );
}

/// (3a) The pinned REAL root is consulted AND accepted as an anchor: a
/// single-cert chain whose terminal cert IS a pinned Google root gets PAST the
/// trust-anchor gate (step 4) — proving the vendored root was accepted as a
/// valid anchor — and then fails only for a downstream reason (a bare root
/// carries no Key-Attestation leaf extension). The verdict is therefore the
/// downstream "no attestation extension" Mismatch, NOT the "trust anchor" one.
#[test]
fn pinned_google_root_is_accepted_as_anchor() {
    for root in [GOOGLE_ROOT_RSA4096, GOOGLE_ROOT_CA1_P384] {
        let chain: [&[u8]; 1] = [root];
        let verdict =
            verify_key_attestation(&chain, &expected_with_roots(vec![root.to_vec()]));
        match verdict {
            Verdict::Mismatch(reason) => {
                assert!(
                    reason.contains("no attestation extension"),
                    "expected to pass the anchor gate and fail downstream, got Mismatch({reason:?})"
                );
                assert!(
                    !reason.contains("trust anchor"),
                    "the pinned real root must NOT be rejected at the trust-anchor gate"
                );
            }
            other => panic!("expected a downstream Mismatch past the anchor gate, got {other:?}"),
        }
    }
}

/// (3b) A chain that does NOT terminate at a pinned Google root is refused at
/// the trust-anchor gate — the flip side of (3a), confirming the pin actually
/// decides the anchor. Here we pin the ECDSA root but present the RSA root as
/// the (self-signed, non-anchored) chain: it is neither DER-equal to nor signed
/// by the pinned root, so the verdict is the "trust anchor" Mismatch.
#[test]
fn chain_not_under_a_pinned_google_root_is_refused_at_anchor() {
    let chain: [&[u8]; 1] = [GOOGLE_ROOT_RSA4096];
    let verdict =
        verify_key_attestation(&chain, &expected_with_roots(vec![GOOGLE_ROOT_CA1_P384.to_vec()]));
    match verdict {
        Verdict::Mismatch(reason) => assert!(
            reason.contains("trust anchor"),
            "a non-anchored chain must be refused at the trust-anchor gate, got Mismatch({reason:?})"
        ),
        other => panic!("expected trust-anchor Mismatch, got {other:?}"),
    }
}
