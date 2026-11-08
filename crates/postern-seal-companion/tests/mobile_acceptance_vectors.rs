//! Acceptance-vector lock for the `postern-seal-verify-mobile` deliverable.
//!
//! Every OTHER mobile-attest test synthesizes its cert chain in-process with
//! `rcgen`, so the **checked-in** vectors under `testdata/mobile/` (the exact
//! files the acceptance runbook drives the CLI against) were, until this file,
//! guarded by NOTHING: they could rot, be regenerated with a drifting policy,
//! or lose their Key-Attestation extension and no test would fail. This test
//! closes that gap by loading the vendored DER off disk and asserting the
//! full acceptance contract:
//!
//!   * `leaf.der ← intermediate.der ← root.der`  ⇒  **Genuine**, and the
//!     authenticated facts (StrongBox / verified-boot / device-locked /
//!     OS-patch 202401 / app `labs.postern.wallet`) are exactly what the golden
//!     KeyDescription embeds — a re-labelling regression (e.g. TEE mislabelled
//!     StrongBox) would trip here.
//!   * `leaf_tampered.der`  ⇒  named **Mismatch("chain signature …")**.
//!   * `leaf_expired.der` at a clock past its `notAfter`  ⇒  named
//!     **Mismatch("certificate validity …")**.
//!   * `wrong_root.der` pinned  ⇒  named **Mismatch("trust anchor …")**.
//!
//! SYNTHETIC, offline, `vector-tested ≠ attested`: these DER files were minted
//! by `examples/gen_mobile_attest_vectors.rs` with a test root, never a real
//! StrongBox. They exercise the parse + chain-verify + anchor + policy path end
//! to end without Android hardware — the same discipline as the snp/tdx synth
//! vectors. A Genuine here proves the verifier's logic, NOT a genuine phone.
//!
//! The golden policy embedded in `GOLDEN_KD_DER` (see the generator): nonce
//! `A1B2C3D4`, StrongBox(2), verified-boot(0) + device-locked, OS patch 202401,
//! package `labs.postern.wallet`, signing digest `[0x11; 32]`.

#![cfg(feature = "mobile-attest")]

use postern_seal_companion::mobile::{
    verify_key_attestation_detailed, AppIdentity, MobileExpected, SecurityLevel, VerifiedBootState,
};
use postern_seal_companion::Verdict;
use std::path::PathBuf;

/// The attestation challenge (nonce) the golden KeyDescription was minted with.
const GOLDEN_NONCE: &[u8] = &[0xA1, 0xB2, 0xC3, 0xD4];

/// Absolute path to a vendored acceptance fixture under `testdata/mobile/`.
fn fixture(name: &str) -> PathBuf {
    [env!("CARGO_MANIFEST_DIR"), "testdata", "mobile", name].iter().collect()
}

/// Read a vendored DER fixture, failing loudly if the acceptance vector is
/// missing (a regenerate-forgot-to-commit regression is itself a bug).
fn der(name: &str) -> Vec<u8> {
    std::fs::read(fixture(name))
        .unwrap_or_else(|e| panic!("missing acceptance vector testdata/mobile/{name}: {e}"))
}

/// The full, hardened policy the acceptance drives: pin the (synthetic) root,
/// require the golden nonce, StrongBox floor, verified boot, device locked, the
/// OS-patch anti-rollback floor and the attesting-app identity. Every floor is
/// set to exactly what the golden KeyDescription reports, so a Genuine verdict
/// means the chain satisfied the STRONGEST posture the fixtures can prove.
fn hardened_expected(roots: Vec<Vec<u8>>, now_unix: Option<i64>) -> MobileExpected {
    MobileExpected {
        roots,
        challenge: GOLDEN_NONCE.to_vec(),
        require_device_locked: true,
        require_verified_boot: true,
        min_security_level: SecurityLevel::StrongBox,
        min_os_patch_level: Some(202401),
        expected_app: Some(AppIdentity {
            package_names: vec!["labs.postern.wallet".to_string()],
            signature_digests: vec![vec![0x11; 32]],
        }),
        now_unix,
    }
}

// ── the Genuine acceptance ──────────────────────────────────────────────────

/// `leaf.der ← intermediate.der ← root.der`, root pinned, golden policy ⇒
/// Genuine — and the authenticated facts are EXACTLY the golden ones (no
/// tier/boot/patch/app re-labelling drift).
#[test]
fn vendored_genuine_chain_verifies_and_reports_golden_facts() {
    let leaf = der("leaf.der");
    let inter = der("intermediate.der");
    let root = der("root.der");
    let chain: Vec<&[u8]> = vec![&leaf, &inter, &root];

    // Pin the synthetic test root (the acceptance runbook's `--root root.der`).
    let expected = hardened_expected(vec![root.clone()], None);

    let att = verify_key_attestation_detailed(&chain, &expected)
        .expect("the genuine vendored chain must verify Genuine under the golden policy");

    // The tier is read STRAIGHT from the authenticated attestation — never
    // up-labelled. A regression that mislabels the tier trips right here.
    assert_eq!(att.security_level, SecurityLevel::StrongBox, "attested tier must be StrongBox");
    assert_eq!(att.verified_boot_state, VerifiedBootState::Verified, "boot state must be Verified");
    assert!(att.device_locked, "device must be reported locked");
    assert_eq!(att.os_patch_level, Some(202401), "OS patch level must be 202401");
    assert_eq!(
        att.package_names,
        vec!["labs.postern.wallet".to_string()],
        "attesting app package must be labs.postern.wallet"
    );
}

/// The nonce is genuinely enforced: swap in a WRONG challenge and the same
/// otherwise-genuine vendored chain must be rejected (anti-replay), not
/// Genuine. Proves the Genuine above is not a nonce-blind pass.
#[test]
fn vendored_genuine_chain_with_wrong_nonce_is_rejected() {
    let leaf = der("leaf.der");
    let inter = der("intermediate.der");
    let root = der("root.der");
    let chain: Vec<&[u8]> = vec![&leaf, &inter, &root];

    let mut expected = hardened_expected(vec![root.clone()], None);
    expected.challenge = vec![0xDE, 0xAD, 0xBE, 0xEF]; // not the golden A1B2C3D4

    let v = verify_key_attestation_detailed(&chain, &expected)
        .expect_err("a wrong nonce must never verify Genuine");
    assert!(
        matches!(v, Verdict::Mismatch(_)),
        "wrong nonce must be a named Mismatch (anti-replay), got {v:?}"
    );
}

// ── the three named-rejection acceptances ──────────────────────────────────

/// `leaf_tampered.der` (one signature byte flipped) ⇒ named Mismatch on the
/// chain-signature link. The wire cannot mutate a cert and keep the chain.
#[test]
fn vendored_tampered_leaf_is_named_chain_signature_mismatch() {
    let leaf = der("leaf_tampered.der");
    let inter = der("intermediate.der");
    let root = der("root.der");
    let chain: Vec<&[u8]> = vec![&leaf, &inter, &root];

    let expected = hardened_expected(vec![root.clone()], None);

    match verify_key_attestation_detailed(&chain, &expected) {
        Ok(_) => panic!("a tampered leaf must NEVER verify Genuine"),
        Err(Verdict::Mismatch(reason)) => assert!(
            reason.contains("chain signature"),
            "expected a named chain-signature Mismatch, got Mismatch({reason:?})"
        ),
        Err(other) => panic!("expected Mismatch(chain signature …), got {other:?}"),
    }
}

/// `leaf_expired.der` (validity 2020-09-13 .. 2021-09-13) checked at a clock
/// PAST its `notAfter` ⇒ named Mismatch on certificate validity. Uses a fixed
/// 2023-11-14 clock (1_700_000_000) so the test is deterministic.
#[test]
fn vendored_expired_leaf_is_named_certificate_validity_mismatch() {
    let leaf = der("leaf_expired.der");
    let inter = der("intermediate.der");
    let root = der("root.der");
    let chain: Vec<&[u8]> = vec![&leaf, &inter, &root];

    // now = 2023-11-14, well past the expired leaf's 2021 notAfter.
    let expected = hardened_expected(vec![root.clone()], Some(1_700_000_000));

    match verify_key_attestation_detailed(&chain, &expected) {
        Ok(_) => panic!("an expired leaf must NEVER verify Genuine at a clock past notAfter"),
        Err(Verdict::Mismatch(reason)) => assert!(
            reason.contains("certificate validity"),
            "expected a named certificate-validity Mismatch, got Mismatch({reason:?})"
        ),
        Err(other) => panic!("expected Mismatch(certificate validity …), got {other:?}"),
    }
}

/// The genuine chain pinned against `wrong_root.der` (an UNRELATED self-signed
/// root) ⇒ named Mismatch on the trust anchor. The wire can never supply its
/// own anchor; only the caller-pinned root grants trust.
#[test]
fn vendored_genuine_chain_under_wrong_pinned_root_is_named_trust_anchor_mismatch() {
    let leaf = der("leaf.der");
    let inter = der("intermediate.der");
    let root = der("root.der");
    let wrong_root = der("wrong_root.der");
    let chain: Vec<&[u8]> = vec![&leaf, &inter, &root];

    // Pin the WRONG root — the genuine chain does not terminate at it.
    let expected = hardened_expected(vec![wrong_root], None);

    match verify_key_attestation_detailed(&chain, &expected) {
        Ok(_) => panic!("a chain not under the pinned root must NEVER verify Genuine"),
        Err(Verdict::Mismatch(reason)) => assert!(
            reason.contains("trust anchor"),
            "expected a named trust-anchor Mismatch, got Mismatch({reason:?})"
        ),
        Err(other) => panic!("expected Mismatch(trust anchor …), got {other:?}"),
    }
}

/// Fail-closed at the CLI boundary: with NO root pinned (empty set — what a
/// missing `--root` produces) even the genuine vendored chain is refused with
/// `Verdict::Unverified`, never Genuine. The anchor gate fires before any
/// crypto — the wire never supplies its own trust anchor.
#[test]
fn vendored_genuine_chain_with_no_pinned_root_fails_closed_unverified() {
    let leaf = der("leaf.der");
    let inter = der("intermediate.der");
    let root = der("root.der");
    let chain: Vec<&[u8]> = vec![&leaf, &inter, &root];

    let expected = hardened_expected(Vec::new(), None); // no anchor

    let v = verify_key_attestation_detailed(&chain, &expected)
        .expect_err("no pinned root must fail closed, never Genuine");
    assert!(
        matches!(v, Verdict::Unverified(_)),
        "no pinned root must fail closed with Verdict::Unverified, got {v:?}"
    );
}
