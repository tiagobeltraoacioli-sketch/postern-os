// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fail-closed roundtrip tests for the signed release-manifest step.
//!
//! The happy path proves build → sign → verify works end to end; every other
//! test proves that ONE deliberate corruption — of the manifest bytes, of an
//! artifact after `build`, of a single signature leg, or of the input set
//! itself — is a hard error. Hybrid signing/verifying is
//! `postern_release::sign`, reused unmodified, so the AND-of-both rule tested
//! here is the same one crates/postern-release pins down in its own tests.

use std::fs;
use std::path::Path;

use postern_release::sign::{sign_manifest, verify_manifest, KeyPair};
use postern_release_manifest::{
    build_manifest, check_against_dir, from_json_bytes, merge_signed_sha256sums,
    parse_sha256sums, to_json_bytes, ManifestError, HONESTY_NOTE, SCHEMA_VERSION,
};

/// A throwaway bundle dir with two artifacts, plus the outputs/`SHA256SUMS`
/// names that `build` must skip.
fn sample_bundle(dir: &Path) {
    fs::write(dir.join("postern-app-0.0.0-dev.bin"), b"dummy bundle artifact").unwrap();
    fs::write(dir.join("postern-cli-0.0.0-dev.bin"), b"second artifact, different bytes").unwrap();
    fs::write(dir.join("SHA256SUMS"), b"not an artifact\n").unwrap();
    fs::write(dir.join("release-manifest.json.pqsig"), b"stale sig, must be skipped").unwrap();
}

#[test]
fn honest_build_sign_verify_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    sample_bundle(dir.path());

    let manifest = build_manifest(dir.path()).unwrap();
    assert_eq!(manifest.schema_version, SCHEMA_VERSION);
    assert_eq!(manifest.honesty, HONESTY_NOTE);
    // Sorted, and only the two real artifacts (SHA256SUMS + stale sig skipped).
    let names: Vec<_> = manifest.artifacts.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(names, ["postern-app-0.0.0-dev.bin", "postern-cli-0.0.0-dev.bin"]);
    assert_eq!(manifest.artifacts[0].size, b"dummy bundle artifact".len() as u64);

    // JSON bytes roundtrip and are what gets signed.
    let bytes = to_json_bytes(&manifest).unwrap();
    assert_eq!(from_json_bytes(&bytes).unwrap(), manifest);

    let kp = KeyPair::generate();
    let sig = sign_manifest(&bytes, &kp).unwrap();
    verify_manifest(&bytes, &sig, &kp.public_key()).unwrap();

    // And the against-dir re-check passes on the untouched bundle.
    check_against_dir(&manifest, dir.path()).unwrap();
}

#[test]
fn flipping_one_manifest_byte_fails_verify() {
    let dir = tempfile::tempdir().unwrap();
    sample_bundle(dir.path());

    let bytes = to_json_bytes(&build_manifest(dir.path()).unwrap()).unwrap();
    let kp = KeyPair::generate();
    let sig = sign_manifest(&bytes, &kp).unwrap();

    let mut tampered = bytes.clone();
    tampered[bytes.len() / 2] ^= 0x01;
    assert!(verify_manifest(&tampered, &sig, &kp.public_key()).is_err());
    // Sanity: the untampered bytes still verify.
    verify_manifest(&bytes, &sig, &kp.public_key()).unwrap();
}

#[test]
fn modifying_artifact_after_build_fails_dir_recheck() {
    let dir = tempfile::tempdir().unwrap();
    sample_bundle(dir.path());
    let manifest = build_manifest(dir.path()).unwrap();
    check_against_dir(&manifest, dir.path()).unwrap();

    // Same size, different bytes: only the SHA-256 re-hash can catch this.
    let target = dir.path().join("postern-app-0.0.0-dev.bin");
    let mut content = fs::read(&target).unwrap();
    content[0] ^= 0xFF;
    fs::write(&target, &content).unwrap();
    assert!(matches!(
        check_against_dir(&manifest, dir.path()).unwrap_err(),
        ManifestError::Sha256Mismatch { .. }
    ));
}

#[test]
fn growing_artifact_after_build_fails_dir_recheck_on_size() {
    let dir = tempfile::tempdir().unwrap();
    sample_bundle(dir.path());
    let manifest = build_manifest(dir.path()).unwrap();

    let target = dir.path().join("postern-cli-0.0.0-dev.bin");
    let mut content = fs::read(&target).unwrap();
    content.push(b'!');
    fs::write(&target, &content).unwrap();
    assert!(matches!(
        check_against_dir(&manifest, dir.path()).unwrap_err(),
        ManifestError::SizeMismatch { .. }
    ));
}

#[test]
fn deleting_artifact_after_build_fails_dir_recheck() {
    let dir = tempfile::tempdir().unwrap();
    sample_bundle(dir.path());
    let manifest = build_manifest(dir.path()).unwrap();

    fs::remove_file(dir.path().join("postern-app-0.0.0-dev.bin")).unwrap();
    assert!(matches!(
        check_against_dir(&manifest, dir.path()).unwrap_err(),
        // The remaining file trips either check first depending on iteration
        // order; both are the same fail-closed outcome.
        ManifestError::MissingArtifact(_) | ManifestError::UnlistedFile(_)
    ));
}

#[test]
fn unlisted_file_added_after_build_fails_dir_recheck() {
    let dir = tempfile::tempdir().unwrap();
    sample_bundle(dir.path());
    let manifest = build_manifest(dir.path()).unwrap();

    fs::write(dir.path().join("smuggled.bin"), b"not in the manifest").unwrap();
    assert!(matches!(
        check_against_dir(&manifest, dir.path()).unwrap_err(),
        ManifestError::UnlistedFile(name) if name == "smuggled.bin"
    ));
}

#[test]
fn corrupting_one_signature_leg_fails_the_hybrid() {
    let dir = tempfile::tempdir().unwrap();
    sample_bundle(dir.path());
    let bytes = to_json_bytes(&build_manifest(dir.path()).unwrap()).unwrap();

    let kp = KeyPair::generate();
    let good = sign_manifest(&bytes, &kp).unwrap();
    verify_manifest(&bytes, &good, &kp.public_key()).unwrap();

    // Corrupt ONLY the Falcon leg — the ML-DSA leg alone would still verify,
    // but the hybrid is AND-of-both (postern-release's rule), so it must fail.
    let mut falcon_bad = good.clone();
    let last = falcon_bad.falcon.len() - 1;
    falcon_bad.falcon[last] ^= 0xFF;
    assert!(verify_manifest(&bytes, &falcon_bad, &kp.public_key()).is_err());

    // And symmetrically: corrupt ONLY the ML-DSA leg (byte 0 is inside
    // c_tilde, which always decodes — see postern-release's own test notes).
    let mut ml_dsa_bad = good.clone();
    ml_dsa_bad.ml_dsa[0] ^= 0xFF;
    assert!(verify_manifest(&bytes, &ml_dsa_bad, &kp.public_key()).is_err());
}

#[test]
fn empty_bundle_dir_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        build_manifest(dir.path()).unwrap_err(),
        ManifestError::EmptyBundle(_)
    ));

    // Skipped-only content is still "empty" — a manifest may never describe
    // nothing.
    fs::write(dir.path().join("SHA256SUMS"), b"only skipped names here\n").unwrap();
    assert!(matches!(
        build_manifest(dir.path()).unwrap_err(),
        ManifestError::EmptyBundle(_)
    ));
}

// ── Verified SHA256SUMS merge (fail closed) ──────────────────────────────────
//
// Regression suite for the verify-BEFORE-merge rule: the publish pipeline's
// shared-SUMS merge must never re-sign remote bytes it did not verify. A
// remote SUMS that is unsigned, tampered with, or signed by the wrong key is
// a hard error; only a remote whose hybrid signature verifies over the exact
// fetched bytes is merged (and the fresh local entry wins name collisions).

const LOCAL_SUMS: &str =
    "1111111111111111111111111111111111111111111111111111111111111111  postern-os-v0.2.iso\n";

/// An older shared SUMS: a previous image plus a STALE line for the very
/// name the local build replaces.
fn remote_sums() -> Vec<u8> {
    b"2222222222222222222222222222222222222222222222222222222222222222  postern-os-v0.1.iso\n\
0000000000000000000000000000000000000000000000000000000000000000  postern-os-v0.2.iso\n"
        .to_vec()
}

#[test]
fn verified_remote_sums_merge_roundtrip_local_wins() {
    let kp = KeyPair::generate();
    let remote = b"2222222222222222222222222222222222222222222222222222222222222222  postern-os-v0.1.iso\n0000000000000000000000000000000000000000000000000000000000000000  postern-os-v0.2.iso\n".to_vec();
    let sig = sign_manifest(&remote, &kp).unwrap().to_bytes();

    let merged =
        merge_signed_sha256sums(LOCAL_SUMS, Some(&remote), Some(&sig), &kp.public_key()).unwrap();

    // Union of both files, sorted, with the LOCAL v0.2 hash (fresh build)
    // overriding the stale remote line for the same name.
    assert_eq!(
        merged,
        "2222222222222222222222222222222222222222222222222222222222222222  postern-os-v0.1.iso\n\
         1111111111111111111111111111111111111111111111111111111111111111  postern-os-v0.2.iso\n"
    );
    // And the merged output parses back cleanly (canonical format).
    assert_eq!(parse_sha256sums(merged.as_bytes()).unwrap().len(), 2);
}

#[test]
fn tampered_remote_sums_refuses_to_merge() {
    let kp = KeyPair::generate();
    let remote = b"2222222222222222222222222222222222222222222222222222222222222222  postern-os-v0.1.iso\n".to_vec();
    let sig = sign_manifest(&remote, &kp).unwrap().to_bytes();

    // Flip ONE hex digit of the remote hash AFTER signing — exactly what a
    // bucket attacker swapping an image + its SUMS line looks like.
    let mut tampered = remote.clone();
    tampered[0] = b'3';
    let err = merge_signed_sha256sums(LOCAL_SUMS, Some(&tampered), Some(&sig), &kp.public_key())
        .unwrap_err();
    assert!(
        matches!(err, ManifestError::RemoteSumsSignature(_)),
        "a tampered remote SUMS must fail the signature check, got: {err}"
    );

    // Sanity: the untampered remote still merges.
    merge_signed_sha256sums(LOCAL_SUMS, Some(&remote), Some(&sig), &kp.public_key()).unwrap();
}

#[test]
fn unsigned_remote_sums_refuses_to_merge() {
    let kp = KeyPair::generate();
    let remote = remote_sums();
    // No signature at all: fail closed — never "merge anyway and re-sign".
    let err =
        merge_signed_sha256sums(LOCAL_SUMS, Some(&remote), None, &kp.public_key()).unwrap_err();
    assert!(matches!(err, ManifestError::RemoteSumsUnsigned), "got: {err}");
}

#[test]
fn remote_sums_signed_by_a_different_key_refuses_to_merge() {
    let signer = KeyPair::generate();
    let verifier = KeyPair::generate(); // NOT the key that signed
    let remote = remote_sums();
    let sig = sign_manifest(&remote, &signer).unwrap().to_bytes();
    let err = merge_signed_sha256sums(LOCAL_SUMS, Some(&remote), Some(&sig), &verifier.public_key())
        .unwrap_err();
    assert!(matches!(err, ManifestError::RemoteSumsSignature(_)), "got: {err}");
}

#[test]
fn bootstrap_with_no_remote_sums_keeps_local_only() {
    let kp = KeyPair::generate();
    // No remote SUMS exists yet (first publish): local lines pass through,
    // normalized. A signature without remote bytes is inconsistent input.
    let merged = merge_signed_sha256sums(LOCAL_SUMS, None, None, &kp.public_key()).unwrap();
    assert_eq!(merged, LOCAL_SUMS);
    assert!(merge_signed_sha256sums(LOCAL_SUMS, None, Some(b"orphan"), &kp.public_key()).is_err());
}

#[test]
fn malformed_remote_sums_lines_fail_closed_even_when_signed() {
    let kp = KeyPair::generate();
    // Validly signed, but the content is not sha256sum format: still refuse.
    let remote = b"not a sums line at all\n".to_vec();
    let sig = sign_manifest(&remote, &kp).unwrap().to_bytes();
    let err = merge_signed_sha256sums(LOCAL_SUMS, Some(&remote), Some(&sig), &kp.public_key())
        .unwrap_err();
    assert!(matches!(err, ManifestError::SumsLine { .. }), "got: {err}");
}

#[test]
fn manifest_with_no_artifacts_fails_dir_recheck() {
    let dir = tempfile::tempdir().unwrap();
    sample_bundle(dir.path());
    let mut manifest = build_manifest(dir.path()).unwrap();
    manifest.artifacts.clear();
    assert!(matches!(
        check_against_dir(&manifest, dir.path()).unwrap_err(),
        ManifestError::EmptyManifest
    ));
}
