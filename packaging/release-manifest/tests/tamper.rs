// SPDX-License-Identifier: MIT OR Apache-2.0

//! Adversarial tamper tests for the signed release-manifest step.
//!
//! `tests/roundtrip.rs` corrupts the BUNDLE DIRECTORY after `build` and proves
//! the against-directory re-check catches it. This file attacks from the other
//! side: it corrupts the MANIFEST itself (the JSON an attacker would rewrite to
//! make a swapped bundle look honest) and the detached HYBRID signature, and
//! proves each forgery is a hard `Err`:
//!
//!   * a manifest whose recorded digest, size, or path no longer matches the
//!     real bytes on disk FAILS the re-check (a mutated digest / wrong size /
//!     added / removed / renamed path);
//!   * a truncated manifest body FAILS to parse and FAILS signature check;
//!   * a signature computed over the WRONG bytes is rejected, and editing any
//!     field of an already-signed manifest breaks its signature.
//!
//! Hybrid signing/verifying is `postern_release::sign`, reused unmodified — the
//! AND-of-both rule exercised here is the same one crates/postern-release pins
//! in its own tests. Dev keys only, UNAUDITED, LOCAL metadata only: a passing
//! check proves origin+integrity of the listed bytes, NOT attestation.

use std::fs;
use std::path::Path;

use postern_release::sign::{sign_manifest, verify_manifest, KeyPair};
use postern_release_manifest::{
    build_manifest, check_against_dir, from_json_bytes, to_json_bytes, ArtifactEntry,
    ManifestError,
};

const APP: &str = "postern-app-0.0.0-dev.bin";
const CLI: &str = "postern-cli-0.0.0-dev.bin";

/// A throwaway bundle dir with two real artifacts, plus the outputs /
/// `SHA256SUMS` names that `build` must skip — same fixture shape as
/// `tests/roundtrip.rs::sample_bundle`.
fn sample_bundle(dir: &Path) {
    fs::write(dir.join(APP), b"dummy bundle artifact").unwrap();
    fs::write(dir.join(CLI), b"second artifact, different bytes").unwrap();
    fs::write(dir.join("SHA256SUMS"), b"not an artifact\n").unwrap();
    fs::write(dir.join("release-manifest.json.pqsig"), b"stale sig, must be skipped").unwrap();
}

/// Index of the artifact named `name` in a freshly built manifest (fixtures
/// are sorted by name, so this is stable).
fn entry_index(manifest: &postern_release_manifest::ReleaseManifest, name: &str) -> usize {
    manifest
        .artifacts
        .iter()
        .position(|a| a.name == name)
        .expect("fixture artifact present")
}

/// A MUTATED DIGEST in the manifest (attacker points an honest-looking entry at
/// a hash of their choosing while the real bytes are untouched) must fail the
/// re-check on the SHA-256 comparison.
#[test]
fn mutated_digest_in_manifest_fails_dir_recheck() {
    let dir = tempfile::tempdir().unwrap();
    sample_bundle(dir.path());
    let mut manifest = build_manifest(dir.path()).unwrap();
    // Sanity: the honest manifest re-checks clean.
    check_against_dir(&manifest, dir.path()).unwrap();

    let i = entry_index(&manifest, APP);
    // Flip one hex nibble of the recorded digest — still 64 lowercase hex
    // chars, just no longer the hash of the file on disk.
    let mut digest: Vec<u8> = manifest.artifacts[i].sha256.clone().into_bytes();
    digest[0] = if digest[0] == b'a' { b'b' } else { b'a' };
    manifest.artifacts[i].sha256 = String::from_utf8(digest).unwrap();

    assert!(matches!(
        check_against_dir(&manifest, dir.path()).unwrap_err(),
        ManifestError::Sha256Mismatch { name, .. } if name == APP
    ));
}

/// A WRONG SIZE in the manifest is caught by the cheap `stat` comparison before
/// the hash is even recomputed.
#[test]
fn wrong_size_in_manifest_fails_dir_recheck() {
    let dir = tempfile::tempdir().unwrap();
    sample_bundle(dir.path());
    let mut manifest = build_manifest(dir.path()).unwrap();

    let i = entry_index(&manifest, CLI);
    manifest.artifacts[i].size += 1;
    assert!(matches!(
        check_against_dir(&manifest, dir.path()).unwrap_err(),
        ManifestError::SizeMismatch { name, .. } if name == CLI
    ));
}

/// A RENAMED PATH in the manifest (the entry describes the right bytes but
/// under a name that does not exist on disk) fails closed: the real file is now
/// unlisted, and/or the renamed entry is missing — both are hard errors.
#[test]
fn renamed_path_in_manifest_fails_dir_recheck() {
    let dir = tempfile::tempdir().unwrap();
    sample_bundle(dir.path());
    let mut manifest = build_manifest(dir.path()).unwrap();

    let i = entry_index(&manifest, APP);
    manifest.artifacts[i].name = "postern-app-9.9.9-EVIL.bin".to_string();
    assert!(matches!(
        check_against_dir(&manifest, dir.path()).unwrap_err(),
        // on-disk `APP` is now unlisted, or the renamed entry is missing —
        // whichever the walk trips first; both are the same fail-closed verdict.
        ManifestError::UnlistedFile(_) | ManifestError::MissingArtifact(_)
    ));
}

/// An ADDED PATH in the manifest (a phantom artifact the attacker lists but
/// never ships) fails closed: the listed file is missing from the bundle dir.
#[test]
fn added_path_in_manifest_fails_dir_recheck() {
    let dir = tempfile::tempdir().unwrap();
    sample_bundle(dir.path());
    let mut manifest = build_manifest(dir.path()).unwrap();

    manifest.artifacts.push(ArtifactEntry {
        name: "postern-ghost-0.0.0-dev.bin".to_string(),
        size: 12,
        sha256: "0".repeat(64),
    });
    assert!(matches!(
        check_against_dir(&manifest, dir.path()).unwrap_err(),
        ManifestError::MissingArtifact(name) if name == "postern-ghost-0.0.0-dev.bin"
    ));
}

/// A REMOVED PATH from the manifest (attacker drops an entry so a real file in
/// the bundle goes undescribed) fails closed: an unlisted on-disk file is
/// exactly what tampering looks like.
#[test]
fn removed_path_from_manifest_fails_dir_recheck() {
    let dir = tempfile::tempdir().unwrap();
    sample_bundle(dir.path());
    let mut manifest = build_manifest(dir.path()).unwrap();

    let i = entry_index(&manifest, CLI);
    manifest.artifacts.remove(i);
    assert!(matches!(
        check_against_dir(&manifest, dir.path()).unwrap_err(),
        ManifestError::UnlistedFile(name) if name == CLI
    ));
}

/// A TRUNCATED manifest body must neither parse nor verify: the JSON is no
/// longer well-formed, and the honest signature covers the FULL bytes.
#[test]
fn truncated_manifest_body_fails_parse_and_verify() {
    let dir = tempfile::tempdir().unwrap();
    sample_bundle(dir.path());
    let bytes = to_json_bytes(&build_manifest(dir.path()).unwrap()).unwrap();

    let kp = KeyPair::generate();
    let sig = sign_manifest(&bytes, &kp).unwrap();
    // Sanity: full bytes parse and verify.
    from_json_bytes(&bytes).unwrap();
    verify_manifest(&bytes, &sig, &kp.public_key()).unwrap();

    // Chop the manifest in half: malformed JSON, and not the signed bytes.
    let truncated = &bytes[..bytes.len() / 2];
    assert!(matches!(
        from_json_bytes(truncated).unwrap_err(),
        ManifestError::Json(_)
    ));
    assert!(
        verify_manifest(truncated, &sig, &kp.public_key()).is_err(),
        "a signature over the full manifest must not verify a truncated body"
    );
}

/// A signature computed over the WRONG BYTES is rejected: signing bundle A's
/// manifest and presenting that signature over bundle B's manifest must fail
/// (both signature legs, AND-of-both — the transcript simply never matches).
#[test]
fn signature_over_the_wrong_bytes_is_rejected() {
    let dir_a = tempfile::tempdir().unwrap();
    sample_bundle(dir_a.path());
    let bytes_a = to_json_bytes(&build_manifest(dir_a.path()).unwrap()).unwrap();

    let dir_b = tempfile::tempdir().unwrap();
    fs::write(dir_b.path().join(APP), b"a DIFFERENT app build entirely").unwrap();
    fs::write(dir_b.path().join(CLI), b"a different cli too, other bytes").unwrap();
    let bytes_b = to_json_bytes(&build_manifest(dir_b.path()).unwrap()).unwrap();
    assert_ne!(bytes_a, bytes_b, "test setup: the two manifests must differ");

    let kp = KeyPair::generate();
    let sig_a = sign_manifest(&bytes_a, &kp).unwrap();
    // The signature is bound to A's exact bytes; it cannot vouch for B.
    assert!(
        verify_manifest(&bytes_b, &sig_a, &kp.public_key()).is_err(),
        "a signature over manifest A must not verify manifest B"
    );
    // Sanity: it does verify its own bytes.
    verify_manifest(&bytes_a, &sig_a, &kp.public_key()).unwrap();
}

/// Editing ANY field of an already-signed manifest (here: bumping a recorded
/// size) breaks the signature — the detached hybrid signature is over the exact
/// serialized bytes, so a re-serialization of a mutated struct will not verify.
#[test]
fn editing_a_signed_manifest_field_breaks_the_signature() {
    let dir = tempfile::tempdir().unwrap();
    sample_bundle(dir.path());
    let manifest = build_manifest(dir.path()).unwrap();
    let honest_bytes = to_json_bytes(&manifest).unwrap();

    let kp = KeyPair::generate();
    let sig = sign_manifest(&honest_bytes, &kp).unwrap();
    verify_manifest(&honest_bytes, &sig, &kp.public_key()).unwrap();

    // Attacker edits the signed manifest (any field) and re-serializes.
    let mut forged = manifest.clone();
    let i = entry_index(&forged, APP);
    forged.artifacts[i].size += 4096;
    let forged_bytes = to_json_bytes(&forged).unwrap();
    assert_ne!(honest_bytes, forged_bytes);
    assert!(
        verify_manifest(&forged_bytes, &sig, &kp.public_key()).is_err(),
        "the old signature must not vouch for an edited manifest"
    );
}
