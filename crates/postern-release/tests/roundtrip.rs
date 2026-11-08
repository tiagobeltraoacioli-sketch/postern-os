//! Integration tests for `postern-release`: build a real `SHA256SUMS`
//! manifest over a real (temp) artifacts directory, then hybrid
//! sign/verify it end-to-end through the crate's public API only.
//!
//! These exercise exactly the scenarios the packaging-signing acceptance
//! criteria call for:
//!   1. sign -> verify roundtrip PASSES;
//!   2. a single tampered manifest byte -> FAILS;
//!   3. verifying with the wrong key pair's public keys -> FAILS;
//!   4. corrupting ONLY the Falcon-1024 leg -> FAILS (the ML-DSA leg alone
//!      would still verify — proving the hybrid is a true AND, not an OR);
//!   5. corrupting ONLY the ML-DSA-87 leg -> FAILS (symmetric proof).

use std::fs;
use std::path::Path;

use postern_release::sign::{HybridSignature, KeyPair, VerifyError};
use postern_release::{manifest, sign};

/// Populate a fresh temp directory with a small, multi-file "release" and
/// return its `SHA256SUMS` manifest bytes (written to disk, matching what
/// the CLI's `sign` subcommand does).
fn build_release_manifest(dir: &Path) -> Vec<u8> {
    fs::write(dir.join("bloch-node"), b"pretend ELF binary #1").unwrap();
    fs::create_dir_all(dir.join("nested")).unwrap();
    fs::write(dir.join("nested/postern-desktop.AppImage"), b"pretend AppImage #2").unwrap();
    fs::write(dir.join("RELEASE_NOTES.txt"), b"v0.1.0\n").unwrap();

    manifest::write_manifest(dir).expect("building the manifest over a real artifacts dir must succeed")
}

#[test]
fn sign_then_verify_roundtrip_passes() {
    let dir = tempfile::tempdir().unwrap();
    let manifest_bytes = build_release_manifest(dir.path());

    // The manifest actually landed on disk, byte-identical to what we sign.
    let on_disk = fs::read(dir.path().join(manifest::MANIFEST_NAME)).unwrap();
    assert_eq!(on_disk, manifest_bytes);

    let key_pair = KeyPair::generate();
    let signature = sign::sign_manifest(&manifest_bytes, &key_pair)
        .expect("signing a real manifest with a freshly generated hybrid key pair must succeed");

    sign::verify_manifest(&manifest_bytes, &signature, &key_pair.public_key())
        .expect("a genuine hybrid signature over the exact signed bytes must verify");
}

#[test]
fn tampered_manifest_byte_fails() {
    let dir = tempfile::tempdir().unwrap();
    let manifest_bytes = build_release_manifest(dir.path());

    let key_pair = KeyPair::generate();
    let signature = sign::sign_manifest(&manifest_bytes, &key_pair).unwrap();

    // Flip exactly one byte anywhere in the signed manifest (e.g. one hex
    // digit of a listed artifact's hash) and confirm verification fails.
    let mut tampered = manifest_bytes.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0x01;
    assert_ne!(tampered, manifest_bytes);

    let result = sign::verify_manifest(&tampered, &signature, &key_pair.public_key());
    assert!(
        result.is_err(),
        "a single tampered manifest byte must fail hybrid verification"
    );
}

#[test]
fn wrong_verifying_key_fails() {
    let dir = tempfile::tempdir().unwrap();
    let manifest_bytes = build_release_manifest(dir.path());

    let signer = KeyPair::generate();
    let signature = sign::sign_manifest(&manifest_bytes, &signer).unwrap();

    // A completely different key pair's public keys must not verify a
    // signature they never produced.
    let attacker_or_unrelated_key = KeyPair::generate();
    let result = sign::verify_manifest(&manifest_bytes, &signature, &attacker_or_unrelated_key.public_key());
    assert!(
        result.is_err(),
        "verifying with the wrong public key pair must fail"
    );
}

#[test]
fn corrupting_only_the_falcon_leg_fails_the_whole_hybrid() {
    let dir = tempfile::tempdir().unwrap();
    let manifest_bytes = build_release_manifest(dir.path());

    let key_pair = KeyPair::generate();
    let mut signature = sign::sign_manifest(&manifest_bytes, &key_pair).unwrap();

    // Confirm the ML-DSA leg is untouched and would, in isolation, still be
    // a legitimate signature over this transcript — then confirm the HYBRID
    // still rejects because the AND check does not let a good leg rescue a
    // bad one.
    let ml_dsa_leg_before = signature.ml_dsa.clone();

    let last = signature.falcon.len() - 1;
    signature.falcon[last] ^= 0xFF;

    assert_eq!(
        signature.ml_dsa, ml_dsa_leg_before,
        "only the Falcon leg should have been mutated"
    );

    let result = sign::verify_manifest(&manifest_bytes, &signature, &key_pair.public_key());
    match result {
        Err(VerifyError::FalconFailed) => {}
        Err(other) => panic!("expected FalconFailed, got a different error: {other}"),
        Ok(()) => panic!(
            "a hybrid signature with a corrupted Falcon-1024 leg must NOT verify, \
             even though the ML-DSA-87 leg alone is still valid — the hybrid must \
             be a true AND-of-both, not an either-leg OR"
        ),
    }
}

#[test]
fn corrupting_only_the_ml_dsa_leg_fails_the_whole_hybrid() {
    let dir = tempfile::tempdir().unwrap();
    let manifest_bytes = build_release_manifest(dir.path());

    let key_pair = KeyPair::generate();
    let mut signature = sign::sign_manifest(&manifest_bytes, &key_pair).unwrap();

    let falcon_leg_before = signature.falcon.clone();

    // Flip a byte within the leading `c_tilde` challenge-hash portion of the
    // encoded ML-DSA signature (an opaque hash with no format constraints of
    // its own), so this is guaranteed to fail at cryptographic verification
    // rather than at decode time (flipping deep into the bit-packed hint
    // suffix instead can make decoding itself reject the bytes — also a
    // correct fail-closed outcome, just a different error variant).
    signature.ml_dsa[0] ^= 0xFF;

    assert_eq!(
        signature.falcon, falcon_leg_before,
        "only the ML-DSA leg should have been mutated"
    );

    let result = sign::verify_manifest(&manifest_bytes, &signature, &key_pair.public_key());
    match result {
        Err(VerifyError::MlDsaFailed) => {}
        Err(other) => panic!("expected MlDsaFailed, got a different error: {other}"),
        Ok(()) => panic!(
            "a hybrid signature with a corrupted ML-DSA-87 leg must NOT verify, \
             even though the Falcon-1024 leg alone is still valid — the hybrid must \
             be a true AND-of-both, not an either-leg OR"
        ),
    }
}

#[test]
fn cli_style_serialized_signature_round_trips_through_disk_bytes() {
    // Exercises the same `to_bytes`/`from_bytes` container the CLI writes to
    // `SHA256SUMS.pqsig`, end to end through a real file on disk.
    let dir = tempfile::tempdir().unwrap();
    let manifest_bytes = build_release_manifest(dir.path());

    let key_pair = KeyPair::generate();
    let signature = sign::sign_manifest(&manifest_bytes, &key_pair).unwrap();

    let sig_path = dir.path().join(format!("{}.pqsig", manifest::MANIFEST_NAME));
    fs::write(&sig_path, signature.to_bytes()).unwrap();

    // `SHA256SUMS.pqsig` must itself be excluded if the manifest is rebuilt.
    let rebuilt = manifest::build_manifest(dir.path()).unwrap();
    assert_eq!(rebuilt, manifest_bytes);

    let read_back = fs::read(&sig_path).unwrap();
    let decoded = HybridSignature::from_bytes(&read_back).unwrap();
    sign::verify_manifest(&manifest_bytes, &decoded, &key_pair.public_key()).unwrap();
}
