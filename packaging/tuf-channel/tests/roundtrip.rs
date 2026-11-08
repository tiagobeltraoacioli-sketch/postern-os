// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Integration tests for the DEV-ONLY TUF update-channel scaffold:
//
//   1. Honest round trip: init → add-target → verify returns matching
//      bytes/hash through tough's full fail-closed client path.
//   2. Fail closed: corrupting targets.json makes verification FAIL.
//   3. Fail closed: swapping the target artifact itself makes the fetch FAIL.
//
// Everything runs in tempdirs with freshly generated dev keys; nothing
// touches the network (FilesystemTransport only) and nothing here implies a
// live update channel exists.

use sha2::{Digest, Sha256};

const FIXTURE_NAME: &str = "postern-app-0.0.0-dev.bin";
const FIXTURE_BYTES: &[u8] = b"postern dev bundle fixture - NOT a real artifact\n";

/// init → add fixture → verify: fetched bytes and SHA-256 must match.
#[tokio::test(flavor = "current_thread")]
async fn roundtrip_init_add_verify() {
    let repo_dir = tempfile::tempdir().expect("tempdir");
    let out_dir = tempfile::tempdir().expect("tempdir");

    let paths = postern_tuf::init_repo(repo_dir.path())
        .await
        .expect("init_repo");
    // The dev-key directory must exist under its warning name, with README.
    assert!(paths.keys_dir.ends_with("dev-keys-DO-NOT-SHIP"));
    let keys_readme =
        std::fs::read_to_string(paths.keys_dir.join("README.md")).expect("keys README");
    assert!(keys_readme.contains("UNAUDITED"));
    assert!(keys_readme.contains("No live update endpoint"));

    // Write and add the fixture artifact.
    let fixture = repo_dir.path().join(FIXTURE_NAME);
    std::fs::write(&fixture, FIXTURE_BYTES).expect("write fixture");
    let name = postern_tuf::add_target(repo_dir.path(), &fixture)
        .await
        .expect("add_target");
    assert_eq!(name, FIXTURE_NAME);

    // Verify through the full TUF client path.
    let sha256 = postern_tuf::verify_target(repo_dir.path(), FIXTURE_NAME, out_dir.path())
        .await
        .expect("verify_target");
    let expected = hex::encode(Sha256::digest(FIXTURE_BYTES));
    assert_eq!(sha256, expected, "SHA-256 of fetched target must match");

    let fetched = std::fs::read(out_dir.path().join(FIXTURE_NAME)).expect("fetched bytes");
    assert_eq!(fetched, FIXTURE_BYTES, "fetched bytes must match fixture");
}

/// Corrupting targets.json (bit-flip inside the signed body) must make the
/// repository FAIL to verify — fail closed, never fail open.
#[tokio::test(flavor = "current_thread")]
async fn tampered_targets_metadata_fails_closed() {
    let repo_dir = tempfile::tempdir().expect("tempdir");
    let out_dir = tempfile::tempdir().expect("tempdir");

    postern_tuf::init_repo(repo_dir.path()).await.expect("init");
    let fixture = repo_dir.path().join(FIXTURE_NAME);
    std::fs::write(&fixture, FIXTURE_BYTES).expect("write fixture");
    postern_tuf::add_target(repo_dir.path(), &fixture)
        .await
        .expect("add_target");

    // Sanity: verification passes before tampering.
    postern_tuf::verify_target(repo_dir.path(), FIXTURE_NAME, out_dir.path())
        .await
        .expect("verify before tampering");

    // Tamper: flip the artifact length recorded in targets.json. The file
    // stays valid JSON but no longer matches its signature (nor the
    // hash/length pinned in snapshot.json).
    let targets_path = repo_dir.path().join("metadata").join("targets.json");
    let metadata = std::fs::read_to_string(&targets_path).expect("read targets.json");
    let honest_len = format!("\"length\": {}", FIXTURE_BYTES.len());
    assert!(
        metadata.contains(&honest_len),
        "test setup: expected length field in targets.json"
    );
    let tampered = metadata.replace(&honest_len, "\"length\": 999999");
    assert_ne!(metadata, tampered);
    std::fs::write(&targets_path, tampered).expect("write tampered targets.json");

    let result =
        postern_tuf::verify_target(repo_dir.path(), FIXTURE_NAME, out_dir.path()).await;
    assert!(
        result.is_err(),
        "tampered targets.json MUST fail verification, got Ok"
    );
}

/// Swapping the artifact bytes in targets/ (metadata untouched) must make the
/// target fetch FAIL its pinned hash/length check.
#[tokio::test(flavor = "current_thread")]
async fn tampered_target_artifact_fails_closed() {
    let repo_dir = tempfile::tempdir().expect("tempdir");
    let out_dir = tempfile::tempdir().expect("tempdir");

    postern_tuf::init_repo(repo_dir.path()).await.expect("init");
    let fixture = repo_dir.path().join(FIXTURE_NAME);
    std::fs::write(&fixture, FIXTURE_BYTES).expect("write fixture");
    postern_tuf::add_target(repo_dir.path(), &fixture)
        .await
        .expect("add_target");

    // Tamper: replace the served artifact with different bytes of the SAME
    // length (so only the hash check can catch it).
    let served = repo_dir.path().join("targets").join(FIXTURE_NAME);
    let mut evil = FIXTURE_BYTES.to_vec();
    evil[0] ^= 0xFF;
    std::fs::write(&served, &evil).expect("write tampered artifact");

    let result =
        postern_tuf::verify_target(repo_dir.path(), FIXTURE_NAME, out_dir.path()).await;
    assert!(
        result.is_err(),
        "tampered artifact bytes MUST fail the pinned-hash check, got Ok"
    );
}
