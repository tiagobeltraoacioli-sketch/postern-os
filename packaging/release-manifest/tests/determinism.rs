// SPDX-License-Identifier: MIT OR Apache-2.0

//! SOURCE_DATE_EPOCH determinism for `build`.
//!
//! With `SOURCE_DATE_EPOCH` set (the reproducible-builds convention), two
//! `build` runs over an identical bundle dir must produce BYTE-IDENTICAL
//! `release-manifest.json` bytes; without it, `created_at` is the wall clock
//! and everything still parses and verifies. A set-but-malformed
//! `SOURCE_DATE_EPOCH` is a hard error (fail closed — a silently ignored
//! knob would fake determinism).
//!
//! HONESTY — scope: this pins the MANIFEST bytes only. The bundle artifacts
//! the manifest describes are NOT made (or claimed) bit-reproducible.
//!
//! This lives in its OWN integration-test file (= its own process) because
//! it mutates the process environment; the phases below run inside a single
//! `#[test]` so no parallel test in this binary observes a half-set variable.

use std::fs;
use std::path::Path;

use postern_release_manifest::{build_manifest, check_against_dir, from_json_bytes, to_json_bytes, ManifestError};

fn sample_bundle(dir: &Path) {
    fs::write(dir.join("postern-app-0.0.0-dev.bin"), b"dummy bundle artifact").unwrap();
    fs::write(dir.join("postern-cli-0.0.0-dev.bin"), b"second artifact, different bytes").unwrap();
}

#[test]
fn source_date_epoch_determinism_and_fallback() {
    let dir = tempfile::tempdir().unwrap();
    sample_bundle(dir.path());

    // Phase 1: with SOURCE_DATE_EPOCH set, two builds over the identical
    // bundle dir are byte-identical, and created_at is exactly that instant.
    std::env::set_var("SOURCE_DATE_EPOCH", "1700000000");
    let first = to_json_bytes(&build_manifest(dir.path()).unwrap()).unwrap();
    let second = to_json_bytes(&build_manifest(dir.path()).unwrap()).unwrap();
    assert_eq!(
        first, second,
        "two builds under the same SOURCE_DATE_EPOCH must be BYTE-IDENTICAL"
    );
    let manifest = from_json_bytes(&first).unwrap();
    assert_eq!(
        manifest.created_at.parse::<jiff::Timestamp>().unwrap().as_second(),
        1_700_000_000,
        "created_at must be the SOURCE_DATE_EPOCH instant"
    );
    check_against_dir(&manifest, dir.path()).unwrap();

    // Phase 2: a set-but-malformed SOURCE_DATE_EPOCH is a hard error, never
    // silently ignored.
    std::env::set_var("SOURCE_DATE_EPOCH", "not-an-epoch");
    assert!(matches!(
        build_manifest(dir.path()).unwrap_err(),
        ManifestError::SourceDateEpoch { .. }
    ));

    // Phase 3: without SOURCE_DATE_EPOCH the build still parses and
    // verifies — created_at is simply the (valid RFC 3339) wall clock.
    std::env::remove_var("SOURCE_DATE_EPOCH");
    let bytes = to_json_bytes(&build_manifest(dir.path()).unwrap()).unwrap();
    let manifest = from_json_bytes(&bytes).unwrap();
    manifest.created_at.parse::<jiff::Timestamp>().unwrap();
    check_against_dir(&manifest, dir.path()).unwrap();
}
