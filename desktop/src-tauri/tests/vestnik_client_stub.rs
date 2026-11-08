// SPDX-License-Identifier: MIT OR Apache-2.0
//! Feature-OFF shape tests for the Vestnik matrix-client commands
//! (src/vestnik_client.rs): built WITHOUT the opt-in `vestnik-matrix` cargo
//! feature, the commands stay registered but must return the clean
//! "not built with matrix support" error — never a silent no-op — and
//! `vestnik_matrix_status` must report `{ built: false, logged_in: false,
//! honesty }` so the pane gates on real capability (the vault-keychain
//! `available: false` pattern).
//!
//! The whole file is compiled ONLY without the feature: with
//! `--features vestnik-matrix` these stubs do not exist (the real client
//! layer does — tests/vestnik_client.rs, required-features gated, covers
//! that flavor against the loopback MatrixMockServer).
#![cfg(not(feature = "vestnik-matrix"))]

use bloch_desktop::vestnik_client::{status_json, HONESTY, MATRIX_NOT_BUILT};

#[test]
fn not_built_error_names_the_problem_and_the_fix() {
    // The exact contract the frontend (api.js/messenger.js) relies on: a
    // clean, actionable refusal that names the feature to rebuild with.
    assert!(
        MATRIX_NOT_BUILT.contains("not built with matrix support"),
        "must state the capability is not compiled in"
    );
    assert!(
        MATRIX_NOT_BUILT.contains("--features vestnik-matrix"),
        "must tell the operator exactly how to rebuild"
    );
    assert!(
        MATRIX_NOT_BUILT.contains("vestnik-matrix"),
        "must name the cargo feature"
    );
}

#[test]
fn status_shape_reports_not_built_with_the_honesty_text() {
    // What the feature-off vestnik_matrix_status command returns: the pane's
    // capability gate must see built:false and NEVER assume otherwise.
    let status = status_json(false, false);
    assert_eq!(status["built"], false);
    assert_eq!(status["logged_in"], false);
    assert_eq!(status["honesty"].as_str(), Some(HONESTY));
}

#[test]
fn honesty_text_keeps_every_load_bearing_phrase_in_the_no_feature_build_too() {
    // The disclosure must not depend on how the binary was built.
    for needle in [
        "UNAUDITED",
        "vestnik-matrix",
        "ONLY when the user acts",
        "never in CI",
        "app startup",
        "social graph",
        "no Tor",
        "not post-quantum",
        "SavedSession blob ONLY",
        "SDK-layer",
        "NOT PQ-vault-wrapped",
        "not a TEE until real hardware",
    ] {
        assert!(HONESTY.contains(needle), "vestnik_client::HONESTY lost '{needle}'");
    }
}
