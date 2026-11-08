//! Cross-language conformance for the `sloboda-bridge.state` PROJECTION BODY.
//!
//! UNAUDITED reference-prototype. This does not test any on-device wrapper (which
//! does not exist); it pins a byte-for-byte contract between the TWO writers that
//! can each emit this projection:
//!
//!   * the JS reference writer — `slobodaBridgeStateFile()` in
//!     apps/noporis-gate/gate-store.mjs (exercised by `node
//!     apps/noporis-gate/test-store.mjs` against the SAME golden), and
//!   * the Rust orchestrator — [`project_sloboda_bridge_state`], the on-device
//!     sole file writer (Dev A).
//!
//! A polling consumer (paw-lib.sh, Porog) reads this file to see the span come up
//! or drop. It keys off line 1 only, but the whole body is a stable contract, so
//! the two writers MUST agree byte-for-byte — otherwise a consumer that ever grew
//! to read a marker line would see a different file depending on who wrote it.
//!
//! The `enabled` posture is covered per-side by each writer's own unit tests. The
//! KILLED posture — line 1 `disabled`, `kill=engaged`, `schema_version=1` — is the
//! exact body a consumer relies on to see the span DROP, and it is what this file
//! pins byte-equal across writers via the shared golden fixture:
//!
//!     tests/golden/sloboda-bridge.disabled.state   (authored by the JS writer)
//!
//! Run: `cargo test -p noporis-bridge-glue --test cross_lang_conformance`

use noporis_bridge_glue::substrate::{
    project_sloboda_bridge_state, verify_sloboda_bridge_schema, ConsentScope, GateState,
    SLOBODA_BRIDGE_SCHEMA_VERSION,
};

/// The shared golden the JS writer authored and committed. Loaded at compile time
/// from the crate's own tree so the fixture travels with the test.
const DISABLED_GOLDEN: &str =
    include_str!("golden/sloboda-bridge.disabled.state");

/// The canonical killed posture: consent accepted, a lane thrown open, but the
/// kill-switch engaged — the defensive override that drops the span. Line 1 must
/// read `disabled` and the body must carry the `kill=engaged` marker.
fn killed_state() -> GateState {
    let mut g = GateState::consented_with_crossing(ConsentScope::Session);
    g.kill_switch_engaged = true;
    g
}

// ── (a) The golden IS exactly the killed-posture body it claims to be. ──────────
#[test]
fn golden_disabled_body_is_the_pinned_kill_switch_contract() {
    // The exact three lines a consumer relies on, in order, with a trailing NL and
    // nothing else — no comment lines, no per-capability enumeration.
    assert_eq!(
        DISABLED_GOLDEN, "disabled\nkill=engaged\nschema_version=1\n",
        "the committed golden must be the byte-exact kill-switched projection body"
    );
    // Restate the acceptance shape line-by-line so a future format nudge is loud.
    let mut lines = DISABLED_GOLDEN.lines();
    assert_eq!(lines.next(), Some("disabled"), "line 1 is the load-bearing toggle");
    assert_eq!(lines.next(), Some("kill=engaged"), "the defensive override marker");
    assert_eq!(
        lines.next(),
        Some(&*format!("schema_version={SLOBODA_BRIDGE_SCHEMA_VERSION}")),
        "the versioned trust marker, appended last"
    );
    assert_eq!(lines.next(), None, "no trailing content beyond the three lines");
    assert!(DISABLED_GOLDEN.ends_with('\n'), "trailing newline is part of the contract");
    // A killed body must NOT advertise the far side as runnable.
    assert!(
        !DISABLED_GOLDEN.contains("container=allowed"),
        "a killed span never emits container=allowed"
    );
}

// ── (b) Rust's writer emits the golden byte-for-byte on a kill-switched state. ──
#[test]
fn rust_project_sloboda_bridge_state_matches_the_js_authored_golden() {
    let body = project_sloboda_bridge_state(&killed_state());
    assert_eq!(
        body, DISABLED_GOLDEN,
        "project_sloboda_bridge_state() must be byte-identical to the JS-authored golden"
    );
}

// ── Every distinct killed posture collapses to the SAME golden bytes. ──────────
//    kill-switch is a defensive override: it dominates consent and any open lane,
//    so all of these MUST project to the one killed body a consumer keys off.
#[test]
fn all_kill_switched_postures_project_the_same_golden() {
    let mut consented_killed = GateState::consented(ConsentScope::Persistent);
    consented_killed.kill_switch_engaged = true;

    let mut deny_all_killed = GateState::deny_all();
    deny_all_killed.kill_switch_engaged = true;

    for gate in [killed_state(), consented_killed, deny_all_killed] {
        assert_eq!(
            project_sloboda_bridge_state(&gate),
            DISABLED_GOLDEN,
            "an engaged kill-switch must project the one canonical disabled body"
        );
    }
}

// ── (c) The read-side schema check accepts the golden. ─────────────────────────
#[test]
fn verify_sloboda_bridge_schema_accepts_the_golden() {
    assert!(
        verify_sloboda_bridge_schema(DISABLED_GOLDEN).is_ok(),
        "the versioned read-side must trust the projection it (co-)writes"
    );
}

// ── Guard: the golden is NOT the enabled posture, so a swapped fixture is loud. ─
#[test]
fn golden_is_the_disabled_posture_not_the_enabled_one() {
    let enabled = project_sloboda_bridge_state(&GateState::consented_with_crossing(
        ConsentScope::Session,
    ));
    assert_ne!(
        enabled, DISABLED_GOLDEN,
        "the enabled projection must differ from the pinned disabled golden"
    );
    assert!(enabled.starts_with("enabled\n"), "sanity: the enabled posture reads enabled");
}
