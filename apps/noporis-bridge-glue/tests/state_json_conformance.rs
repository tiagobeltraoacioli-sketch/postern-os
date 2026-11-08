// SPDX-License-Identifier: MIT OR Apache-2.0
//! HOST conformance: `GateState` ⇄ `state.json` round-trips against the frozen v1
//! `postern.noporis-gate.state` schema — and the per-lane `directions` projection
//! the orchestrator carries alongside it.
//!
//! Reference-prototype, UNAUDITED. This exercises the *pure* parse/render boundary
//! (`GateState::from_gate_json` / `to_gate_json`) exactly as sloboda/Porog would read
//! the file, plus the structurally-derived `LaneDirections` that is NOT a v1 schema
//! field (direction is derived from the pairing, Composition-UX §2). None of this is
//! a security boundary — a rooted host defeats every check here.
//!
//! Why this file exists: `GateState` grew a `directions` field. Every golden literal
//! that constructs the struct by hand must name that field, and at least one must
//! prove the field is *load-bearing* — read back through `directions.of(cap)` at a
//! NON-default value, not merely default-filled — so the accessor can never silently
//! regress to the canonical default for a lane the operator flipped.

use noporis_bridge_glue::substrate::ConsentScope;
use noporis_bridge_glue::{Capability, Direction, GateState, LaneDirections, LaneSet, Persona};

/// The exact discriminators the v1 schema pins. A file missing any of these must
/// fail-closed to `deny_all` (covered by `foreign_or_partial_files_deny_wholesale`).
const SCHEMA: &str = "postern.noporis-gate.state";

/// A schema-valid v1 `state.json` for a consented, persistent posture with the
/// clipboard + files lanes thrown open and the kill-switch clear. Rendered by hand
/// (not via `to_gate_json`) so the golden is an independent oracle, not a mirror of
/// the code under test.
fn golden_json() -> String {
    format!(
        "{{\"schema\":\"{SCHEMA}\",\"version\":1,\"tier\":\"non-attestable\",\
         \"consent\":{{\"accepted\":true,\"scope\":\"persistent\"}},\
         \"crossings\":{{\"clipboard\":{{\"open\":true}},\"files\":{{\"open\":true}},\
         \"mic\":{{\"open\":false}},\"camera\":{{\"open\":false}},\"location\":{{\"open\":false}}}},\
         \"killSwitch\":{{\"engaged\":false}},\
         \"sealedWallet\":{{\"preserved\":true}}}}"
    )
}

#[test]
fn to_gate_json_renders_a_schema_valid_v1_file() {
    // The rendered bytes must equal the independent golden oracle exactly — the
    // orchestrator only ever persists a byte-for-byte schema-valid file.
    let posture = GateState::consented(ConsentScope::Persistent)
        .open_crossing(Capability::Clipboard)
        .open_crossing(Capability::Files);
    assert_eq!(posture.to_gate_json(), golden_json());
}

#[test]
fn from_gate_json_reads_back_every_schema_carried_field() {
    let parsed = GateState::from_gate_json(&golden_json());
    assert!(parsed.consent_accepted);
    assert_eq!(parsed.consent_scope, ConsentScope::Persistent);
    assert!(parsed.crossings.is_open(Capability::Clipboard));
    assert!(parsed.crossings.is_open(Capability::Files));
    assert!(!parsed.crossings.is_open(Capability::Mic));
    assert!(!parsed.kill_switch_engaged);
    assert!(parsed.sealed_wallet_preserved);
}

#[test]
fn schema_carried_fields_round_trip_render_then_parse() {
    // render → parse must be a fixed point on every *schema* field.
    let start = GateState::consented(ConsentScope::Session).open_crossing(Capability::Mic);
    let reparsed = GateState::from_gate_json(&start.to_gate_json());
    assert_eq!(reparsed.consent_accepted, start.consent_accepted);
    assert_eq!(reparsed.consent_scope, start.consent_scope);
    assert_eq!(reparsed.crossings, start.crossings);
    assert_eq!(reparsed.kill_switch_engaged, start.kill_switch_engaged);
    assert_eq!(reparsed.sealed_wallet_preserved, start.sealed_wallet_preserved);
}

#[test]
fn directions_field_is_load_bearing_not_default_filled() {
    // The golden operator PUSHED the clipboard lane outward (Clean → GooglePlay),
    // the reverse of the canonical GooglePlay → Clean pull. Build the struct by hand
    // so the `directions` field is named explicitly, then read the lane back through
    // the accessor — the field must carry the non-default value, never silently
    // collapse to canonical.
    let pushed_out = Direction::new(Persona::Clean, Persona::GooglePlay);
    let golden = GateState {
        consent_accepted: true,
        consent_scope: ConsentScope::Persistent,
        crossings: LaneSet::none()
            .with(Capability::Clipboard, true)
            .with(Capability::Files, true),
        kill_switch_engaged: false,
        sealed_wallet_preserved: true,
        directions: LaneDirections::canonical().with(Capability::Clipboard, pushed_out),
    };

    // The flipped lane round-trips through `directions.of(cap)` at its set value…
    assert_eq!(golden.directions.of(Capability::Clipboard), pushed_out);
    // …while every untouched lane keeps the canonical GooglePlay → Clean pull.
    let canonical = Direction::new(Persona::GooglePlay, Persona::Clean);
    for cap in [
        Capability::Files,
        Capability::Mic,
        Capability::Camera,
        Capability::Location,
    ] {
        assert_eq!(golden.directions.of(cap), canonical, "lane {cap:?} must stay canonical");
    }
}

#[test]
fn deny_all_carries_canonical_directions() {
    // The fail-closed default names no lane, so every lane is the canonical pull.
    let canonical = Direction::new(Persona::GooglePlay, Persona::Clean);
    let deny = GateState::deny_all();
    for cap in Capability::ALL {
        assert_eq!(deny.directions.of(cap), canonical);
    }
    // deny_all is genuinely closed — this file must not accidentally assert an open posture.
    assert!(!deny.any_crossing_open());
    assert!(!deny.consent_accepted);
}

#[test]
fn foreign_or_partial_files_deny_wholesale() {
    // Wrong schema, wrong version, wrong tier, foreign sealedWallet, and outright
    // garbage all collapse to deny_all — the normalize() trust boundary.
    let deny = GateState::deny_all();
    for bad in [
        r#"{"schema":"evil","version":1,"tier":"non-attestable","sealedWallet":{"preserved":true}}"#,
        r#"{"schema":"postern.noporis-gate.state","version":2,"tier":"non-attestable","sealedWallet":{"preserved":true}}"#,
        r#"{"schema":"postern.noporis-gate.state","version":1,"tier":"attestable","sealedWallet":{"preserved":true}}"#,
        r#"{"schema":"postern.noporis-gate.state","version":1,"tier":"non-attestable","sealedWallet":{"preserved":false}}"#,
        "not json at all",
    ] {
        assert_eq!(GateState::from_gate_json(bad), deny, "foreign file must deny: {bad}");
    }
}
