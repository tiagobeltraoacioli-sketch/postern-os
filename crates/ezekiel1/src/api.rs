//! The **one** target-independent decision API.
//!
//! These functions are the single source of truth that backs *both* the native
//! `ezekiel1-parity` binary and the `#[wasm_bindgen]` surface ([`crate::wasm`]).
//! Because the browser console and `cargo test` call the *same* code — one
//! compiled to `x86_64`/`aarch64`, the other to `wasm32` — the console's
//! verdicts are, by construction, the crate's verdicts. The WASM↔native parity
//! harness proves that equality on a fixture set.
//!
//! Everything here is string/JSON in, string/JSON out, so it crosses the
//! wasm-bindgen boundary without exposing internal types. No filesystem is
//! touched: the full-policy evaluator uses [`Engine::new_ephemeral`].

use std::collections::BTreeSet;

use crate::eval::Action;
use crate::lattice::Lattice;
use crate::walls::{ConflictClass, Wall};
use crate::{Decision, Engine, Policy};

/// Map the wire action string to [`Action`]. `read-write`/`readwrite` both map
/// to [`Action::ReadWrite`]; anything else is rejected (fail-closed).
fn action_of(s: &str) -> Option<Action> {
    match s {
        "read" => Some(Action::Read),
        "write" => Some(Action::Write),
        "read-write" | "readwrite" | "rw" => Some(Action::ReadWrite),
        _ => None,
    }
}

/// Render a [`Decision`] as the canonical wire JSON.
fn decision_json(d: &Decision) -> String {
    match d {
        Decision::Allow => r#"{"ok":true,"decision":"allow"}"#.to_string(),
        Decision::Deny { reason } => serde_json::json!({
            "ok": true,
            "decision": "deny",
            "reason": reason,
        })
        .to_string(),
    }
}

fn error_json(msg: &str) -> String {
    serde_json::json!({ "ok": false, "error": msg }).to_string()
}

/// Evaluate a single access against a full governance policy, fail-closed.
///
/// Runs the **entire** [`Engine`] pipeline (edition gate → no-widening lattice →
/// firmament → Brewer-Nash walls → Bell-LaPadula → unexpired grant) via
/// [`Engine::new_ephemeral`] (no trail file). Returns, as JSON:
/// * `{"ok":true,"decision":"allow"}`
/// * `{"ok":true,"decision":"deny","reason":"…"}`
/// * `{"ok":false,"error":"…"}` when the policy fails to parse or is
///   inadmissible (e.g. a child layer widens its parent), or the action/time is
///   unparseable — every one of which is itself a fail-closed refusal.
///
/// `now_rfc3339` is required and explicit (an RFC-3339 instant) so evaluation is
/// deterministic and never calls the host clock — which the WASM target lacks.
pub fn evaluate_json(
    policy_toml: &str,
    subject: &str,
    resource: &str,
    context: &str,
    action: &str,
    now_rfc3339: &str,
) -> String {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    let action = match action_of(action) {
        Some(a) => a,
        None => return error_json(&format!("unknown action {action:?}")),
    };
    let now = match OffsetDateTime::parse(now_rfc3339, &Rfc3339) {
        Ok(t) => t,
        Err(e) => return error_json(&format!("now {now_rfc3339:?} is not RFC-3339: {e}")),
    };
    let policy = match Policy::parse(policy_toml) {
        Ok(p) => p,
        Err(e) => return error_json(&e.to_string()),
    };
    let mut engine = match Engine::new_ephemeral(policy) {
        Ok(e) => e,
        Err(e) => return error_json(&e.to_string()),
    };
    match engine.evaluate_at(subject, resource, context, action, now) {
        Ok(d) => decision_json(&d),
        Err(e) => error_json(&e.to_string()),
    }
}

/// Validate a policy without evaluating anything. Returns
/// `{"ok":true}` or `{"ok":false,"error":"…"}` — the same admissibility gate
/// `cargo test` exercises, so the console can reject a bad policy (a
/// widening child, a wall with a bypass, an out-of-edition construct) with the
/// crate's own reason string.
pub fn validate_json(policy_toml: &str) -> String {
    match Policy::parse(policy_toml).and_then(|p| p.validate().map(|_| ())) {
        Ok(()) => r#"{"ok":true}"#.to_string(),
        Err(e) => error_json(&e.to_string()),
    }
}

/// Bell-LaPadula **no read up**, straight from [`Lattice::may_read`]: a subject
/// at `subject_level` may read a resource at `resource_level` iff at or above it.
pub fn blp_may_read(subject_level: u32, resource_level: u32) -> bool {
    Lattice::may_read(subject_level, resource_level)
}

/// Bell-LaPadula **no write down**, straight from [`Lattice::may_write`].
pub fn blp_may_write(subject_level: u32, resource_level: u32) -> bool {
    Lattice::may_write(subject_level, resource_level)
}

/// The Brewer-Nash **Chinese-wall** verdict, straight from
/// [`crate::walls::may_access`]. `classes_json` is the console's conflict
/// classes (`[{"name":"…","members":["…"]}]`); `history_json` is the datasets
/// the subject has already touched (`["…"]`). Returns `true` iff the wall
/// **bars** `target` (the subject already touched a competing member).
///
/// Returns `Err(reason)` only if the JSON does not parse — a caller-side bug,
/// never a silent allow.
pub fn wall_barred_json(
    classes_json: &str,
    history_json: &str,
    target: &str,
) -> Result<bool, String> {
    let classes: Vec<ConflictClass> = serde_json::from_str(classes_json)
        .map_err(|e| format!("conflict classes JSON: {e}"))?;
    let history: BTreeSet<String> =
        serde_json::from_str(history_json).map_err(|e| format!("history JSON: {e}"))?;
    // One wall wrapping every conflict class the console holds. `may_access`
    // walks each class exactly as the engine does inside a full evaluation.
    let wall = Wall {
        name: "console-coi".to_string(),
        classes,
        bypass: false,
    };
    Ok(matches!(
        crate::walls::may_access(&[wall], &history, target),
        Decision::Deny { .. }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal valid business policy: alice at level 3 (root), a resource at
    // level 2 (internal), one grant. Mirrors the integration fixture.
    const BIZ: &str = r#"
edition = "business"
[[tenants]]
name = "acme"
[[layers]]
name  = "root"
level = 3
[[layers]]
name   = "internal"
parent = "root"
level  = 2
[[subjects]]
name = "alice"
tenant = "acme"
assignments = [{ context = "default", layer = "root" }]
[[resources]]
id     = "acme/ledger"
layer  = "internal"
tenant = "acme"
[[grants]]
subject  = "alice"
resource = "acme/ledger"
action   = "read"
expires  = "2027-01-01T00:00:00Z"
"#;

    #[test]
    fn evaluate_allows_granted_read() {
        let out = evaluate_json(BIZ, "alice", "acme/ledger", "default", "read", "2026-07-11T00:00:00Z");
        assert_eq!(out, r#"{"ok":true,"decision":"allow"}"#, "got {out}");
    }

    #[test]
    fn evaluate_denies_without_grant() {
        // write is not granted -> deny (fail-closed).
        let out = evaluate_json(BIZ, "alice", "acme/ledger", "default", "write", "2026-07-11T00:00:00Z");
        assert!(out.contains(r#""decision":"deny""#), "got {out}");
    }

    #[test]
    fn evaluate_denies_expired_grant() {
        let out = evaluate_json(BIZ, "alice", "acme/ledger", "default", "read", "2030-01-01T00:00:00Z");
        assert!(out.contains(r#""decision":"deny""#), "got {out}");
    }

    #[test]
    fn evaluate_rejects_widening_policy() {
        let bad = BIZ.replace("level  = 2", "level  = 9");
        let out = evaluate_json(&bad, "alice", "acme/ledger", "default", "read", "2026-07-11T00:00:00Z");
        assert!(out.contains(r#""ok":false"#), "widening policy must be refused, got {out}");
    }

    #[test]
    fn blp_primitives_match_lattice() {
        assert!(blp_may_read(3, 2)); // read down
        assert!(!blp_may_read(1, 3)); // read up denied
        assert!(blp_may_write(1, 3)); // write up
        assert!(!blp_may_write(3, 1)); // write down denied
    }

    #[test]
    fn wall_bars_competitor_after_touch() {
        let classes = r#"[{"name":"banks","members":["bank-a","bank-b"]}]"#;
        assert!(!wall_barred_json(classes, r#"[]"#, "bank-a").unwrap());
        assert!(wall_barred_json(classes, r#"["bank-a"]"#, "bank-b").unwrap());
        assert!(!wall_barred_json(classes, r#"["bank-a"]"#, "bank-a").unwrap());
    }
}
