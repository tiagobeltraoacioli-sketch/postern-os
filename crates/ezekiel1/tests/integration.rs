//! End-to-end tests for the Ezekiel 1 governance engine.
//!
//! Covers: a valid policy passes; each reject rule fires (child > parent,
//! wall-with-bypass, grant-without-expiry, inverted-control in personal,
//! tenants-sharing-resource in business, subject > 1 layer); Brewer-Nash denies
//! a competing dataset after first access; fail-closed denies the undeclared;
//! the trail chain verifies and tampering is detected.

use std::path::Path;

use ezekiel1::{verify_chain, Action, Decision, Engine, Policy, PolicyError};
use time::macros::datetime;

// A well-formed BUSINESS policy: two-wheel lattice, one tenant, one Chinese
// wall over two competing banks, and grants that all carry an expiry.
const VALID_BUSINESS: &str = r#"
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
name   = "alice"
tenant = "acme"
role   = "finance-analyst"
assignments = [{ context = "default", layer = "root" }]

[[resources]]
id      = "acme/bank-a-ledger"
layer   = "internal"
tenant  = "acme"
dataset = "bank-a"

[[resources]]
id      = "acme/bank-b-ledger"
layer   = "internal"
tenant  = "acme"
dataset = "bank-b"

[[walls]]
name = "banking-coi"
classes = [{ name = "banks", members = ["bank-a", "bank-b"] }]

[[grants]]
subject  = "alice"
resource = "acme/bank-a-ledger"
action   = "read"
expires  = "2027-01-01T00:00:00Z"

[[grants]]
subject  = "alice"
resource = "acme/bank-b-ledger"
action   = "read"
expires  = "2027-01-01T00:00:00Z"
"#;

// A well-formed PERSONAL policy: guardian (root) over child (leaf), control
// flowing parent -> child, one grant with an expiry.
const VALID_PERSONAL: &str = r#"
edition = "personal"

[[layers]]
name  = "guardian"
level = 3

[[layers]]
name   = "child"
parent = "guardian"
level  = 1

[[subjects]]
name = "guardian-alice"
assignments = [{ context = "home", layer = "guardian" }]

[[subjects]]
name = "kid-bob"
assignments = [{ context = "home", layer = "child" }]

[[resources]]
id    = "kid-bob/screen-time"
layer = "child"

[[grants]]
subject  = "guardian-alice"
resource = "kid-bob/screen-time"
action   = "read"
expires  = "2027-01-01T00:00:00Z"
"#;

const NOW: time::OffsetDateTime = datetime!(2026-07-11 00:00:00 UTC);

fn engine(policy_text: &str, dir: &Path, name: &str) -> Engine {
    let policy = Policy::parse(policy_text).expect("policy parses");
    Engine::new(policy, dir.join(name)).expect("policy is admissible; engine builds")
}

#[test]
fn valid_business_policy_passes_validation() {
    let policy = Policy::parse(VALID_BUSINESS).expect("parses");
    assert!(policy.validate().is_ok(), "valid business policy must validate");
}

#[test]
fn valid_personal_policy_passes_validation() {
    let policy = Policy::parse(VALID_PERSONAL).expect("parses");
    assert!(policy.validate().is_ok(), "valid personal policy must validate");
}

// --- reject rules ---------------------------------------------------------

#[test]
fn reject_child_widens_parent() {
    let bad = VALID_BUSINESS.replace("parent = \"root\"\nlevel  = 2", "parent = \"root\"\nlevel  = 9");
    let err = Policy::parse(&bad).unwrap().validate().unwrap_err();
    assert!(
        matches!(err, PolicyError::ChildWidensParent { .. }),
        "expected ChildWidensParent, got {err:?}"
    );
}

#[test]
fn reject_wall_with_bypass() {
    let bad = VALID_BUSINESS.replace(
        "classes = [{ name = \"banks\", members = [\"bank-a\", \"bank-b\"] }]",
        "bypass = true\nclasses = [{ name = \"banks\", members = [\"bank-a\", \"bank-b\"] }]",
    );
    let err = Policy::parse(&bad).unwrap().validate().unwrap_err();
    assert!(
        matches!(err, PolicyError::WallHasBypass { .. }),
        "expected WallHasBypass, got {err:?}"
    );
}

#[test]
fn reject_grant_without_expiry_fails_to_parse() {
    // Remove the expiry from a grant: the field is required, so parse fails.
    let bad = VALID_BUSINESS.replace("expires  = \"2027-01-01T00:00:00Z\"\n\n[[grants]]", "\n[[grants]]");
    // (only the first grant's expiry removed; that alone must break the parse)
    let bad = bad.replacen("expires  = \"2027-01-01T00:00:00Z\"", "", 1);
    assert!(
        Policy::parse(&bad).is_err(),
        "a grant missing its expiry must fail to parse (fail-closed)"
    );
}

#[test]
fn reject_inverted_control_in_personal() {
    // Grant the child subject access to a resource classified in the GUARDIAN
    // (parent) layer — a child reaching up: inverted control.
    let bad = VALID_PERSONAL
        .replace(
            "[[resources]]\nid    = \"kid-bob/screen-time\"\nlayer = \"child\"",
            "[[resources]]\nid    = \"guardian-alice/private-journal\"\nlayer = \"guardian\"",
        )
        .replace(
            "subject  = \"guardian-alice\"\nresource = \"kid-bob/screen-time\"",
            "subject  = \"kid-bob\"\nresource = \"guardian-alice/private-journal\"",
        );
    let err = Policy::parse(&bad).unwrap().validate().unwrap_err();
    assert!(
        matches!(err, PolicyError::InvertedControl { .. }),
        "expected InvertedControl, got {err:?}"
    );
}

#[test]
fn reject_tenants_sharing_resource_in_business() {
    // Give bank-b-ledger the SAME id as bank-a-ledger but under a second tenant.
    let bad = VALID_BUSINESS
        .replace(
            "[[tenants]]\nname = \"acme\"",
            "[[tenants]]\nname = \"acme\"\n\n[[tenants]]\nname = \"globex\"",
        )
        .replace(
            "id      = \"acme/bank-b-ledger\"\nlayer   = \"internal\"\ntenant  = \"acme\"",
            "id      = \"acme/bank-a-ledger\"\nlayer   = \"internal\"\ntenant  = \"globex\"",
        );
    let err = Policy::parse(&bad).unwrap().validate().unwrap_err();
    assert!(
        matches!(err, PolicyError::FirmamentBreach { .. }),
        "expected FirmamentBreach, got {err:?}"
    );
}

#[test]
fn reject_subject_mapped_to_more_than_one_layer_per_context() {
    let bad = VALID_BUSINESS.replace(
        "assignments = [{ context = \"default\", layer = \"root\" }]",
        "assignments = [{ context = \"default\", layer = \"root\" }, { context = \"default\", layer = \"internal\" }]",
    );
    let err = Policy::parse(&bad).unwrap().validate().unwrap_err();
    assert!(
        matches!(err, PolicyError::SubjectMultipleLayers { .. }),
        "expected SubjectMultipleLayers, got {err:?}"
    );
}

#[test]
fn reject_resource_with_unknown_layer() {
    // A resource whose `layer` was never declared (a policy typo) must be
    // refused at validation — never silently admitted with a defaulted
    // classification. This is the fail-closed gate for the same hardening
    // that also changed `eval::Engine::decide` to deny (rather than default
    // to level 0/u32::MAX) on an unresolved layer.
    let bad = VALID_BUSINESS.replace(
        "id      = \"acme/bank-a-ledger\"\nlayer   = \"internal\"",
        "id      = \"acme/bank-a-ledger\"\nlayer   = \"no-such-layer\"",
    );
    let err = Policy::parse(&bad).unwrap().validate().unwrap_err();
    assert!(
        matches!(
            err,
            PolicyError::UnknownLayerRef { ref referent, .. } if referent == "resource"
        ),
        "expected UnknownLayerRef{{referent: \"resource\", ..}}, got {err:?}"
    );
}

#[test]
fn personal_refuses_business_constructs() {
    // A personal policy that names a Chinese wall must be refused by the gate.
    let bad = VALID_PERSONAL.to_string()
        + "\n[[walls]]\nname = \"x\"\nclasses = [{ name = \"c\", members = [\"a\"] }]\n";
    let err = Policy::parse(&bad).unwrap().validate().unwrap_err();
    assert!(
        matches!(err, PolicyError::OutOfEdition { .. }),
        "expected OutOfEdition, got {err:?}"
    );
}

// --- evaluation -----------------------------------------------------------

#[test]
fn brewer_nash_denies_competing_dataset_after_first_access() {
    let dir = tempfile::tempdir().unwrap();
    let mut eng = engine(VALID_BUSINESS, dir.path(), "bn.jsonl");

    // First access to bank-a: allowed.
    let d1 = eng
        .evaluate_at("alice", "acme/bank-a-ledger", "default", Action::Read, NOW)
        .unwrap();
    assert_eq!(d1, Decision::Allow, "first access to bank-a should be allowed");

    // Competing bank-b now falls behind the wall: permanently denied.
    let d2 = eng
        .evaluate_at("alice", "acme/bank-b-ledger", "default", Action::Read, NOW)
        .unwrap();
    assert!(
        matches!(d2, Decision::Deny { .. }),
        "bank-b must be denied after bank-a, got {d2:?}"
    );
}

#[test]
fn fail_closed_denies_the_undeclared() {
    let dir = tempfile::tempdir().unwrap();
    let mut eng = engine(VALID_BUSINESS, dir.path(), "fc.jsonl");

    // A resource that exists but has no grant for this subject: silent -> deny.
    // (bank-a exists; ask for an action/resource with no grant.)
    let d = eng
        .evaluate_at("alice", "acme/nonexistent", "default", Action::Read, NOW)
        .unwrap();
    assert!(
        matches!(d, Decision::Deny { .. }),
        "an undeclared resource must be denied, got {d:?}"
    );

    // A declared subject with no grant to write bank-a: also denied.
    let d2 = eng
        .evaluate_at("alice", "acme/bank-a-ledger", "default", Action::Write, NOW)
        .unwrap();
    assert!(
        matches!(d2, Decision::Deny { .. }),
        "an unauthorized action must be denied, got {d2:?}"
    );
}

#[test]
fn expired_grant_is_denied() {
    let dir = tempfile::tempdir().unwrap();
    let mut eng = engine(VALID_BUSINESS, dir.path(), "exp.jsonl");
    // Evaluate as if "now" is far past the grant expiry (2027-01-01).
    let future = datetime!(2030-01-01 00:00:00 UTC);
    let d = eng
        .evaluate_at("alice", "acme/bank-a-ledger", "default", Action::Read, future)
        .unwrap();
    assert!(
        matches!(d, Decision::Deny { .. }),
        "an expired grant must be denied, got {d:?}"
    );
}

#[test]
fn lowering_a_wall_requires_owner_action_and_lets_the_access_through() {
    let dir = tempfile::tempdir().unwrap();
    let mut eng = engine(VALID_BUSINESS, dir.path(), "lower.jsonl");

    eng.evaluate_at("alice", "acme/bank-a-ledger", "default", Action::Read, NOW)
        .unwrap();
    // Blocked by the wall...
    assert!(matches!(
        eng.evaluate_at("alice", "acme/bank-b-ledger", "default", Action::Read, NOW)
            .unwrap(),
        Decision::Deny { .. }
    ));
    // ...until the owner explicitly lowers it, with a recorded reason.
    eng.lower_wall("banking-coi", "owner-tiago", "audit engagement AC-2026-07: dual review approved")
        .unwrap();
    assert_eq!(
        eng.evaluate_at("alice", "acme/bank-b-ledger", "default", Action::Read, NOW)
            .unwrap(),
        Decision::Allow,
        "after the wall is lowered, the access proceeds"
    );
}

// --- the trail (rims full of eyes) ---------------------------------------

#[test]
fn trail_chain_verifies_and_tamper_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let trail_path = dir.path().join("audit.jsonl");
    {
        let mut eng = engine(VALID_BUSINESS, dir.path(), "audit.jsonl");
        eng.evaluate_at("alice", "acme/bank-a-ledger", "default", Action::Read, NOW)
            .unwrap();
        eng.evaluate_at("alice", "acme/bank-b-ledger", "default", Action::Read, NOW)
            .unwrap();
    }
    // Genesis + 2 evaluations = 3 entries, and the chain verifies.
    assert_eq!(verify_chain(&trail_path).unwrap(), 3);

    // Tamper: rewrite a reason in the middle of the trail.
    let original = std::fs::read_to_string(&trail_path).unwrap();
    let tampered = original.replacen("\"deny\"", "\"allow\"", 1);
    assert_ne!(original, tampered, "the tamper edit changed the file");
    std::fs::write(&trail_path, tampered).unwrap();

    assert!(
        verify_chain(&trail_path).is_err(),
        "a rewritten trail line must be detected by verify_chain"
    );
}
