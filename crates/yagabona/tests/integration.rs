//! End-to-end tests for the Threshold Test, the audit trail, and the scheduler.

use std::fs;
use std::path::Path;

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use yagabona::scheduler::NoopTask;
use yagabona::{
    validate_at, verify_chain, Manifest, PollResult, Record, RefusalReason, Runner, ScopedFs,
    Trail,
};

/// A deterministic "now" well before the manifests' expiry.
fn now() -> OffsetDateTime {
    OffsetDateTime::parse("2026-07-11T00:00:00Z", &Rfc3339).unwrap()
}

/// Build a workspace with `notes/` and `index/` subdirs and return its root.
fn workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("notes")).unwrap();
    fs::write(dir.path().join("notes/a.txt"), b"hello").unwrap();
    fs::create_dir(dir.path().join("index")).unwrap();
    dir
}

fn manifest_with(network: &str, expires: &str, read: &str, write: &str, desc: &str) -> String {
    format!(
        r#"
        [task]
        name        = "nightly-notes-index"
        description = "{desc}"
        schedule    = "daily 02:30"
        expires     = "{expires}"

        [capabilities]
        read_paths  = ["{read}"]
        write_paths = ["{write}"]
        network     = "{network}"

        [ritual]
        granted_by  = "tiago"
        granted_at  = "2026-07-11T14:02:00-03:00"
        formula     = "izbushka-turn-your-face-to-me"
    "#
    )
}

fn valid_manifest() -> String {
    manifest_with(
        "none",
        "2026-12-31T23:59:59Z",
        "notes",
        "index",
        "Index notes into a local search db every night",
    )
}

#[test]
fn valid_manifest_passes_threshold() {
    let ws = workspace();
    let m = Manifest::parse(&valid_manifest()).unwrap();
    let grant = validate_at(&m, ws.path(), now()).expect("valid manifest must pass");
    assert_eq!(grant.read_paths.len(), 1);
    assert_eq!(grant.write_paths.len(), 1);
    assert!(grant.read_paths[0].starts_with(ws.path().canonicalize().unwrap()));
}

#[test]
fn refuses_path_escaping_workspace_via_dotdot() {
    let ws = workspace();
    let m = Manifest::parse(&manifest_with(
        "none",
        "2026-12-31T23:59:59Z",
        "../outside",
        "index",
        "Index notes into a local search db every night",
    ))
    .unwrap();
    let refusal = validate_at(&m, ws.path(), now()).unwrap_err();
    assert!(matches!(
        refusal.reason(),
        RefusalReason::PathTraversal { .. }
    ));
}

#[test]
fn refuses_symlink_escape_after_canonicalize() {
    let ws = workspace();
    // A symlink inside the workspace pointing outside it.
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret.txt"), b"x").unwrap();
    let link = ws.path().join("escape");
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.path(), &link).unwrap();

    let m = Manifest::parse(&manifest_with(
        "none",
        "2026-12-31T23:59:59Z",
        "escape",
        "index",
        "Index notes into a local search db every night",
    ))
    .unwrap();
    let refusal = validate_at(&m, ws.path(), now()).unwrap_err();
    assert!(
        matches!(refusal.reason(), RefusalReason::PathEscapesWorkspace { .. }),
        "expected escape refusal, got {:?}",
        refusal.reason()
    );
}

#[test]
fn refuses_expired_grant() {
    let ws = workspace();
    let m = Manifest::parse(&manifest_with(
        "none",
        "2020-01-01T00:00:00Z", // in the past
        "notes",
        "index",
        "Index notes into a local search db every night",
    ))
    .unwrap();
    let refusal = validate_at(&m, ws.path(), now()).unwrap_err();
    assert!(matches!(refusal.reason(), RefusalReason::ExpiryInPast { .. }));
}

#[test]
fn refuses_inline_secret() {
    let ws = workspace();
    let m = Manifest::parse(&manifest_with(
        "none",
        "2026-12-31T23:59:59Z",
        "notes",
        "index",
        "Index notes; password = hunter2 for the db",
    ))
    .unwrap();
    let refusal = validate_at(&m, ws.path(), now()).unwrap_err();
    assert!(matches!(refusal.reason(), RefusalReason::InlineSecret { .. }));
}

#[test]
fn refuses_capabilities_exceeding_description() {
    let ws = workspace();
    // network to anthropic, but the description gives no networking reason.
    let m = Manifest::parse(&manifest_with(
        "api.anthropic.com",
        "2026-12-31T23:59:59Z",
        "notes",
        "index",
        "Index notes into a local database", // no network hint
    ))
    .unwrap();
    let refusal = validate_at(&m, ws.path(), now()).unwrap_err();
    assert!(matches!(
        refusal.reason(),
        RefusalReason::CapabilityExceedsDescription { .. }
    ));
}

#[test]
fn accepts_anthropic_when_description_justifies_it() {
    let ws = workspace();
    let m = Manifest::parse(&manifest_with(
        "api.anthropic.com",
        "2026-12-31T23:59:59Z",
        "notes",
        "index",
        "Summarize notes with the Anthropic api and write an index",
    ))
    .unwrap();
    assert!(validate_at(&m, ws.path(), now()).is_ok());
}

#[test]
fn scoped_fs_enforces_the_grant() {
    let ws = workspace();
    let m = Manifest::parse(&valid_manifest()).unwrap();
    let grant = validate_at(&m, ws.path(), now()).unwrap();
    let fs_guard = ScopedFs::new(&grant);

    // Reading a granted read_path works.
    assert_eq!(fs_guard.read("notes/a.txt").unwrap(), b"hello");
    // Writing inside the granted write_path works.
    fs_guard.write("index/db", b"data").unwrap();
    assert!(ws.path().join("index/db").exists());
    // Reading outside read_paths (the index dir) is denied.
    assert!(fs_guard.read("index/db").is_err());
    // Writing outside write_paths (the notes dir) is denied.
    assert!(fs_guard.write("notes/b.txt", b"nope").is_err());
}

#[test]
fn trail_chain_verifies_and_detects_tampering() {
    let dir = tempfile::tempdir().unwrap();
    let trail_path = dir.path().join("nightly-notes-index.jsonl");

    let mut trail = Trail::open(&trail_path).unwrap();
    for i in 0..3 {
        trail
            .append(Record {
                ts: format!("2026-07-1{}T02:30:00Z", i + 1),
                task: "nightly-notes-index".into(),
                action: "run".into(),
                paths_touched: vec!["index/db".into()],
                network_used: "none".into(),
                result: "ok".into(),
            })
            .unwrap();
    }

    // A clean chain verifies.
    assert_eq!(verify_chain(&trail_path).unwrap(), 3);

    // Tamper with the middle line's payload, leaving its hash untouched.
    tamper_line(&trail_path, 1, "\"result\":\"ok\"", "\"result\":\"HACKED\"");

    let err = verify_chain(&trail_path).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("hash mismatch") || msg.contains("broken link"),
        "expected tamper detection, got: {msg}"
    );
}

#[test]
fn trail_resumes_chain_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let trail_path = dir.path().join("t.jsonl");
    let first_hash = {
        let mut t = Trail::open(&trail_path).unwrap();
        t.append(Record {
            ts: "2026-07-11T02:30:00Z".into(),
            task: "t".into(),
            action: "run".into(),
            paths_touched: vec![],
            network_used: "none".into(),
            result: "ok".into(),
        })
        .unwrap()
        .hash
    };
    // Reopen and append; the new entry must link to the first hash.
    let mut t = Trail::open(&trail_path).unwrap();
    assert_eq!(t.head(), first_hash);
    let second = t
        .append(Record {
            ts: "2026-07-12T02:30:00Z".into(),
            task: "t".into(),
            action: "run".into(),
            paths_touched: vec![],
            network_used: "none".into(),
            result: "ok".into(),
        })
        .unwrap();
    assert_eq!(second.prev_hash, first_hash);
    assert_eq!(verify_chain(&trail_path).unwrap(), 2);
}

#[test]
fn scheduler_runs_when_due_and_stops_when_expired() {
    let ws = workspace();
    let m = Manifest::parse(&valid_manifest()).unwrap();
    let grant = validate_at(&m, ws.path(), now()).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let trail = Trail::open(dir.path().join("run.jsonl")).unwrap();
    let start = OffsetDateTime::parse("2026-07-11T00:00:00Z", &Rfc3339).unwrap();
    let mut runner = Runner::new(&grant, NoopTask, trail, start).unwrap();

    // Before the 02:30 fire: not due.
    let before = OffsetDateTime::parse("2026-07-11T02:00:00Z", &Rfc3339).unwrap();
    assert!(matches!(runner.poll(before).unwrap(), PollResult::NotDue));

    // At/after the fire: it runs.
    let at = OffsetDateTime::parse("2026-07-11T02:30:00Z", &Rfc3339).unwrap();
    assert!(matches!(runner.poll(at).unwrap(), PollResult::Fired(_)));

    // After expiry: it stops with an Expired entry, and the task does not run.
    let after_expiry = OffsetDateTime::parse("2027-01-01T00:00:00Z", &Rfc3339).unwrap();
    assert!(matches!(
        runner.poll(after_expiry).unwrap(),
        PollResult::Expired(_)
    ));
}

/// Regression (tripwire window): a credential pasted into `ritual.granted_at`
/// used to sail past the inline-secret scan — that field was the one manifest
/// string the tripwire did not cover (nothing else ever parses it either).
/// The scan must now refuse it like any other field.
#[test]
fn secret_in_ritual_granted_at_is_refused() {
    let ws = workspace();
    let text = valid_manifest().replace(
        r#"granted_at  = "2026-07-11T14:02:00-03:00""#,
        r#"granted_at  = "2026-07-11 password=hunter2-super-secret""#,
    );
    let m = Manifest::parse(&text).unwrap();
    let refusal = validate_at(&m, ws.path(), now())
        .expect_err("a credential-bearing granted_at must be refused at the threshold");
    assert!(
        matches!(
            refusal.reason(),
            RefusalReason::InlineSecret { field, .. } if field == "ritual.granted_at"
        ),
        "expected InlineSecret on ritual.granted_at, got: {refusal}"
    );
}

/// Regression (audit overstate): a fired run used to record the grant's whole
/// `write_paths` list as `paths_touched`, even for a task that opened nothing
/// — the trail claimed enforcement/activity that never happened. The entry
/// must record what the task ACTUALLY touched through the scoped boundary.
#[test]
fn trail_records_actually_touched_paths_not_the_granted_list() {
    use yagabona::scheduler::{Task, TaskError};
    use yagabona::threshold::Grant;

    let ws = workspace();
    let m = Manifest::parse(&valid_manifest()).unwrap();
    let grant = validate_at(&m, ws.path(), now()).unwrap();
    assert!(!grant.write_paths.is_empty(), "precondition: the grant does request write paths");

    let start = OffsetDateTime::parse("2026-07-11T00:00:00Z", &Rfc3339).unwrap();
    let at = OffsetDateTime::parse("2026-07-11T02:30:00Z", &Rfc3339).unwrap();

    // 1. A task that touches NOTHING must produce an entry with NO paths.
    let dir = tempfile::tempdir().unwrap();
    let trail = Trail::open(dir.path().join("noop.jsonl")).unwrap();
    let mut runner = Runner::new(&grant, NoopTask, trail, start).unwrap();
    match runner.poll(at).unwrap() {
        PollResult::Fired(entry) => assert!(
            entry.content.paths_touched.is_empty(),
            "a no-op run must not claim the granted write_paths were touched, got {:?}",
            entry.content.paths_touched
        ),
        other => panic!("expected Fired, got {other:?}"),
    }

    // 2. A task that writes ONE file must record exactly that resolved path.
    struct WriteOne;
    impl Task for WriteOne {
        fn run(&mut self, _grant: &Grant, fs: &ScopedFs) -> Result<String, TaskError> {
            fs.write("index/db", b"one write").map_err(|e| TaskError(e.to_string()))?;
            Ok("wrote index/db".to_string())
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let trail = Trail::open(dir.path().join("one.jsonl")).unwrap();
    let mut runner = Runner::new(&grant, WriteOne, trail, start).unwrap();
    match runner.poll(at).unwrap() {
        PollResult::Fired(entry) => {
            let expected = ws
                .path()
                .canonicalize()
                .unwrap()
                .join("index/db")
                .display()
                .to_string();
            assert_eq!(
                entry.content.paths_touched,
                vec![expected],
                "the entry must list exactly the path actually written"
            );
        }
        other => panic!("expected Fired, got {other:?}"),
    }
}

#[test]
fn scheduler_treats_revocation_as_never_given() {
    let ws = workspace();
    let m = Manifest::parse(&valid_manifest()).unwrap();
    let grant = validate_at(&m, ws.path(), now()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let trail = Trail::open(dir.path().join("run.jsonl")).unwrap();
    let start = OffsetDateTime::parse("2026-07-11T00:00:00Z", &Rfc3339).unwrap();
    let mut runner = Runner::new(&grant, NoopTask, trail, start).unwrap();

    runner.revoke();
    let at = OffsetDateTime::parse("2026-07-11T02:30:00Z", &Rfc3339).unwrap();
    assert!(matches!(runner.poll(at).unwrap(), PollResult::Revoked(_)));
}

/// Overwrite line `idx` (0-based) of a JSONL file, replacing `from` with `to`.
fn tamper_line(path: &Path, idx: usize, from: &str, to: &str) {
    let text = fs::read_to_string(path).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    lines[idx] = lines[idx].replace(from, to);
    fs::write(path, lines.join("\n") + "\n").unwrap();
}
