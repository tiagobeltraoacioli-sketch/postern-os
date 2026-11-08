// SPDX-License-Identifier: MIT OR Apache-2.0
//! # writer_lock_cli — F2's WriterLock, now enforced by the real `[[bin]]`
//!
//! ## ⚠️ SCAFFOLD / reference-prototype — UNAUDITED. Certifies nothing.
//!
//! `WriterLock::acquire`/`WriterLock::steal` (`substrate.rs`) were implemented
//! and unit-tested from the start, but nothing called them at runtime — the
//! `noporis-orchestrator` `[[bin]]` never acquired the lock, so two orchestrator
//! processes pointed at the same `--state-dir` really could interleave writes.
//! This test spawns the ACTUAL COMPILED BINARY (not just library calls) to
//! prove the fix holds end to end:
//!
//! 1. A lock already held for a `--state-dir` makes the binary refuse to start
//!    (nonzero exit, no tick output, an explicit stderr message) — never a
//!    silent second writer.
//! 2. Once the lock is released, the same `--state-dir` runs cleanly.
//! 3. A STALE lock (simulating a crashed prior process) still blocks a plain
//!    run, but `--steal-lock` is the explicit, named recovery that starts
//!    anyway.
//!
//! Run: `cargo test -p noporis-bridge-glue --test writer_lock_cli`

use std::process::Command;

use noporis_bridge_glue::{read_sloboda_bridge_state, GateState, StatePaths, WriterLock};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_noporis-orchestrator")
}

/// Run the real binary `--once` against `dir`, returning the process output.
fn run_once(dir: &std::path::Path, extra: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(bin());
    cmd.args(["--once", "--state-dir"])
        .arg(dir)
        .arg("--now")
        .arg("1752000000");
    cmd.args(extra);
    cmd.output().expect("spawn noporis-orchestrator")
}

#[test]
fn a_held_lock_makes_the_real_binary_refuse_to_start() {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = StatePaths::under(dir.path());

    // Hold the lock ourselves, exactly as a live orchestrator process would.
    let _held = WriterLock::acquire(&paths).expect("test process acquires first");

    let out = Command::new(bin())
        .args(["--once", "--state-dir"])
        .arg(dir.path())
        .arg("--now")
        .arg("1752000000")
        .output()
        .expect("spawn noporis-orchestrator");

    assert!(
        !out.status.success(),
        "the binary must refuse to start while another writer holds the lock"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("sole-writer lock"),
        "stderr should name the sole-writer lock as the reason: {stderr}"
    );
    // Fail-closed: it must not have produced tick output (never proceed to
    // touch state.json/sloboda-bridge.state without the lock).
    assert!(out.stdout.is_empty(), "no tick report should print if the lock was never acquired");
}

#[test]
fn releasing_the_lock_lets_the_real_binary_run_cleanly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = StatePaths::under(dir.path());

    {
        let _held = WriterLock::acquire(&paths).expect("acquire");
        // Dropped at the end of this block — releases the lock file, mirroring
        // a prior orchestrator's normal (non-crash) shutdown.
    }

    let out = Command::new(bin())
        .args(["--once", "--state-dir"])
        .arg(dir.path())
        .arg("--now")
        .arg("1752000000")
        .output()
        .expect("spawn noporis-orchestrator");

    assert!(
        out.status.success(),
        "the binary should run cleanly once the prior writer released its lock: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.stdout.is_empty(), "a successful --once run prints its tick report");
}

#[test]
fn a_stale_lock_still_blocks_a_plain_run_but_steal_lock_recovers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = StatePaths::under(dir.path());

    // Simulate a crashed prior orchestrator: acquire, then leak it (never
    // drop it), exactly as a killed process would leave the lock file behind.
    let held = WriterLock::acquire(&paths).expect("acquire");
    std::mem::forget(held);

    // A plain run still refuses — no silent auto-steal.
    let out = Command::new(bin())
        .args(["--once", "--state-dir"])
        .arg(dir.path())
        .arg("--now")
        .arg("1752000000")
        .output()
        .expect("spawn noporis-orchestrator");
    assert!(!out.status.success(), "a stale lock must still block a plain run");

    // The explicit, named recovery path starts anyway.
    let out = Command::new(bin())
        .args(["--once", "--state-dir"])
        .arg(dir.path())
        .arg("--now")
        .arg("1752000000")
        .arg("--steal-lock")
        .output()
        .expect("spawn noporis-orchestrator --steal-lock");
    assert!(
        out.status.success(),
        "--steal-lock should recover from a stale lock: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn crash_leaves_a_stale_lock_then_steal_lock_recovers_with_no_torn_writes_e2e() {
    // The full crash-recovery story at the DAEMON level, end to end through the
    // real compiled binary — not just the WriterLock unit.
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = StatePaths::under(dir.path());

    // ── [1] A first orchestrator process runs a clean --once tick: it becomes
    //     the sole writer, commits a posture (state.json + the schema-versioned
    //     sloboda-bridge.state projection), and releases its lock on exit. ─────
    let first = run_once(dir.path(), &[]);
    assert!(first.status.success(), "first run: stderr={}", String::from_utf8_lossy(&first.stderr));
    assert!(paths.state_json.exists(), "the first run wrote state.json");
    assert!(paths.sloboda_bridge_state.exists(), "the first run wrote the projection");
    // What it wrote verifies on read-back (write-side ↔ read-side schema agree).
    assert!(
        matches!(read_sloboda_bridge_state(&paths), Ok(Some(_))),
        "the committed projection passes the schema-preflight"
    );

    // ── [2] Simulate a SIGKILLed successor: acquire the lock and leak it so the
    //     lock file lingers on disk with no live process behind it. ────────────
    let leaked = WriterLock::acquire(&paths).expect("acquire the would-be crashed writer's lock");
    std::mem::forget(leaked);

    // ── [3] A plain restart is refused fail-closed — the crash is never silently
    //     ignored, and NOTHING is written/mangled by the refused process. ──────
    let before = std::fs::read(&paths.state_json).unwrap();
    let refused = run_once(dir.path(), &[]);
    assert!(!refused.status.success(), "a stale lock must block a plain restart");
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("sole-writer lock"),
        "the refusal names the sole-writer lock"
    );
    assert_eq!(
        std::fs::read(&paths.state_json).unwrap(),
        before,
        "a refused restart never touches the committed state"
    );

    // ── [4] The explicit, named recovery (--steal-lock) resumes and re-commits a
    //     clean posture — and the on-disk state is intact, not torn. ───────────
    let recovered = run_once(dir.path(), &["--steal-lock"]);
    assert!(
        recovered.status.success(),
        "--steal-lock resumes after the crash: stderr={}",
        String::from_utf8_lossy(&recovered.stderr)
    );

    // No torn write survived recovery: the projection still verifies, state.json
    // still parses to a valid (fail-closed) posture, and no temp files leaked.
    assert!(
        matches!(read_sloboda_bridge_state(&paths), Ok(Some(_))),
        "the recovered projection still passes the schema-preflight — no torn write"
    );
    let recovered_gate = GateState::from_gate_json(&std::fs::read_to_string(&paths.state_json).unwrap());
    assert_eq!(
        recovered_gate,
        GateState::deny_all(),
        "the resumed daemon (no lanes, no consent file) re-commits a clean deny-all posture"
    );
    let tmp_leftovers = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().ends_with(".tmp"));
    assert!(!tmp_leftovers, "no torn/partial temp file survived recovery");
}
