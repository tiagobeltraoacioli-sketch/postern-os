// SPDX-License-Identifier: MIT OR Apache-2.0
//! Terem POC cargo integration test — the real thing POC-SCOPE.md §3 step 4
//! describes: create -> start (under `-accel tcg`, no KVM) -> drive the
//! guest via the ALLOWLISTED QMP passthrough (`query-status` while running)
//! -> confirm the marker-boot fixture's own serial-console output -> the
//! guest self-powers-off -> `terem_destroy`. Also asserts a disallowed QMP
//! command (`drive_add`) is REJECTED while the guest is live, and that
//! `terem_stop` ends the process without deleting the guest's disk.
//!
//! HONEST SCOPE: this test needs `qemu-system-x86_64` + `qemu-img` on
//! `$PATH` (`brew install qemu` on macOS) and the prebuilt marker-boot
//! fixture in `tests/terem_fixtures/` (a real Alpine Linux `vmlinuz-lts`
//! kernel + a from-scratch busybox-static initramfs whose `/init` prints
//! `TEREM-POC-BOOT-OK` and powers off — see `tests/terem_fixtures/`). It
//! does NOT need `/dev/kvm` — `-accel tcg` (pure software emulation) is
//! sufficient and is what this box actually uses (macOS has no `/dev/kvm`
//! at all). If the fixture or QEMU is missing, the test SKIPS with a clear
//! message rather than silently passing or faking a result — see
//! `POC-SCOPE.md`'s "do NOT fake a boot" instruction.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use bloch_desktop::terem::{
    create_impl, destroy_impl, qmp_call_impl, resolve_qemu_binary, resolve_qemu_img_binary,
    start_impl, status_impl, stop_impl, TeremState,
};
use serde_json::json;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/terem_fixtures")
}

/// `None` if QEMU or the marker-boot fixture aren't available on this box —
/// callers `return` early (a skip, not a fake pass) when this is `None`.
fn preflight() -> Option<(PathBuf, PathBuf)> {
    if resolve_qemu_binary("qemu-system-x86_64").is_err() {
        eprintln!("SKIP: qemu-system-x86_64 not on PATH (`brew install qemu`)");
        return None;
    }
    if resolve_qemu_img_binary("qemu-img").is_err() {
        eprintln!("SKIP: qemu-img not on PATH (`brew install qemu`)");
        return None;
    }
    let kernel = fixtures_dir().join("bzImage");
    let initrd = fixtures_dir().join("initramfs.cpio.gz");
    if !kernel.is_file() || !initrd.is_file() {
        eprintln!(
            "SKIP: marker-boot fixture missing ({} / {}) — see tests/terem_fixtures/README",
            kernel.display(),
            initrd.display()
        );
        return None;
    }
    Some((kernel, initrd))
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "terem-itest-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Poll `status_impl` until `running` matches `want`, or panic after `timeout`.
fn wait_for_running(state: &TeremState, want: bool, timeout: Duration) {
    let start = Instant::now();
    loop {
        let v = status_impl(state);
        if v["running"] == json!(want) {
            return;
        }
        if start.elapsed() > timeout {
            panic!("timed out waiting for running={want}; last status was {v}");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Poll the ALLOWLISTED `query-status` QMP command until it succeeds — the
/// QMP unix-socket server isn't bound at the instant the QEMU process
/// becomes observably running, so a first round-trip can race it. Retries
/// for `timeout`, then panics with the last error. Returns the successful
/// QMP reply.
fn qmp_query_status_when_ready(
    state: &TeremState,
    timeout: Duration,
) -> serde_json::Value {
    let start = Instant::now();
    let mut last_err;
    loop {
        match qmp_call_impl(state, "query-status", json!({})) {
            Ok(reply) => return reply,
            Err(e) => last_err = e,
        }
        if start.elapsed() > timeout {
            panic!("QMP query-status never became ready within {timeout:?}; last error: {last_err}");
        }
        std::thread::sleep(Duration::from_millis(150));
    }
}

#[test]
fn full_lifecycle_boots_to_marker_via_allowlisted_qmp_then_destroy() {
    let Some((kernel, initrd)) = preflight() else { return };

    let dir = scratch("full");
    let disk = dir.join("guest.qcow2");
    let state = TeremState::new();

    // CREATE — qemu-img create -f qcow2, defines the one v1 guest.
    create_impl(&state, "qemu-img", disk.to_str().unwrap(), 64).expect("terem_create");
    assert!(disk.is_file(), "qcow2 disk should exist after terem_create");

    // START — boots the marker fixture directly via -kernel/-initrd under
    // -accel tcg (no /dev/kvm on this box — the real, honest, box-agnostic
    // path POC-SCOPE.md §4 calls the "headline finding": the QMP control
    // plane needs no KVM at all to validate).
    let pid = start_impl(
        &state,
        "qemu-system-x86_64",
        Some(kernel.to_str().unwrap()),
        Some(initrd.to_str().unwrap()),
        Some("console=ttyS0 panic=1"),
        |line| eprintln!("[qemu stderr] {line}"),
    )
    .expect("terem_start")
    .pid;
    assert!(pid > 0, "terem_start should return a real PID");

    // The process should be observably running immediately after spawn.
    wait_for_running(&state, true, Duration::from_secs(5));

    // QMP, ALLOWLISTED — query-status must succeed while the guest is up.
    // Poll: the QMP socket server binds a beat after the process starts, and
    // the fixture stays up (its init sleeps) so there is a stable window.
    let status = qmp_query_status_when_ready(&state, Duration::from_secs(20));
    assert!(status.get("return").is_some(), "query-status should return a QMP 'return' envelope: {status}");
    // While up, the run-state should literally be "running".
    assert_eq!(
        status["return"]["status"],
        json!("running"),
        "guest run-state should be 'running' while booted: {status}"
    );

    // QMP, DISALLOWED — the red-team fix under test. `drive_add` could
    // attach a NEW host-backed block device to the running guest; it must
    // be rejected before a single byte reaches the QMP socket, even though
    // the guest is live and the socket is reachable right now.
    let rejected = qmp_call_impl(&state, "drive_add", json!({"driver": "raw"}));
    assert!(rejected.is_err(), "drive_add must be rejected, not forwarded");
    let msg = rejected.unwrap_err();
    assert!(msg.contains("not on the Terem allowlist"), "unexpected rejection message: {msg}");
    // A second dangerous verb, for good measure — the human-monitor-command
    // escape hatch the red-team pass named explicitly.
    let rejected2 = qmp_call_impl(&state, "human-monitor-command", json!({"command-line": "info block"}));
    assert!(rejected2.is_err(), "human-monitor-command must be rejected, not forwarded");

    // The marker-boot fixture's own init prints one line then `poweroff -f`
    // — under TCG this is fast (low single-digit seconds per POC-SCOPE.md
    // §1.2), but give it a generous ceiling for a loaded CI box.
    wait_for_running(&state, false, Duration::from_secs(60));

    // Confirm the ACTUAL boot happened — not inferred from the process
    // exiting (which could also mean it crashed), but from the guest's own
    // serial-console output containing the exact marker line.
    let serial = dir.join("guest.serial.log");
    let log = std::fs::read_to_string(&serial).unwrap_or_default();
    assert!(
        log.contains("TEREM-POC-BOOT-OK"),
        "serial console log should contain the marker line; got:\n{log}"
    );

    // DESTROY — deletes the guest's own disk file (and only that file).
    destroy_impl(&state).expect("terem_destroy");
    assert!(!disk.exists(), "qcow2 disk should be gone after terem_destroy");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn terem_stop_ends_the_process_without_deleting_the_disk() {
    let Some((kernel, initrd)) = preflight() else { return };

    let dir = scratch("stop");
    let disk = dir.join("guest.qcow2");
    let state = TeremState::new();

    create_impl(&state, "qemu-img", disk.to_str().unwrap(), 64).expect("terem_create");
    start_impl(
        &state,
        "qemu-system-x86_64",
        Some(kernel.to_str().unwrap()),
        Some(initrd.to_str().unwrap()),
        Some("console=ttyS0 panic=1"),
        |_line| {},
    )
    .expect("terem_start");

    // Stop as soon as it's observably running — exercises terem_stop's
    // graceful-QMP-then-kill-fallback path (stop_running_guest) whether or
    // not the guest has already reached its own poweroff by the time this
    // runs (both are valid outcomes; the assertion below only requires the
    // process be gone and the disk untouched afterward).
    wait_for_running(&state, true, Duration::from_secs(5));
    stop_impl(&state).expect("terem_stop");

    let v = status_impl(&state);
    assert_eq!(v["running"], json!(false), "guest should not be running after terem_stop");
    assert_eq!(v["defined"], json!(true), "terem_stop must not undefine the guest");
    assert!(disk.is_file(), "terem_stop must NOT delete the guest's disk — only terem_destroy does");

    // A second terem_stop (already stopped) must error, not silently pass.
    assert!(stop_impl(&state).is_err());

    destroy_impl(&state).expect("terem_destroy");
    assert!(!disk.exists());

    let _ = std::fs::remove_dir_all(&dir);
}
