// SPDX-License-Identifier: MIT OR Apache-2.0
//
// DESIGN PREVIEW — written ≠ built ≠ booted. UNAUDITED. This test CAN spawn
// a REAL operator-supplied qemu-system-x86_64 — which is exactly why it is
// `#[ignore]`-gated and never runs in CI. It compiles in every `cargo test`
// run but executes only under `cargo test -- --ignored` on a host whose
// operator has supplied a QEMU binary and guest images via environment
// variables. No claim is made that a real guest has ever booted: as of this
// writing this test has never been executed against a real QEMU in CI.
// Product name "Terem" is proposed only, pending trademark clearance.

//! Opt-in, operator-driven real-spawn test: resolve → plan → spawn → poll →
//! kill, against a REAL `qemu-system-x86_64` the operator supplies.
//!
//! Required environment (all three, or the test panics with instructions):
//!
//! * `TEREM_QEMU_BIN`   — path to (or bare pinned name of) the operator's
//!   `qemu-system-x86_64`, vetted through `resolve_qemu_binary`.
//! * `TEREM_BOOT_IMAGE` — a bootable image (e.g. the POC-SCOPE §2.2 marker
//!   fixture ISO) passed as `-cdrom`.
//! * `TEREM_GUEST_DISK` — an existing qcow2 disk file for `-drive`.
//!
//! Run explicitly: `TEREM_QEMU_BIN=... TEREM_BOOT_IMAGE=... \
//! TEREM_GUEST_DISK=... cargo test --test real_spawn -- --ignored`
//!
//! The success bar here is deliberately modest and honest: the process stays
//! alive and the serial log file appears within a timeout, then kill+reap.
//! It does NOT assert a boot marker — "booted" remains an unclaimed state.
//!
//! Cross-reference: `tests/live_qemu_boot_marker.rs` is the companion test
//! that DOES assert a serial boot marker, using a hermetic in-repo fixture
//! ISO instead of operator-supplied images. It is gated differently on
//! purpose (`TEREM_LIVE_QEMU=1` + skip-not-panic); this test's loud
//! panic-without-env-vars behavior is unchanged and deliberate.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use terem_core::config::TeremConfig;
use terem_core::guest::GuestSpec;
use terem_core::launch::{LaunchMode, LaunchPlan};
use terem_core::resolve::resolve_qemu_binary;
use terem_core::spawn::spawn_plan;

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!(
            "real_spawn is opt-in only: set {name} (and TEREM_QEMU_BIN, \
             TEREM_BOOT_IMAGE, TEREM_GUEST_DISK) to run it. It needs an \
             operator-supplied qemu-system-x86_64 and guest image; it never \
             runs in CI."
        )
    })
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "terem-core-real-spawn-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
#[ignore = "needs an operator-supplied qemu-system-x86_64 and guest image; never run in CI"]
fn real_qemu_spawns_stays_alive_and_writes_serial_log() {
    // 1. Operator-supplied inputs, or a loud skip-with-instructions panic.
    let qemu_bin = required_env("TEREM_QEMU_BIN");
    let boot_image = PathBuf::from(required_env("TEREM_BOOT_IMAGE"));
    let guest_disk = PathBuf::from(required_env("TEREM_GUEST_DISK"));

    // 2. Vet the binary through the pinned-name resolver — the same path
    //    every real caller must take.
    let resolved = resolve_qemu_binary(&qemu_bin)
        .expect("TEREM_QEMU_BIN must resolve to a real qemu-system-x86_64");

    // 3. Build the opted-in plan. The DEFAULT config would refuse at both
    //    plan and spawn time; opting in is this test's explicit act.
    let state = scratch("state");
    let config = TeremConfig { full_vm_qemu: true, wine_proton: false };
    let spec = GuestSpec {
        disk_path: guest_disk,
        disk_size_mb: 0, // not used by the run argv; the disk already exists
        boot_image,
    };
    let qmp_sock = state.join("guest0.qmp.sock");
    let serial_log = state.join("guest0.serial.log");
    let plan = LaunchPlan::build(
        LaunchMode::DryRun,
        &config,
        &resolved,
        &spec,
        &qmp_sock,
        &serial_log,
    )
    .expect("opted-in plan should build");

    // 4. Spawn the real QEMU.
    let mut guest = spawn_plan(&config, &plan).expect("real QEMU should spawn");
    let pid = guest.pid();

    // 5. Poll: the process must stay alive and the serial log file must
    //    appear within the timeout. (QEMU creates the -serial file: target
    //    at startup, so this is a "the emulator came up" signal, NOT a
    //    "guest booted" claim.)
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut serial_seen = false;
    while Instant::now() < deadline {
        let status = guest.status();
        assert!(
            status.running,
            "QEMU (pid {pid}) exited early — check stderr above for QEMU's own diagnostics"
        );
        assert_eq!(status.pid, Some(pid));
        if serial_log.is_file() {
            serial_seen = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        serial_seen,
        "serial log {} did not appear within the timeout while QEMU (pid {pid}) ran",
        serial_log.display()
    );
    assert!(guest.status().running, "QEMU (pid {pid}) must still be alive after the poll");

    // 6. Tear down: kill + reap, then confirm it is gone.
    guest.kill_and_wait().expect("kill_and_wait should succeed");
    assert!(!guest.status().running);

    let _ = std::fs::remove_dir_all(&state);
}
