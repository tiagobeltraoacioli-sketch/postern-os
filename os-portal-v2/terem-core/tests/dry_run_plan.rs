// SPDX-License-Identifier: MIT OR Apache-2.0
//
// DESIGN PREVIEW — written ≠ built ≠ booted. UNAUDITED. This test SPAWNS NO
// VM: the "QEMU" it resolves is a fake shell-script file in a temp dir
// (never executed — resolution and planning are both pure data operations),
// exactly the resolve-module test pattern. Product name "Terem" is proposed
// only, pending trademark clearance.

//! Integration-style wiring test: [`terem_core::resolve`] →
//! [`terem_core::launch::LaunchPlan`], end to end, without anything running.

use std::path::{Path, PathBuf};

use terem_core::config::TeremConfig;
use terem_core::guest::GuestSpec;
use terem_core::launch::{LaunchMode, LaunchPlan};
use terem_core::resolve::{resolve_qemu_binary, QEMU_SYSTEM_BIN_NAME};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "terem-core-itest-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[cfg(unix)]
fn write_exec(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, b"#!/bin/sh\ntrue\n").unwrap();
    let mut perm = std::fs::metadata(path).unwrap().permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(path, perm).unwrap();
}

#[cfg(unix)]
#[test]
fn resolve_then_plan_yields_exact_argv() {
    // 1. A fake operator-installed QEMU: correct pinned name, exec bit set,
    //    in a temp dir. It is resolved and planned around, never run.
    let dir = scratch("resolve-plan");
    let fake_qemu = dir.join(QEMU_SYSTEM_BIN_NAME);
    write_exec(&fake_qemu);

    let resolved =
        resolve_qemu_binary(fake_qemu.to_str().unwrap()).expect("fake qemu should resolve");
    // canonicalize() may rewrite prefixes (e.g. /var → /private/var on
    // macOS), so derive expectations from the RESOLVED path, as a real
    // caller would.
    assert_eq!(
        resolved.file_name().and_then(|n| n.to_str()),
        Some(QEMU_SYSTEM_BIN_NAME)
    );

    // 2. Guest inputs, as a future terem_create/terem_start would hold them.
    let state = scratch("resolve-plan-state");
    let spec = GuestSpec {
        disk_path: state.join("guest0.qcow2"),
        disk_size_mb: 2048,
        boot_image: state.join("marker-boot.img"),
    };
    let qmp_sock = state.join("guest0.qmp.sock");
    let serial_log = state.join("guest0.serial.log");

    // 3. License gate first: the DEFAULT config refuses even with a
    //    perfectly resolved binary in hand.
    assert!(LaunchPlan::build(
        LaunchMode::DryRun,
        &TeremConfig::default(),
        &resolved,
        &spec,
        &qmp_sock,
        &serial_log,
    )
    .is_err());

    // 4. Opted in → the exact argv, including the QMP socket argument.
    let config = TeremConfig { full_vm_qemu: true, wine_proton: false };
    let plan = LaunchPlan::build(
        LaunchMode::DryRun,
        &config,
        &resolved,
        &spec,
        &qmp_sock,
        &serial_log,
    )
    .expect("opted-in plan should build");

    let disk = spec.disk_path.to_str().unwrap();
    let boot = spec.boot_image.to_str().unwrap();
    let sock = qmp_sock.to_str().unwrap();
    let serial = serial_log.to_str().unwrap();
    assert_eq!(
        plan.argv(),
        vec![
            resolved.to_str().unwrap().to_string(),
            "-machine".into(),
            "pc".into(),
            "-m".into(),
            "2048M".into(),
            "-smp".into(),
            "2".into(),
            "-display".into(),
            "none".into(),
            "-serial".into(),
            format!("file:{serial}"),
            "-qmp".into(),
            format!("unix:{sock},server,nowait"),
            "-drive".into(),
            format!("file={disk},if=virtio,format=qcow2"),
            "-cdrom".into(),
            boot.into(),
            "-boot".into(),
            "d".into(),
            "-nic".into(),
            "user".into(),
        ]
    );

    // The QMP socket arg is present and well-formed — the piece qmp_client
    // would later connect to (in a future slice, on an opted-in host).
    assert!(plan
        .args()
        .iter()
        .any(|a| a == &format!("unix:{sock},server,nowait")));

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&state);
}
