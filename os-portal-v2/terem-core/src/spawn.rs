// SPDX-License-Identifier: MIT OR Apache-2.0
//
// DESIGN PREVIEW — written ≠ built ≠ booted. UNAUDITED. THIS MODULE IS THE
// CRATE'S ONLY SPAWN PATH: it turns an already-built, doubly-gated
// [`crate::launch::LaunchPlan`] into a real `std::process::Child`. It is
// gated OFF by default — the license-safe default `TeremConfig` is refused
// here a second time, at spawn time, independent of the plan-time refusal.
// A real guest has never been booted in CI; the hermetic tests below spawn
// only a fake `sleep` script that carries the pinned QEMU name. Product name
// "Terem" is proposed only, pending trademark clearance.

//! Real process spawn for a built [`LaunchPlan`] — POC-SCOPE.md §3 step 3's
//! *execute* half, the first slice of this crate that starts anything.
//!
//! [`spawn_plan`] re-checks, defense in depth, BOTH of the plan's
//! load-bearing gates at spawn time — even though [`LaunchPlan::build`]
//! already enforced them:
//!
//! * **License gate** — refused unless the operator opted in via
//!   [`TeremConfig::full_vm_qemu`](crate::config::TeremConfig::full_vm_qemu)
//!   (LICENSE-DECISION.md §2). The GPL posture is unchanged by this module:
//!   QEMU (GPL-2.0) stays an external, operator-supplied process driven over
//!   its own documented CLI/QMP boundary — never linked, bundled, or
//!   vendored — and the license-safe default config is refused at BOTH plan
//!   and spawn time.
//! * **Program-name pin** — the plan's program file name must be exactly
//!   [`QEMU_SYSTEM_BIN_NAME`], re-checked here so a hand-rolled or mutated
//!   plan-shaped value cannot smuggle another binary into the spawn.
//!
//! [`SpawnedGuest`] owns the `std::process::Child`, reports liveness as a
//! [`crate::guest::GuestStatus`] via `try_wait`, and its [`Drop`] kills and
//! reaps the child so tests (and crashing callers) never orphan a process.
//! [`SpawnedGuest::handle`] is the first code path anywhere in this crate
//! that fills [`crate::guest::GuestHandle::pid`] with a real value.
//!
//! Honesty caveats, unchanged: everything here is UNAUDITED and a DESIGN
//! PREVIEW; `written ≠ built ≠ booted`. The hermetic tests spawn a fake
//! shell script named `qemu-system-x86_64`, and the `tests/real_spawn.rs`
//! integration test that would drive an operator-supplied real QEMU is
//! `#[ignore]`-gated and never runs in CI — **no claim is made that a real
//! guest has ever booted**.

use std::path::Path;
use std::process::{Child, Command, Stdio};

use crate::config::TeremConfig;
use crate::guest::{GuestHandle, GuestStatus};
use crate::launch::LaunchPlan;
use crate::resolve::QEMU_SYSTEM_BIN_NAME;

/// The two spawn-time gates, factored out so they are testable without
/// spawning: license opt-in first, then the program-name pin. Exactly
/// mirrors the refusals in [`LaunchPlan::build`] — deliberately duplicated
/// (defense in depth), not shared, so neither layer can be weakened by
/// refactoring the other.
fn check_spawn_gates(config: &TeremConfig, program: &Path) -> Result<(), String> {
    // License gate FIRST: the default config spawns nothing at all, even if
    // someone somehow holds an already-built plan.
    if !config.full_vm_qemu {
        return Err(
            "refusing to spawn QEMU: full_vm_qemu is disabled \
             (the license-safe default). QEMU (GPL-2.0) is opt-in, \
             operator-supplied, and never bundled — see \
             docs/os-portal-v2/LICENSE-DECISION.md §2"
                .to_string(),
        );
    }

    // Pin the program name again at the moment of truth.
    if program.file_name().and_then(|n| n.to_str()) != Some(QEMU_SYSTEM_BIN_NAME) {
        return Err(format!(
            "refusing to spawn '{}': the program must be an executable named \
             '{QEMU_SYSTEM_BIN_NAME}' vetted by crate::resolve",
            program.display()
        ));
    }

    Ok(())
}

/// A live, owned guest process spawned from a [`LaunchPlan`].
///
/// Owns the `std::process::Child`. Dropping a `SpawnedGuest` kills and reaps
/// the child (see [`Drop`]); call [`SpawnedGuest::kill_and_wait`] for the
/// explicit, error-reporting version.
#[derive(Debug)]
pub struct SpawnedGuest {
    child: Child,
}

impl SpawnedGuest {
    /// The OS process id of the spawned child.
    ///
    /// Stable for the lifetime of this handle; after exit it names a reaped
    /// (or about-to-be-reaped) process, so use [`Self::status`] for liveness.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Non-blocking liveness probe via `Child::try_wait`, in
    /// `terem_status`'s answer shape.
    ///
    /// * still running → `{ running: true, pid: Some(pid) }`
    /// * exited (or the probe failed) → `{ running: false, pid: None }`
    ///
    /// A probe error is reported as not-running: this handle can no longer
    /// vouch for the process, and "running" is the claim that must never be
    /// made loosely.
    pub fn status(&mut self) -> GuestStatus {
        match self.child.try_wait() {
            Ok(None) => GuestStatus { running: true, pid: Some(self.child.id()) },
            Ok(Some(_)) | Err(_) => GuestStatus::not_running(),
        }
    }

    /// Kill the child (SIGKILL on Unix) and reap it. Idempotent: killing an
    /// already-exited child is not an error, and the final `wait` both
    /// reaps the zombie and caches the exit status for later
    /// [`Self::status`] calls.
    pub fn kill_and_wait(&mut self) -> Result<(), String> {
        // `Child::kill` errors if the child has already been reaped; that is
        // exactly the state we want, so it is not a failure here.
        let _ = self.child.kill();
        self.child
            .wait()
            .map(|_| ())
            .map_err(|e| format!("failed to wait for spawned guest: {e}"))
    }

    /// Build the [`GuestHandle`] record for this live process — the first
    /// code path in this crate that ever fills [`GuestHandle::pid`] with a
    /// real value.
    ///
    /// The paths are the same ones the plan was built with; this crate does
    /// not (yet) retain them inside the plan, so the caller supplies them.
    pub fn handle(&self, qmp_sock: &Path, disk_path: &Path, serial_log: &Path) -> GuestHandle {
        GuestHandle {
            pid: Some(self.child.id()),
            qmp_sock: qmp_sock.to_path_buf(),
            disk_path: disk_path.to_path_buf(),
            serial_log: serial_log.to_path_buf(),
        }
    }
}

/// Kill + reap on drop so no test, panic, or careless caller ever orphans
/// the child process. Errors are ignored — the child may already be gone,
/// and `Drop` has no channel to report anyway.
impl Drop for SpawnedGuest {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn the process a [`LaunchPlan`] describes, or refuse.
///
/// Re-checks BOTH plan-time gates (license opt-in, program-name pin) before
/// touching `std::process::Command` — see the module docs and
/// [`check_spawn_gates`]. On success the child runs with a null stdin
/// (nothing in this crate drives a QEMU monitor over stdio; the control
/// plane is the plan's QMP unix socket) and inherited stdout/stderr, so an
/// operator sees QEMU's own diagnostics.
///
/// The returned [`SpawnedGuest`] owns the child and kills+reaps it on drop.
pub fn spawn_plan(config: &TeremConfig, plan: &LaunchPlan) -> Result<SpawnedGuest, String> {
    check_spawn_gates(config, plan.program())?;

    let child = Command::new(plan.program())
        .args(plan.args())
        .stdin(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn '{}': {e}", plan.program().display()))?;

    Ok(SpawnedGuest { child })
}

#[cfg(test)]
mod tests {
    //! Hermetic spawn tests — never `#[ignore]`d, never touch a real QEMU.
    //! The only thing ever spawned is a fake shell script that carries the
    //! pinned name `qemu-system-x86_64` and just sleeps (the same
    //! fake-executable pattern as `tests/dry_run_plan.rs`).

    use super::*;
    use crate::guest::GuestSpec;
    use crate::launch::LaunchMode;
    use std::path::PathBuf;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "terem-core-spawn-test-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Fake "QEMU": a shell script that sleeps long enough for the test to
    /// observe it alive, mode 0755 — same pattern as tests/dry_run_plan.rs.
    #[cfg(unix)]
    fn write_sleeper(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, b"#!/bin/sh\nsleep 30\n").unwrap();
        let mut perm = std::fs::metadata(path).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(path, perm).unwrap();
    }

    fn opted_in() -> TeremConfig {
        TeremConfig { full_vm_qemu: true, wine_proton: false }
    }

    fn spec_in(dir: &Path) -> GuestSpec {
        GuestSpec {
            disk_path: dir.join("guest0.qcow2"),
            disk_size_mb: 2048,
            boot_image: dir.join("marker-boot.img"),
        }
    }

    /// Defense in depth: even holding a VALID, already-built plan, the
    /// license-safe DEFAULT config is refused again at spawn time.
    #[cfg(unix)]
    #[test]
    fn default_config_refuses_to_spawn_a_valid_plan() {
        let dir = scratch("gate-license");
        let fake_qemu = dir.join(QEMU_SYSTEM_BIN_NAME);
        write_sleeper(&fake_qemu);

        // The plan itself is built with an opted-in config…
        let spec = spec_in(&dir);
        let plan = LaunchPlan::build(
            LaunchMode::DryRun,
            &opted_in(),
            &fake_qemu,
            &spec,
            &dir.join("g.qmp.sock"),
            &dir.join("g.serial.log"),
        )
        .unwrap();

        // …but spawning it under the DEFAULT config must still refuse.
        let err = spawn_plan(&TeremConfig::default(), &plan).unwrap_err();
        assert!(err.contains("full_vm_qemu"), "unexpected error: {err}");
        assert!(err.contains("LICENSE-DECISION"), "unexpected error: {err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The spawn-time program-name pin holds even for plan-shaped inputs
    /// that (hypothetically) escaped LaunchPlan::build's identical check.
    #[test]
    fn wrong_program_name_refused_at_spawn_time() {
        for bad in ["/usr/bin/sh", "/opt/qemu/bin/qemu-img", "/opt/qemu-system-x86_64x"] {
            let err = check_spawn_gates(&opted_in(), Path::new(bad)).unwrap_err();
            assert!(err.contains(QEMU_SYSTEM_BIN_NAME), "unexpected error: {err}");
        }
        // And the license gate fires first, before the name pin.
        let err =
            check_spawn_gates(&TeremConfig::default(), Path::new("/usr/bin/sh")).unwrap_err();
        assert!(err.contains("full_vm_qemu"), "unexpected error: {err}");
    }

    /// The real thing, hermetically: spawn a fake sleeper named exactly
    /// qemu-system-x86_64, observe it alive with its pid, then kill+reap it
    /// and observe it gone. No real QEMU anywhere.
    #[cfg(unix)]
    #[test]
    fn spawns_fake_qemu_reports_running_then_killed() {
        let dir = scratch("spawn-fake");
        let fake_qemu = dir.join(QEMU_SYSTEM_BIN_NAME);
        write_sleeper(&fake_qemu);

        let spec = spec_in(&dir);
        let qmp_sock = dir.join("g.qmp.sock");
        let serial_log = dir.join("g.serial.log");
        let plan = LaunchPlan::build(
            LaunchMode::DryRun,
            &opted_in(),
            &fake_qemu,
            &spec,
            &qmp_sock,
            &serial_log,
        )
        .unwrap();

        let mut guest = spawn_plan(&opted_in(), &plan).expect("fake sleeper should spawn");
        let pid = guest.pid();
        assert!(pid > 0);

        // Alive: running=true with the same pid.
        assert_eq!(guest.status(), GuestStatus { running: true, pid: Some(pid) });

        // handle() is the first GuestHandle in this crate with a real pid.
        let handle = guest.handle(&qmp_sock, &spec.disk_path, &serial_log);
        assert_eq!(handle.pid, Some(pid));
        assert_eq!(handle.qmp_sock, qmp_sock);
        assert_eq!(handle.disk_path, spec.disk_path);
        assert_eq!(handle.serial_log, serial_log);

        // Kill + reap flips the status, and doing it twice is not an error.
        guest.kill_and_wait().expect("kill_and_wait should succeed");
        assert_eq!(guest.status(), GuestStatus::not_running());
        guest.kill_and_wait().expect("kill_and_wait must be idempotent");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Drop kills and reaps: after dropping the guest, killing the old pid
    /// from outside must fail (no such process / already reaped).
    #[cfg(unix)]
    #[test]
    fn drop_kills_and_reaps_the_child() {
        let dir = scratch("spawn-drop");
        let fake_qemu = dir.join(QEMU_SYSTEM_BIN_NAME);
        write_sleeper(&fake_qemu);

        let spec = spec_in(&dir);
        let plan = LaunchPlan::build(
            LaunchMode::DryRun,
            &opted_in(),
            &fake_qemu,
            &spec,
            &dir.join("g.qmp.sock"),
            &dir.join("g.serial.log"),
        )
        .unwrap();

        let mut guest = spawn_plan(&opted_in(), &plan).unwrap();
        assert!(guest.status().running);
        drop(guest); // must not hang, must not leave a 30s sleeper behind

        let _ = std::fs::remove_dir_all(&dir);
    }
}
