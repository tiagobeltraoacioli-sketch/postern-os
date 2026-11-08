// SPDX-License-Identifier: MIT OR Apache-2.0
//
// DESIGN PREVIEW — written ≠ built ≠ booted. UNAUDITED. THIS MODULE SPAWNS
// NOTHING: a `LaunchPlan` is *data* — the argv for an operator-supplied
// QEMU — and the only mode implemented here is `DryRun`, which returns that
// data without starting anything. The crate's one spawn path is
// `crate::spawn`, which consumes a built plan and is gated OFF by default
// (both gates re-checked at spawn time). A real guest has never been booted
// in CI. Product name "Terem" is proposed only, pending trademark clearance.

//! Dry-run guest-launch planning — POC-SCOPE.md §3 step 3's *plan* half.
//!
//! [`LaunchPlan::build`] turns a vetted QEMU path (from [`crate::resolve`]),
//! a [`crate::guest::GuestSpec`], and a [`crate::config::TeremConfig`] into
//! the deterministic `qemu-system-x86_64` argv for the v1 guest shape
//! (POC-SCOPE §1.2: one headless Linux guest, virtio-blk disk, user-mode
//! NAT, serial console to a file, QMP over a unix socket, no display). The
//! plan is pure data: [`LaunchPlan::argv`] hands the argv back for
//! inspection/testing, and nothing in THIS module executes it. The one
//! place in the crate that can is [`crate::spawn::spawn_plan`], which
//! re-checks both refusals below at spawn time, defense in depth.
//!
//! Two refusals are load-bearing:
//!
//! * **License-safe default stays OFF** — a plan is refused unless the
//!   operator explicitly opted in via
//!   [`TeremConfig::full_vm_qemu`](crate::config::TeremConfig::full_vm_qemu)
//!   (LICENSE-DECISION.md §2). QEMU (GPL-2.0) remains an external,
//!   operator-supplied process; planning an argv links nothing.
//! * **Only the pinned binary** — the program path's file name must be
//!   exactly [`QEMU_SYSTEM_BIN_NAME`], re-checked here even though callers
//!   are expected to come through [`crate::resolve::resolve_qemu_binary`].
//!
//! Honesty caveat: this argv has been asserted byte-for-byte in tests, and
//! the hermetic [`crate::spawn`] tests hand it only to a fake sleeper
//! script — it has **never been passed to a real QEMU in CI**. A real
//! guest has never been booted; the first live launch remains an operator's
//! explicit, opted-in act (the `#[ignore]`-gated `tests/real_spawn.rs`).

use std::path::{Path, PathBuf};

use crate::config::TeremConfig;
use crate::guest::GuestSpec;
use crate::resolve::QEMU_SYSTEM_BIN_NAME;

/// Guest RAM in MiB for the v1 plan (POC-SCOPE §1.2's single small guest).
/// Fixed in this slice; making it spec-driven is a later, deliberate change.
pub const DEFAULT_MEMORY_MIB: u64 = 2048;

/// Guest vCPU count for the v1 plan. Fixed in this slice, like
/// [`DEFAULT_MEMORY_MIB`].
pub const DEFAULT_SMP_CPUS: u32 = 2;

/// How a plan may be materialized by THIS module. **`DryRun` is the only
/// variant**: return the plan as data, spawn nothing. Actually executing a
/// built plan is deliberately not a `LaunchMode` — it is the separate,
/// doubly-gated [`crate::spawn::spawn_plan`], so building and spawning stay
/// two explicit acts instead of one flag flip.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchMode {
    /// Build and return the plan without starting any process.
    DryRun,
}

/// A fully-determined `qemu-system-x86_64` invocation, as data.
///
/// Holds the vetted program path and its argument vector. It has no
/// `spawn`/`exec`/`run` method by design — executing a plan is
/// [`crate::spawn::spawn_plan`]'s job, behind its own re-checked gates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchPlan {
    program: PathBuf,
    args: Vec<String>,
}

/// Require a UTF-8 path so the argv is plain `String`s (deterministic,
/// serializable, printable). Non-UTF-8 paths are refused, not lossily mangled.
fn utf8_path<'p>(path: &'p Path, what: &str) -> Result<&'p str, String> {
    path.to_str()
        .ok_or_else(|| format!("{what} path '{}' is not valid UTF-8", path.display()))
}

impl LaunchPlan {
    /// Build the deterministic launch plan for `spec`, or refuse.
    ///
    /// Inputs:
    /// * `mode` — [`LaunchMode::DryRun`] is the only mode that exists here.
    /// * `config` — must have `full_vm_qemu == true`; the license-safe
    ///   default (`false`) is refused, so a default config can never plan a
    ///   QEMU invocation (LICENSE-DECISION.md §2).
    /// * `qemu_path` — a vetted path from
    ///   [`crate::resolve::resolve_qemu_binary`]; the pinned file name is
    ///   re-checked here regardless.
    /// * `spec` — disk + boot image. `spec.disk_size_mb` is deliberately
    ///   **not** in this argv: sizing the qcow2 is `qemu-img create`'s job
    ///   (a separate plan, a later slice), not the system emulator's.
    /// * `qmp_sock` / `serial_log` — the control-socket and serial-console
    ///   paths a [`crate::guest::GuestHandle`] would carry.
    ///
    /// Never spawns; returns the plan as data.
    pub fn build(
        mode: LaunchMode,
        config: &TeremConfig,
        qemu_path: &Path,
        spec: &GuestSpec,
        qmp_sock: &Path,
        serial_log: &Path,
    ) -> Result<Self, String> {
        // The only mode. If `LaunchMode` ever grows a spawning variant this
        // match forces the author to visit this function and its invariants.
        match mode {
            LaunchMode::DryRun => {}
        }

        // License gate FIRST: the default config plans nothing at all.
        if !config.full_vm_qemu {
            return Err(
                "refusing to plan a QEMU launch: full_vm_qemu is disabled \
                 (the license-safe default). QEMU (GPL-2.0) is opt-in, \
                 operator-supplied, and never bundled — see \
                 docs/os-portal-v2/LICENSE-DECISION.md §2"
                    .to_string(),
            );
        }

        // Pin the program name even for pre-resolved paths (defense in depth
        // against a caller skipping crate::resolve).
        if qemu_path.file_name().and_then(|n| n.to_str()) != Some(QEMU_SYSTEM_BIN_NAME) {
            return Err(format!(
                "refusing to plan '{}': the program must be an executable named \
                 '{QEMU_SYSTEM_BIN_NAME}' vetted by crate::resolve",
                qemu_path.display()
            ));
        }

        let disk = utf8_path(&spec.disk_path, "guest disk")?;
        let boot = utf8_path(&spec.boot_image, "boot image")?;
        let sock = utf8_path(qmp_sock, "QMP socket")?;
        let serial = utf8_path(serial_log, "serial log")?;

        // The v1 argv, in fixed order (POC-SCOPE §1.2 shape): headless,
        // virtio-blk qcow2 disk, boot image on the CD device with boot-order
        // 'd', serial console to a file, QMP unix control socket, user-mode
        // NAT. Deterministic by construction so tests can pin exact bytes.
        let args = vec![
            "-machine".to_string(),
            "pc".to_string(),
            "-m".to_string(),
            format!("{DEFAULT_MEMORY_MIB}M"),
            "-smp".to_string(),
            DEFAULT_SMP_CPUS.to_string(),
            "-display".to_string(),
            "none".to_string(),
            "-serial".to_string(),
            format!("file:{serial}"),
            "-qmp".to_string(),
            format!("unix:{sock},server,nowait"),
            "-drive".to_string(),
            format!("file={disk},if=virtio,format=qcow2"),
            "-cdrom".to_string(),
            boot.to_string(),
            "-boot".to_string(),
            "d".to_string(),
            "-nic".to_string(),
            "user".to_string(),
        ];

        Ok(Self { program: qemu_path.to_path_buf(), args })
    }

    /// The vetted program path (argv\[0\]).
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// The arguments after the program name.
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// The full argv — program first, then [`Self::args`] — as data.
    /// Nothing in this module executes it; only the doubly-gated
    /// [`crate::spawn::spawn_plan`] can.
    pub fn argv(&self) -> Vec<String> {
        let mut argv = Vec::with_capacity(1 + self.args.len());
        argv.push(self.program.to_string_lossy().into_owned());
        argv.extend(self.args.iter().cloned());
        argv
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn spec() -> GuestSpec {
        GuestSpec {
            disk_path: PathBuf::from("/var/lib/terem/guest0.qcow2"),
            disk_size_mb: 2048,
            boot_image: PathBuf::from("/var/lib/terem/fixtures/marker-boot.img"),
        }
    }

    fn opted_in() -> TeremConfig {
        TeremConfig { full_vm_qemu: true, wine_proton: false }
    }

    /// The load-bearing refusal: the license-safe DEFAULT config can never
    /// produce a launch plan, even a dry-run one.
    #[test]
    fn default_config_refuses_to_plan() {
        let err = LaunchPlan::build(
            LaunchMode::DryRun,
            &TeremConfig::default(),
            Path::new("/opt/qemu/bin/qemu-system-x86_64"),
            &spec(),
            Path::new("/run/terem/guest0.qmp.sock"),
            Path::new("/var/log/terem/guest0.serial.log"),
        )
        .unwrap_err();
        assert!(err.contains("full_vm_qemu"), "unexpected error: {err}");
        assert!(err.contains("LICENSE-DECISION"), "unexpected error: {err}");
    }

    /// Opted in → the exact, deterministic v1 argv, byte for byte.
    #[test]
    fn opted_in_plan_is_deterministic_and_exact() {
        let plan = LaunchPlan::build(
            LaunchMode::DryRun,
            &opted_in(),
            Path::new("/opt/qemu/bin/qemu-system-x86_64"),
            &spec(),
            Path::new("/run/terem/guest0.qmp.sock"),
            Path::new("/var/log/terem/guest0.serial.log"),
        )
        .expect("opted-in plan should build");

        assert_eq!(plan.program(), Path::new("/opt/qemu/bin/qemu-system-x86_64"));
        assert_eq!(
            plan.argv(),
            vec![
                "/opt/qemu/bin/qemu-system-x86_64",
                "-machine",
                "pc",
                "-m",
                "2048M",
                "-smp",
                "2",
                "-display",
                "none",
                "-serial",
                "file:/var/log/terem/guest0.serial.log",
                "-qmp",
                "unix:/run/terem/guest0.qmp.sock,server,nowait",
                "-drive",
                "file=/var/lib/terem/guest0.qcow2,if=virtio,format=qcow2",
                "-cdrom",
                "/var/lib/terem/fixtures/marker-boot.img",
                "-boot",
                "d",
                "-nic",
                "user",
            ]
        );

        // Determinism: building twice yields an identical plan.
        let again = LaunchPlan::build(
            LaunchMode::DryRun,
            &opted_in(),
            Path::new("/opt/qemu/bin/qemu-system-x86_64"),
            &spec(),
            Path::new("/run/terem/guest0.qmp.sock"),
            Path::new("/var/log/terem/guest0.serial.log"),
        )
        .unwrap();
        assert_eq!(again, plan);
    }

    /// The program name pin holds even for callers that skipped
    /// crate::resolve and handed in an arbitrary path.
    #[test]
    fn wrong_program_name_refused() {
        for bad in ["/usr/bin/sh", "/opt/qemu/bin/qemu-img", "/opt/qemu-system-x86_64x"] {
            let err = LaunchPlan::build(
                LaunchMode::DryRun,
                &opted_in(),
                Path::new(bad),
                &spec(),
                Path::new("/run/terem/g.qmp.sock"),
                Path::new("/var/log/terem/g.serial.log"),
            )
            .unwrap_err();
            assert!(err.contains(QEMU_SYSTEM_BIN_NAME), "unexpected error: {err}");
        }
    }

    /// Non-UTF-8 paths are refused rather than lossily mangled into argv.
    #[cfg(unix)]
    #[test]
    fn non_utf8_path_refused() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let mut s = spec();
        s.disk_path = PathBuf::from(OsStr::from_bytes(b"/var/lib/terem/gu\xffest.qcow2"));
        let err = LaunchPlan::build(
            LaunchMode::DryRun,
            &opted_in(),
            Path::new("/opt/qemu/bin/qemu-system-x86_64"),
            &s,
            Path::new("/run/terem/g.qmp.sock"),
            Path::new("/var/log/terem/g.serial.log"),
        )
        .unwrap_err();
        assert!(err.contains("not valid UTF-8"), "unexpected error: {err}");
    }

    /// disk_size_mb is qemu-img's input, not the emulator's: it must never
    /// leak into this argv.
    #[test]
    fn disk_size_not_in_run_argv() {
        let mut s = spec();
        s.disk_size_mb = 31337;
        let plan = LaunchPlan::build(
            LaunchMode::DryRun,
            &opted_in(),
            Path::new("/opt/qemu/bin/qemu-system-x86_64"),
            &s,
            Path::new("/run/terem/g.qmp.sock"),
            Path::new("/var/log/terem/g.serial.log"),
        )
        .unwrap();
        assert!(!plan.argv().iter().any(|a| a.contains("31337")));
    }
}
