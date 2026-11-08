// SPDX-License-Identifier: MIT OR Apache-2.0
//
// DESIGN PREVIEW — written ≠ built ≠ booted. UNAUDITED. THIS MODULE SPAWNS
// NOTHING: `GuestHandle` holds a plain-data PID, never a process. The
// crate's one spawn path is `crate::spawn` (gated OFF by default), whose
// `SpawnedGuest::handle` is the only code that ever fills `GuestHandle.pid`
// with a real value. A real guest has never been booted in CI. Product
// name "Terem" is proposed only, pending trademark clearance.

//! The POC-SCOPE.md §2.1 guest-lifecycle data shapes, as plain types.
//!
//! These are the *data* halves of the eventual `terem_create` /
//! `terem_start` / `terem_status` command surface. The *process* half that
//! exists so far is [`crate::spawn`] — opt-in, doubly gated, holding the
//! `Child` itself — while this module stays pure data; the other pieces are
//! [`crate::launch::LaunchPlan`] (the argv as data, dry-run only) and
//! [`crate::qmp_client`] (socket-shaped I/O, mock-tested only). Spawning
//! `qemu-img` remains a later slice.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// What a v1 guest *is*, before anything runs: the inputs to
/// `terem_create` + `terem_start` (POC-SCOPE.md §2.1), as data.
///
/// v1 scope per POC-SCOPE §1.2: one headless Linux guest, legacy BIOS
/// (SeaBIOS), virtio-blk, user-mode NAT, serial console — no UEFI, no TPM,
/// no display pipeline, no Windows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestSpec {
    /// The qcow2 disk file this guest owns (`terem_create`'s `disk_path`).
    pub disk_path: PathBuf,
    /// Disk size in MiB (`terem_create`'s `size_mb`; `qemu-img create ...
    /// <size_mb>M` in the later slice that actually runs it).
    pub disk_size_mb: u64,
    /// The boot image (`terem_start`'s `boot_image`) — for the POC, the
    /// marker-printing kernel+initramfs fixture of POC-SCOPE §2.2, or any
    /// pre-built bootable image. Never an OS Postern provides or bundles
    /// (03-license-honesty.md §1's doctrine).
    pub boot_image: PathBuf,
}

/// The v1 running-guest state — POC-SCOPE.md §2.1's `GuestHandle`, minus
/// the process.
///
/// The design doc's shape holds `child: Child` (the `qemu-system-x86_64`
/// process). **This type deliberately does not**: the `Child` lives in
/// [`crate::spawn::SpawnedGuest`], and this record stays serializable pure
/// data. No constructor here starts anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestHandle {
    /// The child QEMU process's id (mirroring `node_start`'s returned PID),
    /// or `None` for "never spawned". The only code path that fills this
    /// with a real value is [`crate::spawn::SpawnedGuest::handle`], behind
    /// the opt-in `full_vm_qemu` gate; everything else in the crate only
    /// ever produces `None`.
    pub pid: Option<u32>,
    /// QMP unix-socket path that would be passed at spawn
    /// (`-qmp unix:<sock>,server,nowait`).
    pub qmp_sock: PathBuf,
    /// The qcow2 file this guest owns. `terem_stop` never deletes it;
    /// only the separate, explicit `terem_destroy` verb does
    /// (POC-SCOPE §2.1 / A-virtualization.md §1.2).
    pub disk_path: PathBuf,
    /// Serial-console log target (`-serial file:<path>`) — v1's only
    /// "did it boot" signal, grepped for the boot marker (POC-SCOPE §1.2).
    pub serial_log: PathBuf,
}

///`terem_status`'s answer shape — mirrors `node_status`'s
/// `{ "running": bool, "pid": Option<u32> }` (POC-SCOPE.md §2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestStatus {
    pub running: bool,
    pub pid: Option<u32>,
}

impl GuestStatus {
    /// The status of a guest that was never started (or has exited) — the
    /// only answer any non-[`crate::spawn`] code path can honestly give.
    pub fn not_running() -> Self {
        Self { running: false, pid: None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_spec_round_trips() {
        let spec = GuestSpec {
            disk_path: PathBuf::from("/var/lib/terem/guest0.qcow2"),
            disk_size_mb: 2048,
            boot_image: PathBuf::from("/var/lib/terem/fixtures/marker-boot.img"),
        };
        let json = serde_json::to_string(&spec).unwrap();
        let back: GuestSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back, spec);
    }

    #[test]
    fn guest_handle_round_trips_and_defaults_to_never_spawned() {
        let handle = GuestHandle {
            pid: None, // never spawned — every non-crate::spawn path's value
            qmp_sock: PathBuf::from("/run/terem/guest0.qmp.sock"),
            disk_path: PathBuf::from("/var/lib/terem/guest0.qcow2"),
            serial_log: PathBuf::from("/var/log/terem/guest0.serial.log"),
        };
        let json = serde_json::to_string(&handle).unwrap();
        let back: GuestHandle = serde_json::from_str(&json).unwrap();
        assert_eq!(back, handle);
        assert!(back.pid.is_none(), "a never-spawned handle keeps pid None");
    }

    #[test]
    fn status_shape_mirrors_node_status() {
        // The wire shape must be exactly { "running": bool, "pid": ... },
        // mirroring node_status (POC-SCOPE §2.1).
        let json = serde_json::to_string(&GuestStatus::not_running()).unwrap();
        assert_eq!(json, r#"{"running":false,"pid":null}"#);

        let running: GuestStatus =
            serde_json::from_str(r#"{"running":true,"pid":4242}"#).unwrap();
        assert_eq!(running, GuestStatus { running: true, pid: Some(4242) });
    }
}
