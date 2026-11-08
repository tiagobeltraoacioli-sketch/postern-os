// SPDX-License-Identifier: MIT OR Apache-2.0
//! Terem — the QEMU/QMP guest-runtime POC (Tauri backend half).
//!
//! Scope: exactly `docs/os-portal-v2/POC-SCOPE.md`'s v1 slice — ONE headless
//! Linux guest, legacy BIOS (SeaBIOS, QEMU's own default; no UEFI/OVMF, no
//! swtpm, no Windows), driven directly over its QMP unix-socket control
//! plane with **no libvirt anywhere in the process tree**
//! (`docs/os-portal-v2/01-architecture.md` §2.1/§2.6,
//! `docs/os-portal-v2/A-virtualization.md` §0/§1.1). Binary resolution
//! mirrors `main.rs`'s `resolve_node_binary` shape byte-for-byte (name +
//! location + canonicalize + exec-bit), applied to `qemu-system-x86_64` and
//! `qemu-img` instead of `bloch`.
//!
//! ## Deliberate deviations from POC-SCOPE.md §2.1's literal command sketch
//!
//! POC-SCOPE.md sketches `terem_start(disk_path, boot_image)` and
//! `terem_destroy()` (zero args). Taken literally those two signatures are
//! inconsistent: a zero-arg `terem_destroy` has to get the disk path from
//! *somewhere*, so this implementation treats `terem_create` as also
//! **defining** the one guest v1 manages (disk path + derived QMP-socket and
//! serial-log paths, remembered in `TeremState` across start/stop, cleared
//! only by `terem_destroy`) — matching `01-architecture.md` §2.3's lifecycle
//! diagram, where CREATE/DESTROY are paired "define/undefine" verbs and
//! START/STOP only toggle the running state in between. `terem_start` takes
//! `kernel_path`/`initrd_path`/`kernel_append` instead of one `boot_image`
//! string, because the marker-boot fixture (`tests/terem_fixtures/`) is
//! booted via QEMU's direct-kernel-boot flags (`-kernel`/`-initrd`), the
//! standard "QEMU CI smoke test" shape POC-SCOPE.md §2.2 itself names as an
//! acceptable substitute when a full bootloader-carrying disk image is out
//! of budget. Both are minor, disclosed simplifications of an unbuilt
//! sketch, not deviations from any of `01`–`03`/`A`/`B`'s actual design
//! decisions (no libvirt, QMP-only control plane, file-only disk, no bridge
//! opened by default).
//!
//! ## Honesty labels (carried from `B-sandbox-consent.md` — READ before
//! trusting anything else in this file)
//!
//! - The guest this module boots is the NON-ATTESTABLE tier, by
//!   construction, forever: it runs a kernel+initramfs *this repo's own CI
//!   fixture* supplies today, but the same code path would run an arbitrary
//!   user-supplied kernel/disk tomorrow. `os_roothash` (Postern OS's own
//!   measured-boot chain, if the host happens to be Postern OS) never
//!   describes what runs inside this guest and never will.
//! - This module does not implement, and must never be read as
//!   implementing, ANY of `02-security-consent-privacy.md`/
//!   `B-sandbox-consent.md`'s bridge/consent machinery (clipboard, shared
//!   folders, audio, USB, bridged networking). v1 opens **zero** bridges —
//!   default-closed is achieved here by *not writing that code*, not by a
//!   consent gate. The network device below is QEMU user-mode NAT only
//!   (guest→internet only, never guest↔host-LAN), the one default-open
//!   exception `02` §3's own network rail already states.
//! - `terem_qmp` is an ALLOWLISTED passthrough, not raw QMP (see
//!   `QMP_ALLOWED_COMMANDS` below) — this is the load-bearing fix a v2
//!   red-team pass required: raw QMP includes `human-monitor-command`,
//!   `drive_add`, and block/device-hotplug verbs that could hand a guest (or
//!   a confused caller) a raw host block-device handle or an arbitrary
//!   monitor-command escape hatch, undercutting the "no guest ever gets a
//!   raw host block-device handle" guarantee `01-architecture.md` §2.4
//!   states as the single hardest structural guarantee in this whole design.
//! - This code is NOT audited, NOT attested, and NOT hardware-backed in any
//!   sense. It is unaudited, non-attestable software: a POC, never a
//!   security control, and it makes no attestation claim of any kind.
//!
//! ## QMP allowlist — what's in, what's out, and why
//!
//! `terem_qmp` only ever forwards a command that is an EXACT match (no
//! prefix/substring tricks) against [`QMP_ALLOWED_COMMANDS`]:
//!
//! | Command | Why it's safe to allow |
//! |---|---|
//! | `query-status` | Read-only: returns the guest's run-state. No side effect. |
//! | `query-name` | Read-only: returns the guest's configured name, if any. |
//! | `query-version` | Read-only: returns the QEMU build's version info. |
//! | `qom-list` | Read-only object-model introspection (what devices exist) — cannot create, delete, or attach anything. |
//! | `system_powerdown` | The ONE lifecycle verb v1 needs: asks the guest's ACPI stack to shut down gracefully. It cannot attach storage, execute code, or widen the guest's reach — it only ever narrows the guest's own runtime toward "off". |
//!
//! Everything else is REJECTED, in particular (non-exhaustive, the point is
//! the allowlist's exact-match default-deny, not this list):
//! `human-monitor-command` (an arbitrary-HMP-command escape hatch — this
//! alone can do everything below and more), `drive_add`/`blockdev-add`
//! (attaches a NEW host-backed block device to the running guest — the
//! exact "raw host block-device handle" hole the red-team pass named),
//! `device_add`/`device_del` (arbitrary device hot-plug, including USB/PCI
//! passthrough devices), `netdev_add`/`chardev-add` (new network/character
//! backends, widening the guest's I/O surface at runtime), `migrate`/
//! `migrate-incoming` (live-migration, entirely out of POC scope and a real
//! data-exfiltration shape if ever misused), `quit` (kills the whole QEMU
//! process out from under Terem's own lifecycle bookkeeping — `terem_stop`/
//! `terem_destroy` own process termination, not a free-form QMP verb),
//! `inject-nmi`/`pmemsave`/`memsave` (host-side memory dump/fault-injection
//! primitives). None of these can ever reach the guest through this module,
//! no matter what a caller passes to `terem_qmp` — [`qmp_command_allowed`]
//! is checked BEFORE anything is written to the QMP socket, fail-closed.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Value};

// ─────────────────────────────────────────────────────────────────────────
// Binary resolution — literal copy of `main.rs`'s `resolve_node_binary`
// shape (name + location + canonicalize + exec-bit), parameterized over the
// two QEMU binaries instead of hard-coding `bloch`. See main.rs for the
// fuller rationale comment; not re-derived here to avoid drift risk from a
// stale second copy of the same prose.
// ─────────────────────────────────────────────────────────────────────────

#[cfg(windows)]
const QEMU_BIN_NAME: &str = "qemu-system-x86_64.exe";
#[cfg(not(windows))]
const QEMU_BIN_NAME: &str = "qemu-system-x86_64";

#[cfg(windows)]
const QEMU_IMG_BIN_NAME: &str = "qemu-img.exe";
#[cfg(not(windows))]
const QEMU_IMG_BIN_NAME: &str = "qemu-img";

/// Minimal `$PATH` lookup for a bare command name (avoids a `which` dep).
/// Intentionally duplicated from `main.rs` (private there) rather than
/// shared — a small, stable, pure helper; not worth a cross-module `pub`
/// surface for four lines.
fn which_on_path(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// Resolve `binary` to a vetted absolute path whose file name is exactly
/// `expected_name`, or reject it. Same three checks `resolve_node_binary`
/// makes: a bare name is accepted only if it equals `expected_name`
/// (resolved via `$PATH`, never the CWD); a path is canonicalized and must
/// point at an existing regular file named `expected_name`; on Unix the
/// file must have an execute bit set. This is a name+location+existence
/// check, not a signature/hash check — same disclosed limit as the node
/// binary's own pin.
fn resolve_pinned_binary(binary: &str, expected_name: &str) -> Result<PathBuf, String> {
    let binary = binary.trim();
    if binary.is_empty() {
        return Err(format!("{expected_name} path is empty"));
    }

    let candidate = if binary.chars().any(std::path::is_separator) {
        PathBuf::from(binary)
    } else {
        if binary != expected_name {
            return Err(format!(
                "refusing to run '{binary}': a bare command name must be '{expected_name}'"
            ));
        }
        which_on_path(binary).ok_or_else(|| format!("'{binary}' not found on PATH"))?
    };

    let real = candidate
        .canonicalize()
        .map_err(|e| format!("cannot resolve '{}': {e}", candidate.display()))?;

    if real.file_name().and_then(|n| n.to_str()) != Some(expected_name) {
        return Err(format!(
            "refusing to run '{}': expected an executable named '{expected_name}'",
            real.display()
        ));
    }

    let meta =
        std::fs::metadata(&real).map_err(|e| format!("cannot stat '{}': {e}", real.display()))?;
    if !meta.is_file() {
        return Err(format!("'{}' is not a regular file", real.display()));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o111 == 0 {
            return Err(format!("'{}' is not executable", real.display()));
        }
    }

    Ok(real)
}

/// Resolve and pin the `qemu-system-x86_64` binary.
pub fn resolve_qemu_binary(binary: &str) -> Result<PathBuf, String> {
    resolve_pinned_binary(binary, QEMU_BIN_NAME)
}

/// Resolve and pin the `qemu-img` binary.
pub fn resolve_qemu_img_binary(binary: &str) -> Result<PathBuf, String> {
    resolve_pinned_binary(binary, QEMU_IMG_BIN_NAME)
}

/// QEMU short options (`-drive file=…,if=…`, `-qmp unix:…,server=on`) are
/// comma-separated `key=value` lists, so a comma INSIDE a caller-supplied
/// path would terminate the value early and INJECT arbitrary extra QEMU
/// options (e.g. a `file.driver=host_device` or a second host-backed
/// device — exactly the "raw host block-device handle" hole the module doc
/// promises never to open). Fail-closed: reject any comma outright rather
/// than rely on QEMU's `,,` double-comma escaping — a comma-free path is
/// the only shape this POC ever needs, and a rejection cannot be
/// mis-escaped. (There is no fixed "VM dir" in this POC to fence paths
/// under — `terem_create` chooses the path — so this is a syntax pin, not
/// a directory sandbox; disclosed limit.)
pub fn validate_qemu_pathlike(what: &str, path: &str) -> Result<(), String> {
    if path.contains(',') {
        return Err(format!(
            "{what} '{path}' contains a comma — commas separate QEMU options \
             (-drive file=...,if=...), so a comma inside the path would inject \
             extra QEMU options; choose a comma-free path"
        ));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────
// The QMP allowlist — see the module doc's table for the full rationale.
// ─────────────────────────────────────────────────────────────────────────

/// The ONLY QMP commands `terem_qmp` will ever forward to the guest's QMP
/// socket. Exact string match, case-sensitive, no prefix/substring
/// matching — anything not listed here is rejected before a single byte is
/// written to the socket. See the module doc for the per-command rationale
/// and the (non-exhaustive) list of what this deliberately excludes.
pub const QMP_ALLOWED_COMMANDS: &[&str] =
    &["query-status", "query-name", "query-version", "qom-list", "system_powerdown"];

/// Fail-closed allowlist check: `true` only for an exact match against
/// [`QMP_ALLOWED_COMMANDS`].
pub fn qmp_command_allowed(cmd: &str) -> bool {
    QMP_ALLOWED_COMMANDS.contains(&cmd)
}

// ─────────────────────────────────────────────────────────────────────────
// State — v1 manages exactly ONE guest at a time (`Mutex<Option<Guest>>`,
// literally `NodeProc`'s own shape, per POC-SCOPE.md §1.3's explicit
// "multi-guest is a mechanical follow-up, not a v1 concern"). `Guest`
// persists across start/stop (only `terem_destroy` clears it) — see the
// module doc's "deliberate deviations" note for why.
// ─────────────────────────────────────────────────────────────────────────

/// One defined guest: its own disk file, its own QMP socket, its own serial
/// (marker-boot) log — all derived, deterministically, from `disk_path`.
/// `child` is `Some` only while the QEMU process is actually running.
struct Guest {
    disk_path: PathBuf,
    qmp_sock: PathBuf,
    serial_log: PathBuf,
    child: Option<Child>,
}

/// The managed Terem guest (at most one). `Default`/`new()` both start empty
/// (no guest defined) — the same shape `NodeProc` uses for `bloch`.
#[derive(Default)]
pub struct TeremState(Mutex<Option<Guest>>);

impl TeremState {
    // Used by the lib target's own tests and by `tests/terem_lifecycle.rs`;
    // the bin (main.rs) constructs it via `::default()` in the Tauri
    // builder, so `new` reads as dead from the bin crate's point of view.
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Best-effort kill-switch: if a guest is currently running, SIGKILL it
    /// (no graceful QMP attempt — this is the "the window is closing right
    /// now" path). Used by `main.rs`'s `on_window_event(Destroyed)` handler,
    /// mirroring `NodeProc`'s own "kill the node if the window closes"
    /// safety net. Leaves the guest's disk/definition intact — this is a
    /// process kill, not a `terem_destroy`.
    pub fn kill_if_running(&self) {
        if let Ok(mut guard) = self.0.lock() {
            if let Some(guest) = guard.as_mut() {
                if let Some(mut child) = guest.child.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
    }
}

/// What a successful [`start_impl`] returns: the spawned PID and which QEMU
/// accelerator actually engaged (`"kvm"` or `"tcg"`) — the honest
/// capability-detection disclosure POC-SCOPE.md §2.1 calls for (mirrors
/// `verify_node_integrity`'s "tell the UI what was and wasn't checked"
/// discipline, applied here to "was and wasn't hardware-accelerated").
pub struct StartOutcome {
    pub pid: u32,
    pub accel: &'static str,
}

/// `true` iff `/dev/kvm` exists AND is actually open()-able read+write by
/// this process — existence alone doesn't imply access (group membership
/// matters). On macOS (this POC's primary dev host) `/dev/kvm` never
/// exists, so this is always `false` here — TCG is used unconditionally,
/// exactly as POC-SCOPE.md §1.3/§4 says is expected and sufficient to
/// validate the QMP control plane.
fn kvm_accessible() -> bool {
    std::fs::OpenOptions::new().read(true).write(true).open("/dev/kvm").is_ok()
}

// ─────────────────────────────────────────────────────────────────────────
// Core lifecycle — plain functions over `&TeremState`, deliberately free of
// `tauri::State`/`AppHandle` so `tests/*.rs` (a separate crate, no live
// Tauri app) can call them directly. The `#[tauri::command]` fns at the
// bottom of this file are thin wrappers that add UI log-event emission.
// ─────────────────────────────────────────────────────────────────────────

/// `terem_create`: `qemu-img create -f qcow2 <disk_path> <size_mb>M`, then
/// DEFINES this as the one guest v1 tracks (remembers `disk_path` plus its
/// derived QMP-socket/serial-log paths). Refuses to overwrite an existing
/// file and refuses to redefine a guest that's already defined — call
/// `terem_destroy` first.
pub fn create_impl(
    state: &TeremState,
    qemu_img_binary: &str,
    disk_path: &str,
    size_mb: u64,
) -> Result<(), String> {
    let mut guard = state.0.lock().unwrap();
    if guard.is_some() {
        return Err(
            "a guest is already defined — call terem_destroy before creating another \
             (v1 manages exactly one guest at a time)"
                .into(),
        );
    }
    if size_mb == 0 {
        return Err("size_mb must be > 0".into());
    }
    let disk_path = disk_path.trim();
    if disk_path.is_empty() {
        return Err("disk_path is empty".into());
    }
    // QEMU option-injection guard: this path is later interpolated into
    // `-drive file=…` (and its derived paths into `-qmp unix:…`), whose
    // comma-separated syntax a comma in the path would break out of.
    validate_qemu_pathlike("disk_path", disk_path)?;
    let disk = PathBuf::from(disk_path);
    if disk.exists() {
        return Err(format!("refusing to overwrite existing file '{}'", disk.display()));
    }
    if let Some(parent) = disk.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("create disk dir: {e}"))?;
        }
    }

    let bin = resolve_qemu_img_binary(qemu_img_binary)?;
    let out = Command::new(&bin)
        .arg("create")
        .arg("-f")
        .arg("qcow2")
        .arg(&disk)
        .arg(format!("{size_mb}M"))
        .output()
        .map_err(|e| format!("spawn {}: {e}", bin.display()))?;
    if !out.status.success() {
        return Err(format!(
            "qemu-img create failed (exit {:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    // Deterministic, collision-free-enough-for-a-single-guest derived paths:
    // same directory, same stem, different extension.
    let qmp_sock = disk.with_extension("qmp.sock");
    let serial_log = disk.with_extension("serial.log");
    *guard = Some(Guest { disk_path: disk, qmp_sock, serial_log, child: None });
    Ok(())
}

/// `terem_start`: spawns `qemu-system-x86_64` against the defined guest's
/// disk (`-drive …,if=virtio`), a user-mode-NAT virtio-net device (the one
/// default-open network exception `02-security-consent-privacy.md` §3
/// states), the guest's own QMP unix socket (`server=on,wait=off`), and a
/// `-serial file:<path>` sink for boot-verification. `-accel kvm` is used
/// only when `/dev/kvm` is genuinely accessible; otherwise `-accel tcg`
/// (always true on this POC's macOS dev host — see [`kvm_accessible`]).
/// `on_log` receives each line QEMU itself writes to its own stderr (not
/// the guest's console — that's the serial log), draining it on a
/// background thread so a chatty QEMU process can never block on a full
/// pipe. Boots the guest directly from a kernel+initramfs
/// (`-kernel`/`-initrd`/`-append`) when given — the marker-boot fixture's
/// shape — rather than requiring a bootloader baked into the disk image;
/// see the module doc's "deliberate deviations" note.
pub fn start_impl(
    state: &TeremState,
    qemu_binary: &str,
    kernel_path: Option<&str>,
    initrd_path: Option<&str>,
    kernel_append: Option<&str>,
    on_log: impl Fn(String) + Send + 'static,
) -> Result<StartOutcome, String> {
    let mut guard = state.0.lock().unwrap();
    let guest = guard.as_mut().ok_or("no guest defined — call terem_create first")?;

    if let Some(child) = guest.child.as_mut() {
        match child.try_wait() {
            Ok(Some(_)) => guest.child = None, // exited on its own; fall through and restart
            Ok(None) => return Err("guest already running".into()),
            Err(e) => return Err(format!("cannot check guest status: {e}")),
        }
    }

    // QEMU option-injection guard, re-checked at the exact point the values
    // are interpolated into comma-separated `-drive`/`-qmp` option strings
    // (defense in depth on top of `create_impl`'s check — the state could
    // in principle have been populated some other way).
    validate_qemu_pathlike("guest disk path", &guest.disk_path.to_string_lossy())?;
    validate_qemu_pathlike("guest QMP socket path", &guest.qmp_sock.to_string_lossy())?;

    let bin = resolve_qemu_binary(qemu_binary)?;
    if !guest.disk_path.is_file() {
        return Err(format!("guest disk '{}' does not exist", guest.disk_path.display()));
    }
    // A stale socket file from a prior run would make QEMU's unix,server=on
    // bind fail — clear it first. Best-effort: a missing file is fine.
    let _ = std::fs::remove_file(&guest.qmp_sock);

    let accel: &'static str = if kvm_accessible() { "kvm" } else { "tcg" };

    let mut cmd = Command::new(&bin);
    cmd.arg("-drive")
        .arg(format!("file={},if=virtio,format=qcow2", guest.disk_path.display()))
        .arg("-netdev")
        .arg("user,id=n0")
        .arg("-device")
        .arg("virtio-net-pci,netdev=n0")
        .arg("-qmp")
        .arg(format!("unix:{},server=on,wait=off", guest.qmp_sock.display()))
        .arg("-serial")
        .arg(format!("file:{}", guest.serial_log.display()))
        .arg("-display")
        .arg("none")
        .arg("-m")
        .arg("256")
        .arg("-accel")
        .arg(accel)
        // A guest self-poweroff ends the qemu-system-x86_64 PROCESS instead
        // of silently rebooting — makes exit observable via try_wait(),
        // same reap-on-exit discipline node_status already uses for bloch.
        .arg("-no-reboot");
    if let Some(k) = kernel_path {
        cmd.arg("-kernel").arg(k);
    }
    if let Some(i) = initrd_path {
        cmd.arg("-initrd").arg(i);
    }
    if let Some(a) = kernel_append {
        cmd.arg("-append").arg(a);
    }
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| format!("spawn {}: {e}", bin.display()))?;
    let pid = child.id();

    if let Some(stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                on_log(line);
            }
        });
    }

    guest.child = Some(child);
    Ok(StartOutcome { pid, accel })
}

/// `terem_qmp`: the ALLOWLISTED QMP passthrough — see the module doc's
/// table. Rejects any command not in [`QMP_ALLOWED_COMMANDS`] BEFORE
/// touching the socket, fail-closed. Requires a defined AND running guest.
pub fn qmp_call_impl(state: &TeremState, cmd: &str, args: Value) -> Result<Value, String> {
    if !qmp_command_allowed(cmd) {
        return Err(format!(
            "refusing QMP command '{cmd}': not on the Terem allowlist ({}). Raw QMP passthrough \
             is deliberately NOT offered — commands like human-monitor-command, drive_add, \
             blockdev-add, device_add/device_del, netdev_add, chardev-add, and migrate* could \
             attach host storage, hot-plug devices, or otherwise widen what the guest can reach; \
             see terem.rs's module doc for the full reasoning.",
            QMP_ALLOWED_COMMANDS.join(", ")
        ));
    }
    let guard = state.0.lock().unwrap();
    let guest = guard.as_ref().ok_or("no guest defined — call terem_create first")?;
    if guest.child.is_none() {
        return Err("guest is not running — call terem_start first".into());
    }
    qmp_send_recv(&guest.qmp_sock, cmd, args)
}

/// `terem_status`: `{ "defined": bool, "running": bool, "pid": Option<u32> }`.
/// Reaps the child (clears `guest.child`) if it exited on its own — same
/// "reap on read" discipline `node_status` already uses.
pub fn status_impl(state: &TeremState) -> Value {
    let mut guard = state.0.lock().unwrap();
    match guard.as_mut() {
        None => json!({ "defined": false, "running": false, "pid": null }),
        Some(guest) => {
            let running = match guest.child.as_mut() {
                Some(child) => match child.try_wait() {
                    Ok(Some(_)) => {
                        guest.child = None;
                        false
                    }
                    Ok(None) => true,
                    Err(_) => false,
                },
                None => false,
            };
            let pid = if running { guest.child.as_ref().map(Child::id) } else { None };
            json!({ "defined": true, "running": running, "pid": pid })
        }
    }
}

/// Best-effort graceful stop (QMP `system_powerdown`, poll for exit) with a
/// SIGTERM/SIGKILL fallback — mirrors `node_stop`'s kill+wait, extended
/// with a graceful attempt first. Does NOT touch `guest.disk_path`/
/// `qmp_sock`/`serial_log` — those are `terem_destroy`'s job. A no-op
/// (`Ok`) if the guest is already stopped, so `terem_destroy` can call this
/// unconditionally.
fn stop_running_guest(guest: &mut Guest) -> Result<(), String> {
    let Some(mut child) = guest.child.take() else {
        return Ok(());
    };
    // Best-effort: the guest may not have a QMP server ready yet, or may
    // already be mid-poweroff — either way we still fall through to the
    // kill fallback below, so a failure here is not fatal.
    let _ = qmp_send_recv(&guest.qmp_sock, "system_powerdown", Value::Null);

    let mut exited = false;
    for _ in 0..50 {
        // ~5s at 100ms, generous for TCG's slower boot/shutdown path.
        match child.try_wait() {
            Ok(Some(_)) => {
                exited = true;
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => break,
        }
    }
    if !exited {
        let _ = child.kill();
        let _ = child.wait();
    }
    Ok(())
}

/// `terem_stop`: stop the running guest process. Errors if no guest is
/// defined, or the defined guest isn't running. The guest's disk/QMP-sock/
/// serial-log paths are remembered (still `terem_start`-able again).
pub fn stop_impl(state: &TeremState) -> Result<(), String> {
    let mut guard = state.0.lock().unwrap();
    let guest = guard.as_mut().ok_or("no guest defined — call terem_create first")?;
    if guest.child.is_none() {
        return Err("guest is not running".into());
    }
    stop_running_guest(guest)
}

/// `terem_destroy`: stop (if running) then delete the guest's own qcow2
/// disk file — and ONLY that file, plus its own derived QMP-socket/
/// serial-log artifacts. This is the "destroy = delete a file Terem
/// created; the HOST DISK is NEVER touched" guarantee
/// (`01-architecture.md` §2.3) — no verb in this module ever holds, or
/// deletes, a raw host block-device path. Un-defines the guest (a
/// subsequent `terem_create` is required before `terem_start` again).
pub fn destroy_impl(state: &TeremState) -> Result<(), String> {
    let mut guard = state.0.lock().unwrap();
    let Some(mut guest) = guard.take() else {
        return Err("no guest defined — nothing to destroy".into());
    };
    stop_running_guest(&mut guest)?;
    if guest.disk_path.exists() {
        std::fs::remove_file(&guest.disk_path)
            .map_err(|e| format!("destroy: remove disk '{}': {e}", guest.disk_path.display()))?;
    }
    let _ = std::fs::remove_file(&guest.qmp_sock);
    let _ = std::fs::remove_file(&guest.serial_log);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────
// QMP wire protocol — a minimal, single-round-trip client over a unix
// socket. Connects, negotiates capabilities, sends ONE command, reads its
// reply, disconnects. QEMU's `-qmp unix:<sock>,server=on,wait=off` accepts
// sequential connections fine (this is not a persistent/multiplexed
// session) — good enough for v1's one-command-per-call shape.
// ─────────────────────────────────────────────────────────────────────────

#[cfg(unix)]
fn qmp_send_recv(sock_path: &Path, cmd: &str, args: Value) -> Result<Value, String> {
    use std::os::unix::net::UnixStream;

    let stream = UnixStream::connect(sock_path)
        .map_err(|e| format!("qmp connect {}: {e}", sock_path.display()))?;
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let mut writer =
        stream.try_clone().map_err(|e| format!("qmp: cannot clone socket handle: {e}"))?;
    let reader = BufReader::new(stream);
    let mut msgs = serde_json::Deserializer::from_reader(reader).into_iter::<Value>();

    // 1. Greeting: `{"QMP": {"version": …, "capabilities": […]}}`.
    let greeting = next_json(&mut msgs)?;
    if greeting.get("QMP").is_none() {
        return Err(format!("qmp: unexpected greeting: {greeting}"));
    }

    // 2. Enter command mode.
    write_json(&mut writer, &json!({ "execute": "qmp_capabilities" }))?;
    let cap_reply = next_response(&mut msgs)?;
    if cap_reply.get("error").is_some() {
        return Err(format!("qmp: capabilities negotiation failed: {cap_reply}"));
    }

    // 3. The actual (already allowlist-checked by the caller) command.
    let mut msg = json!({ "execute": cmd });
    if let Value::Object(map) = &args {
        if !map.is_empty() {
            msg["arguments"] = args;
        }
    }
    write_json(&mut writer, &msg)?;
    let reply = next_response(&mut msgs)?;
    if let Some(err) = reply.get("error") {
        return Err(format!("qmp {cmd} error: {err}"));
    }
    Ok(reply)
}

#[cfg(not(unix))]
fn qmp_send_recv(_sock_path: &Path, _cmd: &str, _args: Value) -> Result<Value, String> {
    // Terem v1 is unix-host-only (QMP rides a unix-domain socket per
    // POC-SCOPE.md §2.1/§2.6) — a Windows host is out of scope for this POC.
    Err("Terem's QMP control plane requires a unix-socket-capable host (macOS/Linux); \
         this POC does not support a Windows host"
        .into())
}

fn write_json<W: Write>(w: &mut W, v: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec(v).map_err(|e| format!("qmp: encode: {e}"))?;
    w.write_all(&bytes).map_err(|e| format!("qmp: write: {e}"))
}

/// Read the next complete JSON value off the stream (used once, for the
/// greeting, which has no `return`/`error` envelope to filter on).
fn next_json(
    msgs: &mut impl Iterator<Item = serde_json::Result<Value>>,
) -> Result<Value, String> {
    msgs.next()
        .ok_or_else(|| "qmp: connection closed unexpectedly".to_string())?
        .map_err(|e| format!("qmp: malformed message: {e}"))
}

/// Read JSON values off the stream until one carries a `return` or `error`
/// key (i.e. skip past any interleaved asynchronous QMP events, e.g. a
/// `SHUTDOWN` event racing a `system_powerdown` reply).
fn next_response(
    msgs: &mut impl Iterator<Item = serde_json::Result<Value>>,
) -> Result<Value, String> {
    loop {
        let v = next_json(msgs)?;
        if v.get("return").is_some() || v.get("error").is_some() {
            return Ok(v);
        }
        // else: an asynchronous QMP event — not a command reply, skip it.
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Tauri command wrappers — thin. All the actual logic lives in the
// `*_impl` functions above so `tests/*.rs` can call it directly. Registered
// in `main.rs`'s `tauri::generate_handler!`, `#[cfg(unix)]`-gated there
// (see this module's doc + `qmp_send_recv`'s `#[cfg(not(unix))]` stub).
// ─────────────────────────────────────────────────────────────────────────

use tauri::{AppHandle, Emitter, State};

#[tauri::command]
pub fn terem_create(
    state: State<TeremState>,
    qemu_img_binary: String,
    disk_path: String,
    size_mb: u64,
) -> Result<(), String> {
    create_impl(&state, &qemu_img_binary, &disk_path, size_mb)
}

#[tauri::command]
pub fn terem_start(
    app: AppHandle,
    state: State<TeremState>,
    qemu_binary: String,
    kernel_path: Option<String>,
    initrd_path: Option<String>,
    kernel_append: Option<String>,
) -> Result<u32, String> {
    let app_for_log = app.clone();
    let outcome = start_impl(
        &state,
        &qemu_binary,
        kernel_path.as_deref(),
        initrd_path.as_deref(),
        kernel_append.as_deref(),
        move |line| {
            let _ = app_for_log.emit("terem-log", line);
        },
    )?;
    let _ = app.emit(
        "terem-log",
        format!("▶ guest started (pid {}, accel {})", outcome.pid, outcome.accel),
    );
    Ok(outcome.pid)
}

#[tauri::command]
pub fn terem_qmp(state: State<TeremState>, cmd: String, args: Value) -> Result<Value, String> {
    qmp_call_impl(&state, &cmd, args)
}

#[tauri::command]
pub fn terem_status(state: State<TeremState>) -> Value {
    status_impl(&state)
}

#[tauri::command]
pub fn terem_stop(app: AppHandle, state: State<TeremState>) -> Result<(), String> {
    stop_impl(&state)?;
    let _ = app.emit("terem-log", "■ guest stopped".to_string());
    Ok(())
}

#[tauri::command]
pub fn terem_destroy(app: AppHandle, state: State<TeremState>) -> Result<(), String> {
    destroy_impl(&state)?;
    let _ = app.emit("terem-log", "🗑 guest destroyed (disk deleted; host disk untouched)".to_string());
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────
// Unit tests — host-testable, no QEMU/KVM needed (POC-SCOPE.md §3 step 1).
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "terem-test-{tag}-{}-{:?}",
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

    // ── resolve_qemu_binary / resolve_qemu_img_binary ──────────────────────
    // Parameterized copies of main.rs's resolve_node_binary test shape.

    #[test]
    fn resolve_rejects_empty() {
        assert!(resolve_qemu_binary("   ").is_err());
        assert!(resolve_qemu_img_binary("").is_err());
    }

    #[test]
    fn resolve_rejects_bare_wrong_name() {
        let err = resolve_qemu_binary("sh").unwrap_err();
        assert!(err.contains("bare command name"), "unexpected error: {err}");
        let err = resolve_qemu_img_binary("qemu-system-x86_64").unwrap_err();
        assert!(err.contains("bare command name"), "unexpected error: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn resolve_accepts_real_qemu_path() {
        let dir = scratch("qemu-ok");
        let bin = dir.join(QEMU_BIN_NAME);
        write_exec(&bin);
        let resolved = resolve_qemu_binary(bin.to_str().unwrap()).expect("should resolve");
        assert_eq!(resolved.file_name().and_then(|n| n.to_str()), Some(QEMU_BIN_NAME));

        let img = dir.join(QEMU_IMG_BIN_NAME);
        write_exec(&img);
        let resolved = resolve_qemu_img_binary(img.to_str().unwrap()).expect("should resolve");
        assert_eq!(resolved.file_name().and_then(|n| n.to_str()), Some(QEMU_IMG_BIN_NAME));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn resolve_rejects_wrong_file_name() {
        let dir = scratch("wrongname");
        let bin = dir.join("qemu-system-aarch64"); // a real QEMU binary, wrong arch/name
        write_exec(&bin);
        assert!(resolve_qemu_binary(bin.to_str().unwrap()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn resolve_rejects_non_executable() {
        let dir = scratch("noexec");
        let bin = dir.join(QEMU_BIN_NAME);
        std::fs::write(&bin, b"not executable").unwrap();
        let err = resolve_qemu_binary(bin.to_str().unwrap()).unwrap_err();
        assert!(err.contains("not executable"), "unexpected error: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_rejects_missing_path() {
        let missing = std::env::temp_dir().join("terem-does-not-exist").join(QEMU_BIN_NAME);
        assert!(resolve_qemu_binary(missing.to_str().unwrap()).is_err());
    }

    // ── QEMU option-injection guard (comma in disk_path) ────────────────────
    // REGRESSION: before validate_qemu_pathlike, a disk_path like
    // "/tmp/x,file.driver=host_device" flowed verbatim into
    // `-drive file=<disk_path>,if=virtio,format=qcow2` — the comma ends the
    // file= value and the remainder becomes EXTRA QEMU options. These tests
    // fail against that behavior and pass with the guard in place.

    #[test]
    fn qemu_pathlike_rejects_commas_and_accepts_plain_paths() {
        assert!(validate_qemu_pathlike("disk_path", "/tmp/guest.qcow2").is_ok());
        assert!(validate_qemu_pathlike("disk_path", "/tmp/with space/guest.qcow2").is_ok());
        for bad in [
            "/tmp/x,file.driver=host_device",
            "/tmp/x,if=none",
            ",leading",
            "trailing,",
        ] {
            let err = validate_qemu_pathlike("disk_path", bad).unwrap_err();
            assert!(err.contains("comma"), "unexpected error for {bad}: {err}");
        }
    }

    #[test]
    fn create_rejects_comma_disk_path_before_any_side_effect() {
        // The comma check runs before qemu-img resolution/spawn and before
        // any directory is created, so this needs NO qemu-img on PATH.
        let state = TeremState::new();
        let err = create_impl(
            &state,
            QEMU_IMG_BIN_NAME,
            "/tmp/terem-inject,file.driver=host_device.qcow2",
            64,
        )
        .unwrap_err();
        assert!(err.contains("comma"), "unexpected error: {err}");
        // Fail-closed: nothing was defined.
        assert_eq!(status_impl(&state)["defined"], json!(false));
    }

    #[test]
    fn start_rejects_comma_disk_path_before_building_qemu_args() {
        // Inject a Guest with a comma-bearing disk path directly (same-module
        // access to the private struct), proving start_impl re-checks the
        // exact string it would interpolate into `-drive file=…` — BEFORE
        // resolving/spawning QEMU, so no QEMU install is needed here.
        let state = TeremState(Mutex::new(Some(Guest {
            disk_path: PathBuf::from("/tmp/terem-inject,if=none,readonly=off.qcow2"),
            qmp_sock: PathBuf::from("/tmp/terem-inject.qmp.sock"),
            serial_log: PathBuf::from("/tmp/terem-inject.serial.log"),
            child: None,
        })));
        // (match instead of unwrap_err: StartOutcome deliberately has no Debug impl)
        let err = match start_impl(&state, QEMU_BIN_NAME, None, None, None, |_| {}) {
            Err(e) => e,
            Ok(_) => panic!("start_impl must reject a comma-bearing disk path"),
        };
        assert!(err.contains("comma"), "unexpected error: {err}");
    }

    // ── QMP allowlist ───────────────────────────────────────────────────────

    #[test]
    fn allowlist_accepts_exactly_the_documented_set() {
        for c in QMP_ALLOWED_COMMANDS {
            assert!(qmp_command_allowed(c), "{c} should be allowed");
        }
    }

    #[test]
    fn allowlist_rejects_dangerous_raw_qmp_verbs() {
        let dangerous = [
            "human-monitor-command",
            "drive_add",
            "blockdev-add",
            "device_add",
            "device_del",
            "netdev_add",
            "chardev-add",
            "migrate",
            "migrate-incoming",
            "quit",
            "inject-nmi",
            "pmemsave",
            "memsave",
            // case/substring tricks must not sneak past an exact match:
            "Query-Status",
            "query-status ",
            " query-status",
            "query-statusx",
            "xquery-status",
        ];
        for c in dangerous {
            assert!(!qmp_command_allowed(c), "{c} must be rejected");
        }
    }

    #[test]
    fn qmp_call_impl_rejects_disallowed_command_before_touching_state() {
        // No guest defined at all — if the allowlist check ran AFTER the
        // "no guest defined" check, this would fail with the wrong error.
        // It must fail-closed on the allowlist first.
        let state = TeremState::new();
        let err = qmp_call_impl(&state, "drive_add", json!({})).unwrap_err();
        assert!(err.contains("not on the Terem allowlist"), "unexpected error: {err}");
    }

    // ── terem_create / terem_destroy (qemu-img only, no KVM needed) ────────
    // Host-testable per POC-SCOPE.md §3 step 2 wherever `qemu-img` is on
    // PATH (true in this box: `brew install qemu`). Skips gracefully if not.

    #[test]
    fn create_then_destroy_roundtrip() {
        if which_on_path(QEMU_IMG_BIN_NAME).is_none() {
            eprintln!("skip: {QEMU_IMG_BIN_NAME} not on PATH");
            return;
        }
        let dir = scratch("create-destroy");
        let disk = dir.join("guest.qcow2");
        let state = TeremState::new();

        create_impl(&state, QEMU_IMG_BIN_NAME, disk.to_str().unwrap(), 64).expect("create");
        assert!(disk.is_file(), "qcow2 file should exist after terem_create");

        // A second create without destroying first must be refused (v1 —
        // exactly one guest at a time).
        let err =
            create_impl(&state, QEMU_IMG_BIN_NAME, disk.to_str().unwrap(), 64).unwrap_err();
        assert!(err.contains("already defined"), "unexpected error: {err}");

        destroy_impl(&state).expect("destroy");
        assert!(!disk.exists(), "qcow2 file should be gone after terem_destroy");

        // destroy again with nothing defined is an error, not a silent no-op.
        assert!(destroy_impl(&state).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_refuses_to_overwrite_existing_file() {
        if which_on_path(QEMU_IMG_BIN_NAME).is_none() {
            eprintln!("skip: {QEMU_IMG_BIN_NAME} not on PATH");
            return;
        }
        let dir = scratch("no-overwrite");
        let disk = dir.join("already-here.qcow2");
        std::fs::write(&disk, b"not a real qcow2, just occupying the path").unwrap();
        let state = TeremState::new();
        let err =
            create_impl(&state, QEMU_IMG_BIN_NAME, disk.to_str().unwrap(), 64).unwrap_err();
        assert!(err.contains("overwrite"), "unexpected error: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── status / stop / destroy on an undefined or non-running guest ───────

    #[test]
    fn status_on_undefined_guest_is_honest() {
        let state = TeremState::new();
        let v = status_impl(&state);
        assert_eq!(v["defined"], json!(false));
        assert_eq!(v["running"], json!(false));
        assert_eq!(v["pid"], json!(null));
    }

    #[test]
    fn stop_without_a_defined_guest_errors() {
        let state = TeremState::new();
        assert!(stop_impl(&state).is_err());
    }
}
