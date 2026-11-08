<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- Copyright (c) Postern Labs and Postern community contributors -->

# Terem v2 — minimal buildable v1 (POC scope)

**Status: DESIGN CONCEPT ONLY. Nothing in this document is built, deployed,
or audited.** Scopes the smallest slice of `01-architecture.md` /
`02-security-consent-privacy.md` / `03-license-honesty.md` that is (a)
honestly describable as "shipped a real thing" and (b) buildable and
testable **without** requiring a dedicated Linux/KVM box for most of the
work. Same discipline as every doc in this tree: `written ≠ built`,
`built ≠ booted`, `designed ≠ audited`. This document does not re-litigate
any architectural decision already made in `01`–`03`/`A`/`B` — it picks one
thin vertical slice of that design and states exactly what a first
prototype does and does not do.

> **Update (2026-07-16) — "nothing built" is now imprecise; here is the exact
> state.** The first slice of this POC now exists in-tree and is committed:
> `desktop/src-tauri/src/terem.rs` (the Tauri backend / QMP spawn path) and the
> `apps/terem-gate` crate (the consent spine) **compile and pass their unit
> tests (terem-gate 32/32 + terem.rs 16) — but only under QEMU/TCG on the macOS
> workstation, never under Linux/KVM and never on hardware.**
> `os/terem-compat.nix` (the OS module) exists and is committed but is a Nix
> module not evaluated on this non-Nix host. The
> headless-Linux-guest boot this document scopes as v1 is **not yet built** —
> everything beyond the files above remains **unbuilt, unbooted, and
> unaudited** — `written ≠ built`, `built ≠ booted`, `TCG ≠ KVM ≠ hardware`.

---

## 1 · Which path first, and why

**Recommendation: Path A (Guest Mode), narrowed to the single smallest
useful slice — one headless Linux guest, BIOS (no UEFI/OVMF, no swtpm),
booted via QEMU/KVM driven directly over QMP from the Tauri shell. No Wine/
App Mode in v1.**

### 1.1 Why Guest Mode over Wine, for the *first* prototype specifically

`01` §4's decision matrix correctly recommends App Mode (Wine) first for
the *end-user* "run one Windows program" need — that guidance is unchanged
and still correct for the shipped product's UX. This document asks a
different question: **which path should a first internal prototype build,
to retire the most risk per unit of engineering effort?** Answered against
that question, Wine loses for three reasons specific to prototyping, not to
the product:

1. **Wine's core mechanism is not novel to this repo.** `wine app.exe` is
   an external-process spawn with a stdout/stderr pipe and a kill-switch —
   structurally identical to `node_start`/`node_stop` in
   `desktop/src-tauri/src/main.rs`, already built and tested. A Wine
   prototype would mostly re-derive code this repo already has; it retires
   near-zero architectural risk.
2. **Wine's hardest open question is explicitly unresolved and not this
   prototype's job to resolve.** `02` §9.1 (Architect 2's own "largest
   unresolved item") is the App Mode sandbox-wrapper default
   (Bubblewrap/Flatpak/firejail, mandatory-or-optional). Building App Mode
   first means either shipping an honestly unsandboxed prototype (the
   single fact `02` §2.2 says is "most likely to get flattened into
   marketing copy that would be false") or blocking the prototype on a
   security-architecture decision that is out of scope here.
3. **QEMU/QMP-over-no-libvirt is this whole document family's single most
   consequential, least-validated decision.** `01`'s merge note calls the
   libvirt→QMP correction "the single most consequential fix either
   architect made," and `01` §7 item 7 / `A-virtualization.md` §8 item 1
   both flag "drive QEMU directly over QMP, no libvirt" as a **provisional**
   choice needing a real license-counsel pass *and* real engineering
   validation that the no-libvirt control plane actually works end to end.
   Nothing has tested that claim. A prototype's job is to retire exactly
   this kind of unvalidated, load-bearing assumption first.

### 1.2 Why *this* guest, this narrow — a headless Linux guest, no UEFI, no TPM

Windows is excluded from v1 entirely: it drags in OVMF (UEFI), `swtpm`
(vTPM 2.0), `virtio-win` driver injection, and an activation-flow honesty
story (`03` §1.2) — none of which validate the QMP control plane, they only
add integration surface. A Linux guest (a small distro or, for the fastest
possible boot-verification loop, a custom-built kernel+initramfs that
prints a marker string and powers off) needs **legacy BIOS (SeaBIOS, QEMU's
own default), virtio-blk, virtio-net (user-mode NAT), and a serial console**
— nothing else. This is the smallest guest shape that still exercises the
real lifecycle (`create` → `start` → `query-status` over QMP → `destroy`)
end to end.

**No display pipeline in v1.** `01` §2.6 specifies wayvnc/FreeRDP as the
long-term display path (SPICE is licensing-excluded, §2.1). Building that
pipeline validates nothing about the QMP control plane and is deferred
whole. v1's "did it boot" signal is a **serial-console log file**
(`-serial file:<path>` or `-nographic -serial mon:stdio`), grepped for a
known boot marker — scriptable, deterministic, CI-friendly, requires no
display server at all. A human wanting to *see* the guest can pass
`-display gtk` as a manual, undocumented, non-product debug flag; it is not
part of the v1 command surface.

### 1.3 What v1 explicitly does NOT build (deferred, not forgotten)

| Deferred item | Why it's safe to defer for v1 |
|---|---|
| Every bridge crossing (`02` §3 — clipboard, sharedFolder, audio, usbDevice, bridged-lan) | v1 opens **zero** bridges. Default-closed is achieved by *not writing the code*, not by a consent gate that must be built and trusted. The `terem-gate` schema/consent-record work (`02` §3.2, `apps/noporis-bridge-glue`-style) has nothing to gate yet. |
| `widen.gpuPassthrough` (VFIO) | Advanced, hardware-gated, never-default per `01` §2.5/§2.7. Zero relevance to a headless BIOS Linux guest. |
| Windows guest (OVMF, `swtpm`, `virtio-win`, activation) | §1.2 above. |
| Wine / App Mode | §1.1 above — a real v1.1 candidate, not this prototype. |
| `os/terem-compat.nix` formal module (`01` §2.7, `[ARCHITECT-1 STUB]`) | The prototype runs against an ad hoc dev harness (a Linux box with `qemu`/`qemu-img` on `PATH`, user in the `kvm` group) — §4.5. Writing the real Nix module is worth doing only once the Tauri↔QMP control plane is proven; doing it first would be process ahead of evidence. |
| `terem-gate`'s license/consent integration with `enterprise/licensing` (`03` §3) | Out of scope — this is an internal engineering prototype, not a gated product surface. |
| Snapshot/restore (`terem_snapshot`/`terem_restore`) | Real, mature QEMU functionality (`A-virtualization.md` §1.2/§6) but adds nothing to the core risk this prototype retires. First v1.1 addition after the base lifecycle is proven. |
| Multi-guest (`Mutex<HashMap<GuestId, Child>>`) | v1 manages **exactly one guest at a time** (`Mutex<Option<GuestHandle>>`, literally `NodeProc`'s own shape). Generalizing to N guests is a mechanical follow-up once one guest's lifecycle is proven, not a v1 concern. |
| `terem_install_start` (answer-file-driven unattended install) | v1's "install" step is booting a pre-built disk image (or the marker-printing test kernel) directly — no vendor installer flow is exercised. Real OS install (Ubuntu `autoinstall`, Debian preseed) is the next slice after lifecycle is proven. |

---

## 2 · Component list

### 2.1 New Rust module — `desktop/src-tauri/src/terem.rs`

Registered in `main.rs`'s `invoke_handler!` exactly like `pairing.rs` is
today (`mod terem;` + the new commands appended to the
`tauri::generate_handler!` list). No changes to `capabilities/default.json`
needed — per that file's own documented rationale, `#[tauri::command]`s are
application commands, not ACL-gated plugin permissions, the same reasoning
already covers `node_start`/`vault_*`/`pairing::*`.

```rust
// Binary resolution — literal copy of resolve_node_binary's shape (name +
// location + canonicalize + exec-bit), applied to two binaries instead of one.
fn resolve_qemu_binary(binary: &str) -> Result<PathBuf, String>      // pins "qemu-system-x86_64"
fn resolve_qemu_img_binary(binary: &str) -> Result<PathBuf, String>  // pins "qemu-img"

// v1 state: ONE guest at a time — literally NodeProc's own shape, renamed.
struct TeremState(Mutex<Option<GuestHandle>>);
struct GuestHandle {
    child: Child,           // the qemu-system-x86_64 process
    qmp_sock: PathBuf,       // unix socket path passed at spawn
    disk_path: PathBuf,      // the qcow2 file this guest owns
    serial_log: PathBuf,     // -serial file:<path> target, for boot verification
}

// v1 Tauri command surface — a strict subset of 01 §2.6's full proposal:
terem_create(disk_path: String, size_mb: u64) -> Result<(), String>
    // spawns `qemu-img create -f qcow2 <disk_path> <size_mb>M`

terem_start(disk_path: String, boot_image: String) -> Result<u32, String>
    // spawns qemu-system-x86_64: -drive file=<disk_path>,if=virtio
    //   -netdev user,id=n0 -device virtio-net,netdev=n0  (NAT, default-on
    //   per 02 §3's one stated default-open exception)
    //   -qmp unix:<sock>,server,nowait
    //   -nographic -serial file:<serial_log>
    //   -accel kvm  IF /dev/kvm is accessible, else -accel tcg (logged to
    //   the UI via the existing app.emit("node-log", ...) pattern, renamed
    //   "terem-log" — the same honest capability-detection main.rs already
    //   does for the integrity pin (verify_node_integrity's "tell the UI
    //   what was and wasn't checked" discipline, reused here for "was and
    //   wasn't accelerated")
    // returns the child PID, same shape as node_start

terem_qmp(cmd: String, args: Value) -> Result<Value, String>
    // raw QMP passthrough over the unix socket — mirrors rpc(url, method,
    // params)'s JSON shape exactly, just over a unix socket instead of HTTP.
    // v1 only NEEDS query-status and system_powerdown; the passthrough is
    // general so nothing else has to be hand-coded per-command.

terem_status() -> Value   // { "running": bool, "pid": Option<u32> } — mirrors node_status

terem_stop() -> Result<(), String>
    // QMP system_powerdown (graceful) with a SIGTERM/SIGKILL fallback —
    // mirrors node_stop's kill+wait, doesn't delete the disk (mirrors
    // A-virtualization.md §1.2: DESTROY is a separate, explicit verb)

terem_destroy() -> Result<(), String>
    // terem_stop, then delete the qcow2 file — the one verb that removes
    // guest state, kept separate from terem_stop per 01 §2.6's own note
```

### 2.2 Test assets — `desktop/src-tauri/tests/terem_fixtures/` (new)

A tiny, deterministic, network-free "guest" for the integration test, so
the whole lifecycle is verifiable without downloading or installing a real
OS: a minimal Linux kernel + initramfs whose init prints one marker line
(`TEREM-POC-BOOT-OK`) to the serial console and calls `poweroff -f`. This
is the standard "QEMU CI smoke test" shape (busybox-static `init` as PID 1)
— buildable with `linux` + `busybox` (both already permissively-licensed-
external per `01` §2.1's own GPL-kernel exception; busybox is GPL-2.0 but,
same as the kernel, ships as a **prebuilt boot artifact fixture**, never
linked into a Postern binary). If building this from scratch is more than
the prototype budget allows, substitute a small existing cloud image
(Alpine's `netboot` initramfs, or a minimal Debian cloud image) — the test
only needs *some* deterministic boot-to-marker signal, not a specific
distro.

### 2.3 Dev harness (not a Nix module) — a plain README/script

`docs/os-portal-v2/POC-SCOPE.md` (this document) plus a short
`scripts/terem-poc-setup.sh` (not yet written) that, on a real Linux box:
installs `qemu` + `qemu-img` from the distro's package manager, adds the
running user to the `kvm` group, and checks `/dev/kvm` is accessible —
replacing, for now, what `os/terem-compat.nix` will eventually do
declaratively. This is a deliberate, disclosed simplification (§1.3's
table): the throwaway ad hoc setup validates the *engineering*, the Nix
module formalizes the *product*, and doing the second before the first is
proven would be process ahead of evidence, the same critique `A-
virtualization.md` §8 levels at unresolved architecture forks in general.

---

## 3 · Concrete prototype plan

1. **`resolve_qemu_binary`/`resolve_qemu_img_binary` + unit tests**
   (host-testable, no box needed) — literally copy
   `main.rs`'s `resolve_node_binary` test shape (`resolve_rejects_empty`,
   `resolve_rejects_bare_non_node_name`, `resolve_accepts_real_node_path`,
   `resolve_rejects_wrong_file_name`, `resolve_rejects_non_executable`,
   `resolve_rejects_missing_path`), parameterized over the two new binary
   names. Zero new risk — this is pattern reuse, not new design.
2. **`terem_create` + a unit/integration test that only needs `qemu-img`
   on `PATH`** (host-testable on any machine with QEMU's userspace tools
   installed, including the current macOS dev workstation via Homebrew —
   `qemu-img` needs no KVM, no hardware virtualization at all). Assert the
   qcow2 file exists afterward and `terem_destroy` removes it.
3. **Build or fetch the marker-boot fixture** (§2.2). Verify manually,
   once, on any machine with `qemu-system-x86_64` installed (still no KVM
   required — `-accel tcg` boots a kernel this small in low single-digit
   seconds even under pure software emulation) that it prints the marker
   and powers off cleanly. This step is the first one that needs the real
   `qemu-system-x86_64` binary but explicitly **not** a KVM-capable box.
4. **`terem_start` + `terem_qmp` + `terem_status`**, tested against the
   fixture with `-accel tcg` (host-testable, no KVM) — this validates the
   actual novel claim (§1.1.3): a QMP unix-socket control plane, driven
   directly by the Tauri backend, with no libvirt anywhere in the process
   tree. Assert: `terem_start` returns a PID, `terem_qmp("query-status",
   {})` returns a well-formed QMP response while running, the serial log
   contains the marker line after the guest self-powers-off, and
   `terem_status` correctly reflects the process having exited (mirrors
   `node_status`'s reap-on-`try_wait` logic).
5. **`terem_stop`/`terem_destroy` correctness**: start, `terem_stop` mid-
   boot (before the marker prints), assert the process is gone and the
   qcow2 file still exists; separately, `terem_destroy` and assert the file
   is gone. Host-testable, no KVM.
6. **The one KVM-gated step**: repeat step 4 with `-accel kvm` on a real
   Linux machine with `/dev/kvm` accessible (a bare-metal Linux box, or a
   cloud VM instance with nested virtualization enabled — a "box" in the
   sense this task means it, not necessarily physical hardware). This step
   proves nothing architecturally new over step 4 — QMP behaves identically
   under TCG or KVM — it only proves the `-accel kvm` capability-detection
   path (§2.1's `terem_start` logging) correctly engages hardware
   acceleration when available. Budget it as a short verification pass,
   not the bulk of the prototype's effort.
7. **Only after 1–6 pass**: consider a v1.1 slice — either the real-OS
   unattended-install path (Ubuntu `autoinstall` into this same lifecycle)
   or generalizing `Option<GuestHandle>` to the `HashMap<GuestId, Child>`
   multi-guest shape `01` §2.6 ultimately wants. Neither is in this
   document's v1.

---

## 4 · Host-testable vs. KVM-gated — the honest split

| Component | Testable on the current (macOS, no KVM) dev machine? | Testable on any Linux box (no KVM, TCG only)? | Needs real KVM (`/dev/kvm`)? |
|---|---|---|---|
| `resolve_qemu_binary`/`resolve_qemu_img_binary` + unit tests | **Yes** — pure Rust, fake binaries | Yes | No |
| `terem_create` (`qemu-img create`) | **Yes**, if `qemu-img` is installed (Homebrew) | Yes | No |
| Marker-boot fixture build/verify | Yes, if `qemu-system-x86_64` is installed (Homebrew) — slow (TCG) but functional | Yes, faster than macOS TCG in practice | No |
| `terem_start`/`terem_qmp`/`terem_status` core lifecycle (the actual novel QMP-no-libvirt claim, §1.1.3) | **Yes**, under `-accel tcg` | Yes | **No** — this is the headline result: the riskiest part of the whole design needs no box at all to validate |
| `terem_stop`/`terem_destroy` | Yes | Yes | No |
| `-accel kvm` capability-detection + actually-accelerated boot | No (no `/dev/kvm` on macOS) | No | **Yes** — needs a Linux host/VM with hardware virtualization exposed |
| A real distro's unattended install (Ubuntu `autoinstall`, deferred to v1.1) | No (impractically slow under TCG) | Marginal — very slow without KVM | **Yes, practically required** — this is where KVM-gating actually starts to matter |
| `wayvnc`/FreeRDP display pipeline (deferred whole) | N/A — not built in v1 | N/A | N/A |
| `os/terem-compat.nix` formal module (deferred, §1.3) | No — not Nix-evaluable on this workstation (same limit `sloboda-vm.nix`'s own header states) | Yes, on a Nix + Linux host | Only to actually *boot* the resulting NixOS config |

**The headline finding this table is built to surface:** the single most
architecturally consequential thing to prove — that a hand-rolled QMP
control plane can replace libvirt for guest lifecycle management — is
**fully host-testable without KVM at all**. KVM-gating only becomes real
once the goal shifts from "does the control plane work" to "is a real OS
install fast enough to be usable," which this document deliberately places
in v1.1, not v1.

---

## 5 · Honesty ledger

| Claim in this document | Status |
|---|---|
| QEMU/QMP-over-no-libvirt is the single highest-risk, least-validated architectural decision in the `01`–`03`/`A`/`B` document family | **Grounded directly in those documents' own language** (`01`'s merge note, `01` §7 item 7, `A-virtualization.md` §8 item 1) — this document's own synthesis of *why that makes it the right thing to prototype first*, not a new claim about the architecture itself |
| A headless, BIOS-only, marker-printing Linux guest is sufficient to validate that decision | **This document's own scoping judgment** — deliberately excludes UEFI/TPM/display/install-flow complexity that a Windows guest or a real distro install would add, on the argument that none of it touches the QMP control-plane question |
| The QMP lifecycle core (`terem_start`/`terem_qmp`/`terem_status`/`terem_stop`/`terem_destroy`) is testable without KVM, under `-accel tcg` | **A real, checkable property of QEMU** (TCG software emulation is a standard, always-available QEMU accelerator) — not yet verified in this repo, since no code exists yet |
| `resolve_qemu_binary`/`resolve_qemu_img_binary` can directly reuse `resolve_node_binary`'s tested shape | **Grounded in real, existing, tested code** (`desktop/src-tauri/src/main.rs`) |
| Deferring every bridge/consent-gate mechanism is safe because v1 builds no crossings | **A real, checkable architectural property** — `02` §2.1's "cannot reach" table already states every guest↔host channel requires an explicit device/tag that must be *wired up*; v1 wires up none of them |
| The marker-boot fixture approach | **A standard, widely-used QEMU CI pattern** (busybox-init smoke test), not invented for this document — restated here, not fabricated |
| Everything in §3's step-by-step plan | **Unbuilt.** No line of `terem.rs` exists yet. This is a plan, not a report. |

*Design and scaffold only. UNAUDITED. Do not treat any command surface,
test plan, or table in this document as a security control or a completed
build. `written ≠ built`, `built ≠ booted`, `designed ≠ audited`. Product
name "Terem" is proposed only, pending trademark clearance. Never "Postern
Windows," "Postern Ubuntu," or "Postern RedHat." BLCH is worthless and is
not a security. Not legal advice.*
