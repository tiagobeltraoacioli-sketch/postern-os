<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- Copyright (c) Postern Labs and Postern community contributors -->

# OS Portal v2 — Virtualization / guest-runtime + Wine-Proton feasibility (Architect A contribution)

**Status: DESIGN CONCEPT ONLY. Nothing in this document is built, deployed, or
audited.** Architect A's pass, for folding into `docs/os-portal-v2/01-architecture.md`
(the lead architect owns the merge). Scope, per the brief: the virtualization /
guest-runtime engineering and Wine/Proton feasibility for the pivoted product —
**"run another OS in a sandbox on the Postern desktop"** ("Sloboda for desktop":
Windows/Ubuntu/RHEL in a container/VM) plus **Wine/Proton for individual Windows
apps with no container**. This *replaces* the bare-metal-install-via-AI-agent
concept in `docs/os-portal/01-architecture.md` (that document is prior art on the
consent/license/attestation spine, reused below where it fits — it is not this
product anymore). `written ≠ built`, `built ≠ booted`, `designed ≠ audited`.

> **Update (2026-07-16) — "nothing built" is now imprecise; here is the exact
> state.** The first Terem code exists in-tree and is committed:
> `desktop/src-tauri/src/terem.rs` (the Tauri backend / QMP spawn path — the
> guest-runtime seam this document designs) and the `apps/terem-gate` crate
> (the consent spine) **compile and pass their unit tests (terem-gate 32/32 +
> terem.rs 16) — but only under QEMU/TCG on the macOS workstation, never under
> Linux/KVM and never on hardware.** `os/terem-compat.nix` (the OS module)
> exists and is committed but is a Nix module not evaluated on this non-Nix
> host. A real Wine/Proton or guest-OS boot is
> unbuilt. Everything else this document designs remains **unbuilt, unbooted,
> and unaudited** — `written ≠ built`, `built ≠ booted`, `TCG ≠ KVM ≠ hardware`.

---

## 0 · The one constraint that shapes everything below — read first

Before any technical design: this repo has a **standing, repo-wide, load-bearing
licensing rule**, stated in `BLOCH-SIS-LINUX.md` §2.4 and restated in
`docs/specs/POSTERN-CLOUD.md` §8 and `docs/POSTERN-APPS-ROADMAP.md`:

> **permissive-only — no AGPL/GPL/LGPL in the shipped stack.** MPL only as
> unmodified aggregation. AGPL/GPL/LGPL = **no fork, no embed, no link.**

And the repo already has an established, working **exception shape** for exactly
this situation, in `docs/specs/POSTERN-TELEPHONY.md`: ModemManager, oFono, mmsd-tng,
callaudiod are **all GPL daemons**, and Postern OS ships and depends on them —
legally, because they are consumed **only as external system services over
D-Bus**, never forked, embedded, or linked. The telephony doc states the test
explicitly: *"syscalls into the GPL Linux kernel... is neither forking nor
embedding GPL code, so it passes the repo rule."* The same reasoning is applied
in `os/cloud.nix`/`POSTERN-CLOUD.md` §8 to the Linux kernel itself ("the in-kernel
module ships with Linux and is not a distributed component of ours").

**Applying that exact test to every technology this document needs:**

| Component | License | Consumed how | Passes the rule? |
|---|---|---|---|
| **KVM** (kernel module) | GPL-2.0 | In-kernel, `/dev/kvm` ioctl interface | **Yes** — same "ships with Linux, not our distributed component" exception as `POSTERN-CLOUD.md` §8 already grants the kernel. |
| **QEMU** (userspace VMM) | GPL-2.0 | External system binary, driven over its **QMP** JSON socket + CLI flags — never forked/linked into a Postern binary | **Same shape as ModemManager** (external GPL daemon, D-Bus/socket boundary only) — plausibly passes, but this is a **new application of the exception this repo has not made before for a userspace program we'd bundle by default**, not just talk to over D-Bus that's already on the system. Flagged for a real license-counsel pass, not assumed. |
| **libvirt** | LGPL-2.1 | A client library you'd normally **link** | **No** — the rule explicitly excludes LGPL, and libvirt's normal integration path (`libvirt-go`/`libvirt-rs`/`libvirtd` RPC client libs) is exactly the kind of dependency the rule targets. **Recommend: skip libvirt entirely**, drive QEMU directly over QMP (a plain JSON-over-Unix-socket protocol — talking to it is not linking anything). |
| **virt-manager** | GPL-2.0 | Reference only, not shipped (Postern builds its own Tauri UI) | N/A — not a dependency at all, just the thing whose UX pattern is worth studying. |
| **Cloud Hypervisor** (rust-vmm) | Apache-2.0 | Could be **linked/embedded** cleanly | **Yes, cleanly** — this is the genuinely permissive alternative VMM and is already the right neighbor for this repo's SEV-SNP/TDX interest (`os/cloud.nix`), since Cloud Hypervisor has first-class SNP/TDX guest support. |
| **crosvm** (rust-vmm, Google/ChromeOS) | BSD-3-Clause / Apache-2.0 | Could be linked/embedded | **Yes, cleanly** — the other permissive rust-vmm option; less mature for desktop use cases than Cloud Hypervisor, more proven for Linux-guest containers (Crostini heritage). |
| **Firecracker** (rust-vmm, AWS) | Apache-2.0 | N/A here | Permissive, but **microVM-only, no GPU/graphics path** — wrong tool for a desktop guest with a display; noted for completeness, not proposed. |
| **Wine** | LGPL-2.1 | Normally an external **process** (`wine app.exe`), not linked into anything | **Same shape as QEMU-over-QMP** — external unforked binary, invoked as a subprocess. Passes by the same reasoning as the GPL telephony daemons *if* Postern only ever `exec`s the `wine`/`wine64` binary and reads its exit status/output, never links `libwine`. |
| **Proton** (Valve's Wine fork) | LGPL-2.1 + bundled components (DXVK: zlib, vkd3d-proton: LGPL-2.1, FAudio: zlib, wine-mono/wine-gecko: MIT/LGPL mix) | Same — external process | Same reasoning as Wine, **but Proton is Valve's build, distributed for Steam's runtime** — using it outside Steam's own distribution channel needs a real look at what's actually redistributable standalone vs what assumes the Steam client is present. **Flag, don't resolve here.** |
| **Distrobox** | GPL-3.0 | A shell-script wrapper you'd normally vendor/ship | **No, if shipped as-is.** Same "no fork, no embed" wall. |
| **Podman** | Apache-2.0 | Linked/embedded or invoked | **Yes, cleanly.** |
| **systemd-nspawn** | Ships with systemd (LGPL-2.1+ core, some GPL-2.0+ units) | Already the base init system on every NixOS host in this repo | **Same "already-present base OS component, not a new product embed" reasoning as the kernel** — invoking `systemd-nspawn` as a subprocess adds no new dependency beyond what NixOS already requires to boot. Cleaner than adding Distrobox. |

**The concrete recommendation this drives** (stated once here, assumed for the
rest of the document): **skip libvirt and Distrobox entirely.** Drive QEMU
directly over QMP (or, cleaner still, standardize on **Cloud Hypervisor**
where its feature set suffices — it already matters to this repo for
SNP/TDX). For the "toolbox on the host" Linux-app case, build directly on
**Podman** (Apache-2.0) + **systemd-nspawn** (already-present), skipping the
Distrobox wrapper script. This is not a resolved legal opinion — it is the
same honest, cite-the-rule, apply-the-existing-exception exercise this repo
already does for telephony and Postern Cloud, and it should get an explicit
license-counsel/`deny.toml`-style pass before anything ships, exactly like
every other per-component license call in `docs/POSTERN-APPS-ROADMAP.md`.

---

## 1 · Full guest OS — architecture

### 1.1 The two VMM choices, stated honestly

There are two real paths, not one, and they trade off maturity against license
cleanliness:

**(a) QEMU/KVM, driven directly over QMP (no libvirt).** The mature, battle-tested,
does-everything option. `qemu-system-x86_64 -qmp unix:/run/postern/vm/<id>.sock,server,nowait`
gives a JSON-RPC control channel: `query-status`, `system_powerdown`,
`human-monitor-command` for live snapshots, `blockdev-snapshot` for disk
snapshots, `device_add`/`device_del` for hot-plug. This is a **large** feature
surface (virtio-blk/scsi/net/gpu/9p/vsock, TPM emulation via swtpm for
Windows 11's TPM 2.0 requirement, OVMF/UEFI firmware, SPICE or plain VNC
display) and is what every mainstream desktop virtualization product (GNOME
Boxes, virt-manager, Proxmox) actually runs underneath. The license posture is
the open item in §0 — real, not hand-waved.

**(b) Cloud Hypervisor (rust-vmm, Apache-2.0), where its feature set suffices.**
Cleaner license story, Rust-native (fits this repo's own Rust-first posture —
`crates/postern-*`), and already relevant here because it has first-class
AMD SEV-SNP / Intel TDX guest support that this repo already cares about for
Chiostro (`os/cloud.nix`). **The honest gap:** Cloud Hypervisor's guest-graphics
story is far less mature than QEMU's — no SPICE, virtio-gpu support is newer
and narrower, and Windows guest support (needed here, unlike Chiostro's
Linux-only cloud guests) is less proven than QEMU/KVM's. This is the right
fit for a **headless Linux server-shaped guest**; it is a genuinely **open
question, not a settled answer**, whether it is good enough for a graphical
Windows 11 desktop guest today. Recommend prototyping both, deciding on
evidence, not preference.

Given the brief needs Windows/Ubuntu/RHEL **desktop** guests with a display,
**QEMU/KVM-over-QMP is the pragmatic default for v1**, with the §0 license
question resolved (or accepted-with-eyes-open, same posture as the telephony
GPL daemons) before it ships; Cloud Hypervisor is the thing to keep evaluating
for the headless/Linux-service-shaped guest case and for anything that wants
to reuse the SNP/TDX machinery `postern-seal-companion` already has vector-tested.

### 1.2 Lifecycle: create / run / snapshot / destroy

Mirrors the shape `desktop/src-tauri/src/main.rs` already uses for the `bloch`
node process (`node_start`/`node_stop`/`node_status`, one child `Mutex<Option<Child>>`,
log streaming over `app.emit`) — this product needs the same pattern generalized
to N guests instead of one node:

```
CREATE   → allocate a qcow2 disk image (qemu-img create -f qcow2 <path> <size>),
           write a per-guest config (CPU/RAM/disk/net topology, virtio device
           list, OVMF vars file copy for UEFI/Secure-Boot-capable guests),
           NEVER touches a raw host block device directly for this product
           shape (unlike the old bare-metal-install portal's `partition`/`format`
           verbs — a VM disk image is just a file on the host filesystem, which
           is why this pivot is materially SAFER than the old design: no
           raw-disk consent-gate class is needed here at all).
RUN      → spawn `qemu-system-x86_64` (same "resolve + pin the binary name,
           spawn as a plain Command, never a shell" discipline as
           `resolve_node_binary`/`node_start` in main.rs) with a QMP socket;
           the Tauri backend holds the QMP connection, not the shell.
SNAPSHOT → `qemu-img snapshot` (offline) or QMP `blockdev-snapshot-sync`
           (live) — genuinely mature, well-worn QEMU functionality; qcow2's
           copy-on-write internal snapshots are a strength here.
DESTROY  → QMP `quit` (graceful) or SIGTERM/SIGKILL the child (kill-switch
           parity with `node_stop`); the disk image is NOT deleted on destroy
           by default (mirrors Sloboda's kill-switch: "leaves the provisioned
           image intact and re-startable") — a separate, explicit "delete
           guest" verb removes the qcow2 file.
```

### 1.3 Disk image handling

**qcow2** is the right default: copy-on-write, thin-provisioned, supports
internal snapshots, supports backing files (a golden "clean Windows 11" base
image + per-session copy-on-write overlay is a strong pattern for "throwaway
sandbox" use cases — create a guest, use it, discard the overlay, base image
never mutates). Alternative: **raw** for maximum I/O performance when snapshots
aren't needed (no CoW overhead) — offer both, default qcow2.

### 1.4 virtio

Every guest should use the virtio device family (virtio-blk or virtio-scsi
for disk, virtio-net for NIC, virtio-gpu for graphics, virtio-rng for entropy,
virtio-balloon for memory ballooning, virtio-vsock for host↔guest control-plane
messaging without a network stack) rather than emulated legacy hardware
(IDE/e1000/etc.) wherever the guest OS supports it:

- **Ubuntu/RHEL guests**: virtio drivers are in-kernel/in-box. No extra work.
- **Windows guests**: need the **virtio-win** driver ISO (Red Hat-maintained,
  redistributed under a mix of licenses — check `deny.toml`-style per-driver
  before bundling) mounted as a second CD-ROM during install, or injected via
  the answer file's driver-injection mechanism (the old portal doc's §3.1
  `driver-install` verb design is directly reusable here). Skipping virtio in
  favor of emulated IDE/e1000 works but is meaningfully slower (§4).

### 1.5 The Tauri shell as management UI

Directly generalizes the existing pattern: `desktop/src-tauri/src/main.rs`
today exposes `node_start`/`node_stop`/`node_status` plus `rpc`/`rpc_tor` for
the node's JSON-RPC. The guest-runtime module would add a parallel command set
— `guest_create`, `guest_start`, `guest_stop`, `guest_snapshot`, `guest_destroy`,
`guest_status`, `guest_list`, and a `guest_qmp(id, command, args)` passthrough
mirroring the existing `rpc(url, method, params)` shape — with the same
discipline already proven in this file: binary name-pinning
(`resolve_node_binary`'s pattern, applied to `qemu-system-x86_64`), an
integrity-pin hook (`verify_node_integrity`'s pattern) for the QEMU/OVMF
binaries if a pin is configured, log/event streaming over `app.emit`
(`"guest-log"` mirroring `"node-log"`), and one `Mutex<HashMap<GuestId, Child>>`
instead of one `Mutex<Option<Child>>`. The display surface itself (the actual
pixels) is a **separate concern** from the Tauri control plane: QEMU's `-display`
options include GTK/SDL windows (simplest, same-process embedding is awkward
in Tauri) or, cleaner for this architecture, a **SPICE or VNC server the guest
exposes and a viewer widget embeds** — `wayvnc`/xrdp-class permissive remote
display, the same components `os/cloud.nix` §8's licensing table already
vetted as permissive (`wayvnc` ISC, FreeRDP/xrdp Apache-2.0) for exactly this
"remote desktop inside the tunnel" role. Reusing that vetted list here, for a
**local loopback VNC/RDP connection to a local guest**, is the cleanest path:
the same protocol, the same permissive components, a much simpler trust
boundary (localhost, not a WireGuard tunnel to a rented CVM).

### 1.6 NixOS wiring — mirror the Sloboda seal-exclusion pattern

This is the single most important structural precedent to copy. `os/sloboda-compat.nix`
+ `os/sloboda-vm.nix` establish the exact shape a guest-runtime module should
follow:

- A `postern.<name>` option namespace (e.g. `postern.guestRuntime`), `enable`
  behind `lib.mkEnableOption`, sub-options for backend choice
  (`"qemu"`/`"cloud-hypervisor"`), default disk location, network mode.
- **The critical honesty move Sloboda already makes explicit**: a guest OS
  (Windows/Ubuntu/RHEL running inside QEMU) is running on **mutable,
  network-fetched or user-supplied media** — an ISO, an answer file, whatever
  the user installs. Exactly like Waydroid's Android image, **`os_roothash`
  says nothing about what runs inside the guest and never can.** This module
  should carry the same seal-exclusion assertion pattern
  `sloboda-compat.nix` uses (refuse to coexist with a read-only sealed `/`
  the same way, or — more precisely here — simply note that **the guest's
  own disk image is outside any Postern measurement regardless of what host
  it runs on**, which is actually a *simpler* honesty story than Sloboda's:
  the **host** (Postern OS running the hypervisor) stays fully attestable/sealed
  exactly as today; only the **guest** is unattested, by construction, forever
  — there is no "seal-exclusion tripwire" needed on the host side at all,
  because unlike Waydroid (LXC sharing the host kernel), a KVM guest is a
  hardware-isolated VM that does not touch the host's read-only root. **This
  is a materially better attestation story than Sloboda's**: the Postern Seal
  on the *host* stays fully intact even while running an attested-nothing
  guest — worth stating plainly to the lead architect as a positive
  differentiator from the Waydroid precedent, not just a caveat.
- `virtualisation.libvirtd.enable` should specifically **NOT** be used (§0);
  instead a thin `postern-guest-runtime` systemd user/system service that
  exposes the Tauri backend's per-guest QMP sockets under `/run/postern/guests/`,
  analogous to how `sloboda-compat.nix` wires `virtualisation.waydroid.enable`.
- KVM device access (`/dev/kvm`) via the `kvm` group, same shape as Sloboda's
  `waydroid`/`video`/`render` supplementary groups for the dev user.

---

## 2 · Lighter options for Linux guests — when each fits

Not every "run Ubuntu" need justifies a full VM. Three tiers, honestly ranked
by isolation vs overhead:

| Tier | Isolation | Overhead | License path | Fits when |
|---|---|---|---|---|
| **Full VM (QEMU/KVM or Cloud Hypervisor)** | Hardware (separate kernel, separate memory space) | Highest (own kernel boot, own memory reservation) | See §0 | The user genuinely wants **a different OS**, needs kernel-level isolation (untrusted/experimental software), needs a **different kernel version/config** than the host, or wants snapshot/rollback semantics a container can't give as cleanly. |
| **systemd-nspawn container** | Kernel-shared namespace isolation (same kernel as host) | Low (no second kernel boot, near-native CPU/memory) | **Already present** — no new dependency (§0) | The user wants "an Ubuntu/RHEL **userland**" — a different distro's package set and libraries — not a different kernel. Good fit for **dev/build environments**, running an app that needs an older glibc, or a "toolbox" shell. This is architecturally the closest lighter-weight cousin to what Waydroid already does for Android (LXC container sharing the host kernel) — same trust story: **not attestable, host kernel is the actual security boundary, treat as non-attestable tier** exactly like Sloboda. |
| **Podman rootless container** | Namespace + (optional) rootless UID mapping | Lowest | Apache-2.0, clean (§0) | The workload is already containerized (an existing Docker/OCI image) rather than "install a whole distro interactively." Best fit for running a specific Linux **app**, not a Linux **desktop**. |

The systemd-nspawn tier is the direct architectural analogue of what
`apps/sloboda` already does for Android — same "shares the host kernel,
therefore never attestable, therefore the same non-attestable-tier honesty
label applies" reasoning, just for a Linux userland guest instead of an
Android one. It's worth building this tier's UI as a genuine sibling of
Sloboda in the Tauri shell (a `nspawn_*` command set alongside `guest_*`),
not a variant of the full-VM path — the two have different consent/honesty
labels and materially different overhead, and conflating them in the UI would
repeat the exact mislabeling risk `docs/os-portal/01-architecture.md` §5.3
already flags for the bare-metal portal ("never imply a blanket
Postern-secured X").

---

## 3 · GPU / hardware passthrough — honest assessment

This is the single area where overclaiming is easiest and most damaging to
Postern's credibility, so stated plainly:

### 3.1 VFIO / full GPU passthrough — powerful, genuinely finicky

**What it needs, all of it, simultaneously:**
- CPU + motherboard **IOMMU support**, enabled in firmware (Intel VT-d / AMD-Vi)
  — not universal even on modern hardware, and frequently **off by default** in
  consumer BIOS/UEFI.
- The target GPU (and everything sharing its **IOMMU group**) must be
  isolable — consumer motherboards often group the GPU with USB controllers,
  audio, or other PCIe devices in ways that can't be split (`vfio-pci` binds
  the whole group), sometimes fixable with ACS override patches (themselves a
  security/stability trade-off, not free).
- A **second GPU** (or an iGPU) for the host to keep using while the discrete
  GPU is handed to the guest — a laptop or single-GPU desktop typically
  **cannot** do this at all without a "dump the host display, GPU is 100%
  the guest's" setup, which defeats "run a sandboxed OS on your daily-driver
  desktop."
- Vendor-specific reset bugs: NVIDIA consumer cards historically had (and to
  varying degrees still have) **Code 43** driver refusal when detecting
  virtualization, needing kernel-parameter/vendor-ID spoofing workarounds;
  AMD cards have their own history of "GPU reset bug" (the card doesn't
  cleanly reset between guest start/stop without a reboot or a vendor-specific
  reset method). These are real, currently-true, unglamorous facts about VFIO
  passthrough as of the current hardware generation, not solved problems.

**Honest verdict:** VFIO GPU passthrough is real, used by a real (dedicated)
hobbyist community, and gives **near-native GPU performance** when it works.
It is **not** a feature to promise on "the Postern desktop" as a general
capability — it is a **dedicated-hardware, dual-GPU, IOMMU-verified,
per-machine bring-up project**, closer in spirit to this repo's own
`os/boot-harness/` "Rung 2 = real hardware, proven per-device" discipline than
to a one-click feature. If offered at all, it should be gated behind an
explicit hardware-compatibility probe (`probe`-style read-only verb, reusing
the old portal doc's §2.3 naming) that **tells the user honestly** whether
their specific machine's IOMMU groups even support it, before any consent
screen implies it will work.

### 3.2 virtio-gpu / Venus — the realistic default path

**virtio-gpu** (paravirtualized GPU device) with **Venus** (Vulkan-over-virtio,
Mesa's protocol for forwarding Vulkan calls from guest to host GPU) is the
honest, buildable-now middle ground: the guest gets **accelerated 3D**
(enough for a real desktop compositor, video playback, light gaming, most
productivity/CAD-lite work) by forwarding Vulkan calls to the **host's**
already-working GPU driver, with **no IOMMU requirement, no GPU splitting, no
second GPU needed**. This is genuinely mature on the Linux-guest side (Venus
ships in current Mesa, works well with virglrenderer/crosvm/QEMU) and is
**actively catching up but less mature for a Windows guest** (Windows virtio-gpu
+ Venus support exists via community drivers but is meaningfully behind the
Linux-guest experience — flag as "works, but check the exact current state at
build time, do not assume Linux-guest maturity carries over").

### 3.3 Software rendering fallback

llvmpipe/SwiftShader (the same fallback `sloboda-vm.nix`/`sloboda-compat.nix`
already use for the Waydroid VM bring-up) is always available as the
zero-hardware-dependency floor: correct, slow, fine for a plain desktop UI
and office work, not fine for anything graphically demanding.

### 3.4 What actually works on typical client hardware, stated plainly

| Hardware | Realistic guest GPU story |
|---|---|
| Typical laptop (single iGPU, or iGPU+dGPU with Optimus-style switching) | **virtio-gpu/Venus only.** VFIO passthrough is realistically off the table (no spare GPU for the host, IOMMU grouping usually not clean). |
| Typical single-GPU desktop | Same as laptop — virtio-gpu/Venus, or software fallback. VFIO would require dumping the host's own display. |
| **Dedicated dual-GPU desktop, verified IOMMU groups, purpose-built** | VFIO passthrough is real and gives near-native performance — but this is a minority, enthusiast-grade hardware configuration, not "the Postern desktop" as a general product claim. |

---

## 4 · Wine/Proton for a single Windows `.exe`, no container

### 4.1 Architecture

Wine is a **user-mode Windows API translation layer** — it re-implements the
Win32 API surface (kernel32, user32, gdi32, etc.) as Linux shared libraries and
runs the **unmodified Windows PE binary directly**, translating each API call
at runtime rather than emulating a CPU or booting a second kernel. Concretely:
`wine C:\path\to\app.exe` (or, on the Postern desktop, the Tauri shell resolving
and invoking the pinned `wine`/`wine64` binary — **same `resolve_node_binary`
pattern**: name-pin the binary, canonicalize the path, verify it's the real
Wine executable before spawning it, exactly as already done for `bloch`).
Each Windows app gets its own **prefix** (`WINEPREFIX`, a fake `C:\` directory
tree with its own registry hive) — the natural per-app isolation unit, and a
clean place to hang a consent/kill-switch/"forget this app" UX exactly like
the vault's discard semantics.

**Proton** is Valve's Wine fork, bundling **DXVK** (DirectX 9/10/11 →
Vulkan translation) and **VKD3D-Proton** (DirectX 12 → Vulkan translation) plus
Valve's own compatibility patches, distributed primarily through Steam's
runtime (Steam Linux Runtime container + Proton build). Using Proton **outside**
Steam's own distribution (e.g. bundling `GE-Proton` community builds directly
into Postern OS) is technically straightforward but raises the redistribution
question flagged in §0 — resolve before shipping, don't assume.

### 4.2 Compatibility reality — honest tiering, WineHQ AppDB-style

WineHQ's own AppDB uses a five-tier rating that is the right honest framework
to adopt verbatim rather than inventing a new one:

| Tier | Meaning | What lands here |
|---|---|---|
| **Platinum** | Runs out-of-the-box, no tweaks, feature-complete | Many older/simpler Win32 productivity apps, utilities, some legacy enterprise LOB (line-of-business) tools with no exotic dependencies. |
| **Gold** | Runs very well with minor, documented workarounds (a registry tweak, a specific Wine version pin, a DLL override) | A large slice of the practical "runs an old Windows app for productivity" use case — this is where most of the honest value is for this product. |
| **Silver** | Runs with significant, visible issues but is usable | Common for apps with heavier GPU use or unusual installers. |
| **Bronze** | Starts, but has major functional problems | Common failure mode for apps with deep OS integration (custom shell extensions, kernel-mode components bundled with the installer). |
| **Garbage** | Does not run at all | Anti-cheat-protected games, most DRM-gated software, apps requiring specific enterprise middleware (some SAP GUI configurations, certain licensing dongles/HASP-style hardware keys without a Linux-visible USB path). |

**Concretely, what works well:** office-suite-class productivity apps and
many older/simpler Win32 utilities, a large fraction of non-anti-cheat,
non-DRM Windows games (Proton/DXVK/VKD3D-Proton's actual daily-proven use
case — this is the single most battle-tested Wine-family deployment on
Earth, via Steam Deck/Steam on Linux), CAD-lite and engineering tools without
exotic hardware dongles, many line-of-business apps built on plain Win32/GDI.

**Concretely, what fails, and why, honestly:**
- **Kernel-mode anti-cheat** (EasyAntiCheat in kernel mode, BattlEye in
  kernel mode, Vanguard, etc.) — these require a **Windows kernel driver**,
  which Wine categorically cannot provide (Wine has no kernel-mode Windows
  driver model at all). Some anti-cheat vendors now explicitly whitelist
  Proton/Steam Deck (a real, improving trend) — but this is **per-title,
  vendor-opt-in**, not a Wine capability; never state this as "Wine solved
  anti-cheat."
- **DRM-gated video/software** with hardware-backed trust requirements
  (similar shape to the Widevine-L1/Play-Integrity-STRONG failure already
  documented honestly for Sloboda's Android tier — same category of problem,
  different OS: no hardware-rooted trust chain, so DRM that checks for one
  refuses).
- **Deep OS-integration apps**: anything that installs a Windows service,
  a kernel driver, a custom filesystem minifilter, or deeply hooks Explorer
  shell extensions. Enterprise security/EDR agents are the canonical example
  — categorically out.
- **Some modern, heavily DirectX-12/newest-API titles** — DXVK/VKD3D-Proton
  coverage is excellent but not 100%; bleeding-edge titles on release day are
  the highest-risk case, maturing over the following weeks/months as Proton
  patches land.
- **Enterprise apps with hardware dongles/HASP keys** unless the dongle has a
  Linux-visible USB passthrough path (sometimes works via USB passthrough,
  frequently doesn't).

**The honest recommendation for the product**: surface WineHQ AppDB's own
tier for a named app **before** the user tries to run it (a `probe`-style,
read-only lookup, same pattern as the old portal doc's hardware-probe verb),
so the UX sets expectations instead of discovering failure after the fact —
directly analogous to how Sloboda's README states Play Integrity STRONG will
fail *before* the user enters the Android container, rather than after.

---

## 5 · Performance / overhead — honest numbers, qualitatively

| Workload | Reality |
|---|---|
| **CPU-bound work in a KVM VM** | **Near-native.** Hardware virtualization (VT-x/AMD-V) means guest instructions execute directly on the CPU; KVM overhead for pure compute is small (single-digit percent in the common case), not the "slow emulator" reputation software emulation (QEMU-TCG, or full instruction emulation) carries. This applies to Windows/Ubuntu/RHEL guests alike. |
| **I/O in a KVM VM** | **Real overhead exists**, concentrated in disk and network. virtio-blk/virtio-scsi close most of the gap vs a passthrough NVMe device but do not eliminate it — expect a real (workload-dependent, often 10-30%-class, sometimes more for latency-sensitive random I/O) tax vs bare metal; virtio-net is similarly good-not-perfect vs a passed-through NIC. qcow2's copy-on-write layer adds further overhead vs raw for write-heavy workloads — this is the trade against the snapshot convenience in §1.3, not free either way. |
| **Graphics in a KVM VM** | **The widest overhead spread of anything in this document**, entirely dependent on which of §3's tiers is in play: software fallback (llvmpipe) is *slow, correctness-only*; virtio-gpu/Venus is *good, real overhead vs native, genuinely usable*; VFIO passthrough is *near-native* but only reachable on the dedicated hardware described in §3.4. Do not quote one number for "GPU performance in a VM" — it depends entirely on which path shipped. |
| **CPU-bound work under Wine** | **Near-native.** Wine translates API calls, not CPU instructions — the Windows binary's own machine code runs directly on the host CPU, same architecture, no emulation layer. This is the single most under-appreciated fact that makes Wine's story fundamentally different from a VM's: there is no second kernel, no second memory space, no hypervisor tax at all for the CPU-bound case. |
| **Graphics under Wine (DXVK/VKD3D-Proton)** | **Good to very good** for the well-covered case (this is Steam Deck's entire value proposition, running at essentially native-adjacent frame rates for the large majority of its supported library) — the DirectX→Vulkan translation layer adds measurable but usually small overhead versus native Windows+DirectX, and for some titles Vulkan-translated performance has been measured **equal to or better than** native DirectX due to Vulkan's lower driver overhead. Titles outside the well-covered case regress toward the tiering in §4.2, not toward a fixed number. |

**The one-line honest summary for the lead architect's doc**: *VM CPU
performance is close to free; VM I/O and graphics are where the real,
workload-dependent overhead lives, and graphics overhead specifically spans
"large" (software fallback) to "near-zero" (verified VFIO passthrough on
dedicated hardware) depending entirely on which tier ships. Wine sidesteps
almost all of this for CPU-bound work by never virtualizing the CPU at all,
which is the core reason "run one app via Wine" and "run a whole guest OS in
a VM" are different products with different honest performance stories, not
two flavors of the same thing.*

---

## 6 · Buildable now (mature tech) vs hard — summary matrix

| Capability | Maturity today | Verdict |
|---|---|---|
| QEMU/KVM guest lifecycle (create/run/stop/snapshot/destroy) over QMP | Extremely mature, decades of production use | **Buildable now** (license question in §0 to close first) |
| virtio device family (blk/scsi/net/gpu-basic/rng/balloon) | Extremely mature | **Buildable now** |
| Windows unattended install into a VM (answer file → Windows Setup, same mechanism as the old portal doc §3.1) | Mature | **Buildable now** |
| Ubuntu autoinstall / RHEL kickstart into a VM | Mature (identical to old portal doc §3.2/§3.3, just targeting a VM disk instead of bare metal — genuinely **easier** in a VM: no bare-metal driver-coverage variance) | **Buildable now, easier than the old bare-metal design** |
| qcow2 snapshotting for "reset the sandbox" UX | Mature | **Buildable now** |
| systemd-nspawn Linux-userland containers ("lightweight Ubuntu toolbox") | Mature, already present via systemd | **Buildable now, cleanest license story of the whole document** |
| Software-rendered (llvmpipe) guest graphics | Mature, already proven in this repo's own `sloboda-vm.nix` | **Buildable now** |
| virtio-gpu/Venus accelerated guest graphics (Linux guest) | Reasonably mature | **Buildable, needs real bring-up/testing time, not a research project** |
| virtio-gpu/Venus accelerated guest graphics (Windows guest) | Less mature, actively moving | **Buildable-with-caveats — verify current state at build time** |
| Wine for well-covered Win32/Proton-tier apps and games | Extremely mature (Steam Deck-proven at scale) | **Buildable now** (license question in §0 to close first) |
| WineHQ AppDB-driven compatibility lookup UX | Straightforward (it's a lookup/query against an existing public dataset) | **Buildable now** |
| VFIO GPU passthrough as a general product feature | Real but hardware-gated, community-proven only on dedicated dual-GPU/verified-IOMMU rigs | **Hard — dedicated-hardware feature, not a general desktop capability. Gate behind a hardware probe, never promise generally.** |
| Anti-cheat / kernel-driver-dependent Windows software via Wine | Categorically blocked for kernel-mode anti-cheat by Wine's own architecture | **Not buildable — an honest "no," not a roadmap item.** |
| Standalone Proton redistribution outside Steam's own channel | Legally/practically unclear (§0, §4.1) | **Needs resolution before any commitment, not hard engineering** |

---

## 7 · Consent / attestation implications — reusing the existing spine

- **The host stays sealed; the guest never is** — state this as the headline
  honesty claim (§1.6), and note it is a **materially better** story than
  Sloboda's Waydroid tier (LXC sharing the host kernel) precisely because a
  KVM guest is hardware-isolated from the host's attested root. Do not let
  this good news blur into "therefore the guest is attested" — it never is;
  `os_roothash` only ever describes the Postern OS host.
- The **consent-spine pattern** (`apps/consent-contract/`, reused in the old
  portal doc's §3.6 `portal-gate` schema and in Sloboda's own
  `sloboda-gate.state` schema shown above) is the right reusable primitive
  for gating: `guestCreate`, `guestNetworkEgress` (a VM's network access is a
  real crossing, same category as Sloboda's `egress.torOnly`/bridge toggles),
  `gpuPassthroughAttempt` (should be its own explicit, loudly-labeled crossing
  given §3's honesty requirements), `wineRun` (per-`.exe`, mirroring Sloboda's
  per-app launch model). None of this needs the old portal's `diskWipe`/
  `partition`/`bootloaderWrite` crossings at all — as noted in §1.2, this
  product's disk operations are entirely **file-level** (a qcow2 on the host
  filesystem), which is a genuinely smaller, safer consent-gate surface than
  the bare-metal portal ever needed.
- **The kill-switch problem is easier here than in the old portal doc.** The
  old design's §5 open question #2 ("destructive actions cannot be revoked
  the way a wallet crossing can") does not apply the same way: killing a VM
  process or a Wine process is an ordinary process-termination kill-switch,
  identical in shape to Sloboda's `sloboda kill` (stop the process, clear
  runtime state, leave the provisioned image/prefix intact and restartable) —
  not the irreversible-disk-write problem bare-metal installs created.

---

## 8 · Open questions for the lead architect / PMO 2

1. **§0's license table needs a real counsel/`deny.toml`-class pass**,
   specifically: (a) is "external GPL/LGPL process, invoked via its own
   documented protocol/CLI, never linked" an exception this repo is willing
   to extend from *already-present system daemons* (ModemManager, the kernel)
   to a *newly-bundled-by-us* binary (QEMU, Wine)? That is a materially
   bigger step than the telephony precedent and deserves an explicit yes/no,
   not an inferred one. (b) Is standalone Proton redistribution outside
   Steam's channel viable at all, or does "Windows apps via Wine" ship on
   vanilla Wine + DXVK/VKD3D-Proton built independently (both permissively
   licensed on their own, per §0's table) instead of Valve's Proton build?
2. **Cloud Hypervisor vs QEMU is a real, undecided architecture fork**, not
   a detail — it changes the license posture (§0), the graphics maturity
   story (§1.1, §3.2), and the Windows-guest feasibility. Recommend a
   time-boxed prototype of both against the same "install Windows 11 with
   TPM 2.0, get a working desktop with virtio-gpu" test before committing.
3. **VFIO passthrough product framing** — is it in scope at all for v1, or
   explicitly deferred as "enthusiast/advanced, dedicated-hardware only,"
   the same way this repo already defers Lima/Panfrost hardware GL for
   Sloboda to "phone-only, Rung 2"? Recommend the latter, stated as plainly
   in the product copy as Sloboda's Play-Integrity-STRONG-fails disclosure.
4. **Where does the executor/hypervisor process run relative to the
   Tauri shell's own privilege level?** `node_start` today spawns `bloch`
   as the same user running the desktop app. A hypervisor process needs
   `/dev/kvm` group membership at minimum; GPU passthrough (if ever built)
   needs real root/`vfio-pci` driver-binding privilege, a materially bigger
   ask than anything the Tauri shell does today (§7's `gpuPassthroughAttempt`
   crossing should probably require an explicit privileged-helper design,
   not just a consent toggle — flagged, not designed here).
5. **Does the systemd-nspawn "lightweight Ubuntu toolbox" tier get its own
   product surface/name**, sibling to Sloboda and to the full-VM guest
   runtime, or does the Tauri UI unify all three "run something else" shapes
   (VM, nspawn container, Wine) behind one picker? The honesty labels differ
   enough (§2's table) that a unified UI needs to keep the distinctions
   legible, not flatten them into one "run another OS" button.

---

*Design and scaffold only. UNAUDITED. Nothing in this document has been built,
evaluated, or booted. The licensing analysis in §0 is Architect A's honest
best-effort application of this repo's existing, stated rule — it is not a
legal opinion and must be verified before any of the named GPL/LGPL-adjacent
components (QEMU, Wine, Proton) are actually bundled. Never "Postern Windows,"
"Postern Ubuntu," or "Postern RedHat" — same naming discipline as
`docs/os-portal/01-architecture.md`. BLCH is worthless and is not a security.
Not legal advice.*
