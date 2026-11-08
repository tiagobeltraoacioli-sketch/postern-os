<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- Copyright (c) Postern Labs and Postern community contributors -->

# The OS Portal v2 — a sandboxed guest-runtime on the Postern OS desktop (architecture)

**Status: DESIGN CONCEPT ONLY. Nothing in this document is built, deployed, or
audited.** Lead architect's pass on the v2 pivot of the OS Portal concept.
Two architects are dispatched alongside this document: **Architect 1**
(guest-runtime/virtualization + Wine/Proton feasibility) and **Architect 2**
(consent/bridge/sandbox security, owner of `02-security-consent-privacy.md`).
Sections each owns are marked `[ARCHITECT-N STUB]` — fill in place, keep the
rest of the document's citations and honesty ledger consistent with your
additions. Same discipline as every other design doc in this tree:
`written ≠ built`, `built ≠ booted`, `designed ≠ audited`. Where a claim is
genuinely new territory, it is flagged **[SPECULATIVE / NEW]**.

> **Merge note.** Architect 1's and Architect 2's full contributions are
> preserved verbatim in `A-virtualization.md` and `B-sandbox-consent.md`
> (this directory) — read them for depth this merged pass compresses. Their
> single most important correction is folded in below: **the repo has a
> standing, load-bearing permissive-only licensing rule** (`BLOCH-SIS-LINUX.md`
> §2.4, restated in `docs/specs/POSTERN-CLOUD.md` §8 — *"no AGPL/GPL/LGPL in
> the shipped stack"*, with **SPICE client libs named explicitly OUT** as
> LGPL). The first draft of this document recommended libvirt (LGPL) and a
> SPICE display path — both wrong under this repo's own rule. §2.1, §2.6,
> and §2.7 below are corrected accordingly; this is the single most
> consequential fix either architect made.

> **Update (2026-07-16) — "nothing built" is now imprecise; here is the exact
> state.** The first Terem code exists in-tree and is committed:
> `desktop/src-tauri/src/terem.rs` (the Tauri backend / QMP spawn path) and the
> `apps/terem-gate` crate (the consent spine) **compile and pass their unit
> tests (terem-gate 32/32 + terem.rs 16) — but only under QEMU/TCG on the macOS
> workstation, never under Linux/KVM and never on hardware.**
> `os/terem-compat.nix` (the OS module) exists and is committed but is a Nix
> module not evaluated on this non-Nix host. Everything
> else this document designs remains **unbuilt, unbooted, and unaudited** —
> `written ≠ built`, `built ≠ booted`, `TCG ≠ KVM ≠ hardware`.

---

## 0 · The pivot — why v1 is retired, what replaces it

### 0.1 What v1 was, and why the operator killed it

`docs/os-portal/01-architecture.md` and `02-security-privacy.md` (Design
PMOs 1 and 2, working name **Novosel**) designed an AI agent that
**bare-metal installs** a foreign OS: partitions the client's real disk,
writes a real bootloader, touches real firmware (Secure Boot, TPM,
BitLocker), and can leave the machine in a **destructive, irreversible**
state if anything goes wrong. PMO 2's own red-team pass (v1 §5/§6) already
named the sharpest problems without resolving them: a kill-switch that
"halts the next step but cannot un-write bytes already committed to disk,"
vendor activation as "the first place in the whole Postern catalog where the
agent voluntarily touches another vendor's auth material," BIOS/UEFI/Secure
Boot prerequisites that are "often not scriptable at all," and a
compromised-host case with "nothing claimed to survive this." Those are not
implementation gaps — they are the shape of bare-metal AI-driven OS install
itself. **v1 is retired.** Its non-destructive parts (the license spine, the
consent-spine kernel, the honesty-ledger discipline, nominative trademark
use, the brain/hands split as a *general* pattern) carry forward; its
disk-level executor verb set (`partition`, `format`, `write-bootloader`,
bare-metal `apply-image`) does **not**.

### 0.2 What v2 is instead

**Run the foreign OS inside a sandbox, not on the metal.** The desktop
analog of Sloboda (`apps/sloboda`, which runs an Android userland inside a
Waydroid **container** rather than flashing Android onto the phone's own
partitions): Windows, Ubuntu, RHEL, and others run **inside a guest
VM/container** that sits on top of the client's already-installed Postern
OS. The guest's disk is a file (a qcow2 image or an OCI/nspawn rootfs), not
a partition on the host's real disk. Destroying the guest means deleting
that file — the host's firmware, bootloader, and real disk are **never
touched**. This dissolves every v1 CRITICAL by construction, not by policy:

| v1 CRITICAL (bare metal) | v2 status |
|---|---|
| Firmware/Secure Boot/TPM state on the **host** | **Dissolved.** The host's firmware is never written. A guest may have its *own* virtual UEFI/vTPM (§2.2) — that is the guest's business, inside the guest's disk file. |
| BitLocker key custody on the **host** | **Dissolved.** BitLocker, if the guest enables it, encrypts the guest's *virtual* disk — a file Postern OS's host filesystem already protects with its own LUKS (`os/desktop.nix` §"Full-disk encryption"). No host-level BitLocker exists. |
| Destructive, irreversible host disk wipe | **Dissolved.** `partition`/`format`/`write-bootloader` against the client's real disk are retired verbs. The only "destructive" action in v2 is deleting a guest's own disk image — reversible in the sense that it never touched anything the client didn't explicitly create as a guest. |
| Kill-switch cannot undo an in-flight disk write | **Weakened to a real, solvable problem.** A kill mid-guest-install can leave a corrupt *guest* image; the fix is "delete the guest and retry," not "the client's laptop is bricked." Never a host-disk emergency. |
| OS activation / vendor entitlement liability | **Narrowed, not eliminated** (§3, `03-license-honesty.md`). Activation now happens *inside* the guest, against the vendor's own servers, with the user's own key — Postern is further from the transaction than in v1, not closer. |

A second, lighter path exists alongside the full guest: for **one Windows
app** (not a whole OS), a **compatibility layer** (Wine/Proton) translates
Windows API calls to Linux ones and runs the app as a native Postern OS
process — **no guest, no virtual disk, no OS license question at all**,
because no OS is being installed (§3).

### 0.3 Positioning in the bridge family

| Product | Folklore shape | What it bridges |
|---|---|---|
| **Postern** | the fortress's own postern gate | the suite brand itself |
| **Porog** | the threshold | stock Android ⟷ a hardened managed-profile workspace, same device |
| **NoporIS** | the guarded bridge | a clean persona ⟷ a Google-Play persona, same phone |
| **Sloboda** | the settlement outside the walls | a Postern-controlled Linux host ⟷ a non-attestable Waydroid Android container |
| **Chiostro** | the cloister | a Postern OS workstation ⟷ a rented confidential-VM host |
| **Terem** *(this doc, v2 OS Portal)* | the guest chamber — a wing built onto the house, reachable from it, never load-bearing for it | Postern OS Desktop ⟷ a sandboxed foreign-OS guest (full VM/container) or a single translated Windows app (Wine/Proton) |

**Proposed name — PROPOSED, pending trademark clearance, like every other
mark in this family: Terem** (Slavic *терем* — a tower-chamber built onto,
and reachable from, the main house, historically where a guest or a
separate household stayed: physically attached, structurally independent,
demolishable without touching the house). It completes the toponymy
precisely because it is the same shape as Sloboda one host down: Sloboda is
Android-in-a-container on a Linux host; Terem is Windows/Ubuntu/RHEL-in-a-VM
on the Postern OS desktop host. Alternative considered: keeping the v1 name
**Novosel** — rejected, because "the newcomer who moves into a freshly-built
home" evokes v1's *bare-metal install* imagery (a real new house), which is
exactly the concept being retired; a fresh name marks the pivot honestly
rather than quietly re-labeling a different product. **Neither name is
committed.**

**The honest one-liner (draft, keep verbatim once adopted):** *"Terem runs
another OS inside a sandbox on your Postern OS desktop — your Windows or
Ubuntu, your license, your data, walled off from the host. Destroy the
sandbox and the host was never touched."*

- **NEVER "Postern Windows," "Postern Ubuntu," or "Postern RedHat."**
  Nominative use only, carried forward verbatim from v1 §0 — see
  `03-license-honesty.md` §1.
- BLCH is worthless and is not a security. Personal use free-forever
  doctrine applies to Terem's own license gate, not the guest OS vendor's
  licensing (§3, `03-license-honesty.md`). Not legal advice.

---

## 1 · Two paths, one desktop product

```
                         ┌─────────────────────────────────────┐
                         │        Postern OS Desktop            │
                         │        (os/desktop.nix host)          │
                         └───────────────┬───────────────────────┘
                                          │
                    ┌─────────────────────┴─────────────────────┐
                    ▼                                             ▼
     ┌──────────────────────────────┐             ┌───────────────────────────────┐
     │  PATH A — Guest Mode          │             │  PATH B — App Mode             │
     │  full foreign OS, sandboxed   │             │  one Windows app, translated    │
     │                                │             │                                  │
     │  Windows 10/11, Ubuntu, RHEL,  │             │  Wine / Proton (DXVK, VKD3D)     │
     │  other Linux — a full guest    │             │  runs the .exe as a native       │
     │  kernel + userland in a VM      │             │  Postern OS process — no guest    │
     │  (KVM/QEMU over QMP) or, for    │             │  kernel, no virtual disk, no OS   │
     │  trusted Linux-only userlands,  │             │  license question at all         │
     │  a lighter OS-level container   │             │                                  │
     │  (systemd-nspawn/Podman)         │             │  §3                              │
     │  §2                              │             │                                  │
     └──────────────────────────────┘             └───────────────────────────────┘
```

The two paths are not competitors; they are a **decision tree** (§4). Use
App Mode when the goal is "run this one Windows program" and it is
Wine/Proton-compatible (§3.1); use Guest Mode when the goal is "a real
Windows/Ubuntu/RHEL desktop" or the app fails under Wine.

---

## 2 · Path A — Guest Mode: the full-OS sandbox

### 2.1 Virtualization tech — chosen, and why

**License gate first, before any tech choice.** This repo has a standing,
already-enforced rule (`BLOCH-SIS-LINUX.md` §2.4, restated in
`docs/specs/POSTERN-CLOUD.md` §8): **permissive-only, no AGPL/GPL/LGPL in
the shipped stack.** That document already resolved the closest prior art —
it names **SPICE client libs (LGPL) explicitly OUT** and **wayvnc (ISC) +
FreeRDP/xrdp (Apache-2.0) explicitly IN** as "the desktop protocol" for
exactly this kind of remote-display need (Chiostro's confidential-VM
guests). Terem inherits that ruling directly rather than re-deciding it.
Applying the same "external unforked process, invoked over its own
documented protocol/CLI, never linked" exception this repo already grants
GPL system daemons (`docs/specs/POSTERN-TELEPHONY.md`'s ModemManager/oFono
reasoning, and `os/cloud.nix`'s treatment of the GPL Linux kernel itself):

| Component | License | Consumed how | Verdict |
|---|---|---|---|
| **KVM** (kernel module) | GPL-2.0 | In-kernel `/dev/kvm` ioctl | **In** — same "ships with Linux, not our distributed component" exception `POSTERN-CLOUD.md` §8 already grants the kernel |
| **QEMU** (VMM) | GPL-2.0 | External binary, driven over its **QMP** JSON socket — never forked/linked | **Resolved by `LICENSE-DECISION.md` §1:** opt-in only, never bundled by Postern, never in the default attested image. The "external unforked process" exception does not extend to a newly-bundled-by-us binary the way it does for already-present system daemons — see `LICENSE-DECISION.md` §0/§2 for the full reasoning. |
| **libvirt** | LGPL-2.1 | Its normal integration path is a **linked** client library | **Out.** Skip it entirely — drive QEMU directly over QMP instead (§2.6) |
| **Distrobox** | GPL-3.0 | Shell-script wrapper, normally vendored | **Out.** Use Podman (Apache-2.0) + `systemd-nspawn` (already ships with systemd on every NixOS host here) directly instead |
| **Podman** | Apache-2.0 | Linked or invoked | **In, cleanly** |
| **SPICE client libs** | LGPL | Linked display library | **Out** — already ruled out by `POSTERN-CLOUD.md` §8 |
| **wayvnc / FreeRDP,xrdp** | ISC / Apache-2.0 | External process, remote-display protocol | **In** — already vetted by `POSTERN-CLOUD.md` §8 for this exact "remote desktop into a VM" role; reused here for a local-loopback guest display instead of a WireGuard-tunneled cloud one |
| **Wine** | LGPL-2.1 | External process (`wine app.exe`), never linked (`libwine` not embedded) | **Resolved by `LICENSE-DECISION.md` §1:** opt-in only, same shape as QEMU — never bundled by Postern, never in the default attested image. |
| **Proton** (Valve's build) | LGPL-2.1 + bundled components, distributed via Steam's runtime | Redistributing Valve's own build outside Steam's channel is legally/practically unclear | **Open question, not resolved here** — the fallback is shipping vanilla Wine + independently-built DXVK (zlib) + VKD3D-Proton (LGPL-2.1, same external-process reasoning) instead of Valve's redistributed binary |

**The concrete choice this drives — corrected per `LICENSE-DECISION.md`
§1/§2 (the later, stricter ruling that supersedes the "provisionally in"
language above):** **Cloud Hypervisor** (rust-vmm, Apache-2.0 — already
relevant to this repo for `os/cloud.nix`'s SNP/TDX work) is the **default,
in-box VMM** for the guest shapes it currently handles well
(headless/Linux-service guests, SNP/TDX-relevant) — chosen specifically so
the default, attested Terem build ships **zero GPL/LGPL/AGPL code**.
**KVM/QEMU driven directly over QMP, no libvirt** (§2.6) is kept for guest
shapes Cloud Hypervisor's less-mature Windows/graphics support doesn't yet
cover, but only as an **operator-initiated, opt-in add-on**: Postern never
bundles QEMU into the default closure, mirroring the doctrine
`03-license-honesty.md` §1 already established for the guest OS itself. See
`LICENSE-DECISION.md` for the full per-component ruling. For lightweight
Linux-only guests, **Podman + `systemd-nspawn` directly**, skipping the
Distrobox wrapper.

| Tech | Role | Why |
|---|---|---|
| **Cloud Hypervisor (rust-vmm)** | **Primary, default, in-box engine** (`LICENSE-DECISION.md` §1) for the guest shapes it currently handles well — headless/Linux-service-shaped guests, SNP/TDX-relevant | Apache-2.0 (clean license story, no counsel-pass needed, ships in the default attested image with zero GPL/LGPL/AGPL), Rust-native (fits this repo's `crates/postern-*` posture), first-class SEV-SNP/TDX guest support already relevant to Chiostro. Honest gap: guest-graphics and Windows-guest maturity trail QEMU/KVM today — a real open question (§8 open items), covered by the opt-in QEMU path below. |
| **KVM/QEMU, driven over QMP (no libvirt)** | **Opt-in only, never bundled by Postern** (`LICENSE-DECISION.md` §1/§2) — used for full-OS guest shapes (Windows, and Linux distros wanting isolation parity with Windows) that Cloud Hypervisor doesn't yet cover well | Hardware-virtualized (Intel VT-x/AMD-V): the guest gets its **own kernel**, its own virtual firmware, its own virtual disk — a real security boundary between guest and host, not a shared-kernel one. This is not a new choice for this repo: `os/sloboda-vm.nix` + `os/sloboda-compat.nix` already stand up exactly this stack (`virtualisation.qemu-vm.nix`, `virtualisation.memorySize`/`cores`/`diskSize`, QEMU user-mode NAT) — as the **throwaway dev/bring-up host** for the Waydroid tier, not a product. QMP (`qemu-system-x86_64 -qmp unix:<sock>,server,nowait`) gives the same lifecycle control libvirt would (`query-status`, `system_powerdown`, `blockdev-snapshot-sync`, `device_add`/`device_del`) without the LGPL dependency — but the operator, not Postern, must supply the QEMU binary (`LICENSE-DECISION.md` §2): the default attested image never bundles it. |
| **`systemd-nspawn` (direct, no Distrobox) / Podman** | Secondary, opt-in, **Linux-only-guest** lightweight path | OS-level containers sharing the **host kernel** — no new kernel, no virtual firmware, near-zero overhead — but a materially **weaker isolation boundary** than KVM: a kernel exploit inside the container reaches the host kernel directly (`02` §1 owns the full asymmetry). Honest scoping: offered **only** for trusted Linux userlands. Never offered for Windows or RHEL as a security-equivalent alternative to KVM — Windows/RHEL always get the full-VM path. |
| **Wine/Proton** | Not a guest at all | See §3 — a compatibility layer, not virtualization. Listed here only to say explicitly why it is *not* Path A: it shares the host kernel and host process table completely; there is no guest to sandbox. |

**Rejected as primary:** a container-only strategy for Windows (Windows
cannot run as a Linux container — there is no shared kernel to share) and a
Wine-only strategy for "a whole OS" (Wine translates one app's API surface;
it is not, and does not attempt to be, an OS). Both are true limits, not
oversights.

### 2.2 Per-OS guest shape

| Guest OS | Default engine | Virtual firmware | Notes |
|---|---|---|---|
| **Windows 10/11** | Cloud Hypervisor where sufficient; **opt-in KVM/QEMU over QMP** (full VM, never bundled by Postern) where it isn't yet — `LICENSE-DECISION.md` §1 | OVMF (UEFI) + `swtpm` (emulated TPM 2.0) | Windows 11 setup checks for a TPM and (usually) UEFI Secure Boot — both are satisfied by the **guest's own virtual** firmware/vTPM, never the host's. This is the direct fix for v1's "TPM/Secure Boot/BitLocker on the host" CRITICAL: those checks now run against virtual hardware inside a disposable file. Honest gap: today's Windows/graphics-guest maturity trails QEMU/KVM, so Windows guests likely need the opt-in path in practice (§8 open items). |
| **Ubuntu / other Linux (isolation-parity mode)** | **Cloud Hypervisor (default, in-box)**; opt-in KVM/QEMU over QMP where CH is insufficient — `LICENSE-DECISION.md` §1 | OVMF or legacy BIOS | Chosen when the client wants the same sandbox strength as the Windows guest, or plans to run untrusted software inside it. |
| **Ubuntu / RHEL / other Linux (lightweight mode)** | `systemd-nspawn` or Podman (not Distrobox, §2.1) | n/a (shares host kernel) | Chosen when the goal is a userland, not a sandbox — explicitly weaker isolation, disclosed as such (§2.1, and `02-security-consent-privacy.md` §1). |
| **RHEL** | Cloud Hypervisor (default, in-box) or lightweight container, both in-box; **opt-in KVM/QEMU over QMP** (never bundled) for full-VM cases CH doesn't cover — `LICENSE-DECISION.md` §1 | as above | Subscription/entitlement wall is identical either way (`03-license-honesty.md` §2). |

### 2.3 Lifecycle — create / install / snapshot / restore / destroy

```
   CREATE            INSTALL              RUNNING            SNAPSHOT           DESTROY
┌──────────┐     ┌──────────────┐     ┌────────────┐     ┌───────────────┐   ┌──────────┐
│ allocate  │────▶│ boot vendor   │────▶│ guest       │────▶│ point-in-time  │──▶│ undefine  │
│ a NEW,    │     │ ISO/installer │     │ OS running, │     │ qcow2 external │   │ domain +  │
│ empty     │     │ (Windows      │     │ operator    │     │ snapshot, or   │   │ delete    │
│ qcow2/    │     │ setup,        │     │ uses it     │     │ QMP            │   │ disk file │
│ rootfs    │     │ subiquity,    │     │             │     │ snapshot API   │   │           │
│ + a       │     │ anaconda —    │     │             │     │                │   │ HOST DISK │
│ domain    │     │ the vendor's  │     │             │     │ restore = roll │   │ NEVER     │
│ domain    │     │ OWN installer,│     │             │     │ back to that   │   │ TOUCHED   │
│ definition│     │ never a       │     │             │     │ point           │   │           │
│           │     │ Postern one)  │     │             │     │                │   │           │
└──────────┘     └──────────────┘     └────────────┘     └───────────────┘   └──────────┘
```

This is the same "destroy = clean" invariant Sloboda already states for the
Waydroid tier (`apps/sloboda` `kill` command: "clears session runtime state
… leaves the provisioned image intact and re-startable"), extended one step
further: Terem's `destroy` doesn't just clear runtime state, it deletes the
guest's persistent disk too, and that is **always safe** because the disk
being deleted is a file Terem created, never a partition of the host's real
disk. This is the structural fix for v1's unsolved §5.2 ("destructive
actions cannot be revoked the way a wallet crossing can") — in v2 the
crossing genuinely is revocable, because nothing outside the guest's own
file was ever written to.

Unlike v1's install-mechanics table (§3 of the retired doc), the *install*
step here still uses each OS vendor's own native unattended-install
mechanism where the operator wants it automated (Windows answer file /
`autounattend.xml`, Ubuntu `autoinstall`, RHEL kickstart — the same
mechanisms v1 §3.1–3.3 already catalogued **remain accurate and reusable**;
only *where* they write — a guest's virtual disk, never the host's physical
one — has changed) or a plain interactive install, since interactive
install inside a disposable VM carries none of v1's bare-metal risk.

### 2.4 Resource & isolation model

- **Compute/memory**: cgroups applied to the QEMU process directly (via systemd scope/slice, no libvirt daemon in the loop), same shape `os/sloboda-vm.nix`
  already sizes (`virtualisation.memorySize`/`cores`) — extended to
  operator-configurable per-guest limits (a guest cannot starve the host).
- **Disk**: one qcow2 (or nspawn rootfs) file per guest, in a dedicated
  Terem data directory. No guest ever has a raw block-device handle to a
  host disk — this is the single hardest structural guarantee in this
  design and the direct antidote to v1's `partition`/`format` verbs.
- **Network**: NAT'd virtual network by default (QEMU user-mode NAT or a
  a QEMU-managed isolated bridge) — the guest reaches the internet, the
  host's LAN does **not** by default reach the guest, and the guest is not
  bridged onto the client's real LAN unless the operator explicitly opens
  that (a consent-gated bridge crossing, `02-security-consent-privacy.md`
  §3).
- **No shared folders / clipboard by default** — every guest↔host bridge is
  closed until consented, exactly the NoporIS/Sloboda default-closed
  posture (`02-security-consent-privacy.md` owns this in full).

### 2.5 GPU / hardware passthrough — honest, upfront

The default is **software rendering** (`virtio-gpu` with **llvmpipe/
SwiftShader**, the same fallback `os/sloboda-vm.nix`/`sloboda-compat.nix`
already use for the Waydroid VM) — correct, slow, fine for desktop/office/
dev-tooling, not gaming- or CAD-grade. The realistic **middle path,
buildable now, no special hardware needed**: `virtio-gpu` + **Venus**
(Vulkan-over-virtio, current in Mesa) forwards guest Vulkan calls to the
host's own already-working GPU driver — no IOMMU, no GPU splitting, no
second GPU required. Mature and proven on Linux guests; meaningfully behind
on Windows guests (community drivers exist but trail the Linux-guest
experience — verify current state at build time, don't assume parity).

**Real GPU passthrough (VFIO)** exists only as an advanced, hardware-gated
opt-in, never a default, because — filled in from Architect 1's pass
(`A-virtualization.md` §3, full detail there):

- needs IOMMU (Intel VT-d / AMD-Vi) enabled in firmware, off by default on
  many consumer boards;
- needs the target GPU's **IOMMU group** to be cleanly isolable — consumer
  boards often group a GPU with USB/audio controllers in ways that can't be
  split without a risky ACS-override patch;
- needs a **second** GPU or iGPU for the host to keep using — most laptops
  and single-GPU desktops simply cannot do this without giving up the host
  display entirely;
- hits real, currently-true vendor quirks: NVIDIA consumer cards'
  historical **Code 43** driver refusal on detecting virtualization
  (workaroundable, not solved), and AMD's own GPU-reset-bug history (a
  passed-through card not cleanly resetting between guest start/stop
  without a host reboot or a vendor-specific reset method).

**Honest verdict, carried from Architect 1's assessment:** VFIO passthrough
gives near-native performance when it works, but it is a **dedicated
dual-GPU, IOMMU-verified, per-machine bring-up project** — closer to
`os/boot-harness/`'s "Rung 2, proven per real device" discipline than a
one-click feature. If offered at all: gated behind a read-only hardware
probe that tells the operator honestly whether their machine's IOMMU
groups even support it, before any consent screen implies it will work, and
modeled in `02-security-consent-privacy.md` as a boundary-**widening**
grant (direct DMA-capable hardware access), never as one more data-crossing
"bridge" alongside clipboard/files — that distinction is `02`'s own
correction, load-bearing enough to repeat here.

| Hardware | Realistic guest GPU story |
|---|---|
| Typical laptop (single iGPU, or iGPU+dGPU switchable) | `virtio-gpu`/Venus only — VFIO is realistically off the table |
| Typical single-GPU desktop | Same — VFIO would mean giving up the host's own display |
| Dedicated dual-GPU desktop, verified IOMMU groups | VFIO passthrough is real, near-native — a minority, enthusiast-grade configuration, never a general product claim |

### 2.6 Tauri desktop shell integration

Terem is a panel in the desktop shell (`desktop/src`, `desktop/src-tauri`),
following the same discipline `desktop/src-tauri/src/main.rs` already
enforces for the node binary: **no shell interpolation, a fixed,
named-binary invocation, arguments passed as separate argv entries.**
Proposed Tauri commands (new module, e.g. `desktop/src-tauri/src/terem.rs`,
mirroring `pairing.rs`'s existing pattern of a separate module registered in
`main.rs`'s `invoke_handler!`, and directly generalizing the existing
`node_start`/`node_stop`/`node_status` + `rpc`/`rpc_tor` shape — one
`Mutex<HashMap<GuestId, Child>>` instead of one `Mutex<Option<Child>>`):

```
terem_list           // enumerate defined guests (name, os, state, disk size)
terem_create          // qemu-img create a new qcow2 disk + a per-guest config
terem_install_start    // boot the vendor installer (interactive or answer-file)
terem_start / terem_stop / terem_status
terem_qmp(id, cmd, args) // QMP passthrough, mirrors the existing rpc(url, method, params)
terem_snapshot / terem_restore  // qemu-img snapshot / QMP blockdev-snapshot-sync
terem_destroy          // stop + delete the qcow2 disk file (separate, explicit verb from a plain stop)
terem_console_open      // open a wayvnc/FreeRDP session to the guest's local display
```

**No libvirt** — per §2.1's license gate, the Tauri backend talks to QEMU
directly over its **QMP** JSON socket (`qemu-system-x86_64
-qmp unix:/run/postern/terem/<id>.sock,server,nowait`), the same way it
today calls the node's JSON-RPC (`rpc`/`rpc_tor` in `main.rs`). Each Terem
command resolves and pins its binary (`qemu-system-x86_64`, `qemu-img`) the
same way `resolve_node_binary` pins `bloch`: name+location+canonicalize+
exec-bit, generalized to `resolve_qemu_binary`/`resolve_qemu_img_binary`.
**The guest display is a separate concern from the control plane**: not a
SPICE viewer (ruled out, §2.1 — SPICE client libs are LGPL) but a
**wayvnc (ISC) / FreeRDP,xrdp (Apache-2.0)** session to the guest — the
exact permissive pair `docs/specs/POSTERN-CLOUD.md` §8 already vetted for
"the desktop protocol," reused here for a local-loopback connection to a
local guest instead of a WireGuard-tunneled remote CVM, which is a simpler
trust boundary, not a harder one. **No verb here is "run arbitrary
command"** — the same fixed-verb-set discipline v1 established for its
(now-retired) disk executor (v1 §2.3) is the right shape to keep, just
re-scoped to guest-lifecycle verbs instead of disk-partition verbs. The
Tauri capability file (`desktop/src-tauri/capabilities/default.json`) stays
default-deny for Tauri's own fs/shell/process plugin permissions — Terem's
privileged work is application commands (like the existing wallet/vault
commands), not capability-gated plugin calls, per that file's own
documented rationale.

### 2.7 Nix wiring — `os/terem-compat.nix`

A new module, `os/terem-compat.nix`, directly modeled on
`os/sloboda-compat.nix`'s structure and honesty header:

- **No `virtualisation.libvirtd.enable`** (§2.1's license gate rules it
  out). Instead: `/dev/kvm` access via the `kvm` group (same shape as
  Sloboda's `waydroid`/`video`/`render` supplementary groups), the
  `qemu`/`OVMF`/`swtpm` packages on `PATH`, and a thin
  `postern-terem` systemd service that owns `/run/postern/terem/` (the QMP
  socket directory) — analogous to how `sloboda-compat.nix` wires
  `virtualisation.waydroid.enable`, just without a libvirt daemon in the
  middle.
- Architect 1 flags one genuinely positive attestation asymmetry worth
  stating plainly here: **unlike Waydroid (LXC, sharing the host kernel),
  a KVM guest is hardware-isolated and never touches the host's read-only
  root at all** — so `terem-compat.nix` doesn't need `sloboda-compat.nix`'s
  own seal-exclusion *tripwire assertion* (refusing to coexist with a
  read-only `/`) as a safety net; the isolation is structural, not merely
  policed. The **honesty labeling** still applies in full, unconditionally:
  the guest's own disk image is outside any Postern measurement regardless
  of host, `os_roothash` never describes it, and it is never imported into
  `os/attested.nix`'s sealed closure — a guest OS is always mutable,
  user-supplied media, exactly like Waydroid's Android image (`02` §6).
- **Unlike** `sloboda-compat.nix` (imported by exactly one non-attested
  dev/VM host), `terem-compat.nix` is meant to be **opt-in on the real
  Postern OS Desktop host** (`os/desktop.nix`) — the guest disks live
  outside the sealed root, on the same already-LUKS-encrypted host
  filesystem `os/desktop.nix` already provides, so enabling Terem does not
  itself unseal anything. The host stays attestable; the module only adds
  the capability to run non-attestable guests *beside* it.
- `[ARCHITECT-1 STUB]` — fill in the actual module options (guest disk
  storage pool location, default network mode, whether `swtpm` runs as a
  system service or per-guest) and a first-draft `nix flake check`-able
  skeleton, same maturity level as `sloboda-compat.nix`'s own "written, not
  built" stance. **Note:** `virtualisation.spiceUSBRedirection` (mentioned
  in an earlier draft of this section) is itself part of the SPICE stack
  ruled out in §2.1 — USB passthrough should use QEMU's own
  `-device usb-host,vendorid=…,productid=…` hostdev mechanism directly, not
  the SPICE USB-redirection path.

---

## 3 · Path B — App Mode: Wine/Proton, no guest at all

### 3.1 Tech

**Wine** (the upstream Windows-API-on-Linux translation layer) plus
**Proton** (Valve's Wine fork, bundling **DXVK**/**VKD3D-Proton** —
Direct3D 9/10/11/12 → Vulkan translation — and Windows-friendly defaults),
with **Winetricks** for bootstrapping common dependencies (`.NET`, VC++
redistributables, fonts). Each app gets its own isolated **`WINEPREFIX`**
("bottle") — a per-app fake `C:\` drive and registry hive — so apps don't
share state and a broken prefix doesn't take others down with it.

**This is not virtualization.** There is no guest kernel, no virtual disk,
no hypervisor. Wine re-implements the Windows API surface as Linux
libraries; the "Windows app" runs as an ordinary Postern OS process making
ordinary Linux syscalls. This is *why* it is fast (near-native for
supported apps — no VM overhead) and *why* it needs its own, weaker
isolation story (§3.2, and `02-security-consent-privacy.md` §9): a Wine
process is a host process with whatever privileges the operator's account
has, scoped only by the `WINEPREFIX` directory convention, not by hardware.

**License note, carried from §2.1's gate:** Wine (LGPL-2.1) is consumed the
same way QEMU is — an external, unforked binary Terem `exec`s and reads the
exit status/output of, never `libwine` linked in — provisionally in under
the same telephony-daemon exception, pending the same counsel pass. **Valve's
own Proton build** is distributed through Steam's runtime; redistributing it
standalone outside that channel is a genuinely open legal/practical
question, not resolved here (`A-virtualization.md` §0/§4.1 owns the detail).
The honest fallback if that stays unresolved: ship vanilla Wine plus
independently-built DXVK (zlib) and VKD3D-Proton (LGPL-2.1, same
external-process reasoning as Wine itself) instead of Valve's binary — both
permissively licensed on their own terms.

### 3.2 Isolation — honestly weaker than Guest Mode, and the mitigation

Unlike Path A, App Mode is **not sandboxed by construction**. The app can
read/write anything the launching user account can, exactly like any other
native program. The recommended hardening, standard in the Wine/Proton
ecosystem already (Valve ships Proton apps inside a Flatpak/Steam sandbox on
Steam Deck/Linux desktop): wrap the Wine process + its `WINEPREFIX` in a
**Bubblewrap** (`bwrap`) or Flatpak-style namespace jail that restricts
filesystem visibility to the prefix directory plus an explicit allowlist,
and drops network access by default unless the app declares it needs it.
`[ARCHITECT-1 STUB]` — recommend a concrete default sandboxing tool/profile
for Postern OS specifically (bubblewrap invocation, or a `firejail` profile,
or reuse of an existing nixpkgs `wineWowPackages` + sandbox wrapper) and
state plainly whether it is on by default or an opt-in the operator must
enable — this is a security-relevant default, not a cosmetic one, and
belongs in `02-security-consent-privacy.md` §9's cross-reference too.

### 3.3 Lifecycle

```
CREATE PREFIX    INSTALL              RUN                  DESTROY
┌────────────┐  ┌───────────────┐   ┌───────────────┐   ┌──────────────┐
│ wineboot    │─▶│ user runs the  │──▶│ operator       │──▶│ rm -rf the    │
│ initializes │  │ app's OWN      │   │ launches the   │   │ WINEPREFIX     │
│ a fresh     │  │ .exe installer │   │ app; Postern    │   │ directory —    │
│ WINEPREFIX  │  │ inside the     │   │ never ships/    │   │ clean, complete│
│             │  │ prefix — same  │   │ pirates the app │   │ revert          │
│             │  │ installer the  │   │                 │   │                  │
│             │  │ user would run │   │                 │   │                  │
│             │  │ on real Windows│   │                 │   │                  │
└────────────┘  └───────────────┘   └───────────────┘   └──────────────┘
```

Reversibility here is even simpler than Path A's: a `WINEPREFIX` is a plain
directory tree, not a virtual disk image, so `destroy` is a directory
deletion with the same "host was never touched" guarantee as §2.3.

### 3.4 What Path B does *not* need that Path A does

- **No OS license question** (`03-license-honesty.md` §1) — Wine is not
  Windows and does not require a Windows license; only the **app's own**
  license/activation (if any) is in play, and that is the app vendor's
  concern, carried through unchanged from v1's "vendor entitlement is not
  Postern's to grant" wall (v1 §3.5), now scoped to one app instead of a
  whole OS.
- **No guest firmware/TPM/Secure Boot story** — none of that exists in App
  Mode; there is no boot at all, only a process launch.
- **Does still inherit** the anti-cheat/DRM detection wall
  (`03-license-honesty.md` §4) — many titles' anti-cheat/DRM detects Wine
  itself (not just virtualization) and refuses to run, independent of the
  VM-detection problem Path A has.

### 3.5 Tauri/launcher integration

A lighter panel than Guest Mode's, structurally identical to Sloboda's
launcher-sync pattern (`apps/sloboda/bin/sloboda-installwatch`, which writes
host `.desktop` entries for installed Android apps and re-enters the
container on click): a Terem App-Mode install-watch enumerates installed
Wine prefixes/apps and writes host `.desktop` launchers that invoke
`wine "$PREFIX" "$APP.exe"` (or the Proton equivalent) — same
per-user-writable-dir default, same `update-desktop-database` best-effort
refresh, same read-only consent-gate check before allowing a launch, per
`02-security-consent-privacy.md` §3.

---

## 4 · Decision matrix — which path, when

| Need | Recommended path | Why |
|---|---|---|
| "I want to run this one Windows program" | **App Mode (Wine/Proton)** first | Lighter, faster, no OS license needed. Fall back to Guest Mode only if the app fails under Wine (§3.4's honest caveat: not everything runs, `03-license-honesty.md` §4). |
| "I want a real Windows desktop / need Windows-specific tooling beyond one app" | **Guest Mode, Windows VM** | Full OS semantics App Mode cannot provide (multiple interacting apps, Windows-specific system services, driver-level software). |
| "I want an Ubuntu/RHEL toolchain, don't need hard isolation" | **Guest Mode, lightweight container (`systemd-nspawn`/Podman)** | Near-zero overhead; the isolation tradeoff is acceptable because the guest is trusted software the operator chose, not an untrusted third party's binary. |
| "I want an Ubuntu/RHEL sandbox with the same isolation strength as the Windows guest" | **Guest Mode, full VM** | Matches Windows guest's isolation posture when that's the actual requirement. |
| "The app is competitive-multiplayer / has kernel-level anti-cheat / plays DRM video" | **Neither path is likely to work** | Disclosed honestly in `03-license-honesty.md` §4, not hidden — mirrors Sloboda's "Play Integrity STRONG fails by design" posture. |

---

## 5 · How this reuses Postern primitives — summary map

| Terem need | Reused primitive | Path | Status |
|---|---|---|---|
| QEMU/KVM VM stack on NixOS | `virtualisation.qemu-vm.nix` module, memory/cores/diskSize sizing, QEMU user-mode NAT | `os/sloboda-vm.nix` | **Real, already written** (as a dev/bring-up scaffold) — generalized here to a product |
| Seal-exclusion for a non-attestable, mutable guest tier | The "never import into the sealed closure," read-only-`/` assertion pattern | `os/sloboda-compat.nix` | **Real pattern** — `os/terem-compat.nix` reuses it verbatim (§2.7) |
| Fixed-binary, no-shell-interpolation command execution from the Tauri backend | `resolve_node_binary`'s name+location+canonicalize+exec-bit check | `desktop/src-tauri/src/main.rs` | **Real, tested code** — the pattern this doc proposes reusing for `qemu-system-x86_64`/`qemu-img` invocation over QMP (no `virsh`, §2.1/§2.6) |
| Tauri capability allowlist discipline (default-deny plugin permissions, app commands not ACL-gated) | `capabilities/default.json`'s documented default-deny stance | `desktop/src-tauri/capabilities/default.json` | **Real, shipped** — no change needed, Terem commands follow the same shape as the existing wallet/vault commands |
| Host-launcher sync for a containerized app surface | `.desktop` generation + `update-desktop-database` refresh + read-only bridge-state check | `apps/sloboda/bin/sloboda-installwatch`, `bin/paw-lib.sh` | **Real, tested (mock-driven) code** — directly reusable shape for App Mode's launcher sync (§3.5) |
| Default-closed, per-capability consent gate for a container/bridge | The consent-spine kernel (`normalize()`-to-deny, schema discriminator, pinned tier) | `apps/consent-contract/consent-spine.mjs`, `apps/noporis-gate/gate-store.mjs` | **Real, shipped, 117-assertion-tested** — `02-security-consent-privacy.md` extends it to a `terem-gate` tier |
| Honest non-attestable labeling for a container tier | The tier-rail / honesty-header discipline, `scripts/check-trust-labels.sh`'s `NONATTEST_PATHS` enforcement | `apps/sloboda/README.md`, `os/sloboda-compat.nix`, `scripts/check-trust-labels.sh` | **Real, enforced in CI** — Terem's surfaces should be added to `NONATTEST_PATHS` once code exists |
| License spine (offline, personal-free-forever, master→sub) | Ed25519 offline chain, 3-tier model | `enterprise/licensing/`, `functions/license/` | **Real, shipped** — reused unmodified for Terem's own license gate (`03-license-honesty.md` §3) |
| Signed, time-boxed, per-crossing consent record | `ConsentRecord`'s 5-step fail-closed check, 4 revocation paths | `apps/noporis-bridge-glue/src/consent_record.rs` | **Real, tested crate** — direct model for Terem's guest↔host bridge consent (`02-security-consent-privacy.md`) |
| Permissive-only license adjudication for a remote-display / VM-adjacent stack | The `POSTERN-CLOUD.md` §8 licensing table (wayvnc ISC + FreeRDP/xrdp Apache-2.0 **in**; SPICE client libs LGPL **out**) | `docs/specs/POSTERN-CLOUD.md` §8 | **Real, already adjudicated** — reused verbatim by Terem's guest-display choice (§2.6), not re-litigated |

---

## 6 · What's explicitly retired from v1, and what survives

| v1 element | v2 status |
|---|---|
| Bare-metal executor, `partition`/`format`/`write-bootloader` verbs against the host's real disk | **Retired.** No verb in v2 ever holds a raw host-disk handle. |
| Three deployment shapes for the executor (bare-metal live/PXE, Chiostro CVM target, enterprise fleet) | **Retired as a disk-executor concern.** The Chiostro CVM shape's *attestation mechanism* (Seal-gate, `postern-seal-companion`) remains relevant only where Terem might someday run a guest inside a Chiostro confidential VM — out of scope for this desktop-first design. |
| `credential-submit` verb for OS vendor activation keys, with its own non-custody statement | **Narrowed, not retired.** Activation still happens, but now entirely *inside* the guest against the vendor's own installer/activation UI — Terem doesn't need a dedicated verb to "submit" a credential because the operator types it directly into the guest, the same way they would on real hardware. See `03-license-honesty.md` §2. |
| The brain/hands (Planner/Executor) split for an AI agent driving the install | **Not carried forward as a requirement.** v1's hardest problem (an AI agent with disk-write authority) mostly disappears once installs happen inside a disposable guest — an interactive install inside a VM is low-stakes enough that an AI-agent installer is a nice-to-have automation, not the safety-critical design centerpiece it had to be in v1. If a future iteration adds an install-automation agent for Guest Mode, the plan-is-data / fixed-verb-set discipline (v1 §2.2–§2.3) is still the right shape to reuse — noted here as [SPECULATIVE / NEW / OPTIONAL], not designed further in this pass. |
| Consent-spine kernel, license spine, honesty-ledger discipline, nominative trademark rules | **Carried forward unmodified.** See §5 and `02`/`03`. |

---

## 7 · Open questions — resolved-by-merge vs. still genuinely open

Filled by Architect 1's / Architect 2's full passes (`A-virtualization.md`,
`B-sandbox-consent.md`), reconciled here:

1. ~~Venus/VirGL maturity verdict~~ **Answered (§2.5, `A-virtualization.md`
   §3.2/§6):** mature and buildable-now on Linux guests; Windows-guest
   support trails and needs a build-time maturity check, not an assumed
   parity. Software rendering stays the zero-hardware-dependency floor, not
   a permanent forced default.
2. `os/terem-compat.nix` skeleton (§2.7) — **still open**, no concrete
   `.nix` file written in either pass; the module *options* and the
   no-libvirtd/QMP-socket shape are specified, the file itself is not.
3. ~~App Mode sandboxing default~~ **Partially answered.** `02` §9.1
   (Architect 2) frames the decision (bubblewrap vs. Flatpak-portal vs.
   firejail, default-on, filesystem allowlist tied to the `sharedFolder`
   consent model) but leaves the final pick **open** — a real remaining
   item, not resolved by either pass.
4. ~~Wine/Proton compatibility variance~~ **Answered**, non-fabricated:
   WineHQ AppDB's own five-tier scale (Platinum→Garbage,
   `A-virtualization.md` §4.2) adopted verbatim rather than inventing a new
   one, folded into `03-license-honesty.md` §4.4.
5. `02-security-consent-privacy.md` — **filled**, reconciling this
   document's sketch with Architect 2's deeper pass (`B-sandbox-consent.md`):
   the VM-vs-container isolation asymmetry, the bridge/widen distinction for
   GPU-USB passthrough, and the "only the host mints" consent model.
6. Chiostro-hosted (cloud) Terem variant — **still open**, flagged only in
   both passes, not designed.
7. **New, surfaced by Architect 1's pass — needs a real decision, not
   inferred:** is "external GPL/LGPL process, invoked via its own protocol,
   never linked" an exception this repo is willing to extend from
   *already-present* system daemons (ModemManager, the kernel) to a
   *newly-bundled-by-us* binary (QEMU, Wine)? §2.1 provisionally says yes
   pending a real license-counsel/`deny.toml`-class pass — that pass has
   not happened and is a precondition for shipping, not a formality.
8. **New, surfaced by Architect 1's pass:** is standalone Proton
   redistribution outside Steam's channel viable at all, or does Terem ship
   vanilla Wine + independently-built DXVK/VKD3D-Proton instead (§3.1)? Not
   resolved — a legal/practical question, not an engineering one.
9. **New, surfaced by Architect 2's pass:** where does the host-side
   `ConsentAuthority` signing key actually live (`02` §3.2/§8 — a daemon
   process, a per-user keyring, something tied to the host's own attested
   identity)? Necessary that the guest can never reach it; the exact
   custody model is still the lead's open call.

---

## 8 · Honesty ledger — real vs. speculative, at a glance

| Claim in this document | Status |
|---|---|
| The bridge-family naming pattern, extended with Terem | **Real geography, new entry** — "Terem" is proposed only, no trademark clearance sought |
| KVM/QEMU (over QMP, no libvirt — corrected per Architect 1's license finding) as the primary guest engine | **Grounded in an already-written primitive** (`os/sloboda-vm.nix`, `os/sloboda-compat.nix`) used today as a dev scaffold, generalized here to a product — the generalization is [SPECULATIVE / NEW]; the no-libvirt correction is grounded in `docs/specs/POSTERN-CLOUD.md` §8's already-adjudicated licensing rule |
| `systemd-nspawn`/Podman (not Distrobox, corrected) as the lightweight Linux-guest path | **[SPECULATIVE / NEW]** as a product — no existing Postern code uses either; both are real, mature, permissively/already-present tools; Distrobox (GPL-3.0) was in the first draft and is corrected out (§2.1) |
| Wine/Proton/DXVK/VKD3D as the App Mode stack | **[SPECULATIVE / NEW]** for this repo — all are real, mature upstream tools with a well-documented compatibility-varies reality; Proton's standalone-redistribution legality is an explicit open question (§3.1, §7 item 8), not assumed clear |
| The "destroy = clean, host never touched" reversibility guarantee | **Real for Guest Mode's disk model** (a guest disk is a file, never a host partition) — this is the actual architectural fix for v1's unsolved kill-switch problem, not a policy promise |
| The Tauri command surface and fixed-binary-invocation pattern | **Directly reuses tested code** (`resolve_node_binary` in `desktop/src-tauri/src/main.rs`) — the Terem-specific commands are new and unbuilt; the no-libvirt, QMP-direct control plane is this merge's correction |
| GPU passthrough feasibility claims | Honestly bounded (§2.5) with concrete detail from Architect 1's pass (IOMMU groups, Code 43, GPU reset bug) — real, well-known hardware-virtualization facts, not fabricated |
| The permissive-only license gate (§2.1) and its libvirt/SPICE/Distrobox exclusions | **Real, grounded in an already-adjudicated repo rule** (`BLOCH-SIS-LINUX.md` §2.4, `docs/specs/POSTERN-CLOUD.md` §8) that this document's first draft violated and this merge corrects — the QEMU/Wine "external process, not linked" extension of that rule is Architect 1's own honest, flagged-not-assumed application of it (§7 item 7) |
| Every item in §5's reuse map | Grounded in cited, existing repo paths for the "reused primitive" column; the Terem-specific application is this document's own proposal |

*Design and scaffold only. UNAUDITED. Do not treat any diagram, lifecycle, or
claim in this document as a security control. Product name "Terem" is
proposed only, pending trademark clearance. Never "Postern Windows,"
"Postern Ubuntu," or "Postern RedHat." BLCH is worthless and is not a
security. Not legal advice.*
