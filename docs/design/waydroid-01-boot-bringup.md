# Waydroid — boot-on-real-hardware bring-up architecture

> Design doc · Architect A7 · scope: the path from **UNTESTED** to a booted
> Android container. Companion to `apps/sloboda/README.md` (the wrapper)
> and `os/boot-harness/` (the mobile boot ladder this plugs into).

> ## Honesty header — read before trusting anything below
>
> This is the **NON-ATTESTABLE escape-hatch tier** ("Postern for postmarketOS —
> community edition"). It is **not** Porog (the stock-Android managed-profile
> product) and **never** "Postern OS." Everything here concerns a **Waydroid**
> container: a full AOSP/Google userland in LXC on the host kernel.
>
> - **This tier is never covered by the Postern Seal.** `os_roothash` says
>   nothing about what runs inside Waydroid. The Android image is mutable state
>   pulled over the network at `waydroid init`. **Do not attest it.**
> - **Entering Android = data leaves the sealed base.**
> - **Play Integrity STRONG will fail** — uncertified container, no hardware TEE
>   keymaster. We **disclose** this; we never spoof it.
> - **microG-vs-GApps is a config input** (`PAW_SYSTEM_TYPE`), defaulting to the
>   Google-free `VANILLA` base. No GMS is redistributed by this tier.
> - **Status today: nothing here has ever booted an Android container.** This doc
>   is the plan that changes that honestly — it does not claim it has happened.

---

## 0. Scope and the gap this closes

The wrapper (`apps/sloboda`) is validated only by `shellcheck` + a mock
(`test/mock-waydroid`) that "boots nothing." The README's section *"Only
confirmable on a real Waydroid device (UNTESTED here)"* enumerates **13 concrete
unknowns**. This document:

1. States the **kernel/OS prerequisites** to run Waydroid at all.
2. Gives the **exact boot sequence** to `Session: RUNNING`, keyed to the strings
   the wrapper actually parses.
3. Specifies the **Wayland compositor** and **GPU** requirements.
4. Maps every one of the **13 unknowns** to a concrete test, says **where it
   runs** (x86_64 Nix VM vs real aarch64 phone), and **what it proves**.
5. Gives a **phased plan to first-successful-boot** — VM first, phone second.

A load-bearing dependency is **missing**: `os/sloboda-compat.nix` is referenced
by the wrapper README as "owned by another developer," but **it does not exist in
the repo today** (`os/` has `mobile.nix`, `telephony.nix`, etc., but no
`sloboda-compat.nix`). Section 1.4 specifies what that module must contain; it is
Phase 0 of the plan.

---

## 1. Kernel & OS prerequisites

Waydroid is **not** an emulator. It runs the Android userland as native processes
in an LXC container against the **host kernel**. That kernel must speak Android's
IPC. This is the single hardest gate and the reason the tier is UNTESTED: our
build sandbox (macOS) has no such kernel, and stock mobile kernels usually lack
the config.

### 1.1 Required kernel features

| Feature | Config symbol | Why | Notes |
|---|---|---|---|
| Binder IPC | `CONFIG_ANDROID_BINDER_IPC` | Android's core RPC bus; every system service uses it. | Upstream since the staging/android days; on mainline Linux ≥5.x it is in-tree (`drivers/android`). |
| binderfs | `CONFIG_ANDROID_BINDERFS` | Per-instance binder devices mounted at `/dev/binderfs`; Waydroid mounts one binderfs per container. | Preferred over static `CONFIG_ANDROID_BINDER_DEVICES` device nodes. |
| (legacy) ashmem | `CONFIG_ASHMEM` | Older Android shared memory. | **Optional on modern Waydroid** — it uses `memfd` on kernels that provide it. Do **not** treat ashmem as a hard gate; treat binder/binderfs as the hard gate. |
| memfd | `CONFIG_MEMFD_CREATE` | Replaces ashmem for shared memory. | Present on any modern kernel. |

Built as `=y` or `=m` both work; `=m` means the module must be loaded (see 1.3).

### 1.2 Which kernels have it — and which don't

- **Mainline / desktop x86_64 kernels** (incl. the kernel a NixOS VM builds):
  binder + binderfs are available; NixOS exposes them via
  `boot.kernelPatches` / `kernelParams` / a config override, or the
  `linuxPackages.*` that already ship `ANDROID_BINDER_IPC`. **Provable in a VM.**
- **PinePhone / Mobile-NixOS / stock mobile kernels: typically LACK them.** These
  are trimmed device kernels; `CONFIG_ANDROID_BINDER_IPC` is usually off. This is
  the exact failure the wrapper's `start` path warns about. Two remedies:
  1. **Build the device kernel with the configs on** (postmarketOS supports this;
     `pmaports` has a `waydroid`-capable path and the `anbox-support`/binder
     configs). This is the clean route for a Nix-built aarch64 kernel too.
  2. **Out-of-tree `binder_linux` DKMS module** (the anbox-modules / binder_linux
     package) for kernels you cannot rebuild. Higher-friction; version-sensitive.

### 1.3 Runtime prerequisites (userland)

- `binderfs` mounted: `mount -t binder binder /dev/binderfs` (Waydroid's own
  init/systemd does this; a Nix module can provide the mount unit).
- **LXC** + `python3` + the **`waydroid`** package on `PATH` (the wrapper's
  `PAW_WAYDROID`, default `waydroid`).
- Root/systemd for the **`waydroid-container`** service (the wrapper's `kill`
  path already targets `systemctl stop waydroid-container`).
- A **Wayland compositor** running before `show-full-ui` / `app launch` (§2.4).
- Network egress at `init` time — the image is **pulled**, not in the rootfs.

### 1.4 `os/sloboda-compat.nix` — the missing Nix wiring (Phase 0 deliverable)

This module does not exist yet and must be authored. Required contents:

- Kernel: ensure `CONFIG_ANDROID_BINDER_IPC=y` + `CONFIG_ANDROID_BINDERFS=y` on
  the target kernel (VM kernel via config override; aarch64 device kernel via the
  Mobile-NixOS kernel derivation).
- `virtualisation.waydroid.enable = true` (the nixpkgs module pulls LXC, sets up
  the `waydroid-container` systemd service and the binderfs mount).
- A compositor for the display path (Weston for the VM; Phosh on the phone).
- **Honesty rails baked in:** this module must **not** be pulled into the sealed
  measurement / seal-gate. It sits outside `os_roothash`'s attested set by
  construction; the mutable Android image guarantees it can never be attested.
  Keep it excluded from the attested closure and label it as the non-attestable
  tier (the repo's `scripts/check-trust-labels.sh` treats `apps/sloboda*`
  as NONATTEST; keep the Nix wiring consistent with that).

---

## 2. Boot sequence to `Session: RUNNING`

The wrapper's control flow is fixed; bring-up means making each real `waydroid`
call succeed. The exact strings the wrapper keys on are in `bin/paw-lib.sh`
(`paw_session_state`).

### 2.1 Milestones

```
[M0] Host ready     kernel binder/binderfs present; /dev/binderfs mounts;
                    waydroid on PATH; compositor running.
        │
[M1] init           sloboda init
                    → (sudo) waydroid init -s VANILLA
                    Pulls the system+vendor image for PAW_SYSTEM_TYPE over the
                    network into /var/lib/waydroid. First real network trust
                    surface. (VANILLA default = no Google, no microG.)
        │
[M2] container up   waydroid-container systemd service starts the LXC container
                    on demand (root). Owns /dev/binderfs, the LXC rootfs overlay.
        │
[M3] session start  sloboda start
                    → waydroid session start   (user service; wrapper backgrounds
                      it and polls)
        │
[M4] RUNNING        wrapper polls `waydroid status` every PAW_READY_INTERVAL (2s)
                    up to PAW_READY_TIMEOUT (90s), matching Session == RUNNING.
                    THIS is "first successful boot."
        │
[M5] display        sloboda ui   → waydroid show-full-ui   (needs §2.4)
     / app          sloboda app <pkg> → waydroid app launch <pkg>
        │
[M6] store/apps     sloboda store → Aurora; app list → .desktop launchers
        │
[M7] teardown       sloboda stop / kill  (kill-switch, §2.5)
```

### 2.2 The exact status contract the wrapper parses

`paw_session_state()` runs `waydroid status` and classifies **only the Session
line**, case-insensitively:

- `*Session*RUNNING*` (or `Running`) → `RUNNING`  ← the gate `paw_wait_ready` waits on
- `*Session*STOPPED*` (or `Stopped`) → `STOPPED`
- empty output → `UNKNOWN`; anything else → `STOPPED`

Real `waydroid status` prints tab-separated lines, e.g.:

```
Session:        RUNNING
Container:      RUNNING
Vendor type:    MAINLINE
IP address:     192.168.240.x
```

Bring-up verification for M4 = confirm the **real** build's `waydroid status`
emits a line matching `Session` + `RUNNING`. If a Waydroid release changes this
wording, the parser (not the container) is what breaks — this is a concrete thing
to check on the target build, not assume.

### 2.3 `PAW_SYSTEM_TYPE` at init (the microG/GApps config input)

- `VANILLA` (default) — AOSP, no Google, no microG. The private base. Bring-up
  starts here.
- `FOSS` — microG-preinstalled image; **upstream images are frequently missing
  (404)**. Bring-up must record whether the channel actually has an image for the
  target arch, not assume it does.
- `GAPPS` — explicit Google opt-in; less private. Not the default; not
  redistributed by us.
- microG can also be added **after** a VANILLA init via the community
  `waydroid_script` post-init (`PAW_MICROG=1` documents, does not automate, this).

### 2.4 Wayland compositor requirement

Waydroid renders the Android surface into a **Wayland** surface. The container
can be `RUNNING` (M4) with **nothing on screen**. `show-full-ui` and `app launch`
only display if a compositor is live:

- **VM:** run **Weston** (or `cage`) — a minimal Wayland compositor is enough to
  prove the display path.
- **Phone:** **Phosh** (the postmarketOS/Mobile-NixOS mobile shell) is the real
  target compositor.

The wrapper already surfaces this: `doctor` reports `WAYLAND_DISPLAY`, and the
`start` failure path names "no active Wayland compositor" as a top cause.

### 2.5 Teardown / kill-switch

- `stop` → `waydroid session stop`.
- `kill` → `waydroid session stop` + `waydroid container stop` (root; falls back
  to `systemctl stop waydroid-container`) + `rm -rf $XDG_RUNTIME_DIR/waydroid`.
  Must leave the provisioned image in `/var/lib/waydroid` **intact and
  re-startable** — verify a `start` after a `kill` reaches RUNNING again without
  a re-`init`.

---

## 3. GPU path

Waydroid picks a graphics backend via image properties (e.g.
`ro.hardware.gralloc` / EGL backend in `waydroid.cfg`).

| Path | Backend | Where it applies | Bring-up note |
|---|---|---|---|
| **Hardware GL** | Mesa **Lima** (Mali-4xx, e.g. PinePhone Mali-400) / **Panfrost** (Mali Midgard/Bifrost) | **Real aarch64 phone GPUs** | The performant, real-device path. **Cannot be exercised in an x86_64 VM.** |
| **Software fallback** | **SwiftShader** / llvmpipe software rendering | VM and any host without a working GL driver | Slow but proves the render pipeline. This is what the VM uses. |

Consequence for the matrix: **the GPU item (README #11) is genuinely phone-only.**
The VM can prove "pixels reach the compositor via software GL"; it can prove
nothing about Lima/Panfrost on a Mali panel.

---

## 4. Verification matrix — the 13 unknowns

Legend for **Where**: **VM** = an x86_64 Linux+Nix VM with a binder-capable
kernel can prove this (the mechanism). **PHONE** = needs real aarch64 phone
hardware. **VM\*** = VM proves the mechanism; a device-specific detail still
needs the phone.

| # | README unknown | Concrete test | Where | What it proves |
|---|---|---|---|---|
| 1 | Kernel binder support | Boot VM kernel; `zgrep ANDROID_BINDER /proc/config.gz`; `modprobe binder_linux` (if `=m`); `mount -t binder binder /dev/binderfs`; confirm `/dev/binderfs` populated. | **VM** (mechanism); **PHONE** (that the *device* kernel has it) | Binder/binderfs work; and separately, whether the PinePhone/Mobile-NixOS kernel needs a rebuild. |
| 2 | `init` pulls an image per type | `waydroid init -s VANILLA` on VM → image lands in `/var/lib/waydroid`. `curl` the image index for `GAPPS`/`FOSS` and for **aarch64**. | **VM** (x86_64 VANILLA/GAPPS); **PHONE/aarch64** (aarch64 image + whether FOSS 404s per-arch) | The init flow works; and which channels actually have images per arch. |
| 3 | microG post-init (`waydroid_script`) | Run the community microG installer after a VANILLA init; confirm services start, no boot-loop. | **VM** (largely arch-independent) | The microG path succeeds and behaves. |
| 4 | `session start` → `Session: RUNNING` + `waydroid-container` service + exact strings | Under the wrapper: `sloboda start` (PAW_DRYRUN=0, real waydroid); confirm `paw_wait_ready` returns 0; diff real `waydroid status` against the `*Session*RUNNING*` parser. | **VM** | **First successful boot** + the status-string contract holds. |
| 5 | Wayland compositor so display works | Start Weston (VM) / Phosh (phone); `sloboda ui`; see the Android UI window. | **VM** (Weston); **PHONE** (Phosh + real panel/touch) | The display path renders; touch/panel is phone-only. |
| 6 | `app list` parser format | `waydroid app list` on the real build; confirm `Name:` / `packageName:` blocks match the wrapper's parser. | **VM** | The launcher generator reads real output. |
| 7 | `app launch <pkg>` foregrounds | `sloboda app <pkg>`; app comes to foreground; single-app vs full-UI behaviour. | **VM** (software GL) | The single-app path works. |
| 8 | Aurora Store install + account-free delivery | Install Aurora in the container; `sloboda store`; download an app anonymously. | **VM\*** (Aurora + delivery); **PHONE** (arm-native apps without a native-bridge on x86) | Aurora works and delivers; arm-only app installs are phone-real. |
| 9 | Host `.desktop` launchers appear + re-enter container | `sloboda launchers`; confirm files in `PAW_DESKTOP_DIR`; click one in the shell grid → container app opens; check write perms if `/usr/share/applications`. | **VM\*** (generation, perms, click-through in a desktop shell); **PHONE** (Phosh app grid) | Launcher generation + round-trip; grid integration is phone-real. |
| 10 | Kill-switch behaviour | `sloboda kill`; confirm session+container down, runtime dir cleared, **image intact**; then `start` again reaches RUNNING with no re-init. | **VM** | Kill-switch privileges + non-destructive teardown. |
| 11 | GPU path (Lima/Panfrost vs SwiftShader) | Inspect active GL backend; on phone confirm Lima/Panfrost drives the Mali panel; on VM confirm SwiftShader fallback. | **PHONE** (hardware GL); VM only proves software fallback | Real-device GPU acceleration. **Phone-only.** |
| 12 | Play Integrity reality | Run a Play Integrity checker app; confirm **STRONG fails** (and MEETS_DEVICE/BASIC results); note which banking/Wallet/DRM apps refuse. | **VM** (STRONG fails — provable anywhere); **PHONE** (which specific apps refuse on the real device) | The honest STRONG-fails label is real; exact refusals are device-real. |
| 13 | Consent-gate integration | Have the consent-gate write `/run/postern/consent/sloboda-bridge.state`; confirm the wrapper's read-only check matches path + `enabled`-on-line-1 format. | **VM** | The bridge state contract matches (filesystem, arch-independent). |

**Phone-only (hard):** #11 (Lima/Panfrost hardware GL). **Phone-real details on
top of a VM-proven mechanism:** the device-kernel half of #1, aarch64 image of
#2, Phosh/touch of #5 and #9, arm-native apps of #8, exact refusals of #12.
**Everything else — the entire control flow, init, Session: RUNNING, status
parse, app list, launch, store, launchers, kill-switch, Play Integrity STRONG
failing, consent-gate — the x86_64 Nix VM can prove.**

---

## 5. What the incoming Linux+Nix VM can boot

Given a Linux host with Nix + a VM whose kernel we control:

**CAN reach first boot in the VM (x86_64 VANILLA image):**
- Build a VM kernel with `CONFIG_ANDROID_BINDER_IPC` + `CONFIG_ANDROID_BINDERFS`;
  mount `/dev/binderfs`. (Binder in a VM kernel is feasible and is the crux.)
- `waydroid init -s VANILLA` → image pull.
- `sloboda start` → **`Session: RUNNING`** under the real `waydroid`
  (this is the milestone that turns UNTESTED into "booted once").
- Weston + `show-full-ui` + `app launch` with **software GL**.
- app-list parser, `.desktop` launchers, Aurora, kill-switch, microG post-init,
  Play-Integrity-STRONG-fails, consent-gate contract.

**CANNOT prove in the VM (needs the PinePhone / Rung 2):**
- Lima/Panfrost **hardware GL** on a Mali panel (#11).
- That the **PinePhone/Mobile-NixOS device kernel** carries binder (the VM proves
  the mechanism, not that specific kernel build).
- **Phosh** app-grid integration, real display/touch (#5, #9).
- **arm-native** app compatibility without a native-bridge (#8), and the exact
  set of apps that refuse on the real device (#12).
- Coexistence with telephony/modem (`os/telephony.nix`) on the phone.

This mirrors the existing mobile boot ladder in `os/boot-harness/`: **Rung 1 =
QEMU/VM software chain; Rung 2 = real PinePhone.** Waydroid bring-up is the same
two-rung shape.

---

## 6. Phased plan to first-successful-boot

| Phase | Goal | Where | Exit criterion (Definition of Done) |
|---|---|---|---|
| **0** | Author `os/sloboda-compat.nix`: binder-enabled VM kernel, `virtualisation.waydroid.enable`, Weston, binderfs mount — kept **out** of the attested/seal closure. | VM host (Nix) | VM boots; `zgrep ANDROID_BINDER /proc/config.gz` shows the symbols; `/dev/binderfs` mounts; `waydroid` on `PATH`. |
| **1** | **First boot.** `init` VANILLA + `start` → `Session: RUNNING` via the wrapper with real waydroid (not the mock). | VM (x86_64) | `sloboda start` returns 0 through `paw_wait_ready`; real `waydroid status` matches the `*Session*RUNNING*` parser. **UNTESTED → booted.** |
| **2** | Display + apps: Weston, `show-full-ui`, `app launch`, `app list` parser, `launchers`, `store` (Aurora), `kill` (image survives, restart works), microG post-init, consent-gate contract. | VM | Matrix items 3,5(VM),6,7,8(VM),9(VM),10,13 pass. |
| **3** | Honest posture confirmed: Play Integrity **STRONG fails**; record BASIC/DEVICE results and refusing apps. | VM | Item 12 (VM part) documented; the README's STRONG-fails label matches observed behaviour. |
| **4** | Cross-arch mechanism: build the **aarch64** kernel with binder; boot an aarch64 VANILLA image under qemu-aarch64 (software GL). | aarch64 VM / qemu | `Session: RUNNING` on aarch64; item 2 aarch64-image half proven — everything but GPU/panel/touch. |
| **5** | **Phone boot (Rung 2).** PinePhone/postmarketOS: device kernel binder, Phosh, **Lima/Panfrost hardware GL**, touch, app grid, real-device Play Integrity + app behaviour. | Real aarch64 phone | Full 13/13, incl. #11. This is the only place #11 and the device-real halves close. |

### Dev-count & phasing

- **~2 focused devs to first VM boot (Phase 1):**
  - *Nix/kernel dev* — Phase 0 `sloboda-compat.nix` + binder-enabled kernel
    (overlaps the existing `os/` Nix owner).
  - *Waydroid bring-up/test engineer* — drives the wrapper against real waydroid,
    Phases 1–4, owns the verification matrix.
- **+1 hardware-rung owner for the phone boot (Phase 5)** — shares the PinePhone
  with the mobile boot Rung-2 owner (`os/boot-harness/success-markers.txt` is
  already jointly owned; Waydroid bring-up hangs off the same hardware rung).

So: **first successful (VM) boot is reachable at Phase 1 with 2 devs**; **first
successful phone boot (Phase 5) adds the hardware owner** and is the only rung
that closes the hardware-GPU and device-real unknowns.

---

## 7. Top risks

1. **Device-kernel binder gap (highest).** PinePhone/Mobile-NixOS stock kernels
   usually lack `ANDROID_BINDER_IPC/BINDERFS`. Mitigation: rebuild the aarch64
   device kernel with the configs (postmarketOS-proven path) rather than relying
   on out-of-tree `binder_linux`.
2. **`sloboda-compat.nix` does not exist yet.** The whole OS wiring the wrapper
   assumes is a stub reference. Phase 0 must author it — and must keep it out of
   the attested closure so nothing here ever reads as Sealed.
3. **Image availability drift.** `FOSS`/microG channels 404 intermittently, and
   availability is per-arch. Verify at bring-up; never assume the channel exists.
4. **Wayland-less "silent boot."** Container `RUNNING` with no compositor looks
   like success but shows nothing. Always pair M4 with a live compositor before
   claiming the display path works.
5. **arm-vs-x86 app reality.** The VM proves the mechanism, not arm-native app
   compatibility; do not over-generalize VM app results to the phone.
6. **Status-string fragility.** A Waydroid release could reword `waydroid status`
   and break the `Session` parser independent of the container booting — check
   the real build's wording at M4.
7. **Honest-label discipline.** This tier must never acquire attestation-grade
   language; Play Integrity STRONG failing is a **disclosed, expected** property,
   not a defect to paper over.
