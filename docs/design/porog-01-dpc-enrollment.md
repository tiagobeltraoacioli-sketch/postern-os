<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Porog 01 — DPC self-enrollment & work-profile lifecycle

**Architect:** A1 (Porog — DPC self-enrollment & work-profile lifecycle).
**Status:** DESIGN / reference-prototype · **UNAUDITED** · never provisioned on hardware.
**Scope of this doc:** the concrete, buildable path to *FUNCTIONAL* for Porog's
managed-profile provisioning and the `provision → lock → suspend → wipe` lifecycle —
on **stock, un-rooted Android the user already owns**. Attestation internals, Tor
egress, and the Rust SDK are *seams* here (owned by A-attest / A-workspace / Dev-B),
not this doc's deliverable.

> ## Honesty rails (binding — `scripts/check-trust-labels.sh` enforces the absolutes)
> - Porog is a **key-attested device, not a measured-boot workspace** — it attests the
>   **phone**, NOT the workspace. **Never** claim the Postern Seal or measured-boot
>   covers Porog.
> - Porog runs on **stock Android** — **no OS replacement, no root, self-enrolled DPC**.
>   It is **NEVER "Postern OS."**
> - Respect Google licenses: **no GMS redistribution, no Play-Integrity circumvention**,
>   Android/Google marks **nominative only**.
> - **"Porog" is a PROPOSED name, pending trademark clearance** (Slavic *threshold /
>   soleira*, the Izbushka tale).
> - Everything below is a **reference/prototype**. `built ≠ booted`, `emulator ≠
>   hardware`, `self-checked ≠ audited`. No security claim survives without an audit
>   gate and on-device proof.
> - A **rooted / kernel-compromised host defeats the entire boundary.** Hardened, not
>   anonymous.

---

## 0. What already exists (this design is a *delta*, not a greenfield)

The provisioning + lifecycle skeleton is already scaffolded in two modules. **Do not
re-invent them** — extend them. This doc's job is to close the named gaps (`lock`,
`suspend`, the onboarding UI, the *functional* test, the toolchain).

```
android-common/                         # SHARED, hardening-free DPC core (co-owned A-lead + N-lead)
  build.gradle.kts                      #   com.android.library · namespace labs.postern.common · minSdk 30
  src/main/AndroidManifest.xml          #   declares NO components
  .../profile/provision/
    ProvisioningResult.kt               #   Dispatched / Cancelled / Unsupported / Failed   [DONE]
    ProvisioningPreflight.kt            #   FEATURE_MANAGED_USERS + isProvisioningAllowed    [DONE]
    ManagedProfileProvisioningActivity.kt  # abstract; ACTION_PROVISION_MANAGED_PROFILE       [DONE]
  .../profile/lifecycle/
    ManagedProfileState.kt              #   ABSENT/UNSUPPORTED/PROVISIONING/ACTIVE/WIPED      [DONE — needs +PAUSED]
    ManagedProfileManager.kt            #   isProfileOwner/canProvision/currentState/wipe     [DONE — needs +lock/+quietMode]
  .../profile/dpc/
    ManagedProfileAdminReceiver.kt      #   abstract DPC; name → hook → enable sequence       [DONE]

android-container/profile/              # POROG app (thin consumer; carries ONLY its hardening)
  settings.gradle.kts / build.gradle.kts / gradle.properties                                 [DONE]
  app/src/main/AndroidManifest.xml      #   ProvisioningActivity + PosternDeviceAdminReceiver [DONE]
  app/src/main/res/xml/device_admin_receiver.xml                                             [DONE]
  app/src/main/res/values/strings.xml                                                        [DONE]
  .../container/provision/ProvisioningActivity.kt   # subclass; adminComponent()             [DONE — UI is a TODO]
  .../container/dpc/PosternDeviceAdminReceiver.kt   # subclass; profileName + lockdown hook   [DONE]
  .../container/dpc/LockdownPolicy.kt               # screenshot/IME/cross-profile/unknown-src[DONE — needs work-challenge + lifecycle policy]
  .../container/lifecycle/ContainerProfileManager.kt# wipeContainerOnly()                     [DONE — needs panicLock/pause/resume]
  .../container/lifecycle/ContainerState.kt         # typealias of shared state               [DONE]
  .../container/attest/AttestationGateway.kt        # A↔attest seam (NoOp stub)               [SEAM — A-attest]
  .../container/sdk/PosternSdkBridge.kt             # A↔B seam (NoOp stub)                     [SEAM — Dev-B]
```

**Design invariant carried forward:** *one* DPC core, *two* products. Every **generic**
managed-profile operation (provision, state, wipe, and — new here — lock and quiet-mode)
lives in `android-common`; Porog adds **only** its vocabulary and its **hardening**
(`LockdownPolicy`). Nothing hardened leaks into the shared module or into NoporIS.
`android-common` changes require **both** the A-lead and the N-lead to sign off.

---

## 1. Provisioning path (self-enrolled, no root, no EMM)

The only mechanism that gives real cryptographic + process isolation on unmodified
stock Android with no root: an **AOSP managed profile (work profile)** created by a
**self-enrolled Device Policy Controller (DPC)** — the Shelter / Island / Insular
pattern. (Device-owner, Knox SDK, and Waydroid are all rejected for this product; see
`design-android-container.md` §1 for the full comparison. Knox is Samsung-EMM-gated;
device-owner needs a factory reset; Waydroid needs a Linux host we control.)

### 1.1 The wire sequence (personal profile → new managed profile)

```
PERSONAL PROFILE (user 0)                       NEW MANAGED PROFILE (user N)
─────────────────────────                       ────────────────────────────
ProvisioningActivity (Compose onboarding)
  └─ requestContainerProvisioning()
       └─ ProvisioningPreflight.check()          # FEATURE_MANAGED_USERS + isProvisioningAllowed
            · non-null  → ProvisioningResult.Unsupported (honest dead-end, NO system UI)
            · null      → startActivityForResult(
                            ACTION_PROVISION_MANAGED_PROFILE
                            + EXTRA_PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME = Porog DPC
                            + EXTRA_PROVISIONING_SKIP_ENCRYPTION = false)   # keep FBE
   ── system provisioning UI runs (user consents) ──▶  framework creates user N,
                                                        installs Porog into it,
                                                        makes the DPC profile owner
   onProvisioningResult(Dispatched)                            │
   (NEVER render "ready" here — truth lands ────────────────▶ PosternDeviceAdminReceiver
    inside the profile)                                         .onProfileProvisioningComplete():
                                                                  1. dpm.setProfileName("Porog")
                                                                  2. onProfileOwnerEstablished():
                                                                       LockdownPolicy.applyBaseline()
                                                                       + require work-challenge
                                                                       + (seam) AttestationGateway
                                                                       + (seam) always-on Tor VPN
                                                                  3. dpm.setProfileEnabled()
```

The `Dispatched` result means only that the system flow was *accepted*. Enrollment
truth is `onProfileProvisioningComplete` **inside** the new profile. This asymmetry is
already encoded in `ProvisioningResult` and must survive into the UI copy.

### 1.2 Min SDK & the exact API per step

`minSdk = 30` (Android 11), `targetSdk = 34`, `compileSdk = 34`. Rationale: managed-
profile provisioning + per-profile policy are stable and well-behaved from R onward,
StrongBox (API 28) is available, and quiet-mode (API 28) is covered. We **never** trust
an SDK level for support — every dispatch is gated at runtime by `ProvisioningPreflight`
/ `isProvisioningAllowed`.

| Lifecycle step | Platform API | Min API | Where it runs |
|---|---|---|---|
| Preflight | `PackageManager.FEATURE_MANAGED_USERS`, `DevicePolicyManager.isProvisioningAllowed` | 21 | personal |
| Provision | `ACTION_PROVISION_MANAGED_PROFILE` + `EXTRA_PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME` | 21 | personal |
| Enroll callback | `DeviceAdminReceiver.onProfileProvisioningComplete` | 21 | **profile** |
| Name / enable | `setProfileName`, `setProfileEnabled` | 21 | profile |
| Baseline hardening | `setScreenCaptureDisabled`, `setPermittedInputMethods`, `addUserRestriction(DISALLOW_*)` | 21 | profile |
| Work challenge (require) | `setRequiredPasswordComplexity(PASSWORD_COMPLEXITY_MEDIUM)` (S+); fallback `setPasswordQuality` | 31 / 21 | profile |
| Work challenge (prompt) | `ACTION_SET_NEW_PASSWORD` | 21 | profile |
| **Lock (Panic)** | `lockNow(FLAG_EVICT_CREDENTIAL_ENCRYPTION_KEY)` | 26 | profile |
| **Suspend / pause** | `UserManager.requestQuietModeEnabled(true, workHandle)` (whole profile) and/or `setPackagesSuspended(admin, pkgs, true)` (per-app) | 28 / 24 | personal (quiet) / profile (suspend) |
| **Wipe (container-only)** | `wipeData(0)` | 21 | profile |

---

## 2. Profile lifecycle: `provision → lock → suspend → wipe`

The state machine, extended from the current `ABSENT/UNSUPPORTED/PROVISIONING/ACTIVE/
WIPED` with a `PAUSED` state (quiet mode). `LOCKED` is deliberately **not** a persisted
enum value — evicting the CE key returns the profile to the OS's normal locked-storage
state; `currentState()` still reports `ACTIVE` (owned) and the lock is a transient
runtime fact, not ground truth. The OS is authoritative for all of this.

```
                 provision (§1)                 requestQuietMode(true)
   ABSENT ───────────────────────▶ ACTIVE ──────────────────────────▶ PAUSED
     ▲                              │  ▲                                 │
     │  wipeData(0)                 │  └──── requestQuietMode(false) ─────┘
     └──────────── WIPED ◀──────────┤
                                    │
                     lockNow(EVICT_CE_KEY)  ── Panic Lock: storage re-encrypts,
                                    │           key evicted from RAM; profile is
                                    └────────▶  still ACTIVE/owned, just locked.
                                               Re-entry needs the work challenge.

   canProvision()==false  ⇒  UNSUPPORTED (honest dead-end, never faked)
```

### 2.1 Lock — the "Panic Lock" (evict + seal)

`dpm.lockNow(DevicePolicyManager.FLAG_EVICT_CREDENTIAL_ENCRYPTION_KEY)` run **as
profile owner inside the profile**. This purges the profile's credential-encryption key
from memory so the profile's FBE storage is sealed at rest until the user re-enters the
**separate work challenge**. This is the substrate for the panic story (the Panic core
owns the higher-level "seal the vault, evict SDK keys" semantics; this class provides
the OS-level lock only).

**Precondition:** a **separate work challenge must exist**, or eviction is meaningless
(no separate CE key to evict). Therefore `LockdownPolicy` must, at enrollment, *require*
a work-profile lock (`setRequiredPasswordComplexity`) and, if absent, drive the user
through `ACTION_SET_NEW_PASSWORD`. Without this, "lock" degrades to a device lock — an
honest limitation to surface in the UI, not to paper over.

### 2.2 Suspend — two honestly-different meanings

- **Pause the whole profile (quiet mode)** — `UserManager.requestQuietModeEnabled(true,
  workProfileHandle)`. This is the platform's standard "pause work apps" toggle: all
  profile apps stop, notifications silence, background work halts. Quiet mode is normally
  toggled from the **personal profile** (the parent / launcher context), not from inside
  the profile — the personal-side surface (a tile in `ProvisioningActivity` or a small
  parent-profile controller) owns this button. Requires the caller to be the profile's
  parent or hold quiet-mode privilege.
- **Suspend specific apps (in-profile)** — `dpm.setPackagesSuspended(admin, pkgs, true)`
  run by the profile owner inside the profile. Finer-grained; used to freeze an
  individual workspace app without pausing the whole container.

Porog's default "Suspend" UX = **quiet mode** (whole-container pause). Per-app suspend is
a secondary control.

### 2.3 Wipe — container-only, never user 0

Already implemented: `wipeData(0)` from the profile owner **inside** the profile removes
*this* profile and its FBE storage and nothing else. `ContainerProfileManager.
wipeContainerOnly()` guards with `check(isProfileOwner())`. Post-condition: framework
destroys the profile → `WIPED` → `ABSENT`. Personal data is never touched.

### 2.4 OEM caveats — what breaks this on real hardware

The state machine is pure AOSP; the **fragile edges are OEM policy layers**. All of these
must be verified on real devices (§5, T2) and honestly labeled — the emulator cannot see
any of them.

| OEM / layer | What breaks | Mitigation / honest label |
|---|---|---|
| **Samsung One UI / Knox** | Knox permits generally **one** work profile; Knox container / Secure Folder can collide with a self-enrolled profile. Some builds gate `setAlwaysOnVpnPackage` and quiet-mode behind Knox policy. Knox attestation is a *separate* path we do **not** use. | Detect an existing profile in preflight → `Unsupported`. Knox is an *optional future hardening on Samsung*, never the base. Never imply Knox-grade guarantees. |
| **Xiaomi MIUI / HyperOS** | Aggressive background killing murders the DPC and the always-on VPN (Tor lockdown leaks/drops); some regional builds ship **without** `FEATURE_MANAGED_USERS` or return `isProvisioningAllowed == false`; delayed/again-prompt provisioning. | Preflight catches missing feature → honest `Unsupported`. Document the battery-killer risk to always-on VPN; do not claim leak-proof egress on MIUI without on-device proof. |
| **Huawei EMUI / others** | Similar background-kill; no GMS (irrelevant to us — we ship no GMS); occasional managed-user restrictions. | Preflight + honest per-device support matrix. |
| **Android Go / budget** | `FEATURE_MANAGED_USERS` frequently **absent**. | Preflight → `Unsupported`, no fake. |
| **Any OEM** | `setPermittedInputMethods` / `setScreenCaptureDisabled` enforcement quality varies; always-on-VPN lockdown semantics vary. | Treat every policy as *requested*, verify enforcement per device, label "hardened, not anonymous." |

The load-bearing honesty: **these toggles are enforced by the Android framework + kernel,
not by Porog.** They are exactly as strong as the profile boundary. A rooted host ignores
all of them.

---

## 3. The build delta — exact files/classes to create

Ordered, minimal, and confined to the two existing modules. `[new]` = create,
`[edit]` = extend an existing file.

### 3.1 `android-common` (generic; both sign-offs required)

1. `[edit] .../lifecycle/ManagedProfileState.kt` — add **`PAUSED`** (quiet mode) to the
   enum, documented as transient ACTIVE↔PAUSED.
2. `[edit] .../lifecycle/ManagedProfileManager.kt` — add generic, product-neutral
   transitions:
   - `@WorkerThread fun lockProfileNow(evictCeKey: Boolean)` → `lockNow(...)` with the
     `FLAG_EVICT_CREDENTIAL_ENCRYPTION_KEY` flag when `evictCeKey && SDK>=26`; guarded by
     `check(isProfileOwner())`.
   - `fun setPaused(paused: Boolean): Boolean` → `UserManager.requestQuietModeEnabled`;
     returns the platform's success flag (may be intercepted for a user-confirm); marked
     as a **personal/parent-context** call in KDoc.
   - `@WorkerThread fun suspendPackages(pkgs: List<String>, suspended: Boolean)` →
     `setPackagesSuspended`, profile-owner context.
   - extend `currentState()` to report `PAUSED` when quiet mode is on (via
     `UserManager.isQuietModeEnabled`).

### 3.2 `android-container/profile` (Porog-only)

3. `[new] .../dpc/WorkChallengePolicy.kt` — require + prompt a **separate work
   challenge**: `setRequiredPasswordComplexity(PASSWORD_COMPLEXITY_MEDIUM)` (S+) with a
   `setPasswordQuality` fallback for API 30; `promptSetWorkChallenge()` firing
   `ACTION_SET_NEW_PASSWORD`. Precondition for a meaningful Panic Lock (§2.1).
4. `[edit] .../dpc/LockdownPolicy.kt` — in `applyBaseline()`, after the existing
   screenshot/IME/cross-profile/unknown-source policy, call
   `WorkChallengePolicy.require()`. (Tor always-on VPN stays a labeled seam for
   A-workspace.)
5. `[edit] .../lifecycle/ContainerProfileManager.kt` — Porog vocabulary over the new
   shared transitions:
   - `fun panicLock() = lockProfileNow(evictCeKey = true)`
   - `fun pauseContainer() = setPaused(true)` / `fun resumeContainer() = setPaused(false)`
   - (`wipeContainerOnly()` already present)
6. `[new] .../provision/OnboardingScreen.kt` — the Compose "Create Porog" screen: the
   honesty banner ("hardened, not anonymous · key-attested device, not measured-boot
   workspace · DESIGN ONLY · UNAUDITED · never 'Postern OS'"), a single **Create Porog**
   CTA → `requestContainerProvisioning()`, and honest result rendering that **never**
   claims ready on `Dispatched`.
7. `[edit] .../provision/ProvisioningActivity.kt` — `setContent { OnboardingScreen(...) }`;
   render `onProvisioningResult` states; host the personal-side **Suspend/Resume** tile
   (quiet mode is a parent-context action).
8. `[edit] app/src/main/res/xml/device_admin_receiver.xml` — already declares
   `wipe-data`, `force-lock`, `limit-password`, `disable-keyguard-features` — confirms the
   new lock/challenge policies are covered; no change expected, verify only.

### 3.3 Test & toolchain artifacts (§4, §5)

9. `[new] android-container/profile/app/src/androidTest/java/labs/postern/container/ProfileLifecycleE2ETest.kt`
   — the instrumented functional test.
10. `[new] android-container/profile/test/e2e/provision-lifecycle.sh` — adb-driven
    harness that stands in for the interactive system provisioning UI on emulator/CI.
11. `[new] android-container/profile/toolchain/flake.nix` (+ `README`) — pinned Android
    SDK + emulator devshell for the Linux+Nix VM.

No new manifest components beyond what exists. No GMS, no new dangerous permissions.

---

## 4. Toolchain & infra — where this is built and tested

**The macOS host has NO Android SDK and cannot build or run this.** Nothing in the Porog
Kotlin tree has ever been compiled. The build/test target is the **incoming Linux + Nix
VM**. On macOS the ceiling is `ktlint`/static read-through only — never a build claim.

### 4.1 Toolchain (pin all of it in Nix)

- **JDK 17**, **Android Gradle Plugin 8.5.0**, **Kotlin 1.9.24** (already pinned in the
  Gradle files), **Compose compiler 1.5.14**.
- **Android SDK**: `cmdline-tools` (latest), `platform-tools`, `platforms;android-34`,
  `build-tools;34.0.0`, `emulator`, and a **system image** (see below). Pin via
  nixpkgs `androidenv.composeAndroidPackages` (or `android-nixpkgs`) in
  `toolchain/flake.nix` so the VM is reproducible and license-accepted non-interactively.
- **KVM** on the Linux VM for a usable emulator (hardware accel). Match the emulator ABI
  to the VM CPU (`x86_64` on an x86 VM; `arm64-v8a` on a Graviton/Apple-silicon VM).

### 4.2 Which emulator image — and what it can vs cannot prove

**Use a work-profile-capable image: `system-images;android-34;google_apis;<abi>` or the
AOSP `default` image.** These support `FEATURE_MANAGED_USERS` and let a self-enrolled DPC
create a managed profile. **Avoid `google_apis_playstore` images** — the Play-flavored
images restrict provisioning and are the wrong test surface (we also make zero
Play-Integrity or GMS claims).

| The emulator **CAN** prove (CI-grade functional) | The emulator **CANNOT** prove (hardware-only) |
|---|---|
| The full `provision → lock → suspend → wipe` state machine runs, self-enrolled, **no root**. | **StrongBox / TEE hardware attestation** — the emulator's keymaster is software; the cert chain is the emulator's, `Tier` is `TEE`/`NONE`, never `STRONGBOX`. |
| `onProfileProvisioningComplete` fires the shared name → hardening → enable sequence. | Real **OEM behavior** (Knox, MIUI battery-kill, missing `FEATURE_MANAGED_USERS`). |
| `LockdownPolicy` toggles apply (screenshot off, IME allowlist, cross-profile off, unknown-sources off) — observable via DPM/adb. | **Play Integrity STRONG** reality on banking/Wallet/DRM. |
| Lock evicts the CE key; quiet mode pauses; `wipeData(0)` removes **only** the profile. | Real **Orbot Tor always-on-VPN** lockdown with no leaks on cellular. |
| `ProvisioningPreflight` returns honest `Unsupported` when the platform says so. | Battery/thermal/real-network resilience of the always-on VPN + DPC. |

The interactive `ACTION_PROVISION_MANAGED_PROFILE` consent UI is not scriptable
headlessly. The CI harness therefore **exercises the same enrolled code path** via adb
(§5) and defers the true one-tap consent flow to the real-device tier.

---

## 5. The FUNCTIONAL-proof test (and exactly where it runs)

**Definition of FUNCTIONAL for Porog's DPC/lifecycle scope:** on a work-profile-capable
Android target, a **self-enrolled, no-root** DPC drives the complete `provision → lock →
suspend → wipe` lifecycle, and **every transition is observable via platform ground
truth** (DPM queries + adb), with honest `Unsupported` dead-ends where the platform
refuses. Two tiers, because one tier alone would over- or under-claim:

### T1 — CI functional smoke (Linux+Nix VM emulator; gates every change)

`test/e2e/provision-lifecycle.sh` + `ProfileLifecycleE2ETest.kt`. Because the consent UI
is not headless, the harness enrolls the **same** `PosternDeviceAdminReceiver` via adb,
then asserts each transition against the OS:

1. `pm create-user --profileOf 0 --managed Porog` → capture user N.
2. Install the APK into user N; `dpm set-profile-owner <PosternDeviceAdminReceiver> N`.
3. Trigger the enrollment sequence (broadcast `PROFILE_PROVISIONING_COMPLETE` to the
   receiver in user N) → assert `setProfileName`/`setProfileEnabled` ran and
   `LockdownPolicy` applied: `dumpsys device_policy` shows screen-capture disabled,
   permitted-IME allowlist set, `DISALLOW_CROSS_PROFILE_COPY_PASTE` +
   `DISALLOW_INSTALL_UNKNOWN_SOURCES` present, work-challenge complexity required.
4. **Lock:** invoke `panicLock()`; assert the profile is locked (`am get-current-user` /
   profile locked state; CE storage sealed).
5. **Suspend:** `requestQuietModeEnabled(true)`; assert `isQuietModeEnabled == true` and
   `currentState() == PAUSED`; resume and assert back to `ACTIVE`.
6. **Wipe:** `wipeContainerOnly()`; assert user N is gone (`pm list users`) and user 0
   untouched.
7. **Negative:** on an image lacking `FEATURE_MANAGED_USERS`, assert
   `ProvisioningPreflight` → `Unsupported` (no system flow launched).

Green T1 proves the **state machine + policy application + honest-refusal logic** on the
SDK. It proves **nothing** about hardware attestation or OEM behavior — labeled as such.
**Runs on the Linux+Nix VM only. Cannot run on macOS (no SDK) and cannot prove the
hardware-only rows of §4.2.**

### T2 — Real-device acceptance (stock AOSP-clean Pixel; the true product claim)

The `provision → lock → suspend → wipe` claim on *the phone you already own* is only
*proven* here. A manual/instrumented checklist on a stock, un-rooted, AOSP-clean **Pixel**
(no root, no unlock-required): drive the **real** one-tap `ACTION_PROVISION_MANAGED_PROFILE`
flow from `OnboardingScreen`; confirm the profile is created and named; confirm
`AttestationGateway` reports **`Tier.STRONGBOX`** with a valid Google-rooted chain (the
A-attest seam); then exercise Panic Lock, quiet-mode suspend, and container-only wipe. A
second pass on **Samsung One UI** and **Xiaomi MIUI/HyperOS** populates the honest §2.4
support matrix (expect the documented failures). **Must run on hardware — impossible on
macOS or emulator.**

**Ship-gate:** T1 green in CI **and** T2 acceptance passed on ≥1 stock Pixel, with the §2.4
matrix filled from real Samsung + Xiaomi runs, before any surface drops the "SCAFFOLD /
DESIGN ONLY" label. Until then: **UNAUDITED, never provisioned on hardware.**

---

## 6. Phased dev task-list (build order)

Estimated **3 developers** for the DPC/lifecycle scope (A-lead + A2 UI + a shared-VM/test
dev), coordinating with A-attest (StrongBox), A-workspace (Tor VPN + consent gate), and
Dev-B (SDK) across their seams. Phases are strictly ordered; P0 unblocks everything.

- **P0 — Toolchain stand-up (VM/test dev).** Bring up the Linux+Nix VM; write
  `toolchain/flake.nix` pinning the Android SDK + `google_apis` API-34 image + KVM
  emulator; get `./gradlew :app:assembleDebug` to compile the existing scaffold for the
  first time ever. *Exit:* the tree builds; emulator boots a work-profile-capable image.
- **P1 — Lifecycle core (A-lead, in `android-common`, both sign-offs).** Add `PAUSED`;
  add `lockProfileNow` / `setPaused` / `suspendPackages` and the `PAUSED` reporting to
  `ManagedProfileManager`. *Exit:* generic transitions compile with unit coverage of the
  `isProfileOwner` guards.
- **P2 — Porog lifecycle + challenge (A-lead, Porog tree).** `WorkChallengePolicy`; wire
  it into `LockdownPolicy.applyBaseline()`; add `panicLock`/`pauseContainer`/
  `resumeContainer` to `ContainerProfileManager`. *Exit:* Panic Lock has a real separate
  work challenge to evict.
- **P3 — Onboarding UI (A2).** `OnboardingScreen` + `ProvisioningActivity` wiring; honesty
  banner; honest `Dispatched`-vs-complete rendering; personal-side Suspend/Resume tile.
  *Exit:* one-tap "Create Porog" drives the real provisioning intent.
- **P4 — T1 functional smoke (VM/test dev).** `provision-lifecycle.sh` +
  `ProfileLifecycleE2ETest`; wire into CI on the VM. *Exit:* T1 green; every §5 assertion
  passes on the emulator.
- **P5 — Seam integration (A-lead + A-attest + A-workspace).** Replace the `AttestationGateway`
  and always-on-VPN NoOps at the labeled call sites; keep `PosternSdkBridge` NoOp (workspace
  apps embed the SDK, not this shell). *Exit:* enrollment optionally fires a StrongBox
  attested-key generation and the Tor lockdown VPN.
- **P6 — T2 real-device acceptance (A-lead + A2).** Run the §5 T2 checklist on a stock
  Pixel; fill the §2.4 OEM matrix from Samsung + Xiaomi. *Exit:* the ship-gate is met; the
  label can move from "SCAFFOLD" to "prototype validated on hardware" (still UNAUDITED
  until a security audit).

---

## 7. Honesty constraints to keep verbatim on every surface

- **Key-attested device, not a measured-boot workspace.** Attests the **phone**, not the
  workspace. **Never** claim the Postern Seal / measured-boot / `os_roothash` covers Porog.
- **Stock Android, no OS replacement, no root, self-enrolled DPC. NEVER "Postern OS."**
- **Hardened, not anonymous. A rooted / kernel-compromised host defeats the whole boundary.**
- **No GMS redistribution, no Play-Integrity circumvention; Android/Google marks nominative
  only.** StrongBox is classical P-256 — **no post-quantum in hardware**.
- **"Porog" is a PROPOSED name, pending trademark clearance.**
- **SCAFFOLD · DESIGN ONLY · UNAUDITED · never provisioned on hardware** until the §5
  ship-gate. `built ≠ booted`, `emulator ≠ hardware`, `self-checked ≠ audited`.

---

## Sources & cross-refs

- `apps/sloboda/README.md` — the two-products disambiguation table (this is *not*
  the Waydroid tier).
- `docs/design/design-android-container.md` — the mechanism comparison (§1) and the
  REAL-vs-NOT ceiling this doc builds on.
- `docs/specs/POSTERN-CONTAINER.md` — the in-repo spec that first picked managed-profile +
  StrongBox.
- `android-common/README.md` — the shared-core contract and co-ownership seam.
- Existing scaffold: `android-common/**`, `android-container/profile/**`.
