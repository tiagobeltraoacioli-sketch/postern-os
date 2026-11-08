<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Porog — managed-profile DPC scaffold (A2)

**Porog** *(name PROPOSED, pending trademark clearance)* is the Android front of the
**Postern** suite: a hardened, key-attested privacy workspace on the **stock Android
you already own** — no OS replacement, no root. This tree is the **housing**: the
self-enrolled Device Policy Controller that provisions and manages the container
profile.

> **UNAUDITED · reference-prototype.** The debug APK now **builds for real** with the
> Android SDK (`./gradlew :app:assembleDebug`, or `./build-and-verify.sh` for the
> assemble-then-assert gate) — but nothing here has ever been provisioned on a device,
> nothing is audited, and no NDK cores are embedded (the housing is core-free by
> design). `built ≠ booted`, `QEMU ≠ hardware`, `self-checked ≠ audited`. No security
> claims until an audit gate.

## The honest one-liner (keep verbatim)

Porog attests the **phone**, not the **workspace**. It is **hardened, not anonymous;
key-attested, not measured-boot.** A rooted / kernel-compromised host defeats the
profile boundary entirely — say so. For end-to-end measured boot of an audited image,
that is **Postern OS Mobile**, a different product. This is **NEVER "Postern OS."**

The full decision + trust boundary is in `../POSTERN-CONTAINER.md` (the A1 record).

## What's here (A1–A2 scope: provisioning + lifecycle + the AOSP decision)

The generic, hardening-free provisioning + lifecycle + DPC skeleton has been **extracted
to the shared `android-common/` module** (repo root, `../../android-common`) so Porog and
NoporIS consume **one** DPC core instead of forking a second. Porog is now a **thin
consumer** that subclasses `android-common`'s abstract seams and adds **only** its
hardening (`LockdownPolicy`). Behavior is identical to the pre-extraction scaffold.

```
../../android-common/  ← SHARED (co-owned Porog A-lead + NoporIS N-lead)
    provision/ ManagedProfileProvisioningActivity (abstract) · ProvisioningPreflight · ProvisioningResult
    lifecycle/ ManagedProfileManager · ManagedProfileState
    dpc/       ManagedProfileAdminReceiver (abstract; onProfileOwnerEstablished hook)

profile/       ← POROG (this tree)
├── settings.gradle.kts                  includes :android-common (../../android-common) + :app
├── build.gradle.kts / gradle.properties
└── app/
    ├── build.gradle.kts                  minSdk 30, Compose; implementation(project(":android-common")); NO postern-sdk dep (seam only)
    ├── proguard-rules.pro                 keep the DeviceAdminReceiver
    └── src/main/
        ├── AndroidManifest.xml            ProvisioningActivity + PosternDeviceAdminReceiver (BIND_DEVICE_ADMIN)
        ├── res/xml/device_admin_receiver.xml   declared device-admin policies (wipe, lock, keyguard features)
        ├── res/values/strings.xml         Porog labels + honest DPC description
        └── java/labs/postern/container/
            ├── provision/
            │   └── ProvisioningActivity.kt   thin: subclasses ManagedProfileProvisioningActivity, supplies Porog admin component
            ├── dpc/
            │   ├── PosternDeviceAdminReceiver.kt  thin: subclasses ManagedProfileAdminReceiver; applies LockdownPolicy in onProfileOwnerEstablished
            │   └── LockdownPolicy.kt          POROG-ONLY baseline lockdown (screen capture off, IME allowlist, cross-profile off, no unknown sources)
            ├── lifecycle/
            │   ├── ContainerState.kt          typealias → common ManagedProfileState (ABSENT / UNSUPPORTED / PROVISIONING / ACTIVE / WIPED)
            │   └── ContainerProfileManager.kt  thin: subclasses ManagedProfileManager; wipeContainerOnly() → wipeProfileOnly()
            ├── attest/AttestationGateway.kt   A↔attest seam: nonce → cert chain → verdict/tier (NO-OP stub)
            └── sdk/PosternSdkBridge.kt         A↔B seam: libpostern_sdk.so availability (NO-OP stub)
```

`ProvisioningPreflight` and `ProvisioningResult` moved to `android-common` (they were
generic); the Porog copies were removed. `LockdownPolicy` — the only hardening — stays
here, Porog-only, and is never pulled into the shared module or into NoporIS.

## Scope & seams (who owns what)

**Dev A-lead owns here (A1–A2):** the `ACTION_PROVISION_MANAGED_PROFILE` flow, the DPC
receiver + becoming profile owner, the baseline lockdown, profile lifecycle + the
container-only wipe, and the A1 decision record.

**NOT owned here — consumed as clearly-labeled seams:**
- **StrongBox key generation + the mobile Key-Attestation verify backend** → Dev
  A-attest. Consumed via `attest/AttestationGateway` (nonce → chain → verdict); ships a
  NO-OP stub that fabricates nothing.
- **Tor always-on lockdown VPN + `postern-policy` consent gate + workspace apps** → Dev
  A-workspace. `LockdownPolicy.applyBaseline()` documents the `setAlwaysOnVpnPackage`
  call site as a seam; Orbot wiring and leak testing are A4, not here.
- **The Rust cores / `postern-sdk` UniFFI facade** → Dev-B. Consumed via
  `sdk/PosternSdkBridge` (NO-OP stub). The housing embeds no cores; workspace apps
  inside the profile do.

## Build chain (the recipe — now actually built)

Building needs the Android SDK (platform `android-34` + build-tools `34.0.0`) and a
**JDK 17** (AGP 8.5). Given those, this is a self-contained Gradle project and the
debug APK builds for real — this is the "first-ever real build" the toolchain README
described, no longer deferred-to-VM.

```bash
# From android-container/profile/ (a self-contained Gradle project):
./gradlew :app:assembleDebug        # → app/build/outputs/apk/debug/app-debug.apk

# Or the reproducible build + acceptance gate (assembles, then asserts via aapt that
# the APK carries the DeviceAdminReceiver and minSdk 30 / targetSdk 34):
./build-and-verify.sh
```

Verified output (`aapt dump`): `app/build/outputs/apk/debug/app-debug.apk`, with
`sdkVersion:'30'`, `targetSdkVersion:'34'`, `provides-component:'device-admin'`, and
the `labs.postern.container.dpc.PosternDeviceAdminReceiver` receiver gated by
`BIND_DEVICE_ADMIN` (`DEVICE_ADMIN_ENABLED` + `PROFILE_PROVISIONING_COMPLETE` filters).

**`built ≠ booted`.** This is a debug APK, signed with the debug key. It is NOT
provisioned on hardware, NOT run through the T1 instrumented lifecycle (that path
still needs a work-profile AVD / device — see `toolchain/README.md`), and NOT audited.
Distribution channel is **F-Droid + a signed direct APK** (Google Play is a poor fit
for the DPC provisioning APIs); a real release additionally needs a release APK signing
config, still absent by design.

## Rails (non-negotiable)

- UNAUDITED / reference-prototype; no security claims; `self-checked ≠ audited`.
- "Hardened, not anonymous. Key-attested device, not measured-boot workspace."
- A rooted / kernel-compromised host defeats the boundary — stated on every surface.
- **NEVER "Postern OS."** The guardian's hut in the brand is **Yagabona**, never
  "Baba Yaga."
- BLCH is worthless and is not a security. Personal use is free. Ownerless base ⟂ owned
  products.
- SPDX `MIT OR Apache-2.0` on every file. Do **not** git commit (the integrator does).
