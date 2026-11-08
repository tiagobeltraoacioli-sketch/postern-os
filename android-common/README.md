<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# android-common — shared managed-profile plumbing

The **generic, hardening-free** AOSP managed-profile (work-profile) provisioning +
lifecycle core, extracted from Porog so that **both** Porog (the hardened *door*) and
**NoporIS** (the dual-persona *bridge*) consume **one** Device Policy Controller
implementation instead of forking a second DPC.

> **This is a SCAFFOLD. DESIGN ONLY · UNAUDITED · reference-prototype.** Nothing here
> has been built with the Android SDK/NDK, and nothing has ever been provisioned on a
> device. It reads idiomatically; that is all. `built ≠ booted`, `QEMU ≠ hardware`,
> `self-checked ≠ audited`. No security claims until an audit gate.

## What is in here (and what is deliberately NOT)

This module holds **only** the plain managed-profile plumbing — no hardening, no
product branding, no GMS:

```
android-common/
├── build.gradle.kts                 com.android.library, namespace labs.postern.common, minSdk 30
└── src/main/
    ├── AndroidManifest.xml          declares NO components (consumers register their own)
    └── java/labs/postern/common/profile/
        ├── provision/
        │   ├── ProvisioningResult.kt                 Dispatched / Cancelled / Unsupported / Failed
        │   ├── ProvisioningPreflight.kt              FEATURE_MANAGED_USERS + isProvisioningAllowed gate
        │   └── ManagedProfileProvisioningActivity.kt abstract; ACTION_PROVISION_MANAGED_PROFILE, parameterized admin component
        ├── lifecycle/
        │   ├── ManagedProfileState.kt                ABSENT / UNSUPPORTED / PROVISIONING / ACTIVE / WIPED
        │   └── ManagedProfileManager.kt              isProfileOwner / canProvision / currentState / profile-scoped wipe
        └── dpc/
            └── ManagedProfileAdminReceiver.kt        abstract DPC skeleton; onProfileOwnerEstablished() hook
```

**NOT here (stays in each product):**
- **Hardening.** Porog's `LockdownPolicy.applyBaseline()` (screen-capture off, IME
  allowlist, cross-profile off, unknown-sources off) is **Porog-only** and lives in
  `android-container/`. The shared DPC skeleton applies **no** policy of its own.
- **Persona flavors + the guarded crossing.** NoporIS's Google-Play persona,
  `enableSystemApp(Play + GMS)`, the consent-gate bridge, and the "less-private side"
  labeling live in the NoporIS app.
- **The attestation and SDK seams.** `AttestationGateway` / `PosternSdkBridge` stay in
  the Porog tree for now (they are not provisioning/lifecycle plumbing).

## How a product consumes it

1. In the product's `settings.gradle.kts`:
   ```kotlin
   include(":android-common")
   project(":android-common").projectDir = file("<relative>/android-common")
   ```
   (Porog uses `../../android-common`.)
2. In the app module's `build.gradle.kts`: `implementation(project(":android-common"))`.
3. Subclass the three abstract seams — supply the admin component, the profile name,
   and (optionally) a post-provisioning policy:
   - `ManagedProfileProvisioningActivity` → override `adminComponent()`.
   - `ManagedProfileAdminReceiver` → override `profileName()`, and override
     `onProfileOwnerEstablished()` **only if** the product applies post-provisioning
     policy. **Porog** overrides it to call `LockdownPolicy.applyBaseline()`;
     **NoporIS** overrides it for a persona flavor, or leaves it empty for the
     deliberately less-private Google-Play persona.
   - `ManagedProfileManager` → instantiate with the app context + admin component
     (Porog wraps it as `ContainerProfileManager`).
4. Register the concrete `DeviceAdminReceiver` and provisioning Activity in the
   product's own manifest with `BIND_DEVICE_ADMIN` and a `device-admin` policy resource.

The enrollment sequence (name → post-provisioning hook → enable) is **shared and
identical** across products; only the hook varies. That is the whole point: one DPC
core, two products, no drift.

## Co-ownership seam

Per the NoporIS Master Plan (§6) this module is **co-owned by the Porog A-lead and the
NoporIS N-lead**. Changes to the generic provisioning plumbing require both to sign off,
so neither product's lifecycle silently breaks the other.

## Licensing / trademark posture

- SPDX `MIT OR Apache-2.0` on every file.
- This module **only calls** Android platform APIs (`DevicePolicyManager`,
  `DeviceAdminReceiver`, `ComponentActivity`). It **redistributes no AOSP source** and
  **bundles no Google Mobile Services**. See `NOTICE`.
- "Android" is used **nominatively** only; this is an app on stock Android — it is
  **NEVER "Postern OS."**

## Rails (non-negotiable)

- UNAUDITED / reference-prototype; no security claims; `self-checked ≠ audited`.
- The managed-profile boundary is only as strong as the Android kernel + SELinux — a
  rooted / kernel-compromised host defeats it. Stated on every surface.
- **NEVER "Postern OS."** Guardian is **Yagabona**, never "Baba Yaga."
- BLCH is worthless and is not a security. Personal use is free. Ownerless base ⟂ owned
  products.
- SPDX `MIT OR Apache-2.0` on every file. Do **not** git commit (the integrator does).
