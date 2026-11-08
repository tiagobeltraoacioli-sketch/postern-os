<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# NoporIS — persona MECHANISM scaffold (Dev N-lead)

**NoporIS** *(name PROPOSED, pending trademark clearance — shares the "Nopor" root with an
existing filing)* is the Android **bridge** of the **Postern** suite: a dual-persona layer
that runs a *second world* — a business/clean side or a deliberately **less-private
Google-Play side** — on the **stock Android you already own**, no OS replacement, no root.
Porog is the guarded *door*; NoporIS is the guarded *bridge*.

> **This is a SCAFFOLD. DESIGN ONLY · UNAUDITED · reference-prototype.** It now **compiles**
> and its pure JVM unit tests pass on JDK 17 + a local Android SDK (`./gradlew
> :app:testDebugUnitTest :app:assembleDebug` produces a debug APK — see *Build chain*), but
> nothing here has ever been **provisioned or booted on a device**, and none of it is audited.
> `built ≠ booted`, `QEMU ≠ hardware`, `self-checked ≠ audited`. No security claims until an
> audit gate.

## The honest one-liner (keep verbatim)

NoporIS gives you **separation and convenience, not privacy.** The **Google-Play persona is
the less-private side by construction — it phones home to Google.** The separation is
exactly the Android kernel + SELinux profile boundary; a **rooted / kernel-compromised host
defeats it.** It attests the **phone, not the persona.** This is an app on stock Android —
**NEVER "Postern OS."**

## What this tree is (and is NOT)

This tree owns the **persona mechanism** only: the flavor selector, the single-slot
collision resolution, and the persona lifecycle. It is **Porog's DPC + a thin mechanism
layer** — it does **NOT** re-implement provisioning, lifecycle, lockdown, or the seams.

- **CONSUMES** the shared managed-profile DPC (`android-common/`, extracted from Porog by
  Dev N-common). The exact interface this app builds against — and the two small
  `[extraction ask]` hooks — is pinned in **[`COMMON-INTERFACE.md`](./COMMON-INTERFACE.md)**.
  `android-common` has landed, so the `:android-common` Gradle include and the
  `implementation(project(":android-common"))` dependency are **live** (this app compiles
  against the real module); the Kotlin `import labs.postern.common.*` lines are the contract.
- **Does NOT own** `android-bridge/persona/play/` — the Google-Play persona's Compose
  surface, the "less-private side" in-product labeling, and the microG-vs-GApps posture UI
  belong to **Dev N-play**. This tree exposes only the mechanism seam
  (`flavor/PlayEnablementPlan.kt`) that N-play plugs a chosen posture into.

## The mechanism, concretely

### 1. Flavor selector (`flavor/`)

One extra provisioning input picks which world occupies the single managed profile:

- `PersonaFlavor.CLEAN` — hardened, GMS-free (**== Porog's container**). Reuses the shared
  `LockdownPolicy.applyBaseline()` verbatim.
- `PersonaFlavor.GOOGLE_PLAY` — the **less-private side**. *Omits* the baseline (the one
  removable hardening call), enables Play/GMS **system apps already on the device**
  in-profile (`enableSystemApp` — no GMS redistribution), keeps cross-profile clipboard off.

**Fail-closed:** the flavor crosses the profile boundary as a wire tag in the provisioning
admin-extras bundle; a missing/unknown/malformed tag ⇒ `CLEAN` (the more-private side).
*The less-private Google-Play flavor is only ever selected by an exact `"google-play"`.*

### 2. Single-slot collision resolution (`slot/`) — the CRITICAL constraint

Stock Android allows **exactly one managed (work) profile per user.** So NoporIS **cannot**
add a persona next to an existing work profile. Resolution the mechanism design chose:
**NoporIS is the persona *orchestrator* of that one slot** — the single profile holds the
clean flavor (== Porog) *or* the Google-Play flavor, chosen at provisioning, mutually
exclusive. Two worlds, one guarded crossing; the platform enforces exactly two.

The collision with Porog is handled **fail-closed and honestly**:

| Slot state | Meaning | NoporIS behaviour |
|---|---|---|
| `EMPTY` | no work profile; slot free | provisioning offered (the only such state) |
| `OWNED` | a NoporIS persona we own holds the slot | switch / destroy-this-world-only; no second persona |
| `FOREIGN` | another work profile (Porog, employer, Shelter) holds the slot | **refuse**, surface the honest choice; never fake EMPTY, never a second-provision attempt |
| `UNSUPPORTED` | device can't host a managed profile at all | honest dead-end; note Android 15+ Private Space is an OS-driven fallback, **not** this app's mechanism |

The decision is a **pure, unit-tested** function (`slot/PersonaSlotPolicy.kt`), separated
from the Android-touching resolver so the fail-closed logic runs on a plain JVM.

### 3. Persona lifecycle (`lifecycle/`)

Three verbs over the shared DPC:

- **provision(flavor)** — gated on `EMPTY` (fail-closed); dispatch is the shared
  `ACTION_PROVISION_MANAGED_PROFILE` flow from the personal-profile
  `PersonaProvisioningActivity`, carrying the flavor in admin-extras.
- **switch (pause/resume)** — the honest ceiling: a DPC cannot force the launcher to
  foreground a world, so NoporIS toggles the persona's **quiet-mode** (pause/resume) and
  surfaces which world is live. Fails to `false` rather than fake a switch.
- **destroy-this-world-only** — profile-scoped `wipeData` via the shared manager
  (`wipeProfileOnly()`): tears down **THIS** persona's profile + FBE storage, **never**
  user 0 / personal data. NoporIS's "un-bridge."

## Layout

```
android-bridge/persona/
├── README.md                     this file
├── COMMON-INTERFACE.md           the android-common contract this app builds against
├── settings.gradle.kts / build.gradle.kts / gradle.properties
└── app/
    ├── build.gradle.kts          minSdk 30, Compose; depends on :android-common (live include)
    ├── proguard-rules.pro        keep NoporIsDeviceAdminReceiver
    └── src/
        ├── main/
        │   ├── AndroidManifest.xml           PersonaProvisioningActivity + NoporIsDeviceAdminReceiver
        │   ├── res/xml/device_admin_receiver.xml   wipe-data (destroy-this-world), force-lock, …
        │   ├── res/values/strings.xml         honest DPC description ("less-private side / phones home")
        │   └── java/labs/postern/persona/
        │       ├── flavor/
        │       │   ├── PersonaFlavor.kt        CLEAN | GOOGLE_PLAY + fail-closed fromWireTag()
        │       │   ├── PersonaPolicySet.kt     clean → shared applyBaseline(); play → enableSystemApp, no baseline
        │       │   └── PlayEnablementPlan.kt   mechanism↔N-play seam (posture-aware plan; default enables nothing)
        │       ├── slot/
        │       │   ├── PersonaSlot.kt          EMPTY | OWNED | FOREIGN | UNSUPPORTED
        │       │   ├── PersonaSlotPolicy.kt    PURE fail-closed decision (unit-tested)
        │       │   └── PersonaSlotResolver.kt  reads OS facts via the shared ManagedProfileManager
        │       ├── lifecycle/
        │       │   ├── PersonaState.kt         slot + flavor + paused snapshot
        │       │   └── PersonaLifecycle.kt     provision-gate / pause-resume / destroy-this-world-only
        │       ├── provision/
        │       │   └── PersonaProvisioningActivity.kt   slot gate + flavor extra over the shared flow
        │       ├── bridge/
        │       │   ├── CrossingBearerPolicy.kt  PURE fail-closed sealed-frame screening (unit-tested)
        │       │   ├── DeliveryReceipt.kt        content-free bearing result (fact + size, never bytes)
        │       │   └── CrossProfileBrokerService.kt  dumb-bearer IPC seam (UNTESTED-until-VM)
        │       └── dpc/
        │           └── NoporIsDeviceAdminReceiver.kt    subclass of shared BaseDeviceAdminReceiver; flavor-aware body
        └── test/java/labs/postern/persona/
            ├── PersonaFlavorTest.kt            fail-closed flavor parsing
            ├── PersonaSlotPolicyTest.kt        fail-closed single-slot resolution
            └── CrossingBearerPolicyTest.kt     fail-closed cross-profile bearer screening
```

## Scope & seams (who owns what)

**Dev N-lead owns here:** the flavor selector, single-slot collision resolution, and persona
lifecycle — over the shared DPC.

**NOT owned here — consumed as clearly-labeled seams:**
- **The shared managed-profile DPC** (provisioning + lifecycle + lockdown + attest/sdk
  seams) → **Dev N-common** (`android-common/`, co-owned with the Porog A-lead). Consumed
  per `COMMON-INTERFACE.md`; never forked.
- **The Google-Play persona surface + honest labeling + microG/GApps posture** → **Dev
  N-play** (`android-bridge/persona/play/`). Consumed via the `PlayEnablementPlan` seam.
- **The guarded crossing / consent gate** (what may cross between worlds) → **Dev
  N-crossing**. This tree keeps cross-profile sharing **off**; it never opens a crossing.
- **Attestation + the Rust cores** → the shared `AttestationGateway` / `PosternSdkBridge`
  seams, kept `NoOp`. The Google-Play flavor makes **no** attestation claim.

## Build chain (verified to run)

Prerequisites: **JDK 17** (`JAVA_HOME`) and an **Android SDK** with `platforms;android-34` +
`build-tools;34.0.0` (`ANDROID_HOME`, or `sdk.dir` in a git-ignored `local.properties`). The
Gradle wrapper (8.9) downloads its distribution on first run.

```bash
# From android-bridge/persona/ (a self-contained Gradle project):
./gradlew :app:testDebugUnitTest    # PASSES — 18 pure fail-closed JVM tests across
                                    #   PersonaFlavorTest (7) + PersonaSlotPolicyTest (5)
                                    #   + CrossingBearerPolicyTest (6)
./gradlew :app:assembleDebug        # PRODUCES app/build/outputs/apk/debug/app-debug.apk
```

This proves the scaffold **compiles and its pure logic is green** — it does **not** make it
audited, and nothing here has been provisioned or booted on a device. `built ≠ booted`.

Distribution for the **bridge app** is **F-Droid + a signed direct APK** (Play is a poor fit
for DPC provisioning APIs). The Play *persona* uses Play natively — do not conflate the
bridge app with the persona.

## Rails (non-negotiable)

- UNAUDITED / reference-prototype; no security claims; `self-checked ≠ audited`.
- **Separation + convenience, not privacy.** The **Google-Play persona is the less-private
  side** and self-declares "phones home to Google" (labeling owned by N-play, never omitted).
- A rooted / kernel-compromised host defeats the separation — stated on every surface.
- **NEVER "Postern OS."** The guardian is **Yagabona**, never "Baba Yaga"; Nav imagery is a
  neutral crossing, never a "world of the dead."
- **Respect Google/Android licenses:** AOSP is Apache-2.0; we **do not redistribute GMS**
  (`enableSystemApp` only toggles pre-installed packages); package names are used
  nominatively; **no Play Integrity circumvention** (Integrity is an optional signal, never
  a gate, and never spoofed).
- BLCH is worthless and is not a security. Personal use is free. Ownerless base ⟂ owned
  products.
- SPDX `MIT OR Apache-2.0` on every file. Do **not** git commit (the integrator does).
- Trademark: formal clearance required before committing the "NoporIS" mark.
