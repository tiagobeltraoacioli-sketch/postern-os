<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# `android-common` — the interface NoporIS/persona builds AGAINST

**Status: DESIGN / reference-prototype · UNAUDITED · never run on a device.**

This tree (`android-bridge/persona/`, Dev N-lead) **consumes** the shared managed-profile
DPC being extracted from Porog (`android-container/`) into a shared `android-common/`
module by **Dev N-common**. This file is the **contract**: the exact surface NoporIS
depends on. It is written so that (a) my code compiles the moment `android-common` lands,
and (b) Dev N-common can align the extraction to a named, minimal API rather than guessing.

**I do NOT duplicate the DPC.** Everything below already exists in
`android-container/profile/app/src/main/java/labs/postern/container/*` and is *generic,
hardening-free plumbing*; the extraction only renames the package `labs.postern.container.*`
→ `labs.postern.common.*` and makes two things overridable (the receiver hook and the
provisioning admin-extras passthrough). Where I need a hook the current Porog code does not
yet expose, it is called out as **[extraction ask]**.

If the real `android-common` API diverges from this, the fix is a thin adapter in *this*
tree (a few `flavor/`-local shims), never a fork of the DPC.

---

## `labs.postern.common.provision`

```kotlin
sealed interface ProvisioningResult {
    data object Dispatched : ProvisioningResult          // system flow accepted (≠ enrolled)
    data object Cancelled : ProvisioningResult
    data class  Unsupported(val reason: String) : ProvisioningResult
    data class  Failed(val resultCode: Int) : ProvisioningResult
}

class ProvisioningPreflight(context: Context) {
    /** null ⇒ good to provision; non-null ⇒ the honest reason we can't. */
    fun check(): ProvisioningResult.Unsupported?
}

// [extraction ask] generalize ProvisioningActivity.buildProvisioningIntent() into a
// pure builder that (a) takes the admin ComponentName and (b) forwards an admin-extras
// PersistableBundle across the profile boundary (EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE).
object ManagedProfileProvisioning {
    fun buildIntent(
        context: Context,
        admin: ComponentName,
        adminExtras: android.os.PersistableBundle? = null,
    ): Intent
}
```

The admin-extras passthrough is the **only** new provisioning capability NoporIS needs:
it is the platform-blessed channel that carries the chosen **flavor** from the personal
profile into the DPC running inside the new profile. Porog does not use it today; adding
the passthrough is a two-line change and does not alter Porog's behaviour (it passes
`null`).

## `labs.postern.common.lifecycle`

```kotlin
enum class ProfileState { ABSENT, UNSUPPORTED, PROVISIONING, ACTIVE, WIPED }

class ManagedProfileManager(appContext: Context, adminComponent: ComponentName) {
    fun isProfileOwner(): Boolean            // real DPM call
    fun canProvision(): Boolean              // FEATURE_MANAGED_USERS && isProvisioningAllowed(...)
    fun currentState(): ProfileState
    @WorkerThread fun wipeProfileOnly()       // profile-scoped wipeData(0); MUST be profile owner
}
```

This is Porog's `ContainerProfileManager` verbatim, parameterized by `adminComponent`
(today it hardcodes `PosternDeviceAdminReceiver`). NoporIS passes **its own** receiver.
`wipeProfileOnly()` is Porog's `wipeContainerOnly()` renamed — the substrate for NoporIS's
*destroy-this-world-only*.

## `labs.postern.common.dpc`

```kotlin
class LockdownPolicy(context: Context, admin: ComponentName) {
    fun applyBaseline()   // screen-capture off, IME allowlist, cross-profile off, no unknown sources
}

// [extraction ask] make Porog's PosternDeviceAdminReceiver skeleton reusable by exposing
// an overridable enrollment hook instead of hardcoding setProfileName + applyBaseline().
abstract class BaseDeviceAdminReceiver : android.app.admin.DeviceAdminReceiver() {

    /** Final: reads admin-extras, then calls onProfileEnrolled(). Subclasses do NOT override. */
    final override fun onProfileProvisioningComplete(context: Context, intent: Intent)

    /**
     * Called inside the freshly-created managed profile, once we are profile owner.
     * Porog's subclass applies the hardened baseline here; NoporIS's subclass applies
     * a FLAVOR-selected policy set. `adminExtras` is the bundle handed to provisioning.
     */
    protected abstract fun onProfileEnrolled(
        context: Context,
        dpm: android.app.admin.DevicePolicyManager,
        admin: ComponentName,
        adminExtras: android.os.PersistableBundle?,
    )

    companion object {
        fun componentName(context: Context, cls: Class<*>): ComponentName
    }
}
```

Porog's own receiver becomes a `BaseDeviceAdminReceiver` subclass whose `onProfileEnrolled`
does exactly what `onProfileProvisioningComplete` does today (name + `applyBaseline()` +
enable). NoporIS's receiver (`dpc/NoporIsDeviceAdminReceiver.kt`) is a *different* subclass
— same skeleton, flavor-aware body. **One DPC skeleton, two policy bodies. No fork.**

## `labs.postern.common.attest` / `labs.postern.common.sdk`

```kotlin
interface AttestationGateway { /* nonce → chain → verdict/tier; */ companion { val NoOp } }
interface PosternSdkBridge   { fun isAvailable(): Boolean; /* … */ companion { val NoOp } }
```

Reused **as-is, kept `NoOp`.** NoporIS's clean flavor may later opt into a real
`AttestationGateway`; the Google-Play flavor never claims attestation (see the flavor
policy set). NoporIS adds nothing to these seams.

---

## What NoporIS adds ON TOP of this contract (owned here, Dev N-lead)

- a **flavor selector** (`flavor/PersonaFlavor.kt`) — one extra provisioning input;
- the **flavor policy sets** (`flavor/PersonaPolicySet.kt`) — clean ⇒ reuse
  `LockdownPolicy.applyBaseline()`; Google-Play ⇒ *omit* the baseline, enable Play/GMS
  system apps in-profile, keep cross-profile off;
- the **single-slot collision resolution** (`slot/*`) — stock Android allows exactly one
  managed profile; NoporIS is the persona **orchestrator** of that one slot, fail-closed;
- the **persona lifecycle** (`lifecycle/*`) — provision / switch (quiet-mode) /
  destroy-this-world-only (over `wipeProfileOnly()`).

The Google-Play persona's **user-facing surface + honest labeling + microG-vs-GApps
posture UI** are **NOT here** — they are `android-bridge/persona/play/` (Dev N-play). This
tree exposes only the mechanism seam (`PlayEnablementPlan`) that N-play plugs a posture into.
