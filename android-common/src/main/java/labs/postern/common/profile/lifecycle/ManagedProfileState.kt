// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.common.profile.lifecycle

/**
 * The lifecycle states of a managed profile provisioned by a self-enrolled DPC.
 *
 * Generic, hardening-free, product-neutral — the Porog "container" and a NoporIS
 * "persona" are both just a managed profile in one of these states; each product
 * may alias this type to its own vocabulary.
 *
 * DESIGN ONLY · UNAUDITED · reference-prototype. None of these transitions have
 * been exercised on a device. State is derived from platform facts
 * (DevicePolicyManager profile-owner status, provisioning-allowed checks), never
 * persisted as ground truth — the OS is authoritative.
 */
enum class ManagedProfileState {
    /**
     * No managed profile exists for this app yet. The onboarding entry point is
     * available. Terminal-left state.
     */
    ABSENT,

    /**
     * This device/OS cannot host a managed profile at all
     * (`isProvisioningAllowed(ACTION_PROVISION_MANAGED_PROFILE)` is false, or
     * `FEATURE_MANAGED_USERS` is missing, or a profile already exists and the
     * platform forbids a second). Honest dead-end — we report it, we don't fake it.
     */
    UNSUPPORTED,

    /**
     * `ACTION_PROVISION_MANAGED_PROFILE` has been dispatched and the system
     * provisioning UI is running / the profile is being created. Transient.
     */
    PROVISIONING,

    /**
     * The managed profile exists and this app's DPC is its **profile owner**. Any
     * product-specific post-provisioning policy (e.g. a lockdown baseline, or a
     * persona flavor) has been applied by the DPC. The profile's apps can run.
     */
    ACTIVE,

    /**
     * The managed profile exists (owned) but is **paused** — the platform's quiet
     * mode (`UserManager.requestQuietModeEnabled(true, …)`) is on: all profile apps
     * are stopped, notifications silenced, background work halted. This is a
     * **transient** `ACTIVE ↔ PAUSED` toggle, not a teardown — resuming
     * (`requestQuietModeEnabled(false, …)`) returns the profile to [ACTIVE] with no
     * data loss.
     *
     * Observational note (honest asymmetry): quiet mode is normally toggled and
     * observed from the **personal/parent** profile (the launcher context), whereas
     * profile-owner status ([ACTIVE]) is only visible from **inside** the profile.
     * When a profile is paused its own code does not run, so `PAUSED` is the
     * parent-observable counterpart of the in-profile `ACTIVE` signal. The OS
     * (`UserManager.isQuietModeEnabled`) is authoritative — [ManagedProfileState] can
     * only report PAUSED when a controller in the personal profile queries it with
     * the managed profile's handle.
     *
     * Note that a **Panic-Lock** (CE-key eviction via
     * `lockNow(FLAG_EVICT_CREDENTIAL_ENCRYPTION_KEY)`) is deliberately **NOT** a
     * state here: evicting the credential-encryption key returns the profile to the
     * OS's normal locked-storage state; `currentState()` still reports [ACTIVE]
     * (owned) and the lock is a transient runtime fact, not persisted ground truth,
     * re-entered with the work challenge.
     */
    PAUSED,

    /**
     * A profile-scoped `wipeData` has been requested/performed. The profile is
     * being torn down; no personal data is affected. Transient → ABSENT.
     */
    WIPED,
}
