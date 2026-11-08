// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.container.lifecycle

import android.content.Context
import androidx.annotation.WorkerThread
import labs.postern.common.profile.lifecycle.ManagedProfileManager
import labs.postern.container.dpc.PosternDeviceAdminReceiver

/**
 * The Postern Container **lifecycle** owner: derive container state and drive
 * container-scoped teardown.
 *
 * The OS-truth reading (`isProfileOwner`, `canProvision`, `currentState`) and the
 * profile-scoped wipe are the generic, shared [ManagedProfileManager]
 * (android-common), parameterized on Porog's DPC admin component.
 * `ContainerProfileManager` is Porog's thin naming over it — behavior is identical
 * to the pre-extraction scaffold; `currentState()` returns a [ContainerState]
 * (a typealias of the shared state).
 *
 * ## Honest trust boundary
 * A managed profile is isolation **within** stock Android's security model — its
 * strength is exactly the Android kernel + SELinux profile boundary, no stronger.
 * A rooted / kernel-compromised host **defeats** it.
 *
 * **Status: SCAFFOLD · DESIGN ONLY · UNAUDITED.** Never run on a device.
 */
class ContainerProfileManager(appContext: Context) :
    ManagedProfileManager(
        appContext,
        PosternDeviceAdminReceiver.componentName(appContext),
    ) {

    /**
     * **Container-only wipe** — Porog's name for the shared profile-scoped
     * `wipeData`. Tears down the managed profile and its FBE storage without
     * touching personal data. MUST run as profile owner INSIDE the managed profile.
     *
     * This is the teardown half of the lifecycle and the substrate for the Panic
     * Lock "evict + seal" story (the Panic core, not this class, owns the eviction
     * semantics).
     */
    @WorkerThread
    fun wipeContainerOnly() = wipeProfileOnly()

    /**
     * **Panic Lock** — Porog's name for the shared CE-key-evicting lock. Seals the
     * container's FBE storage at rest by evicting its credential-encryption key from
     * memory (RAM); re-entry requires the **separate work challenge**
     * (`WorkChallengePolicy`, required at enrollment). The profile stays ACTIVE/owned
     * — the lock is a transient runtime fact, not a state change.
     *
     * Delegates to the shared [lockProfileNow] with `evictCeKey = true`. MUST run as
     * profile owner INSIDE the container. This is the OS-level half of the panic
     * story; the Panic core (elsewhere) owns the higher-level "seal the vault, evict
     * SDK keys" semantics. Its guarantee is only as strong as the separate work
     * challenge established by [labs.postern.container.dpc.WorkChallengePolicy];
     * without one, eviction has no separate CE key to purge and degrades to a plain
     * device lock. **UNTESTED-until-VM/device.**
     */
    @WorkerThread
    fun panicLock() = lockProfileNow(evictCeKey = true)

    /**
     * **Pause the container** (Porog's default "Suspend" UX) — whole-profile quiet
     * mode. All container apps stop, notifications silence, background work halts.
     * This is a **personal/parent-context** action (the Suspend/Resume tile in
     * `ProvisioningActivity`, owned by Dev 2, calls this from the parent profile);
     * the target profile handle is auto-resolved by the shared [setPaused].
     *
     * @return the platform success flag from [setPaused] (see its KDoc — `false` may
     *   mean a user-confirmation dialog was shown, not a hard failure).
     *   **UNTESTED-until-VM/device.**
     */
    fun pauseContainer(): Boolean = setPaused(true)

    /**
     * **Resume the container** — clears quiet mode, returning the container to
     * ACTIVE. Personal/parent-context, the mirror of [pauseContainer].
     * **UNTESTED-until-VM/device.**
     */
    fun resumeContainer(): Boolean = setPaused(false)

    /**
     * **Suspend/resume specific apps** inside the container without pausing the whole
     * profile — Porog's name for the finer-grained [suspendPackages]. Profile-owner
     * context (runs INSIDE the container).
     *
     * @return the packages that could NOT be updated (see [suspendPackages]).
     *   **UNTESTED-until-VM/device.**
     */
    @WorkerThread
    fun suspendContainerApps(packages: List<String>, suspended: Boolean): List<String> =
        suspendPackages(packages, suspended)
}
