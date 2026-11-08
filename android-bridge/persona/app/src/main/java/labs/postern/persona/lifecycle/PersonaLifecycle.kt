// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.persona.lifecycle

import android.content.ComponentName
import android.content.Context
import android.os.UserManager
import androidx.annotation.WorkerThread

// CONSUMED from the shared DPC (android-common), NOT duplicated. See ../../COMMON-INTERFACE.md.
import labs.postern.common.profile.lifecycle.ManagedProfileManager

import labs.postern.persona.slot.PersonaSlot
import labs.postern.persona.slot.PersonaSlotPolicy
import labs.postern.persona.slot.PersonaSlotResolver

/**
 * The NoporIS **persona lifecycle**: the three verbs the mechanism owns — *provision*,
 * *switch*, and *destroy-this-world-only* — over the single managed-profile slot. Every
 * verb is a thin, honest orchestration of the shared DPC ([ManagedProfileManager]) plus the
 * single-slot resolver; NoporIS does not re-implement provisioning or the profile-scoped wipe.
 *
 * ## The three verbs
 * - **provision(flavor):** offered *only* when the slot is [PersonaSlot.EMPTY]
 *   (fail-closed). The actual dispatch of `ACTION_PROVISION_MANAGED_PROFILE` runs from the
 *   personal-profile [labs.postern.persona.provision.PersonaProvisioningActivity]; this
 *   class exposes the *gate* ([canProvision]) so no caller can start a flow the platform
 *   will reject or that would collide with an existing profile.
 * - **switch (pause/resume):** the honest ceiling. A DPC/app cannot force the launcher to
 *   foreground a profile; what it *can* do is toggle the persona's **quiet mode** (pause /
 *   resume the work profile). The user's actual "enter the other world" tap is the
 *   launcher's Work tab; NoporIS surfaces which world is live and offers pause/resume.
 * - **destroyThisWorldOnly():** profile-scoped `wipeData` via the shared manager — tears
 *   down THIS persona's managed profile and its FBE storage, **never** user 0 / personal
 *   data. NoporIS's "un-bridge." Must run as profile owner inside the persona.
 *
 * **Status: SCAFFOLD · DESIGN ONLY · UNAUDITED.** Never run on a device. The separation is
 * exactly the Android kernel + SELinux profile boundary — a rooted host defeats it.
 */
class PersonaLifecycle(
    private val appContext: Context,
    private val adminComponent: ComponentName,
) {
    private val profileManager = ManagedProfileManager(appContext, adminComponent)
    private val slotResolver = PersonaSlotResolver(appContext, adminComponent)

    private val userManager: UserManager =
        appContext.getSystemService(Context.USER_SERVICE) as UserManager

    /** The current single-slot state (OS truth). */
    fun slot(): PersonaSlot = slotResolver.resolve()

    /** Whether a persona may be provisioned right now (slot is EMPTY). Fail-closed. */
    fun canProvision(): Boolean = PersonaSlotPolicy.mayProvision(slot())

    /**
     * An honest reason provisioning is refused (collision / unsupported / already-owned),
     * or `null` when the slot is free. Drives the collision UX copy.
     */
    fun provisionRefusalReason(): String? = PersonaSlotPolicy.refusalReason(slot())

    // ── switch: pause / resume the persona (quiet-mode). Honest ceiling. ────────────────

    /**
     * Pause the persona (enable quiet-mode on its work profile). The far world stops
     * running; the near/personal side is untouched. Returns false if we cannot address the
     * persona's user handle (e.g. we are not its profile owner / lack the capability) —
     * NoporIS reports the honest failure rather than pretending it paused.
     *
     * NOTE: `requestQuietModeEnabled` shows a system confirmation and requires the caller to
     * be permitted for that profile; from the personal side this is a *request*, not a
     * guarantee. We surface the boolean the platform returns, never a fabricated success.
     */
    @WorkerThread
    fun pausePersona(): Boolean = setQuietMode(enabled = true)

    /** Resume the persona (disable quiet-mode). Same honest limits as [pausePersona]. */
    @WorkerThread
    fun resumePersona(): Boolean = setQuietMode(enabled = false)

    // ── kill: slam the span shut WITHOUT destroying the world ────────────────────────────

    /**
     * **Kill the span** on the managed-profile substrate — the near-side mapping of the
     * NoporIS kill-switch (design 01 §3, 02 §3). It **pauses** the persona (quiet-mode) so
     * the far world stops running, and the cross-profile broker (Dev B's
     * `CrossProfileBrokerService`) unbinds so no crossing can be in flight. It is the
     * counterpart the Rust orchestrator's `DpcSeam::kill` drives over JNI.
     *
     * Crucially this is **NOT** [destroyThisWorldOnly]: the managed profile, its FBE storage,
     * and — on the near side — the sealed wallet/keys all **survive**. Cutting the span never
     * destroys sealed wallet state (`sealedWallet.preserved` stays true, by construction: this
     * class holds no wallet to destroy). Reopening is an explicit resume, never a timer lapse.
     *
     * Returns the honest boolean the platform's pause returned — the caller must not fabricate
     * success. Dropping the cross-profile grants themselves is the broker's job (it unbinds on
     * the same signal); this verb owns only the profile-pause half.
     *
     * **Status: SCAFFOLD · UNTESTED-until-device.** Real quiet-mode + unbind can only be
     * observed on a dual-profile device/emulator.
     */
    @WorkerThread
    fun killPersona(): Boolean = pausePersona()

    private fun setQuietMode(enabled: Boolean): Boolean {
        // The persona's UserHandle is only addressable where the platform grants it; the
        // scaffold cannot enumerate it from the personal profile without a real
        // provisioned profile to point at. Wiring the concrete UserHandle lookup is an
        // on-hardware task (see README §build path); here we fail-closed to false rather
        // than claim a switch we did not perform.
        return runCatching {
            val personaUser = resolvePersonaUserHandle() ?: return false
            userManager.requestQuietModeEnabled(enabled, personaUser)
        }.getOrDefault(false)
    }

    /**
     * Resolve the persona's `UserHandle`. TODO(N1, hardware): derive from the launcher /
     * cross-profile availability signal once a profile is provisioned. Returns `null` in the
     * scaffold — the caller then honestly reports "can't address the persona," never a lie.
     */
    private fun resolvePersonaUserHandle(): android.os.UserHandle? = null

    // ── destroy this world only ─────────────────────────────────────────────────────────

    /**
     * **Destroy-this-world-only.** Profile-scoped wipe of THIS persona's managed profile —
     * the shared manager's `wipeProfileOnly()`, which is `wipeData(0)` and by platform
     * contract removes only the profile it is called from, never user 0. Personal data is
     * untouched. MUST be invoked from NoporIS's DPC running as profile owner *inside* the
     * persona; the shared manager enforces that with a `check(isProfileOwner())`.
     *
     * This is the teardown half of the lifecycle: NoporIS's "un-bridge" == a persona-scoped
     * wipe, mirroring the enterprise shield's revoke ⇒ self-wipe reference model.
     */
    @WorkerThread
    fun destroyThisWorldOnly() {
        require(profileManager.isProfileOwner()) {
            "destroyThisWorldOnly() must run as profile owner INSIDE the persona's profile; " +
                "it wipes THIS world only and never the personal side."
        }
        profileManager.wipeProfileOnly()
        // Post-condition: the framework destroys the profile → slot returns to EMPTY.
    }
}
