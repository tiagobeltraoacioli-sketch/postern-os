// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.common.profile.lifecycle

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Process
import android.os.UserHandle
import android.os.UserManager
import androidx.annotation.WorkerThread

/**
 * The managed-profile **lifecycle** owner: derive profile state, and drive
 * profile-scoped teardown. This is the single place that reads the OS for the
 * truth about whether the managed profile exists and whether this app owns it.
 *
 * Generic, hardening-free, product-neutral. Parameterized on exactly one input —
 * the DPC [adminComponent] — so both Porog and NoporIS read OS truth through the
 * same code (`open` so a product may wrap it with its own vocabulary). It applies
 * NO policy and NO hardening; it only reads state and performs the profile-scoped
 * wipe.
 *
 * ## Honest trust boundary
 * A managed profile is isolation **within** stock Android's security model — its
 * strength is exactly the Android kernel + SELinux profile boundary, no stronger.
 * A rooted / kernel-compromised host **defeats** it. This class controls the
 * profile's lifecycle; it does not and cannot harden the OS beneath it.
 *
 * **Status: SCAFFOLD · DESIGN ONLY · UNAUDITED.** Never run on a device. Methods
 * read real platform APIs where the shape is stable, and are marked where the
 * behaviour depends on running inside a provisioned profile.
 */
open class ManagedProfileManager(
    private val appContext: Context,
    private val adminComponent: ComponentName,
) {

    private val dpm: DevicePolicyManager =
        appContext.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager

    private val userManager: UserManager =
        appContext.getSystemService(Context.USER_SERVICE) as UserManager

    /**
     * Whether this app's DPC is the **profile owner** of the profile this process
     * runs in. Only true when the app instance is the one inside the managed
     * profile. Real platform call.
     */
    fun isProfileOwner(): Boolean =
        dpm.isProfileOwnerApp(appContext.packageName)

    /**
     * Whether this device/OS can host a managed profile at all. Combines the
     * managed-users system feature with the runtime provisioning check. We gate on
     * this rather than on an SDK level — never assume support.
     */
    fun canProvision(): Boolean {
        val hasManagedUsers = appContext.packageManager
            .hasSystemFeature(PackageManager.FEATURE_MANAGED_USERS)
        val provisioningAllowed =
            dpm.isProvisioningAllowed(DevicePolicyManager.ACTION_PROVISION_MANAGED_PROFILE)
        return hasManagedUsers && provisioningAllowed
    }

    /**
     * Best-effort derivation of the current [ManagedProfileState] from platform
     * facts. Reports [ManagedProfileState.PAUSED] when the managed profile is in
     * quiet mode (`UserManager.isQuietModeEnabled`).
     *
     * Note the honest limit: from the **personal** profile we cannot directly see a
     * managed profile we own (cross-profile visibility is off by design). A
     * production build tracks provisioning via the DPC's
     * `onProfileProvisioningComplete` callback + a cross-profile availability
     * signal; here we return the states we can honestly derive and mark the rest.
     * Quiet mode ([ManagedProfileState.PAUSED]) is precisely the parent-observable
     * signal — see [deriveState] for the pure decision.
     *
     * @param workProfile the managed profile's [UserHandle], optionally supplied by
     *   a controller running in the **personal/parent** profile so PAUSED (quiet
     *   mode) can be observed directly. When omitted, the sibling profile handle is
     *   auto-resolved via [resolveManagedProfileHandle] (`null` when none can be
     *   observed, e.g. called from inside the profile, or none exists).
     *
     * The pure decision lives in [deriveState] so the state machine is unit-testable
     * on the JVM without an Android device. This wrapper only gathers the live
     * platform signals. **UNTESTED-until-VM/device** for the platform-signal
     * gathering; the pure mapping is JVM-unit-tested.
     */
    @JvmOverloads
    fun currentState(workProfile: UserHandle? = null): ManagedProfileState =
        deriveState(
            isProfileOwner = isProfileOwner(),
            canProvision = canProvision(),
            isQuietMode = isManagedProfilePaused(workProfile),
        )

    /**
     * Whether the given managed profile is in **quiet mode** (its apps paused). A
     * parent-context query — [workProfile] is the managed profile's handle, resolved
     * by the personal-side controller (e.g. from `UserManager.getUserProfiles()`).
     */
    fun isPaused(workProfile: UserHandle): Boolean =
        userManager.isQuietModeEnabled(workProfile)

    /**
     * Whether a managed profile owned/associated with this user is currently in
     * quiet mode. Uses [workProfile] when supplied (explicit parent-context call);
     * otherwise falls back to auto-resolving the sibling profile over
     * [resolveManagedProfileHandle]. `false` when no such profile can be observed.
     * **UNTESTED-until-VM/device.**
     */
    private fun isManagedProfilePaused(workProfile: UserHandle? = null): Boolean {
        val handle = workProfile ?: resolveManagedProfileHandle() ?: return false
        return runCatching { isPaused(handle) }.getOrDefault(false)
    }

    /**
     * Best-effort resolution of the *other* profile's [UserHandle] — from the
     * personal/parent context `getUserProfiles()` returns `[personal, managed]`, so
     * we drop our own handle and take the first remaining. Returns `null` when there
     * is no sibling profile to address (e.g. called from inside the profile, or none
     * exists). Used by [setPaused] and the quiet-mode read.
     *
     * **UNTESTED-until-VM/device** — real cross-profile handle enumeration only
     * behaves on a provisioned target.
     */
    protected fun resolveManagedProfileHandle(): UserHandle? {
        val self = Process.myUserHandle()
        return runCatching {
            userManager.userProfiles.firstOrNull { it != self }
        }.getOrNull()
    }

    /**
     * **Panic-Lock substrate — evict + seal.** Runs `lockNow` as profile owner
     * **inside** the profile. When [evictCeKey] and the platform supports it
     * (API 26+, always true at our minSdk 30), passes
     * `FLAG_EVICT_CREDENTIAL_ENCRYPTION_KEY`, which purges the profile's
     * credential-encryption key from memory so the profile's FBE storage is sealed
     * at rest until the user re-enters the **separate work challenge** — the
     * OS-level substrate of the Panic Lock ("evict + seal"). On older platforms it
     * degrades to a plain `lockNow()` — an honest limitation, not a silent failure.
     *
     * ## Honest precondition & limit
     * CE-key eviction is only meaningful if a **separate work challenge exists** (a
     * distinct profile lock, not just the device lock) — otherwise there is no
     * separate CE key to evict and "lock" degrades to a plain device lock. Product
     * hardening (Porog's `WorkChallengePolicy.require()`) is responsible for
     * requiring that challenge at enrollment; this generic core only performs the
     * OS-level lock. The profile stays ACTIVE/owned — a lock is a transient runtime
     * fact, not a state.
     *
     * Guarded by `check(isProfileOwner())`. **UNTESTED-until-VM/device.**
     */
    @WorkerThread
    fun lockProfileNow(evictCeKey: Boolean) {
        check(isProfileOwner()) {
            "lockProfileNow() must run as profile owner INSIDE the managed profile"
        }
        val flags = if (evictCeKey && Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            DevicePolicyManager.FLAG_EVICT_CREDENTIAL_ENCRYPTION_KEY
        } else {
            0
        }
        dpm.lockNow(flags)
    }

    /**
     * Pause / resume the **whole profile** via quiet mode
     * (`UserManager.requestQuietModeEnabled`). This is the platform's standard
     * "pause work apps" toggle: all profile apps stop, notifications silence,
     * background work halts.
     *
     * **Context:** this is a **personal/parent-context** call — quiet mode is toggled
     * from the personal profile (launcher/parent), not from inside the profile, and
     * requires the caller to be the profile's parent or hold quiet-mode privilege.
     *
     * @param workProfile the managed profile's handle. When omitted, the target is
     *   auto-resolved via [resolveManagedProfileHandle] (the sibling profile, never
     *   this process's own handle — passing your own handle would toggle the wrong
     *   profile). Pass explicitly when the caller already knows it.
     * @return the platform's success flag. `false` can mean the platform intercepted
     *   the request to show a user-confirmation dialog (it is not necessarily a hard
     *   failure), or that no target profile could be resolved. Reported honestly, not
     *   coerced to `true`. **UNTESTED-until-VM/device.**
     */
    @JvmOverloads
    fun setPaused(paused: Boolean, workProfile: UserHandle? = null): Boolean {
        val handle = workProfile ?: resolveManagedProfileHandle() ?: return false
        return runCatching { userManager.requestQuietModeEnabled(paused, handle) }
            .getOrDefault(false)
    }

    /**
     * Suspend / un-suspend **specific packages** inside the profile via
     * `setPackagesSuspended`. Finer-grained than [setPaused]: freezes an individual
     * workspace app without pausing the whole container. Profile-owner context —
     * runs **inside** the profile; guarded by `check(isProfileOwner())`.
     *
     * @return the sub-list of [pkgs] the platform could **not** update (unknown /
     *   un-suspendable packages), surfaced honestly rather than swallowed. Empty
     *   means all requested packages were updated. **UNTESTED-until-VM/device.**
     */
    @WorkerThread
    fun suspendPackages(pkgs: List<String>, suspended: Boolean): List<String> {
        check(isProfileOwner()) {
            "suspendPackages() must run as profile owner INSIDE the managed profile"
        }
        if (pkgs.isEmpty()) return emptyList()
        val notUpdated = dpm.setPackagesSuspended(adminComponent, pkgs.toTypedArray(), suspended)
        return notUpdated?.toList() ?: emptyList()
    }

    companion object {
        /**
         * The **pure** state-machine decision, factored out of [currentState] so it
         * is unit-testable on the JVM with no Android device or platform mock.
         *
         * Precedence:
         *  1. `isQuietMode` ⇒ [ManagedProfileState.PAUSED] — quiet mode is only ever
         *     observable on a profile that exists, so it dominates and is the
         *     parent-observable counterpart of the in-profile owner signal.
         *  2. `isProfileOwner` ⇒ [ManagedProfileState.ACTIVE].
         *  3. `!canProvision` ⇒ [ManagedProfileState.UNSUPPORTED] (honest dead-end).
         *  4. otherwise ⇒ [ManagedProfileState.ABSENT] (ABSENT vs PROVISIONING needs
         *     a real cross-profile signal, so we report the conservative ABSENT).
         */
        @JvmStatic
        fun deriveState(
            isProfileOwner: Boolean,
            canProvision: Boolean,
            isQuietMode: Boolean,
        ): ManagedProfileState = when {
            isQuietMode -> ManagedProfileState.PAUSED
            isProfileOwner -> ManagedProfileState.ACTIVE
            !canProvision -> ManagedProfileState.UNSUPPORTED
            else -> ManagedProfileState.ABSENT
        }
    }

    /**
     * **Profile-only wipe.** Profile-scoped `wipeData` — tears down the managed
     * profile and its FBE storage without touching personal data. MUST be invoked
     * from the DPC running **inside** the managed profile (profile-owner context);
     * calling it elsewhere is a no-op/throws by platform contract.
     *
     * This is the generic teardown half of the lifecycle (Porog's "container-only
     * wipe" and NoporIS's "destroy-this-persona-only" are both this call).
     */
    @WorkerThread
    fun wipeProfileOnly() {
        check(isProfileOwner()) {
            "wipeProfileOnly() must run as profile owner INSIDE the managed profile"
        }
        // Profile-scoped by construction when called as a managed-profile owner:
        // it removes THIS profile only, never user 0.
        dpm.wipeData(/* flags = */ 0)
        // Post-condition: framework destroys the profile → state → WIPED → ABSENT.
    }
}
