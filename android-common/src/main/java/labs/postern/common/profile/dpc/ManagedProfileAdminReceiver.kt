// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.common.profile.dpc

import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent

/**
 * The abstract **Device Policy Controller (DPC)** skeleton. A concrete subclass is
 * registered in the consuming app's manifest with `BIND_DEVICE_ADMIN`, and becomes
 * **profile owner** of the managed profile created by
 * `ACTION_PROVISION_MANAGED_PROFILE` (the self-enrolled, no-root, no-EMM path
 * Shelter/Island/Insular use).
 *
 * This is the generic, hardening-free enrollment sequence, shared so that Postern
 * does **not** fork a second DPC. The framework instantiates the concrete subclass
 * **inside the managed profile** and fires [onProfileProvisioningComplete] once the
 * profile exists and the app owns it; this base runs the shared three-step
 * enrollment and calls exactly one product-specific extension point,
 * [onProfileOwnerEstablished]:
 *
 *  1. name the profile ([profileName]),
 *  2. apply product-specific post-provisioning policy ([onProfileOwnerEstablished]) —
 *     Porog applies its lockdown baseline here; NoporIS applies a persona flavor
 *     (or nothing) here; the base itself applies NONE,
 *  3. enable the profile.
 *
 * ## Honest trust boundary (keep it verbatim on every surface)
 * Becoming profile owner of a second Android user gives real per-profile FBE +
 * SELinux isolation. It attests the **phone**, not the **workspace**: key-attested,
 * not measured-boot. A rooted / kernel-compromised host defeats the whole boundary.
 * This is an app on stock Android — it is NEVER "Postern OS".
 *
 * **Status: SCAFFOLD · DESIGN ONLY · UNAUDITED.** Never provisioned on hardware.
 */
abstract class ManagedProfileAdminReceiver : DeviceAdminReceiver() {

    /**
     * The user-facing name to set on the managed profile (shown in the launcher).
     * Product-specific — the concrete subclass supplies it.
     */
    protected abstract fun profileName(context: Context): String

    /**
     * The single product-specific extension point, called **after** this app is
     * confirmed profile owner and the profile is named, but **before** the profile
     * is enabled. Apply post-provisioning policy here.
     *
     * The base implementation is a **no-op** — this skeleton applies no hardening
     * and no policy of its own. Porog overrides this to apply its lockdown baseline;
     * NoporIS overrides it to apply a (non-hardened) persona flavor, or leaves it
     * empty for the deliberately less-private Google-Play persona.
     */
    protected open fun onProfileOwnerEstablished(
        context: Context,
        dpm: DevicePolicyManager,
        admin: ComponentName,
    ) {
        // No-op: the shared skeleton hardens nothing. Subclasses opt in.
    }

    /**
     * Fired **inside the newly-created managed profile** after
     * `ACTION_PROVISION_MANAGED_PROFILE` succeeds and this app is its profile owner.
     * This is the enrollment-completion seam — the most load-bearing callback in the
     * whole provisioning flow. The sequence is shared; only
     * [onProfileOwnerEstablished] varies per product.
     */
    override fun onProfileProvisioningComplete(context: Context, intent: Intent) {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE)
            as DevicePolicyManager
        // The admin component is this concrete receiver, inside this profile.
        val admin = ComponentName(context, this::class.java)

        // 1. Name the profile so it reads meaningfully in the launcher.
        dpm.setProfileName(admin, profileName(context))

        // 2. Product-specific post-provisioning policy (hardening for Porog; a
        //    persona flavor or nothing for NoporIS). The base applies none.
        onProfileOwnerEstablished(context, dpm, admin)

        // 3. Enable the profile so it becomes usable.
        dpm.setProfileEnabled(admin)
    }

    override fun onEnabled(context: Context, intent: Intent) {
        // Device admin activated for this profile. No-op scaffold: real builds may
        // record telemetry-free local state or surface a "ready" signal.
    }

    override fun onDisabled(context: Context, intent: Intent) {
        // Admin deactivated (e.g. the user removed the profile). The framework
        // handles teardown; profile-only data dies with the profile's FBE key.
    }
}
