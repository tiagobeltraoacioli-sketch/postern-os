// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.persona.dpc

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.PersistableBundle

// The shared DPC skeleton (android-common). We SUBCLASS it — never fork it.
import labs.postern.common.profile.dpc.ManagedProfileAdminReceiver

/**
 * **[extraction ask #2 — resolved in-tree] · the admin-extras-aware DPC enrollment hook.**
 *
 * `COMMON-INTERFACE.md` asks `android-common` to *"make Porog's `PosternDeviceAdminReceiver`
 * skeleton reusable by exposing an overridable enrollment hook instead of hardcoding
 * `setProfileName` + `applyBaseline()`"* — specifically an `onProfileEnrolled(context, dpm,
 * admin, adminExtras)` hook that hands the DPC the provisioning **admin-extras** bundle so
 * NoporIS can read the chosen persona flavor **inside** the new profile.
 *
 * The shared module as landed exposes a *different* seam:
 * [ManagedProfileAdminReceiver.onProfileOwnerEstablished] takes `(context, dpm, admin)` and
 * gets **no admin-extras** (Porog's hardening never reads them). Per COMMON-INTERFACE.md's
 * divergence rule — *"a thin adapter in this tree ... never a fork of the DPC"* — this
 * abstract class is that adapter. It:
 *
 *  - **subclasses** the shared [ManagedProfileAdminReceiver] (no fork of provisioning /
 *    lifecycle / the receiver skeleton), and
 *  - overrides the shared `onProfileProvisioningComplete` to read the admin-extras bundle
 *    (`EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE`) off the provisioning intent and route it to
 *    a single product hook, [onProfileEnrolled], which subclasses implement.
 *
 * This is exactly the contract COMMON-INTERFACE.md documents: `onProfileProvisioningComplete`
 * is `final` here (subclasses do NOT override it), it reads admin-extras, then calls
 * `onProfileEnrolled`. NoporIS's concrete receiver applies its flavor-selected sequence in
 * that hook; a hypothetical Porog subclass would apply its baseline there. **One DPC
 * skeleton (shared), two policy bodies. No fork.**
 *
 * **Status: SCAFFOLD · DESIGN ONLY · UNAUDITED.** Never provisioned on hardware.
 */
abstract class BaseDeviceAdminReceiver : ManagedProfileAdminReceiver() {

    /**
     * Called **inside the freshly-created managed profile**, once this app is confirmed
     * profile owner. [adminExtras] is the `PersistableBundle` that was handed to
     * provisioning in the personal profile (it carries the persona flavor tag). The
     * subclass owns the full post-provisioning sequence here (name + policy + enable), so
     * this base does no naming or enabling of its own.
     */
    protected abstract fun onProfileEnrolled(
        context: Context,
        dpm: DevicePolicyManager,
        admin: ComponentName,
        adminExtras: PersistableBundle?,
    )

    /**
     * Final: the shared skeleton's provisioning-complete callback, specialized to read the
     * admin-extras bundle and forward it. Subclasses do **not** override this — they
     * implement [onProfileEnrolled]. We deliberately do NOT call
     * `super.onProfileProvisioningComplete`: the shared base's sequence names + enables the
     * profile with no access to admin-extras, whereas the whole point of this adapter is to
     * give the subclass the extras and let it drive the flavor-aware sequence itself.
     */
    final override fun onProfileProvisioningComplete(context: Context, intent: Intent) {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        // The admin component is this concrete receiver, inside this profile.
        val admin = ComponentName(context, this::class.java)
        onProfileEnrolled(context, dpm, admin, readAdminExtras(intent))
    }

    /**
     * The shared skeleton declares `profileName` abstract (it names the profile in its own
     * `onProfileProvisioningComplete`). Because this adapter overrides that callback and
     * does the naming inside [onProfileEnrolled] instead, this implementation is a
     * never-invoked fallback required only to satisfy the abstract member. Kept honest and
     * neutral rather than pretending to be a product name.
     */
    final override fun profileName(context: Context): String = "Postern managed persona"

    private fun readAdminExtras(intent: Intent): PersistableBundle? {
        @Suppress("DEPRECATION")
        return intent.getParcelableExtra(
            DevicePolicyManager.EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE,
        ) as? PersistableBundle
    }

    companion object {
        /** Convenience mirror of the contract's `componentName(context, cls)` helper. */
        fun componentName(context: Context, cls: Class<*>): ComponentName =
            ComponentName(context, cls)
    }
}
