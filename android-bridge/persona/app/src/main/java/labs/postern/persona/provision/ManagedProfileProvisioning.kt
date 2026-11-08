// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.persona.provision

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.PersistableBundle

/**
 * **[extraction ask #1 — resolved in-tree] · the pure managed-profile provisioning-intent
 * builder with an admin-extras passthrough.**
 *
 * `COMMON-INTERFACE.md` asks `android-common` to "generalize
 * `ProvisioningActivity.buildProvisioningIntent()` into a pure builder that (a) takes the
 * admin `ComponentName` and (b) forwards an admin-extras `PersistableBundle` across the
 * profile boundary (`EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE`)."
 *
 * The shared module as landed did **not** add that pure builder: its
 * [labs.postern.common.profile.provision.ManagedProfileProvisioningActivity] keeps
 * `buildProvisioningIntent()` as a *protected, instance* method on the Activity and does
 * **not** forward admin-extras (Porog never needed it). Per COMMON-INTERFACE.md's own
 * divergence rule — *"the fix is a thin adapter in this tree ... never a fork of the DPC"*
 * — this object is that thin adapter. It is a faithful, side-effect-free superset of the
 * shared Activity's intent construction:
 *
 *  - same action `ACTION_PROVISION_MANAGED_PROFILE`,
 *  - same admin-component extra,
 *  - same `SKIP_ENCRYPTION = false` posture (the separate FBE key is the whole point),
 *  - **plus** the one NoporIS-specific capability: the admin-extras passthrough that
 *    carries the chosen persona **flavor** into the DPC inside the new profile.
 *
 * It does **not** re-implement provisioning, lifecycle, or the receiver — those stay in
 * `android-common`. It only builds an `Intent`. If `android-common` later grows the pure
 * builder the contract described, this shim collapses to a one-line delegate.
 *
 * **Status: SCAFFOLD · DESIGN ONLY · UNAUDITED.** Never dispatched on a device.
 */
object ManagedProfileProvisioning {

    /**
     * Build the managed-profile provisioning intent for [admin], optionally carrying
     * [adminExtras] across the profile boundary via
     * `EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE`. When [adminExtras] is `null` the intent is
     * byte-for-byte the shared Activity's default (Porog's behaviour) — the passthrough is
     * purely additive.
     */
    @Suppress("UNUSED_PARAMETER") // `context` is kept to honour the COMMON-INTERFACE.md
    // builder signature (a pure `buildIntent(context, admin, adminExtras)`); the intent
    // itself needs no context, but a real android-common builder may, so the seam matches.
    fun buildIntent(
        context: Context,
        admin: ComponentName,
        adminExtras: PersistableBundle? = null,
    ): Intent = Intent(DevicePolicyManager.ACTION_PROVISION_MANAGED_PROFILE).apply {
        putExtra(
            DevicePolicyManager.EXTRA_PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME,
            admin,
        )
        // Keep file-based encryption: the profile's separate FBE key is the boundary.
        putExtra(DevicePolicyManager.EXTRA_PROVISIONING_SKIP_ENCRYPTION, false)
        // The platform-blessed channel into the DPC running inside the new profile. Only
        // added when present, so a null-extras call stays identical to the shared default.
        if (adminExtras != null) {
            putExtra(
                DevicePolicyManager.EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE,
                adminExtras,
            )
        }
    }
}
