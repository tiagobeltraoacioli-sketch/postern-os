// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.common.profile.provision

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.PackageManager

/**
 * Pre-flight checks before dispatching `ACTION_PROVISION_MANAGED_PROFILE`.
 *
 * Generic, hardening-free, product-neutral — reused verbatim by every consumer.
 *
 * We refuse to launch provisioning we know will fail, and we return an honest
 * [ProvisioningResult.Unsupported] with a human-readable reason rather than
 * throwing the user into a system flow that dead-ends. Never assume support by
 * SDK level — ask the platform.
 *
 * DESIGN ONLY · UNAUDITED · never run on a device.
 */
class ProvisioningPreflight(private val context: Context) {

    private val dpm: DevicePolicyManager =
        context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager

    /** `null` ⇒ good to provision; non-null ⇒ the honest reason we can't. */
    fun check(): ProvisioningResult.Unsupported? {
        if (!context.packageManager.hasSystemFeature(PackageManager.FEATURE_MANAGED_USERS)) {
            return ProvisioningResult.Unsupported(
                "This device does not support managed profiles (no FEATURE_MANAGED_USERS).",
            )
        }
        if (!dpm.isProvisioningAllowed(DevicePolicyManager.ACTION_PROVISION_MANAGED_PROFILE)) {
            return ProvisioningResult.Unsupported(
                "Managed-profile provisioning is not currently allowed on this device " +
                    "(a work profile may already exist, or policy/OEM restrictions apply).",
            )
        }
        return null
    }
}
