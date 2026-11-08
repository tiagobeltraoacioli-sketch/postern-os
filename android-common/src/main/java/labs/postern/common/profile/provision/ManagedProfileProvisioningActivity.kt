// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.common.profile.provision

import android.app.Activity
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Intent
import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResult
import androidx.activity.result.contract.ActivityResultContracts

/**
 * Abstract onboarding entry point that runs in the **personal** profile to trigger
 * managed-profile provisioning (`ACTION_PROVISION_MANAGED_PROFILE`, the
 * self-enrolled no-EMM path), then hands off to the DPC **inside** the new profile.
 *
 * This is the generic, hardening-free, product-neutral provisioning mechanism.
 * It is parameterized on exactly one input — the DPC admin component
 * ([adminComponent]) — so both the Porog "door" and the NoporIS "bridge" reuse
 * this single flow instead of forking a second provisioning path. What differs
 * between products is which post-provisioning policy the DPC applies (a lockdown
 * baseline for Porog; a persona flavor for NoporIS), NOT this dispatch.
 *
 * ## Honest boundary
 * Provisioning creates a real second Android user with its own FBE key; it does
 * NOT create a new OS and does NOT measure the workspace. It attests the phone,
 * not the workspace. A rooted / kernel-compromised host defeats the boundary.
 * This is an app on stock Android — it is NEVER "Postern OS".
 *
 * **Status: SCAFFOLD · DESIGN ONLY · UNAUDITED.** The Compose onboarding UI is left
 * to the concrete subclass; this shows the provisioning mechanism only. Never run
 * on a device.
 */
abstract class ManagedProfileProvisioningActivity : ComponentActivity() {

    private val provisionLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            onProvisioningResult(mapResult(result))
        }

    /**
     * The DPC admin component to install as profile owner of the new managed
     * profile. The concrete subclass supplies its own `DeviceAdminReceiver`
     * component here — this is the one product-specific input to the shared flow.
     */
    protected abstract fun adminComponent(): ComponentName

    /**
     * Kick off provisioning. Preflights first and reports an honest
     * [ProvisioningResult.Unsupported] dead-end rather than launching a system flow
     * we know will fail. Call this from the subclass's onboarding UI.
     */
    protected fun requestProvisioning() {
        ProvisioningPreflight(this).check()?.let { unsupported ->
            onProvisioningResult(unsupported) // honest dead-end, no system flow launched.
            return
        }
        provisionLauncher.launch(buildProvisioningIntent())
    }

    /**
     * Build the managed-profile provisioning intent. `SKIP_ENCRYPTION = false`
     * keeps file-based encryption (the separate FBE key is the whole point).
     * `open` so a subclass may add product-specific provisioning extras, but the
     * admin component and FBE posture are fixed here.
     */
    protected open fun buildProvisioningIntent(): Intent =
        Intent(DevicePolicyManager.ACTION_PROVISION_MANAGED_PROFILE).apply {
            putExtra(
                DevicePolicyManager.EXTRA_PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME,
                adminComponent(),
            )
            putExtra(DevicePolicyManager.EXTRA_PROVISIONING_SKIP_ENCRYPTION, false)
        }

    protected fun mapResult(result: ActivityResult): ProvisioningResult =
        when (result.resultCode) {
            Activity.RESULT_OK -> ProvisioningResult.Dispatched
            Activity.RESULT_CANCELED -> ProvisioningResult.Cancelled
            else -> ProvisioningResult.Failed(result.resultCode)
        }

    /**
     * Reflect the outcome in the onboarding UI. Default is a no-op; subclasses
     * override to render state. **Never claim the profile is ready on
     * [ProvisioningResult.Dispatched]** — enrollment truly completes only in the
     * DPC's `onProfileProvisioningComplete`, inside the new profile.
     */
    protected open fun onProvisioningResult(result: ProvisioningResult) {
        // No-op scaffold. Concrete subclasses render the result honestly.
    }
}
