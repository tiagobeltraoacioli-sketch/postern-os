// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.persona.provision

import android.app.Activity
import android.os.Bundle
import android.os.PersistableBundle
import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResult
import androidx.activity.result.contract.ActivityResultContracts

// CONSUMED from the shared DPC (android-common), NOT duplicated. See ../../COMMON-INTERFACE.md.
// ProvisioningPreflight + ProvisioningResult are the shared classes verbatim (the shared
// module nests them under `.profile.provision`). ManagedProfileProvisioning is the in-tree
// [extraction ask #1] adapter (the pure admin-extras intent builder the shared module did
// not add) — it lives in THIS package (labs.postern.persona.provision), so no import.
import labs.postern.common.profile.provision.ProvisioningPreflight
import labs.postern.common.profile.provision.ProvisioningResult

import labs.postern.persona.dpc.NoporIsDeviceAdminReceiver
import labs.postern.persona.flavor.PersonaFlavor
import labs.postern.persona.slot.PersonaSlotPolicy
import labs.postern.persona.slot.PersonaSlotResolver

/**
 * The "two worlds" onboarding entry point. Runs in the **personal** profile to (1) resolve
 * the single managed-profile slot fail-closed, (2) carry the chosen [PersonaFlavor] across
 * the profile boundary, and (3) dispatch the shared `ACTION_PROVISION_MANAGED_PROFILE`
 * flow. It reuses the shared preflight + intent builder; it adds only the **slot gate** and
 * the **flavor extra**.
 *
 * This is the NoporIS bridge made literal at creation time: you do not "add a second
 * profile" — the platform gives exactly one managed-profile slot, and you choose the *world*
 * that occupies it (clean == Porog, or the less-private Google-Play side).
 *
 * ## Honest boundary
 * Provisioning creates a real second Android user with its own FBE key; it does NOT create
 * a new OS and does NOT measure the persona. Separation, not privacy — and the Google-Play
 * flavor phones home to Google. A rooted host defeats the boundary. Never "Postern OS."
 *
 * **Status: SCAFFOLD · DESIGN ONLY · UNAUDITED.** The Compose "two worlds" UI (flavor
 * picker + honest labels + the collision message) is Dev N-play's / the switcher's; this
 * shows the provisioning mechanism only. Never run on a device.
 */
class PersonaProvisioningActivity : ComponentActivity() {

    private val provisionLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            onProvisioningResult(mapResult(result))
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // TODO(N1): render the Compose "two worlds" screen — flavor picker, the honest
        // banner ("separation, not privacy · the Google-Play side phones home to Google ·
        // DESIGN ONLY · UNAUDITED · never 'Postern OS'"), and, when the slot is not free,
        // the collision copy from PersonaSlotPolicy.refusalReason(). Scaffold: the flow below.
    }

    /**
     * Called from the (omitted) picker when the user chooses a [flavor] and taps "create."
     * **Fail-closed:** if the single slot is not free (already ours, foreign, or the device
     * can't host a profile), we refuse with the honest reason and never launch a system flow
     * that would dead-end or collide.
     */
    fun requestPersonaProvisioning(flavor: PersonaFlavor) {
        val slot = PersonaSlotResolver(this, NoporIsDeviceAdminReceiver.componentName(this)).resolve()
        PersonaSlotPolicy.refusalReason(slot)?.let { reason ->
            // Honest collision / unsupported dead-end — no system flow launched.
            onProvisioningResult(ProvisioningResult.Unsupported(reason))
            return
        }

        // Belt-and-suspenders: also run the shared preflight (a work profile could appear
        // between the slot read and here). Both must pass; either failing refuses.
        ProvisioningPreflight(this).check()?.let { unsupported ->
            onProvisioningResult(unsupported)
            return
        }

        provisionLauncher.launch(buildProvisioningIntent(flavor))
    }

    /**
     * Build the shared provisioning intent, carrying the chosen [flavor] in the
     * admin-extras bundle (the platform-blessed channel into the DPC inside the new
     * profile). `SKIP_ENCRYPTION` stays false in the shared builder — the separate FBE key
     * is the whole point.
     */
    private fun buildProvisioningIntent(flavor: PersonaFlavor) =
        ManagedProfileProvisioning.buildIntent(
            context = this,
            admin = NoporIsDeviceAdminReceiver.componentName(this),
            adminExtras = PersistableBundle().apply {
                putString(PersonaFlavor.EXTRA_FLAVOR_TAG, flavor.wireTag)
            },
        )

    private fun mapResult(result: ActivityResult): ProvisioningResult = when (result.resultCode) {
        Activity.RESULT_OK -> ProvisioningResult.Dispatched
        Activity.RESULT_CANCELED -> ProvisioningResult.Cancelled
        else -> ProvisioningResult.Failed(result.resultCode)
    }

    private fun onProvisioningResult(result: ProvisioningResult) {
        // TODO(N1): reflect the result in the "two worlds" UI. Do NOT claim the persona is
        // ready on RESULT_OK — enrollment truly completes only in
        // NoporIsDeviceAdminReceiver.onProfileEnrolled, inside the new profile.
        when (result) {
            is ProvisioningResult.Dispatched -> Unit
            is ProvisioningResult.Cancelled -> Unit
            is ProvisioningResult.Unsupported -> Unit
            is ProvisioningResult.Failed -> Unit
        }
    }
}
