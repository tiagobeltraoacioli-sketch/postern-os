// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.persona.dpc

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.os.PersistableBundle

// BaseDeviceAdminReceiver is the in-tree [extraction ask #2] adapter over the shared DPC
// skeleton (labs.postern.common.profile.dpc.ManagedProfileAdminReceiver): it adds the
// admin-extras passthrough the shared module did not expose. It lives in THIS package
// (labs.postern.persona.dpc), so no import. See ../../COMMON-INTERFACE.md.
import labs.postern.persona.flavor.PersonaFlavor
import labs.postern.persona.flavor.PersonaPolicySet
import labs.postern.persona.flavor.PlayEnablementPlan

/**
 * NoporIS's **Device Policy Controller** — a subclass of the shared
 * [BaseDeviceAdminReceiver] skeleton. It does **not** re-implement provisioning or
 * enrollment; it overrides exactly one hook, [onProfileEnrolled], to apply the persona's
 * **flavor-selected** policy set once we become profile owner.
 *
 * One DPC skeleton (shared), two policy bodies (Porog's hardened body; NoporIS's
 * flavor-aware body). No fork of the DPC.
 *
 * ## The flavor crosses the profile boundary here
 * The user picked a [PersonaFlavor] in the personal profile; it travelled in the
 * provisioning **admin-extras** bundle. This callback runs **inside the new profile** and
 * reads it back. **Fail-closed:** a missing/unknown/malformed tag ⇒
 * [PersonaFlavor.SAFE_DEFAULT] ([PersonaFlavor.CLEAN]) — the more-private flavor. A corrupt
 * provisioning bundle can never silently stand up the phone-home Google-Play persona.
 *
 * **Status: SCAFFOLD · DESIGN ONLY · UNAUDITED.** Never provisioned on hardware.
 */
class NoporIsDeviceAdminReceiver : BaseDeviceAdminReceiver() {

    override fun onProfileEnrolled(
        context: Context,
        dpm: DevicePolicyManager,
        admin: ComponentName,
        adminExtras: PersistableBundle?,
    ) {
        val flavor = readFlavorFailClosed(adminExtras)

        // 1. Name the persona so it reads honestly in the launcher's Work tab.
        dpm.setProfileName(admin, profileNameFor(flavor))

        // 2. Apply the FLAVOR policy set — the only place the two worlds diverge.
        //    CLEAN reuses the shared hardened baseline; GOOGLE_PLAY drops it and enables
        //    Play/GMS in-profile. The posture-aware PlayEnablementPlan is Dev N-play's to
        //    inject; the mechanism default enables NOTHING (no silent GApps).
        PersonaPolicySet(context, admin).apply(
            flavor = flavor,
            playPlan = playPlanFor(flavor),
        )

        // 3. Enable the profile so it becomes usable.
        dpm.setProfileEnabled(admin)

        // TODO(N1, hardware): hand off to the in-profile "two worlds" onboarding UX and,
        // for the CLEAN flavor only, optionally kick the AttestationGateway seam (NoOp
        // until Dev N-attest supplies a live StrongBox chain). The GOOGLE_PLAY flavor makes
        // NO attestation claim — it is the less-private side.
    }

    /** Fail-closed flavor read from the provisioning admin-extras bundle. */
    private fun readFlavorFailClosed(adminExtras: PersistableBundle?): PersonaFlavor {
        val tag = adminExtras?.getString(PersonaFlavor.EXTRA_FLAVOR_TAG)
        return PersonaFlavor.fromWireTag(tag) // unknown/null ⇒ CLEAN (the safe default).
    }

    /**
     * The posture-aware Play plan for the Google-Play flavor. In this mechanism scaffold it
     * is the fail-closed [PlayEnablementPlan.Empty] (enables nothing); Dev N-play replaces
     * it with a VANILLA/FOSS/GAPPS posture the user chose, carrying the "less-private side"
     * label. CLEAN never consults it.
     */
    private fun playPlanFor(flavor: PersonaFlavor): PlayEnablementPlan =
        when (flavor) {
            PersonaFlavor.GOOGLE_PLAY -> PlayEnablementPlan.Empty // N-play injects the real posture.
            PersonaFlavor.CLEAN -> PlayEnablementPlan.Empty
        }

    private fun profileNameFor(flavor: PersonaFlavor): String = when (flavor) {
        // User-facing names. PROPOSED, pending trademark clearance.
        PersonaFlavor.CLEAN -> "NoporIS · clean"
        PersonaFlavor.GOOGLE_PLAY -> "NoporIS · Google-Play (less private)"
    }

    companion object {
        /** Convenience for building provisioning intents / DPM calls against this receiver. */
        fun componentName(context: Context): ComponentName =
            ComponentName(context, NoporIsDeviceAdminReceiver::class.java)
    }
}
