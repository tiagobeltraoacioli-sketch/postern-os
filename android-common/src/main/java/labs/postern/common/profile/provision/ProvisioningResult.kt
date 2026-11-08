// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.common.profile.provision

/**
 * The honest outcomes of an `ACTION_PROVISION_MANAGED_PROFILE` attempt.
 *
 * Generic, hardening-free, product-neutral: shared by every Postern app that
 * provisions a managed profile (the Porog "door" and the NoporIS "bridge" both
 * consume this — neither forks it).
 *
 * We never silently claim success: a device that cannot host a managed profile
 * gets [Unsupported], a user who backs out gets [Cancelled], and a platform
 * failure gets [Failed] with the raw result code — no fabricated "provisioned".
 *
 * DESIGN ONLY · UNAUDITED · never exercised on a device.
 */
sealed interface ProvisioningResult {

    /**
     * The system provisioning flow returned OK. NOTE: this only means the flow was
     * dispatched and accepted; the profile-owner completion truth lands separately
     * in the DPC's `onProfileProvisioningComplete`, inside the new profile (see
     * [labs.postern.common.profile.dpc.ManagedProfileAdminReceiver]). "Dispatched
     * OK" ≠ "profile fully enrolled".
     */
    data object Dispatched : ProvisioningResult

    /** The user cancelled / backed out of the system provisioning UI. */
    data object Cancelled : ProvisioningResult

    /**
     * This device/OS cannot host a managed profile (`isProvisioningAllowed` false
     * or `FEATURE_MANAGED_USERS` absent, or a profile already exists). An honest
     * dead-end, reported as-is.
     */
    data class Unsupported(val reason: String) : ProvisioningResult

    /** The platform returned a non-OK result code. */
    data class Failed(val resultCode: Int) : ProvisioningResult
}
