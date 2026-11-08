// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.persona.slot

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager

// CONSUMED from the shared DPC (android-common), NOT duplicated. See ../../COMMON-INTERFACE.md.
import labs.postern.common.profile.lifecycle.ManagedProfileManager

/**
 * Reads the real platform facts about the device's **single managed-profile slot** and
 * hands them to the pure [PersonaSlotPolicy] for a fail-closed decision. The Android-touching
 * half; all judgement lives in the (testable) policy.
 *
 * It leans on the shared [ManagedProfileManager] (Porog's `ContainerProfileManager`,
 * generalized) for `isProfileOwner()` and `canProvision()` — NoporIS does not re-read the
 * OS itself, it reuses the one honest OS-truth reader.
 *
 * ## Honest limit (carried from the shared manager)
 * From the **personal** profile we cannot directly enumerate a managed profile we don't own
 * (cross-profile visibility is off by design). So [PersonaSlot.FOREIGN] is an *inference*
 * from "managed profiles are supported, we're not the owner, yet provisioning is disallowed"
 * — the conservative reading. We would rather refuse a provision that might have worked than
 * fake an EMPTY slot and stack a broken second attempt.
 *
 * **Status: SCAFFOLD · DESIGN ONLY · UNAUDITED.** Never run on a device.
 */
class PersonaSlotResolver(
    private val appContext: Context,
    private val adminComponent: ComponentName,
) {
    private val profileManager = ManagedProfileManager(appContext, adminComponent)

    fun resolve(): PersonaSlot {
        val facts = PersonaSlotPolicy.Facts(
            hasManagedUsersFeature = appContext.packageManager
                .hasSystemFeature(PackageManager.FEATURE_MANAGED_USERS),
            // canProvision() already ANDs FEATURE_MANAGED_USERS with isProvisioningAllowed;
            // we read the raw provisioning-allowed signal via the shared manager's contract.
            provisioningAllowed = profileManager.canProvision(),
            weAreProfileOwner = profileManager.isProfileOwner(),
        )
        return PersonaSlotPolicy.resolve(facts)
    }
}
