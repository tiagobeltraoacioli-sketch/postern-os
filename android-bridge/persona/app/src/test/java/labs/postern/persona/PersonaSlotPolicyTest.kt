// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.persona

import labs.postern.persona.slot.PersonaSlot
import labs.postern.persona.slot.PersonaSlotPolicy
import labs.postern.persona.slot.PersonaSlotPolicy.Facts
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Single-slot collision resolution — the fail-closed decision that implements the critical
 * "stock Android allows exactly ONE managed profile" constraint. Pure over [Facts]; runs on
 * any JVM.
 *
 * The properties under test:
 * 1. Provisioning is offered from **exactly one** state — [PersonaSlot.EMPTY].
 * 2. "Managed profiles supported, not ours, provisioning disallowed" resolves to
 *    [PersonaSlot.FOREIGN] and **refuses** — the honest Porog/employer collision, never a
 *    faked EMPTY that would try to stack a second profile.
 * 3. Owning the slot closes provisioning ([PersonaSlot.OWNED]).
 * 4. No managed-users feature ⇒ [PersonaSlot.UNSUPPORTED].
 */
class PersonaSlotPolicyTest {

    @Test fun freeSlotIsEmptyAndProvisionable() {
        val slot = PersonaSlotPolicy.resolve(
            Facts(hasManagedUsersFeature = true, provisioningAllowed = true, weAreProfileOwner = false),
        )
        assertEquals(PersonaSlot.EMPTY, slot)
        assertTrue(PersonaSlotPolicy.mayProvision(slot))
        assertNull(PersonaSlotPolicy.refusalReason(slot))
    }

    @Test fun weOwnTheSlotIsOwnedAndClosed() {
        val slot = PersonaSlotPolicy.resolve(
            // weAreProfileOwner dominates regardless of the other signals.
            Facts(hasManagedUsersFeature = true, provisioningAllowed = false, weAreProfileOwner = true),
        )
        assertEquals(PersonaSlot.OWNED, slot)
        assertFalse(PersonaSlotPolicy.mayProvision(slot))
        assertNotNull(PersonaSlotPolicy.refusalReason(slot))
    }

    @Test fun foreignOccupantRefusesFailClosed() {
        // Managed profiles supported, we don't own one, yet provisioning is disallowed:
        // the one slot is taken by another work profile (e.g. Porog). Refuse, never fake EMPTY.
        val slot = PersonaSlotPolicy.resolve(
            Facts(hasManagedUsersFeature = true, provisioningAllowed = false, weAreProfileOwner = false),
        )
        assertEquals(PersonaSlot.FOREIGN, slot)
        assertFalse(PersonaSlotPolicy.mayProvision(slot))
        assertNotNull(PersonaSlotPolicy.refusalReason(slot))
    }

    @Test fun noManagedUsersIsUnsupported() {
        val slot = PersonaSlotPolicy.resolve(
            Facts(hasManagedUsersFeature = false, provisioningAllowed = false, weAreProfileOwner = false),
        )
        assertEquals(PersonaSlot.UNSUPPORTED, slot)
        assertFalse(PersonaSlotPolicy.mayProvision(slot))
        assertNotNull(PersonaSlotPolicy.refusalReason(slot))
    }

    @Test fun onlyEmptyIsEverProvisionable() {
        // Exhaustive: EMPTY is the sole provisionable state.
        for (slot in PersonaSlot.entries) {
            assertEquals(slot == PersonaSlot.EMPTY, PersonaSlotPolicy.mayProvision(slot))
        }
    }
}
