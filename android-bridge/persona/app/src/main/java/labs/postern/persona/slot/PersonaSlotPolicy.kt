// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.persona.slot

/**
 * The **pure decision logic** of single-slot collision resolution — deliberately free of
 * any Android type so the fail-closed behaviour is unit-testable on a plain JVM (mirrors
 * the DOM-free, testable `gate-store.mjs` discipline). [PersonaSlotResolver] reads the real
 * platform facts and delegates the *decision* here.
 *
 * ## Fail-closed rule
 * Provisioning is offered **only** from a definitively [PersonaSlot.EMPTY] slot. Every
 * ambiguity resolves *away* from "go ahead":
 * - can't host managed profiles at all → [PersonaSlot.UNSUPPORTED];
 * - we already own the slot → [PersonaSlot.OWNED] (no second-provision);
 * - the platform says a profile can't be provisioned right now, and we don't own one → we
 *   treat the slot as [PersonaSlot.FOREIGN]-or-blocked and **refuse**, because from the
 *   personal profile we cannot see a managed profile we don't own, so "can't provision +
 *   not ours" honestly means "the one slot is taken by someone else."
 *
 * We never infer EMPTY from uncertainty. A device that merely *fails* a check is not an
 * invitation to try harder — it is a closed door we report as closed.
 */
object PersonaSlotPolicy {

    /**
     * Snapshot of the platform facts the resolver can honestly read from the **personal**
     * profile. Deliberately minimal and boolean so the decision is total and testable.
     *
     * @param hasManagedUsersFeature `FEATURE_MANAGED_USERS` present.
     * @param provisioningAllowed `isProvisioningAllowed(ACTION_PROVISION_MANAGED_PROFILE)`.
     * @param weAreProfileOwner NoporIS's DPC is profile owner of the profile we run in
     *        (only true when this process is the one inside our persona).
     */
    data class Facts(
        val hasManagedUsersFeature: Boolean,
        val provisioningAllowed: Boolean,
        val weAreProfileOwner: Boolean,
    )

    /** Resolve the slot state, fail-closed. Total function over [Facts]. */
    fun resolve(facts: Facts): PersonaSlot = when {
        // We own the slot: closed to new provisioning, open to switch/destroy.
        facts.weAreProfileOwner -> PersonaSlot.OWNED

        // Device categorically cannot host a managed profile.
        !facts.hasManagedUsersFeature -> PersonaSlot.UNSUPPORTED

        // The one slot is free and provisioning is allowed: the ONLY EMPTY case.
        facts.provisioningAllowed -> PersonaSlot.EMPTY

        // Managed profiles are supported, we don't own one, yet provisioning is disallowed.
        // The honest reading is: the single slot is already taken by a profile that isn't
        // ours (Porog, employer, another BYOD app). Refuse — never fake EMPTY.
        else -> PersonaSlot.FOREIGN
    }

    /** Provisioning is offered from EMPTY and nowhere else. */
    fun mayProvision(slot: PersonaSlot): Boolean = slot == PersonaSlot.EMPTY

    /**
     * An honest, user-facing reason a slot is not provisionable, for the collision UX.
     * `null` when it *is* provisionable ([PersonaSlot.EMPTY]).
     */
    fun refusalReason(slot: PersonaSlot): String? = when (slot) {
        PersonaSlot.EMPTY -> null
        PersonaSlot.OWNED ->
            "A NoporIS persona already occupies this device's one managed-profile slot. " +
                "Switch to it or destroy-this-world-only; you can't stack a second persona."
        PersonaSlot.FOREIGN ->
            "This device's single managed-profile slot is already taken by another work " +
                "profile (for example a Porog hardened profile or an employer's profile). " +
                "Stock Android allows only one. Use that profile as your clean flavor, or " +
                "remove it first — NoporIS will not (and cannot) create a second."
        PersonaSlot.UNSUPPORTED ->
            "This device can't host a managed profile at all. On Android 15+ a Private " +
                "Space (created in system Settings) is the alternative for a second world — " +
                "that is a different, OS-driven path, not something NoporIS can provision."
    }
}
