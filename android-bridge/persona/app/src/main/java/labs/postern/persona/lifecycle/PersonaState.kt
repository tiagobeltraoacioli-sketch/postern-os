// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.persona.lifecycle

import labs.postern.persona.flavor.PersonaFlavor
import labs.postern.persona.slot.PersonaSlot

/**
 * A NoporIS persona's lifecycle snapshot: **which slot state** we are in, **which flavor**
 * the persona is (once known), and whether it is currently paused (quiet-mode).
 *
 * The slot state ([PersonaSlot]) is the OS truth about the single managed-profile slot; the
 * flavor is only knowable once we are the profile owner and can read our own marker (or,
 * pre-enrollment, from the flavor the user just chose). Before that it is `null` — we do not
 * guess a persona's flavor, and in particular we never assume the less-private Google-Play
 * flavor for an unknown persona.
 *
 * DESIGN ONLY · UNAUDITED · derived from platform facts, never persisted as ground truth.
 */
data class PersonaState(
    val slot: PersonaSlot,
    val flavor: PersonaFlavor? = null,
    /** True when the persona's work profile is paused (quiet-mode) rather than live. */
    val paused: Boolean = false,
) {
    /** The persona exists and we own it (whatever its flavor). */
    val isProvisioned: Boolean get() = slot == PersonaSlot.OWNED

    /** A persona can be provisioned right now (the one slot is free). */
    val canProvision: Boolean get() = slot == PersonaSlot.EMPTY
}
