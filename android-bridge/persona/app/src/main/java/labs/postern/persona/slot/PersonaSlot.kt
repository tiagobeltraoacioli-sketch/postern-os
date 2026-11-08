// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.persona.slot

/**
 * The state of the device's **single managed-profile slot**.
 *
 * ## The load-bearing constraint (mechanism design §0; master plan §2, R1)
 * Stock Android allows **exactly ONE managed (work) profile per user.** So NoporIS cannot
 * "add a second persona next to whatever is already there." The mechanism design resolves
 * this by making **NoporIS the persona *orchestrator* of that one slot**: the single
 * managed profile holds *either* the clean flavor (== Porog's hardened container) *or* the
 * Google-Play flavor — chosen at provisioning, mutually exclusive. Two worlds, one guarded
 * crossing; the platform enforces exactly two, and that is the feature, not a limitation.
 *
 * The collision with Porog is therefore resolved **honestly and fail-closed**: if the one
 * slot is already occupied — by a Porog profile, an employer's work profile, Shelter/Island,
 * anything — NoporIS **refuses** to provision and says why. It never tries (and cannot) to
 * create a second. A user who wants a NoporIS persona where Porog holds the slot is offered
 * the honest choice: use Porog itself as the clean flavor, or remove it first.
 */
enum class PersonaSlot {

    /**
     * No managed profile exists; the slot is free. NoporIS may provision a persona
     * (clean or Google-Play). The only state from which provisioning is offered.
     */
    EMPTY,

    /**
     * The slot holds a persona **we own** (NoporIS is the profile owner). Provisioning is
     * closed; the lifecycle offers switch / destroy-this-world-only instead.
     */
    OWNED,

    /**
     * The slot is occupied by a work profile **that is not ours** (a Porog hardened
     * profile, an employer EMM, another BYOD app). NoporIS must NOT and CANNOT create a
     * second. Fail-closed dead-end, surfaced to the user as a choice — never faked into
     * EMPTY, never a silent second-provision attempt.
     */
    FOREIGN,

    /**
     * This device/OS cannot host a managed profile at all (`FEATURE_MANAGED_USERS` absent
     * or provisioning categorically disallowed). Honest dead-end.
     *
     * NOTE: Android 15+ **Private Space** is the mechanism design's fallback for the
     * "dual phone" persona where this bites — but Private Space is created by the OS
     * Settings flow, not by a DPC, so it is a *different, non-programmatic* path and is
     * **not** this app's mechanism. We report UNSUPPORTED honestly rather than pretend the
     * DPC can stand up a persona here.
     */
    UNSUPPORTED,
}
