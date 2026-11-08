// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.persona.lifecycle

import androidx.annotation.WorkerThread
import labs.postern.persona.slot.PersonaSlot

/**
 * The **near-side substrate seam** the NoporIS Rust orchestrator drives.
 *
 * The Rust spine (`apps/noporis-bridge-glue/src/substrate.rs`) owns the persona-isolation
 * *control-flow* (reconcile / kill / sealed-wallet invariant) behind a `Substrate` trait whose
 * managed-profile backend delegates its effects to a `DpcSeam`. On a real device that
 * `DpcSeam` is **this** interface, reached over a thin JNI bridge; the Kotlin side performs the
 * actual DPC work through the shared managed-profile plumbing ([PersonaLifecycle]). The verb
 * mapping is 1:1 with the Rust seam:
 *
 * | Rust `DpcSeam`            | this seam            | effect on device                        |
 * |--------------------------|----------------------|-----------------------------------------|
 * | `ensure_profile()`       | [ensureProfile]      | provisioning gate → dispatch (UI)       |
 * | `foreground(true/false)` | [foreground]         | resume / pause quiet-mode               |
 * | `kill()`                 | [kill]               | pause + cross-profile broker unbind     |
 * | `revive()`               | [revive]             | allow re-provision after a kill         |
 * | `enforcement()`          | [isOsBoundary]       | OS storage/process split (not attested) |
 *
 * ## Honesty rails (carried verbatim)
 * - The managed-profile storage/process split **is** an OS/kernel boundary — but that is
 *   **not attestation**. NoporIS adds no Seal, no measured boot, no padlock; the Google-Play
 *   persona stays the less-private, non-attestable side. A rooted host defeats the separation.
 * - **Kill never destroys the sealed wallet.** This seam can pause and unbind; it holds no
 *   wallet and never wipes — the near-side keys survive the span dropping. Destroying a world
 *   is the *separate*, explicit [PersonaLifecycle.destroyThisWorldOnly], never [kill].
 *
 * **Status: SCAFFOLD · DESIGN ONLY · UNAUDITED · UNTESTED-until-device.** The JNI binding and
 * every DPC effect below are only observable on a dual-profile device/emulator; nothing here
 * has run on hardware.
 */
interface PersonaSubstrateSeam {

    /** The result of an [ensureProfile] attempt — honest about the platform ceiling. */
    sealed interface EnsureResult {
        /** The persona's managed profile already exists and we own it. */
        data object AlreadyProvisioned : EnsureResult

        /**
         * The single slot is free; the caller must launch the user-driven provisioning flow
         * (`PersonaProvisioningActivity`). A headless seam cannot silently create a profile —
         * `ACTION_PROVISION_MANAGED_PROFILE` requires a user gesture, by platform design.
         */
        data object ProvisioningRequired : EnsureResult

        /** The slot cannot host a persona right now, with the honest reason (collision / unsupported). */
        data class Refused(val reason: String) : EnsureResult
    }

    /** Idempotently ensure the managed profile exists (never destroys anything). */
    @WorkerThread
    fun ensureProfile(): EnsureResult

    /** Resume (`true`) or pause (`false`) the persona via quiet-mode. Returns the platform boolean. */
    @WorkerThread
    fun foreground(on: Boolean): Boolean

    /** Kill the span: pause the persona (broker unbinds separately). Never a wipe. */
    @WorkerThread
    fun kill(): Boolean

    /**
     * Allow the persona to be (re)created after a kill. A kill only *pauses*, so revive is a
     * no-op signal here (the profile was never destroyed); it exists to mirror the Rust seam.
     */
    @WorkerThread
    fun revive() {}

    /**
     * `true` — the managed profile's storage/process split is OS/kernel-enforced. This is the
     * honest `Enforcement::OsBoundary` label, **not** an attestation claim.
     */
    fun isOsBoundary(): Boolean = true
}

/**
 * The device implementation of [PersonaSubstrateSeam], backed by the shared managed-profile
 * plumbing via [PersonaLifecycle]. It adds no policy of its own — it only routes the Rust
 * orchestrator's verbs to the honest lifecycle operations.
 *
 * **Status: SCAFFOLD · UNTESTED-until-device.**
 */
class PersonaLifecycleSeam(
    private val lifecycle: PersonaLifecycle,
) : PersonaSubstrateSeam {

    override fun ensureProfile(): PersonaSubstrateSeam.EnsureResult =
        when (lifecycle.slot()) {
            PersonaSlot.OWNED -> PersonaSubstrateSeam.EnsureResult.AlreadyProvisioned
            PersonaSlot.EMPTY -> PersonaSubstrateSeam.EnsureResult.ProvisioningRequired
            // FOREIGN / UNSUPPORTED — surface the honest refusal from the pure slot policy.
            else -> PersonaSubstrateSeam.EnsureResult.Refused(
                lifecycle.provisionRefusalReason() ?: "the single managed-profile slot is unavailable",
            )
        }

    @WorkerThread
    override fun foreground(on: Boolean): Boolean =
        if (on) lifecycle.resumePersona() else lifecycle.pausePersona()

    @WorkerThread
    override fun kill(): Boolean = lifecycle.killPersona()
}
