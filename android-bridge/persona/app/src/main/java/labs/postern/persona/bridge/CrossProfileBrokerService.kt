// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.persona.bridge

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder

/**
 * **The single cross-profile bearer for a NoporIS crossing** (noporis-02 §1 & §5).
 *
 * NoporIS bridges two personas on one handset — the **clean** managed profile (Porog's
 * de-Googled wallet world) and the **Google-Play** profile (the LESS-PRIVATE side that
 * phones home to Google). The *only* channel between profiles an unprivileged app
 * controls is a **bound cross-profile service**. This is that service — and there is
 * **exactly one method** on it:
 *
 * ```
 * deliverCrossing(sealedFrame: ByteArray): DeliveryReceipt
 * ```
 *
 * ### Why the surface is this small (deliberate refusals)
 * - **The frame is opaque.** `sealedFrame` is the bytes of a `postern_pairing::Frame`
 *   wrapping a `CrossingRequest` (AEAD-sealed, per-direction counter, session AAD). The
 *   broker is a **dumb bearer** — it cannot read the payload. Authority lives in the
 *   pairing Channel + the gate + the signed ConsentRecord, never in this IPC boundary.
 * - **No `ContentProvider` cross-profile URI grants** — those are ambient, hard-to-audit
 *   read channels. Every item is a discrete, logged `deliverCrossing` call instead. This
 *   service declares **no `<provider>`**; [rejectUriGrant] hard-fails any intent that
 *   smuggles a `content://`/`Uri`/`FLAG_GRANT_*` for any future/legacy entry point
 *   (defense in depth — a value-typed cross-profile call cannot carry one anyway).
 * - **No implicit `Intent` broadcast** — the service is bound explicitly by package; a
 *   crossing is a method call, not a fan-out. [rejectImplicitBind] hard-fails any bind
 *   intent that is implicit (null component) or action-bearing.
 * - **Explicit user action anchors every crossing** upstream: the near side only calls
 *   `send_crossing` after the user threw the capability's lever (and, for mic/camera/
 *   location, performed the per-crossing tap).
 *
 * ### What this class does here
 * It (a) screens the incoming frame **fail-closed** ([CrossingBearerPolicy]) and (b)
 * hands the opaque bytes to a [CrossingSink] seam — the receiver that runs the real
 * open-frame → CrossingGuard → ConsentRecord → GateConsent → kill-switch gauntlet
 * (`apps/noporis-bridge-glue`, over the UniFFI facade). The default sink is a NoOp that
 * **refuses** (deny-by-default): until a real receiver is wired in, the broker carries
 * nothing. Wiring the live sink + the actual cross-profile bind is the on-device step.
 *
 * ### The transport that actually crosses the profile split — NOT wired here
 * A plain bound [Service] does not, by itself, bind across the managed↔personal profile
 * boundary. Production NoporIS crosses it via the AndroidX **Connected Apps**
 * `@CrossProfile` layer (a Gradle dependency owned by the build/VM side, not this source
 * tree) **or** the DPC's cross-profile-connection allowlist. This file is the *contract
 * and the in-profile shell*; the cross-profile wiring and the SDK bind are
 * **UNTESTED-until-VM** — provable only on a work-profile emulator/device.
 *
 * ### Kill-switch interaction
 * Engaging the kill-switch (`gate-state.json` `killSwitch.engaged`; projected to
 * `sloboda-bridge.state` = `disabled`) must **unbind** this service so no
 * `deliverCrossing` can be in flight (noporis-02 §3.1). The sink also independently
 * denies while the switch is engaged, so an in-flight call fails closed regardless.
 *
 * **Status: SCAFFOLD · DESIGN ONLY · UNAUDITED · UNTESTED-until-VM.** Userland, not a
 * kernel boundary — a rooted host defeats it. NoporIS is an app on stock Android, never
 * "Postern OS." Respects Google/Android licenses (no GMS redistribution, no Play-Integrity
 * circumvention). The coin is not a security. Not legal advice.
 */
class CrossProfileBrokerService : Service() {

    /**
     * The receiver of borne frames. In production this is backed by the UniFFI facade
     * into `apps/noporis-bridge-glue`'s `receive_crossing`, which enforces the full
     * sealed gauntlet. Default: [CrossingSink.DenyAll] — deny-by-default until wired.
     */
    @Volatile
    var sink: CrossingSink = CrossingSink.DenyAll

    private val binder = BrokerBinder()

    override fun onBind(intent: Intent?): IBinder = binder

    /**
     * The single-method bearer exposed to the bound (cross-profile) client. Local binder:
     * the AndroidX Connected Apps layer marshals this across the profile split in
     * production; here it is the direct contract surface.
     */
    inner class BrokerBinder : Binder() {
        /**
         * Bear one opaque sealed frame toward the far side. Screens fail-closed, then
         * defers the real authorisation to [sink]. Never throws across the boundary — a
         * hostile caller gets a refusing [DeliveryReceipt].
         */
        fun deliverCrossing(sealedFrame: ByteArray?): DeliveryReceipt {
            val screened = CrossingBearerPolicy.screen(sealedFrame)
            if (!screened.borne) return screened
            // Non-null & bounded past the screen; hand the opaque bytes to the sealed sink.
            return sink.deliver(sealedFrame!!)
        }
    }

    companion object {
        /**
         * The explicit package+class the far-side client binds by (never an implicit
         * intent). PROPOSED coordinates, pending the on-device wiring.
         */
        const val PACKAGE: String = "labs.postern.persona"
        const val CLASS: String = "labs.postern.persona.bridge.CrossProfileBrokerService"

        /**
         * Reject any URI grant reaching a broker entry point (rail 1, defense in depth).
         * A value-typed cross-profile `deliverCrossing` call cannot carry one, so this
         * guards only future/legacy intent surfaces (e.g. an [onBind] intent). Any
         * `content://`/`Uri` clip data or `FLAG_GRANT_*` is a hard refusal — the broker
         * never accepts a grant it would have to hold.
         *
         * @return true if the intent is clean; false if it smuggles a URI grant.
         */
        fun rejectUriGrant(intent: Intent): Boolean {
            val grantFlags = Intent.FLAG_GRANT_READ_URI_PERMISSION or
                Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or
                Intent.FLAG_GRANT_PREFIX_URI_PERMISSION
            if (intent.flags and grantFlags != 0) return false
            if (intent.data != null) return false
            if (intent.clipData != null) return false
            return true
        }

        /**
         * Reject any implicit or action-bearing bind (rail 2). The service is reached
         * only by an EXPLICIT component ([PACKAGE]/[CLASS]) from the SDK on the same
         * signing key; anything else is a hard refusal.
         *
         * @return true if the bind intent is an explicit, actionless component call.
         */
        fun rejectImplicitBind(intent: Intent): Boolean {
            if (intent.component == null) return false // implicit → refuse
            if (intent.action != null) return false // action-driven → refuse
            return true
        }
    }
}

/**
 * The seam the broker forwards borne frames to — the real, sealed receiver. Kept as a
 * tiny interface so the on-device UniFFI-backed implementation (running the open-frame →
 * CrossingGuard → ConsentRecord → GateConsent → kill-switch gauntlet) can be injected
 * without the broker knowing anything about crypto or the gate.
 */
fun interface CrossingSink {
    /** Deliver (or deny) one opaque sealed frame. The implementor holds all authority. */
    fun deliver(sealedFrame: ByteArray): DeliveryReceipt

    companion object {
        /**
         * Deny-by-default sink: refuses every frame. This is the SAFE default the broker
         * ships with — until a live receiver is wired, the bridge carries nothing.
         */
        val DenyAll: CrossingSink = CrossingSink {
            DeliveryReceipt.refused("no live receiver wired: deny-by-default (UNTESTED-until-VM)")
        }
    }
}
