// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.persona.bridge

/**
 * The **fail-closed screening** the cross-profile broker applies to a sealed frame
 * **before** it hands it on — a *coarse, dumb-bearer* guard, nothing more. Pure and
 * Android-free by construction, so it runs on any JVM and is the one part of the
 * broker that is unit-testable off a device.
 *
 * ## What this is NOT
 * This is **not** where a crossing is authorised. The broker is a **dumb bearer**
 * (noporis-02 §1.1): the `sealedFrame` is opaque `postern_pairing::Frame` bytes
 * (AEAD-sealed, per-direction counter, session AAD). Authority lives in the pairing
 * **Channel** + the **gate** + the signed **ConsentRecord** on the far side — never
 * in this IPC boundary. So this policy deliberately **cannot** read the payload,
 * decide a capability, or grant anything. It only refuses input that is obviously
 * not a bearer frame at all (empty) or a coarse-DoS oversize, so a garbage/hostile
 * caller is dropped at the door and every real decision is deferred to the sealed
 * layers that actually hold the keys.
 *
 * Fail-closed: null, empty, or oversize ⇒ **refused**. Anything else is *carried*
 * (not *approved*) — the receiver still runs the full open-frame → CrossingGuard →
 * ConsentRecord → GateConsent → kill-switch gauntlet.
 *
 * **Status: SCAFFOLD · DESIGN ONLY · UNAUDITED. UNTESTED-until-VM** for the on-device
 * cross-profile bind (see [CrossProfileBrokerService]); the pure screening below is
 * JVM-testable and covered by `CrossingBearerPolicyTest`.
 */
object CrossingBearerPolicy {

    /**
     * Coarse upper bound on the **sealed frame** the broker will bear, in bytes. This
     * is a DoS/sanity ceiling on the *opaque* frame, **not** a correctness gate: the
     * authoritative payload-size check is `MAX_CROSSING_BYTES` (16 KiB) enforced on the
     * *opened* payload inside `apps/noporis-bridge-glue` (`crossing.rs`). The sealed
     * frame is larger than its payload (PQ-hybrid handshake material, per-direction
     * counter, session AAD, AEAD tag), so this bound is the payload ceiling plus
     * generous framing headroom. If the Rust `MAX_CROSSING_BYTES` changes, this stays a
     * safe over-approximation; it must never be *below* it.
     */
    const val MAX_SEALED_FRAME_BYTES: Int = 64 * 1024

    /**
     * Screen a candidate sealed frame. Returns an accepting [DeliveryReceipt] only for a
     * non-empty frame within [MAX_SEALED_FRAME_BYTES]; otherwise a refusing receipt with
     * an honest reason. Never throws — a hostile caller gets a refusal, not a crash.
     *
     * "Accept" here means **"the bearer will carry these bytes"**, NOT "the crossing is
     * allowed". The delivery is authorised only by the sealed layers downstream.
     */
    fun screen(sealedFrame: ByteArray?): DeliveryReceipt {
        if (sealedFrame == null || sealedFrame.isEmpty()) {
            return DeliveryReceipt.refused("empty frame: nothing to bear (fail-closed)")
        }
        if (sealedFrame.size > MAX_SEALED_FRAME_BYTES) {
            return DeliveryReceipt.refused(
                "sealed frame ${sealedFrame.size}B exceeds bearer ceiling ${MAX_SEALED_FRAME_BYTES}B",
            )
        }
        return DeliveryReceipt.borne(sealedFrame.size)
    }
}
