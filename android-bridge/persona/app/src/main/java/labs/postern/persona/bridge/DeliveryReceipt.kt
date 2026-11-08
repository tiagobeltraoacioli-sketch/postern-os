// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.persona.bridge

/**
 * The result of a single [CrossProfileBrokerService.deliverCrossing] call — the *only*
 * thing the broker returns across the profile boundary.
 *
 * Deliberately **content-free**: it carries the *fact* and *size* of a bearing attempt
 * and, on refusal, an honest reason — **never the payload**, and never anything read
 * out of the sealed frame (the bearer cannot read it). This mirrors the audit stance in
 * noporis-02 §4.2: log the fact and the size, never the bytes.
 *
 * `borne == true` means only that the bearer accepted and forwarded the opaque bytes —
 * it is **not** a statement that the crossing was authorised or delivered. The far-side
 * receiver still runs the full open-frame → CrossingGuard → ConsentRecord → GateConsent
 * → kill-switch gauntlet, any step of which may still deny.
 *
 * **Status: DESIGN ONLY · UNAUDITED · UNTESTED-until-VM** (used across a real profile
 * bind only on device).
 */
data class DeliveryReceipt(
    /** True iff the bearer accepted and forwarded the opaque frame. NOT "authorised". */
    val borne: Boolean,
    /** Size in bytes of the frame that was borne, or 0 on refusal. Size only — never content. */
    val frameLen: Int,
    /** Honest reason on refusal; null when [borne]. */
    val reason: String?,
) {
    companion object {
        /** The bearer carried `len` bytes onward (still subject to the sealed downstream gauntlet). */
        fun borne(len: Int): DeliveryReceipt = DeliveryReceipt(borne = true, frameLen = len, reason = null)

        /** The bearer refused, fail-closed, with an honest reason. Nothing was forwarded. */
        fun refused(reason: String): DeliveryReceipt = DeliveryReceipt(borne = false, frameLen = 0, reason = reason)
    }
}
