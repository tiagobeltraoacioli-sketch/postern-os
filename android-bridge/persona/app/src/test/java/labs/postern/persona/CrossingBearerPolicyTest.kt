// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.persona

import labs.postern.persona.bridge.CrossingBearerPolicy
import labs.postern.persona.bridge.CrossingSink
import labs.postern.persona.bridge.DeliveryReceipt
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Fail-closed screening for the cross-profile bearer — the pure, Android-free slice of
 * [labs.postern.persona.bridge.CrossProfileBrokerService]. Runs on any JVM.
 *
 * The properties under test:
 * 1. Empty/null frames are refused (nothing to bear).
 * 2. Oversize frames are refused at the coarse DoS ceiling.
 * 3. A well-sized frame is *borne* (carried), which is NOT authorisation — the sealed
 *    downstream gauntlet still decides.
 * 4. The default [CrossingSink] denies by default (no live receiver wired).
 *
 * The cross-profile bind itself stays **UNTESTED-until-VM** (a work-profile emulator).
 */
class CrossingBearerPolicyTest {

    @Test fun emptyOrNullFrameIsRefused() {
        val nullR = CrossingBearerPolicy.screen(null)
        assertFalse(nullR.borne)
        assertEquals(0, nullR.frameLen)
        assertNotNull(nullR.reason)

        val emptyR = CrossingBearerPolicy.screen(ByteArray(0))
        assertFalse(emptyR.borne)
        assertNotNull(emptyR.reason)
    }

    @Test fun oversizeFrameIsRefusedAtTheCeiling() {
        val tooBig = ByteArray(CrossingBearerPolicy.MAX_SEALED_FRAME_BYTES + 1)
        val r = CrossingBearerPolicy.screen(tooBig)
        assertFalse(r.borne)
        assertNotNull(r.reason)
    }

    @Test fun wellSizedFrameIsBorneButThatIsNotAuthorisation() {
        val frame = ByteArray(1024) { 0x7 }
        val r = CrossingBearerPolicy.screen(frame)
        assertTrue(r.borne)
        assertEquals(1024, r.frameLen)
        assertNull(r.reason)
        // A frame exactly at the ceiling is still borne (boundary inclusive).
        assertTrue(CrossingBearerPolicy.screen(ByteArray(CrossingBearerPolicy.MAX_SEALED_FRAME_BYTES)).borne)
    }

    @Test fun defaultSinkDeniesByDefault() {
        val r = CrossingSink.DenyAll.deliver(ByteArray(16))
        assertFalse(r.borne)
        assertNotNull(r.reason)
    }

    @Test fun bearerCeilingNeverDropsBelowTheRustPayloadCeiling() {
        // The Kotlin half of the broker bearer-ceiling ↔ payload-max reconciliation
        // (the Rust half is pinned in `apps/noporis-bridge-glue/src/crossing.rs`:
        // `broker_bearer_ceiling_is_never_below_the_payload_ceiling`). The AUTHORITATIVE
        // payload ceiling is Rust `MAX_CROSSING_BYTES` (16 KiB); it is enforced on the
        // OPENED payload downstream. This coarse bearer ceiling screens the OPAQUE sealed
        // frame, which is strictly larger than its payload, so it must never fall below
        // 16 KiB — otherwise a payload the Rust receiver would accept could be refused at
        // the door. If the Rust ceiling ever changes, BOTH this assertion and the Rust
        // pin trip, forcing the two sides to be reconciled instead of silently diverging.
        val rustPayloadCeilingBytes = 16 * 1024
        assertTrue(
            "bearer ceiling ${CrossingBearerPolicy.MAX_SEALED_FRAME_BYTES} must be >= Rust payload ceiling $rustPayloadCeilingBytes",
            CrossingBearerPolicy.MAX_SEALED_FRAME_BYTES >= rustPayloadCeilingBytes,
        )
        // Strictly larger: the sealed frame carries framing overhead beyond the payload,
        // so zero headroom (equality) would itself be a divergence smell.
        assertTrue(
            "sealed frame is larger than its payload; the bearer ceiling needs headroom",
            CrossingBearerPolicy.MAX_SEALED_FRAME_BYTES > rustPayloadCeilingBytes,
        )
        // Pin the documented bearer value (64 KiB) so a change here is deliberate and
        // stays mirrored by the Rust-side `KOTLIN_BEARER_CEILING_BYTES` pin.
        assertEquals(64 * 1024, CrossingBearerPolicy.MAX_SEALED_FRAME_BYTES)
    }

    @Test fun receiptCarriesSizeNeverContent() {
        // A DeliveryReceipt exposes only the fact + size, never payload bytes.
        val borne = DeliveryReceipt.borne(42)
        assertTrue(borne.borne)
        assertEquals(42, borne.frameLen)
        val refused = DeliveryReceipt.refused("nope")
        assertFalse(refused.borne)
        assertEquals(0, refused.frameLen)
        assertEquals("nope", refused.reason)
    }
}
