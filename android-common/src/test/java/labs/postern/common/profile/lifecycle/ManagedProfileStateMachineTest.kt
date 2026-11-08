// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.common.profile.lifecycle

import labs.postern.common.profile.lifecycle.ManagedProfileManager.Companion.deriveState
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Pure-JVM unit tests for the managed-profile state machine.
 *
 * These exercise [ManagedProfileManager.deriveState] — the pure decision factored
 * out of `currentState()` — with **no Android device, emulator, or platform mock**.
 * They run on the plain JVM (`testDebugUnitTest`) and are the only lifecycle assertions
 * provable off-device. Everything else in the lifecycle is `UNTESTED-until-VM/device`.
 *
 * Requires `testImplementation("junit:junit:4.13.2")` — routed to Dev 5 (owns build files).
 */
class ManagedProfileStateMachineTest {

    @Test
    fun quietMode_takesPrecedence_reportsPaused() {
        // Quiet mode is only observable on a profile that EXISTS, so it dominates.
        assertEquals(
            ManagedProfileState.PAUSED,
            deriveState(isProfileOwner = true, canProvision = true, isQuietMode = true),
        )
        // Even the parent-side view (owner not visible) reports PAUSED when quiet.
        assertEquals(
            ManagedProfileState.PAUSED,
            deriveState(isProfileOwner = false, canProvision = true, isQuietMode = true),
        )
    }

    @Test
    fun profileOwner_notQuiet_reportsActive() {
        assertEquals(
            ManagedProfileState.ACTIVE,
            deriveState(isProfileOwner = true, canProvision = true, isQuietMode = false),
        )
        // Owner status dominates provisioning capability when not quiet.
        assertEquals(
            ManagedProfileState.ACTIVE,
            deriveState(isProfileOwner = true, canProvision = false, isQuietMode = false),
        )
    }

    @Test
    fun cannotProvision_notOwner_reportsUnsupported() {
        assertEquals(
            ManagedProfileState.UNSUPPORTED,
            deriveState(isProfileOwner = false, canProvision = false, isQuietMode = false),
        )
    }

    @Test
    fun canProvision_notOwner_reportsAbsent() {
        assertEquals(
            ManagedProfileState.ABSENT,
            deriveState(isProfileOwner = false, canProvision = true, isQuietMode = false),
        )
    }

    @Test
    fun activeToPausedAndBack_isTransientToggle() {
        // ACTIVE → PAUSED (quiet on) → ACTIVE (quiet off), owner unchanged.
        val active = deriveState(isProfileOwner = true, canProvision = true, isQuietMode = false)
        val paused = deriveState(isProfileOwner = true, canProvision = true, isQuietMode = true)
        val resumed = deriveState(isProfileOwner = true, canProvision = true, isQuietMode = false)
        assertEquals(ManagedProfileState.ACTIVE, active)
        assertEquals(ManagedProfileState.PAUSED, paused)
        assertEquals(ManagedProfileState.ACTIVE, resumed)
    }
}
