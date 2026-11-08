// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.container.dpc

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM unit test for the work-challenge prompt gate.
 *
 * Exercises [WorkChallengePolicy.shouldPrompt] — the pure decision behind "does the
 * user still need to set the separate work challenge?" — with **no Android device**.
 * The complexity-application (`require()`) and sufficiency read (`isSatisfied()`) are
 * platform calls, `UNTESTED-until-VM/device`.
 *
 * Requires `testImplementation("junit:junit:4.13.2")` — routed to Dev 5 (owns build files).
 */
class WorkChallengePolicyGuardTest {

    @Test
    fun promptsWhenRequiredButNotSatisfied() {
        assertTrue(WorkChallengePolicy.shouldPrompt(required = true, satisfied = false))
    }

    @Test
    fun doesNotPromptWhenSatisfied() {
        assertFalse(WorkChallengePolicy.shouldPrompt(required = true, satisfied = true))
    }

    @Test
    fun doesNotPromptWhenNotRequired() {
        assertFalse(WorkChallengePolicy.shouldPrompt(required = false, satisfied = false))
        assertFalse(WorkChallengePolicy.shouldPrompt(required = false, satisfied = true))
    }
}
