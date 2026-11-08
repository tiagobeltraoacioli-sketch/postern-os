// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.persona

import labs.postern.persona.flavor.PersonaFlavor
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Fail-closed flavor parsing — the "malformed ⇒ safe side" contract, unit-testable on a
 * plain JVM because [PersonaFlavor.fromWireTag] takes no Android types.
 *
 * The load-bearing honesty property: the **less-private Google-Play flavor is selected ONLY
 * by an exact `"google-play"` tag.** Everything else — null, empty, garbage, wrong case —
 * collapses to [PersonaFlavor.CLEAN], the more-private side. A corrupt provisioning bundle
 * can never silently stand up a phone-home persona.
 *
 * (This project is not built in this repo — no Android SDK. The test documents the intended
 * behaviour and runs on any JVM with JUnit.)
 */
class PersonaFlavorTest {

    @Test fun exactCleanTagParses() {
        assertEquals(PersonaFlavor.CLEAN, PersonaFlavor.fromWireTag("clean"))
    }

    @Test fun exactGooglePlayTagParses() {
        assertEquals(PersonaFlavor.GOOGLE_PLAY, PersonaFlavor.fromWireTag("google-play"))
    }

    @Test fun nullTagFailsClosedToClean() {
        assertEquals(PersonaFlavor.CLEAN, PersonaFlavor.fromWireTag(null))
    }

    @Test fun emptyTagFailsClosedToClean() {
        assertEquals(PersonaFlavor.CLEAN, PersonaFlavor.fromWireTag(""))
    }

    @Test fun unknownTagFailsClosedToClean() {
        assertEquals(PersonaFlavor.CLEAN, PersonaFlavor.fromWireTag("play"))
        assertEquals(PersonaFlavor.CLEAN, PersonaFlavor.fromWireTag("gapps"))
    }

    @Test fun wrongCaseFailsClosedToClean() {
        // No case-folding: only the exact lowercase tag selects the less-private side.
        assertEquals(PersonaFlavor.CLEAN, PersonaFlavor.fromWireTag("Google-Play"))
        assertEquals(PersonaFlavor.CLEAN, PersonaFlavor.fromWireTag("GOOGLE-PLAY"))
    }

    @Test fun safeDefaultIsTheMorePrivateFlavor() {
        assertEquals(PersonaFlavor.CLEAN, PersonaFlavor.SAFE_DEFAULT)
    }
}
