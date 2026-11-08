// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.container.dpc

import android.app.admin.DevicePolicyManager
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * **The anti-drift pin between the two implementations of the one decision.**
 *
 * Plain-JVM unit test (no device, no emulator): replays every committed golden
 * vector (`apps/porog-crossprofile/golden-vectors.json`, emitted deterministically
 * by `export-vectors.mjs` from the authoritative, node-tested
 * `reconcile-kernel.mjs`) through the single Kotlin port
 * [CrossProfileReconciler.decide] and asserts the resulting [CrossProfileReconciler.Decision]
 * matches the kernel's directives **field by field**. If either side changes
 * alone, this test goes red — the ports can never silently drift again.
 *
 * The vectors land on the test classpath via the `test` source-set resources
 * srcDir in `build.gradle.kts` (pointed at `apps/porog-crossprofile/`), so there
 * is exactly ONE committed copy of the truth — never a second, drift-prone copy
 * under src/test/resources.
 *
 * ## Field mapping (kernel directive → Kotlin Decision)
 * - `open`/`cleared`/`reason`/`copyPasteDisallowed`/`clipboardDirection`/
 *   `shareIntoManagedProfileDisallowed`/`revokeOutstandingUriGrants` → same name.
 * - `intentFilters[].flags` (framework flag NAMES) → the OR of the concrete
 *   [DevicePolicyManager] flag bits (compile-time constants, JVM-safe).
 * - `contactsPolicy {open, direction}` → [CrossProfileReconciler.ContactsPolicy].
 * - `crossProfilePackages[]` (entries carrying capability/mechanism/package) →
 *   the flattened per-mechanism allowlists `calendarPackages`/`connectedAppPackages`.
 * - `schema`/`version`/`tier`/`sealedWalletPreserved` are PINNED constants on both
 *   sides — asserted once against the Kotlin companion pins.
 * - `caveats` (the honesty text) has no Decision field: on the Kotlin side the
 *   honest bounds live in code/docs, not on the value object. Asserted non-empty
 *   in the vectors so the kernel can never stop shipping them.
 *
 * Needs `testImplementation(org.json)` — the REAL org.json ahead of the mockable
 * android.jar — because [CrossProfileReconciler.decide] is a pure JSONObject
 * function (deliberately Context-free so this test exists).
 *
 * **Runs on the Nix VM / any JDK via `./gradlew :app:testDebugUnitTest` —
 * device-required only in the sense that THIS host has no Android SDK/Gradle
 * toolchain; the test itself is plain JVM. UNAUDITED.**
 */
class CrossProfileReconcilerParityTest {

    private val flagBits = mapOf(
        "FLAG_PARENT_CAN_ACCESS_MANAGED" to DevicePolicyManager.FLAG_PARENT_CAN_ACCESS_MANAGED,
        "FLAG_MANAGED_CAN_ACCESS_PARENT" to DevicePolicyManager.FLAG_MANAGED_CAN_ACCESS_PARENT,
    )

    private fun loadRoot(): JSONObject {
        val stream = javaClass.classLoader?.getResourceAsStream("golden-vectors.json")
            ?: error(
                "golden-vectors.json not on the unit-test classpath — check the test " +
                    "resources srcDir in build.gradle.kts (apps/porog-crossprofile) and " +
                    "regenerate with `node export-vectors.mjs` if missing.",
            )
        return stream.use { JSONObject(it.reader().readText()) }
    }

    @Test
    fun headerPinsMatchTheKotlinCompanion() {
        val root = loadRoot()
        assertEquals(CrossProfileReconciler.SCHEMA_ID, root.getString("schema"))
        assertEquals(CrossProfileReconciler.SCHEMA_VERSION, root.getInt("version"))
        assertEquals(CrossProfileReconciler.TIER, root.getString("tier"))
        assertTrue("vector file must not be empty", root.getJSONArray("vectors").length() > 0)
        assertEquals(root.getInt("vectorCount"), root.getJSONArray("vectors").length())
    }

    @Test
    fun everyGoldenVectorMatchesFieldByField() {
        val vectors = loadRoot().getJSONArray("vectors")
        for (i in 0 until vectors.length()) {
            val v = vectors.getJSONObject(i)
            val name = v.getString("name")
            val input = v.opt("input") as? JSONObject // JSON null / non-object => null
            val expected = v.getJSONObject("directives")

            val d = CrossProfileReconciler.decide(input)

            assertEquals("$name: open", expected.getBoolean("open"), d.open)
            assertEquals("$name: cleared", expected.getBoolean("cleared"), d.cleared)
            assertEquals("$name: reason", expected.getString("reason"), d.reason)
            assertEquals(
                "$name: copyPasteDisallowed",
                expected.getBoolean("copyPasteDisallowed"), d.copyPasteDisallowed,
            )
            assertEquals(
                "$name: clipboardDirection",
                expected.getString("clipboardDirection"), d.clipboardDirection,
            )
            assertEquals(
                "$name: shareIntoManagedProfileDisallowed",
                expected.getBoolean("shareIntoManagedProfileDisallowed"),
                d.shareIntoManagedProfileDisallowed,
            )
            assertEquals(
                "$name: revokeOutstandingUriGrants",
                expected.getBoolean("revokeOutstandingUriGrants"),
                d.revokeOutstandingUriGrants,
            )

            assertIntentFiltersMatch(name, expected.getJSONArray("intentFilters"), d)
            assertContactsPolicyMatch(name, expected.getJSONObject("contactsPolicy"), d)
            assertPackageAllowlistsMatch(name, expected.getJSONArray("crossProfilePackages"), d)

            // Pinned honesty rails: identical, constant, and never taken from input.
            assertEquals("$name: schema pin", CrossProfileReconciler.SCHEMA_ID, expected.getString("schema"))
            assertEquals("$name: version pin", CrossProfileReconciler.SCHEMA_VERSION, expected.getInt("version"))
            assertEquals("$name: tier pin", CrossProfileReconciler.TIER, expected.getString("tier"))
            assertTrue("$name: sealedWalletPreserved pin", expected.getBoolean("sealedWalletPreserved"))
            // The kernel ships its honest bounds on every decision; hold it to that.
            assertTrue("$name: caveats present", expected.getJSONArray("caveats").length() > 0)
        }
    }

    private fun assertIntentFiltersMatch(
        name: String,
        expected: JSONArray,
        d: CrossProfileReconciler.Decision,
    ) {
        assertEquals("$name: intentFilters size", expected.length(), d.intentFilters.size)
        for (i in 0 until expected.length()) {
            val e = expected.getJSONObject(i)
            val actual = d.intentFilters[i]
            assertEquals("$name: intentFilters[$i].capability", e.getString("capability"), actual.capability)
            assertEquals("$name: intentFilters[$i].direction", e.getString("direction"), actual.direction)
            val expectedBits = e.getJSONArray("flags").let { names ->
                var bits = 0
                for (j in 0 until names.length()) {
                    bits = bits or (
                        flagBits[names.getString(j)]
                            ?: error("$name: unknown kernel flag name ${names.getString(j)}")
                        )
                }
                bits
            }
            assertEquals("$name: intentFilters[$i].flags", expectedBits, actual.flags)
        }
    }

    private fun assertContactsPolicyMatch(
        name: String,
        expected: JSONObject,
        d: CrossProfileReconciler.Decision,
    ) {
        assertEquals("$name: contactsPolicy.open", expected.getBoolean("open"), d.contactsPolicy.open)
        assertEquals(
            "$name: contactsPolicy.direction",
            expected.getString("direction"), d.contactsPolicy.direction,
        )
    }

    private fun assertPackageAllowlistsMatch(
        name: String,
        expected: JSONArray,
        d: CrossProfileReconciler.Decision,
    ) {
        val calendar = mutableListOf<String>()
        val connectedApp = mutableListOf<String>()
        for (i in 0 until expected.length()) {
            val e = expected.getJSONObject(i)
            when (val cap = e.getString("capability")) {
                "calendar" -> {
                    assertEquals("$name: calendar mechanism", "calendarPackages", e.getString("mechanism"))
                    calendar += e.getString("package")
                }
                "connectedApp" -> {
                    assertEquals("$name: connectedApp mechanism", "connectedAppPackages", e.getString("mechanism"))
                    connectedApp += e.getString("package")
                }
                else -> error("$name: unexpected package-cap $cap in kernel vectors")
            }
        }
        assertEquals("$name: calendarPackages", calendar, d.calendarPackages.toList())
        assertEquals("$name: connectedAppPackages", connectedApp, d.connectedAppPackages.toList())
    }
}
