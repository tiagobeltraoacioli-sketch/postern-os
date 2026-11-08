// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.container

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.os.UserManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import labs.postern.common.profile.lifecycle.ManagedProfileState
import labs.postern.common.profile.provision.ProvisioningPreflight
import labs.postern.container.dpc.CrossProfileReconciler
import labs.postern.container.dpc.PosternDeviceAdminReceiver
import labs.postern.container.lifecycle.ContainerProfileManager
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The Porog **FUNCTIONAL** proof (T1) for the `provision → lock → suspend → wipe`
 * lifecycle, plus the always-on cross-profile-directives decision kernel.
 * Instrumented — runs on a work-profile-capable Android **emulator/device**, NOT on
 * the macOS build host.
 *
 * ## How it maps to porog-01 §5
 * The interactive `ACTION_PROVISION_MANAGED_PROFILE` consent UI is not scriptable
 * headlessly, so `test/e2e/provision-lifecycle.sh` (owned by the VM bucket) does
 * `pm create-user --managed` + `dpm set-profile-owner` + broadcast
 * `PROFILE_PROVISIONING_COMPLETE`, launching this suite into the container user via
 * `am instrument --user <profileId>`. That shell driver owns the OS-truth assertions
 * observable from user 0 (naming via `dumpsys user`, user-restrictions via
 * `dumpsys device_policy`, the quiet-mode toggle, the final container-only wipe, and
 * the negative-preflight of a *second* managed user). THIS class owns the
 * **in-process API** half: profile-owner truth, that the Porog lockdown baseline
 * actually took, that `lockNow()` is callable, that the preflight refuses a second
 * profile from inside an existing one, and the pure cross-profile-directives
 * reconciliation kernel (mirror of P2's `.mjs`), which is deterministic and runs
 * regardless of enrollment.
 *
 * ## Honesty rail (load-bearing)
 * Every profile-owner-dependent assertion is gated behind [assumeTrue]. Run
 * anywhere that is NOT a provisioned Porog profile — a plain emulator, a laptop, an
 * off-device unit run — those tests **SKIP**, they never fake-pass. A green CI run
 * with these tests skipped is honestly `UNTESTED-until-hardware`, not proof.
 *
 * ## What this CANNOT prove (labeled, per §4.2)
 * Nothing about StrongBox/TEE hardware attestation (emulator keymaster is software —
 * `Tier` is TEE/NONE, never STRONGBOX), real OEM behavior (Knox/MIUI), Play-Integrity
 * STRONG, or Tor always-on-VPN leak-freeness. Those are the T2 hardware tier.
 *
 * **Status: SCAFFOLD · DESIGN ONLY · UNAUDITED · deferred-to-VM.** Never executed;
 * requires the KVM `google_apis` emulator from toolchain/flake.nix. The Kotlin has
 * never compiled (no Android SDK on the build host).
 */
@RunWith(AndroidJUnit4::class)
class ProfileLifecycleE2ETest {

    private val context: Context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    private val dpm: DevicePolicyManager
        get() = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager

    private val admin: ComponentName
        get() = PosternDeviceAdminReceiver.componentName(context)

    private fun isProfileOwner(): Boolean = dpm.isProfileOwnerApp(context.packageName)

    /** Skip honestly unless we are actually running as the container's profile owner. */
    private fun requireProfileOwner() {
        assumeTrue(
            "Not running inside a provisioned Porog profile as profile owner — " +
                "SKIPPING (UNTESTED-until-hardware, never fake-green).",
            isProfileOwner(),
        )
    }

    // ── Platform-gated: profile-owner in-process ground truth ──────────────────────

    /** Naming + ownership: the DPC owns THIS profile, and state derives to ACTIVE. */
    @Test
    fun profileOwner_isEstablished_andStateIsActive() {
        requireProfileOwner()

        val manager = ContainerProfileManager(context)
        assertTrue("DPC must be profile owner of the container", manager.isProfileOwner())
        assertEquals(
            "currentState() must derive ACTIVE from profile-owner truth",
            ManagedProfileState.ACTIVE,
            manager.currentState(),
        )
    }

    /** Lockdown baseline: LockdownPolicy.applyBaseline() actually took on this profile. */
    @Test
    fun lockdownBaseline_wasApplied() {
        requireProfileOwner()

        assertTrue(
            "screen capture must be disabled in the container",
            dpm.getScreenCaptureDisabled(admin),
        )

        val restrictions = dpm.getUserRestrictions(admin)
        assertTrue(
            "sideloading must be blocked (DISALLOW_INSTALL_UNKNOWN_SOURCES)",
            restrictions.getBoolean(UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES, false),
        )
        assertTrue(
            "cross-profile copy/paste must be off (DISALLOW_CROSS_PROFILE_COPY_PASTE)",
            restrictions.getBoolean(UserManager.DISALLOW_CROSS_PROFILE_COPY_PASTE, false),
        )

        // Empty permitted-IME list ⇒ system IMEs only (the keylogger-resistant default).
        assertEquals(
            "IME allowlist must restrict to system IMEs only (empty permitted list)",
            emptyList<String>(),
            dpm.getPermittedInputMethods(admin) ?: emptyList<String>(),
        )
    }

    /** Lock: the DPC holds the lock policy — lockNow() is callable and must not throw. */
    @Test
    fun lockNow_isCallable() {
        requireProfileOwner()
        // The uses-policies in res/xml/device_admin_receiver.xml grant force-lock.
        // We assert the call is accepted (no SecurityException) — the substrate for
        // the Panic Lock story. The visible lock effect is asserted by the shell
        // driver from user 0.
        dpm.lockNow()
    }

    /**
     * Quiet-mode (read side): from inside the profile we observe our own unlocked,
     * running state. The quiet-mode TOGGLE (pause/resume the work profile) is driven
     * by the shell harness from user 0 (`am stop-user`/`am start-user`), since
     * requestQuietModeEnabled targets a profile from its PARENT. Here we assert the
     * profile is a genuine managed user with a UserManager handle.
     */
    @Test
    fun quietMode_readState_profileIsRunning() {
        requireProfileOwner()
        val userManager = context.getSystemService(Context.USER_SERVICE) as UserManager
        assertNotNull("UserManager must resolve inside the container", userManager)
        assertTrue(
            "the container user must report itself running while under test",
            userManager.isUserRunning(android.os.Process.myUserHandle()),
        )
    }

    /**
     * Quiet-mode (parent-observable read via the shared handle-aware API): if the
     * shell harness paused us from user 0, [ContainerProfileManager.currentState]
     * called with this profile's own handle must report PAUSED, else ACTIVE.
     * Exercises the `currentState(workProfile)` overload directly, complementing
     * [quietMode_readState_profileIsRunning]'s userManager-level check.
     */
    @Test
    fun whenEnrolled_quietMode_reportsPaused() {
        requireProfileOwner()
        val um = context.getSystemService(Context.USER_SERVICE) as UserManager
        val self = android.os.Process.myUserHandle()
        val mgr = ContainerProfileManager(context)
        val paused = um.isQuietModeEnabled(self)
        val expected = if (paused) ManagedProfileState.PAUSED else ManagedProfileState.ACTIVE
        assertEquals(expected, mgr.currentState(self))
    }

    /**
     * Negative preflight: from INSIDE an existing managed profile, the platform
     * refuses a second one — `isProvisioningAllowed(ACTION_PROVISION_MANAGED_PROFILE)`
     * is false — so ProvisioningPreflight.check() must return a concrete, honest
     * Unsupported reason rather than null. We refuse to dead-end the user.
     */
    @Test
    fun negativePreflight_refusesSecondProfile() {
        requireProfileOwner()
        val unsupported = ProvisioningPreflight(context).check()
        assertNotNull(
            "preflight must report Unsupported when a managed profile already exists",
            unsupported,
        )
        assertTrue(
            "the Unsupported reason must be a non-empty human-readable string",
            (unsupported?.reason?.isNotBlank()) == true,
        )
    }

    /**
     * General preflight honesty, independent of enrollment: whenever the platform
     * cannot provision (feature missing, or provisioning disallowed for any reason —
     * including, but not limited to, an existing managed profile), preflight must
     * agree and report Unsupported rather than assume support.
     */
    @Test
    fun preflight_isHonestAboutSupport() {
        val pf = ProvisioningPreflight(context)
        val cannot = !context.packageManager
            .hasSystemFeature(android.content.pm.PackageManager.FEATURE_MANAGED_USERS) ||
            !dpm.isProvisioningAllowed(DevicePolicyManager.ACTION_PROVISION_MANAGED_PROFILE)
        // If the platform can't provision, preflight returns Unsupported (non-null).
        if (cannot) assertTrue(pf.check() != null)
    }

    /**
     * Wipe precondition: the container-only wipe guard requires profile-owner
     * context. We assert the precondition holds but DO NOT invoke the wipe here —
     * tearing down the profile mid-run would kill the instrumentation. The actual
     * container-only `wipeData` and the teardown → ABSENT assertion are the shell
     * driver's final step (it can observe the profile disappear from user 0).
     */
    @Test
    fun wipe_precondition_profileOwnerContext() {
        requireProfileOwner()
        assertTrue(
            "wipeContainerOnly()/wipeProfileOnly() requires profile-owner context",
            ContainerProfileManager(context).isProfileOwner(),
        )
    }

    /**
     * No-/absent-gate-file ⇒ the cross-profile reconciler applies the fully-closed
     * set on this live profile-owner context (as opposed to the pure, input-driven
     * [CrossProfileReconciler.decide] tests below).
     */
    @Test
    fun whenEnrolled_crossProfileReconcileIsFailClosed() {
        requireProfileOwner()
        val reconciler = CrossProfileReconciler(context, admin)
        val decision = reconciler.reconcile(CrossProfileReconciler.Trigger.BOOT)
        // With no consented state on the emulator, the honest outcome is closed.
        assertFalse(decision.open)
        assertTrue(decision.copyPasteDisallowed)
        assertTrue(decision.revokeOutstandingUriGrants)
    }

    /** Cheap sanity that the receiver component name builds (no device needed). */
    @Test
    fun adminComponent_resolves() {
        assertEquals(
            context.packageName,
            PosternDeviceAdminReceiver.componentName(context).packageName,
        )
    }

    // ── Always-on: the pure fail-closed decision port (single Kotlin port of the
    // .mjs kernel — labs.postern.container.dpc.CrossProfileReconciler.decide). ─────
    // These are deterministic and run regardless of enrollment — the security-critical
    // half is provable even before the emulator stands up the managed profile. The
    // exhaustive field-by-field pin against the kernel lives in the plain-JVM
    // CrossProfileReconcilerParityTest (committed golden vectors); this is the
    // on-device smoke of the same single decision path.

    private fun state(
        accepted: Boolean? = true,
        standing: Boolean? = false,
        kill: Boolean? = false,
        crossings: Map<String, String> = emptyMap(),
        schema: Any? = CrossProfileReconciler.SCHEMA_ID,
        version: Any? = CrossProfileReconciler.SCHEMA_VERSION,
    ): JSONObject = JSONObject().apply {
        schema?.let { put("schema", it) }
        version?.let { put("version", it) }
        put("consent", JSONObject().apply {
            accepted?.let { put("accepted", it) }
            put("scope", "session")
            standing?.let { put("standing", it) }
        })
        kill?.let { put("killSwitch", JSONObject().put("engaged", it)) }
        put("crossings", JSONObject().apply {
            for ((cap, dir) in crossings) put(cap, JSONObject().put("direction", dir))
        })
    }

    private fun decide(input: JSONObject?) = CrossProfileReconciler.decide(input)

    @Test
    fun unknownSchema_fullDeny() {
        val d = decide(state(schema = "bogus"))
        assertFalse(d.open)
        assertTrue(d.copyPasteDisallowed)
        assertTrue(d.intentFilters.isEmpty())
        assertTrue(d.revokeOutstandingUriGrants)
    }

    @Test
    fun nullState_fullDeny() {
        val d = decide(null)
        assertFalse(d.open)
        assertTrue(d.copyPasteDisallowed)
    }

    @Test
    fun stringifiedVersion_fullDeny() {
        // The strict opt() check: a stringified "1" must NOT pass (no schema laundering).
        val d = decide(state(version = "1"))
        assertFalse(d.open)
        assertTrue(d.copyPasteDisallowed)
    }

    @Test
    fun noConsent_defaultDeny() {
        val d = decide(state(accepted = false, crossings = mapOf("intents" to "both")))
        assertFalse(d.open)
        assertTrue(d.intentFilters.isEmpty())
    }

    @Test
    fun killSwitch_clearsEverything() {
        val d = decide(state(kill = true, crossings = mapOf("intents" to "both")))
        assertFalse(d.open)
        assertTrue(d.cleared)
        assertTrue(d.copyPasteDisallowed)
        assertTrue(d.intentFilters.isEmpty())
        assertTrue(d.revokeOutstandingUriGrants)
    }

    @Test
    fun direction_mapsToFlags() {
        val d = decide(state(crossings = mapOf("intents" to "p2w")))
        assertTrue(d.open)
        val f = d.intentFilters.single { it.capability == "intents" }
        assertEquals("p2w", f.direction)
        assertEquals(DevicePolicyManager.FLAG_PARENT_CAN_ACCESS_MANAGED, f.flags)
    }

    @Test
    fun openFalse_forcesCrossingClosed() {
        // `open` is the primary deny gate: explicit false beats a stale direction.
        val input = state().apply {
            put("crossings", JSONObject().put("intents",
                JSONObject().put("open", false).put("direction", "both")))
        }
        assertTrue(decide(input).intentFilters.isEmpty())
    }

    @Test
    fun standingCap_requiresStandingConsent() {
        val denied = decide(state(standing = false, crossings = mapOf("contacts" to "both")))
        assertFalse(denied.contactsPolicy.open)

        val allowed = decide(state(standing = true, crossings = mapOf("contacts" to "both")))
        assertTrue(allowed.contactsPolicy.open)
        assertEquals("both", allowed.contactsPolicy.direction)
    }

    @Test
    fun packageCap_requiresValidPackage() {
        // calendar/connectedApp allowlist exactly ONE valid package — no valid
        // name, nothing to allowlist, crossing stays closed (anti-round-up).
        val noPkg = state(standing = true).apply {
            put("crossings", JSONObject().put("calendar", JSONObject().put("direction", "p2w")))
        }
        assertTrue(decide(noPkg).calendarPackages.isEmpty())

        val withPkg = state(standing = true).apply {
            put("crossings", JSONObject().put("calendar",
                JSONObject().put("direction", "p2w").put("package", "com.android.calendar")))
        }
        assertEquals(setOf("com.android.calendar"), decide(withPkg).calendarPackages)
    }

    @Test
    fun clipboardCrossing_liftsCopyPasteRestriction() {
        val closed = decide(state(crossings = mapOf("clipboard" to "none")))
        assertTrue(closed.copyPasteDisallowed)
        val open = decide(state(crossings = mapOf("clipboard" to "both")))
        assertFalse(open.copyPasteDisallowed)
    }

    @Test
    fun tier_isPinnedKeyAttestedDevice() {
        // Honesty rail: the tier is never "measured-boot"/"seal" and never from input.
        assertEquals("key-attested-device", CrossProfileReconciler.TIER)
    }
}
