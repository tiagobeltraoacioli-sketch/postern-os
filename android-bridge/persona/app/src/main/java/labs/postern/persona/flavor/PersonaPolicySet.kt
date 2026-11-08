// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.persona.flavor

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.os.UserManager

// LockdownPolicy is persona-local BY DESIGN: android-common deliberately keeps hardening in
// each product (its README: "Hardening ... stays in each product"), so there is no shared
// baseline to import. This is the in-tree baseline shim (labs.postern.persona.flavor,
// same package as this file → no import). See ../../COMMON-INTERFACE.md and LockdownPolicy.kt.

/**
 * Applies the **flavor-selected policy set** the moment NoporIS becomes profile owner of
 * the persona's managed profile. This is the *only* place the two worlds diverge; the
 * provisioning that got us here is entirely the shared DPC.
 *
 * ## What each flavor does (mechanism design §3.1–§3.3, §4)
 * - [PersonaFlavor.CLEAN] → reuse the shared **`LockdownPolicy.applyBaseline()`** verbatim
 *   (screen-capture off, IME allowlist, cross-profile off, no unknown sources). This *is*
 *   Porog's hardened container as a persona. NoporIS adds nothing to the hardening.
 * - [PersonaFlavor.GOOGLE_PLAY] → **omit** `applyBaseline()` (this is the removable
 *   hardening call the whole product hinges on), enable Play/GMS **system apps already on
 *   the device** inside the profile, and keep **cross-profile sharing OFF** so the Play
 *   world cannot see the personal side. This is the LESS-private side: it phones home to
 *   Google. Separation and process/storage isolation are real (kernel + SELinux); privacy
 *   on this side is not. The in-product label that says so is Dev N-play's.
 *
 * ## Honesty invariants enforced here
 * - Even the Google-Play flavor keeps `DISALLOW_CROSS_PROFILE_COPY_PASTE` — the phone-home
 *   world must not silently read the clean world's clipboard. Any *crossing* is the guarded
 *   bridge's job (Dev N-crossing), explicit and default-deny; it is never opened here.
 * - We never call `enableSystemApp` for a package the plan did not name; the default plan
 *   ([PlayEnablementPlan.Empty]) enables **nothing** — no silent GApps.
 *
 * **Status: SCAFFOLD · DESIGN ONLY · UNAUDITED.** These toggles are enforced by the Android
 * framework + kernel, not by NoporIS. They are exactly as strong as the profile boundary;
 * a rooted host ignores all of them.
 */
class PersonaPolicySet(
    private val context: Context,
    private val admin: ComponentName,
) {
    private val dpm: DevicePolicyManager =
        context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager

    /**
     * Apply the policy set for [flavor]. For [PersonaFlavor.GOOGLE_PLAY], [playPlan] names
     * the system apps to enable in-profile (Dev N-play supplies a posture-aware plan;
     * the mechanism default enables nothing).
     */
    fun apply(
        flavor: PersonaFlavor,
        playPlan: PlayEnablementPlan = PlayEnablementPlan.Empty,
    ) {
        when (flavor) {
            PersonaFlavor.CLEAN -> applyCleanFlavor()
            PersonaFlavor.GOOGLE_PLAY -> applyGooglePlayFlavor(playPlan)
        }
    }

    /** Clean == Porog: reuse the shared hardened baseline verbatim. Nothing new. */
    private fun applyCleanFlavor() {
        LockdownPolicy(context, admin).applyBaseline()
    }

    /**
     * Google-Play: DROP the baseline (keep Play + sideload usable), enable the named
     * Play/GMS system apps inside the profile, but keep the personal↔persona clipboard
     * boundary shut. Storage/process separation from the personal side stays real; privacy
     * on this side does not — and NoporIS labels it so (N-play).
     */
    private fun applyGooglePlayFlavor(playPlan: PlayEnablementPlan) {
        // Deliberately NO applyBaseline() — this is the less-private side by construction.

        // Keep the phone-home world from reading the clean/personal world's clipboard.
        // Any real crossing is the guarded bridge (Dev N-crossing), default-deny, explicit.
        dpm.addUserRestriction(admin, UserManager.DISALLOW_CROSS_PROFILE_COPY_PASTE)

        // Enable Play/GMS system apps that ALREADY EXIST on the device, in-profile only.
        // This toggles visibility; it does not bundle or redistribute GMS. Absent packages
        // are silently skipped by the platform — the persona then simply has no Play.
        for (pkg in playPlan.systemAppsToEnable()) {
            runCatching { dpm.enableSystemApp(admin, pkg) }
            // A missing/uninstallable system app is not a failure of the persona; it is an
            // honest "this device has no such app." We do not fabricate Play availability.
        }
    }
}
