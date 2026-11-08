// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.persona.flavor

/**
 * The **mechanism ↔ Play-persona seam**. The Google-Play flavor's mechanism (this tree,
 * Dev N-lead) enables Play/GMS **system apps that already exist on the device** inside the
 * persona's managed profile via `enableSystemApp(admin, packageName)`. It never bundles or
 * redistributes Google Mobile Services — it only toggles the visibility, inside the
 * profile, of packages the OEM already shipped. If a package is not present on the device,
 * `enableSystemApp` is a no-op for it; the persona then simply has no Play, honestly.
 *
 * **Which packages, and the microG-vs-GApps posture (VANILLA / FOSS / GAPPS), are a
 * user-visible input owned by Dev N-play** (`android-bridge/persona/play/`), not decided
 * here. This interface is the seam: N-play supplies a posture-aware plan; the mechanism
 * consumes it. Keeping the posture out of the mechanism keeps this tree free of the
 * labeling surface and prevents a silent GApps default (the design forbids silently GApps).
 *
 * The [Default] plan names the canonical package identifiers **nominatively** (to identify
 * the apps to toggle — permitted trademark use), enabling nothing on a device where they
 * are absent. A build that wants the honest posture UI replaces it with N-play's plan.
 */
interface PlayEnablementPlan {

    /**
     * The system packages to `enableSystemApp` inside the Google-Play persona, in order.
     * Empty ⇒ enable nothing (a de-facto GMS-free profile — fail-closed if a posture is
     * unset). Only meaningful for [PersonaFlavor.GOOGLE_PLAY]; ignored for [PersonaFlavor.CLEAN].
     */
    fun systemAppsToEnable(): List<String>

    companion object {

        /**
         * Fail-closed plan: enables **nothing**. If Dev N-play has not supplied a
         * posture-aware plan, the Google-Play flavor stands up an *empty* profile rather
         * than silently enabling GApps. The persona is still isolated; it simply has no
         * Play until a posture is explicitly chosen. Never assume GApps.
         */
        val Empty: PlayEnablementPlan = object : PlayEnablementPlan {
            override fun systemAppsToEnable(): List<String> = emptyList()
        }

        /**
         * Reference GApps plan — the canonical Play Store + core GMS package names,
         * named nominatively only to identify which pre-installed system apps to toggle.
         * NOT the mechanism default (that is [Empty]); N-play's posture UI selects this
         * explicitly, with the "less-private side / phones home to Google" label attached.
         */
        val ReferenceGapps: PlayEnablementPlan = object : PlayEnablementPlan {
            override fun systemAppsToEnable(): List<String> = listOf(
                "com.android.vending",              // Google Play Store
                "com.google.android.gms",           // Google Play services (GMS)
                "com.google.android.gsf",           // Google Services Framework
            )
        }
    }
}
