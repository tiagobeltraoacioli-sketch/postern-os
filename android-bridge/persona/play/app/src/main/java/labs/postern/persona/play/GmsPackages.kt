// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Postern Labs
package labs.postern.persona.play

/**
 * Google package identifiers, in **nominative use only** — named to say *what
 * NoporIS interoperates with*, never to imply Google endorses NoporIS and never
 * as a NoporIS product name.
 *
 * ## Licensing rule this file exists to honour
 * **Postern does NOT redistribute Google Play / Google Play Services (GMS).**
 * These packages are the *stock system apps a Google-certified device already
 * ships*. On the Google-Play flavor, NoporIS's profile owner calls
 * `enableSystemApp(admin, pkg)` — which **un-hides** an already-installed system
 * app **inside the managed profile only**. It installs no APK and ships no
 * Google binary. On a device without GMS (a de-Googled ROM), `enableSystemApp`
 * is a **no-op** — NoporIS plants nothing. The user brings their own Google
 * account and installs from Play themselves (see [PlayFlavorPolicy]).
 *
 * The single source of truth for *which* of these may be enabled, and for the
 * deny-by-default gate, is the node-testable contract
 * `policy/play-flavor-policy.mjs` (`PLAY_SYSTEM_APP_ALLOWLIST`,
 * `mayEnableSystemApp`). This object mirrors that allowlist for the Kotlin side;
 * the two must stay byte-identical in intent.
 *
 * **Status: SCAFFOLD · DESIGN ONLY · UNAUDITED.** Never run on a device.
 */
object GmsPackages {
    /** The Google Play Store client (the "vending" app). */
    const val PLAY_STORE = "com.android.vending"

    /** Google Play Services core (GMS). This is the component that phones home —
     *  its presence is exactly why this flavor is the **less-private** side. */
    const val GMS_CORE = "com.google.android.gms"

    /** Google Services Framework — the registration/backing service GMS needs. */
    const val GSF = "com.google.android.gsf"

    /**
     * The minimal allowlist of system apps the Play flavor may `enableSystemApp`
     * **inside the managed profile**: the store plus the two GMS anchors the user
     * needs to sign in and install. Deliberately small — anything not here is
     * denied by [PlayFlavorPolicy]. Mirrors `PLAY_SYSTEM_APP_ALLOWLIST` in
     * `play-flavor-policy.mjs`.
     */
    val ALLOWLIST: List<String> = listOf(PLAY_STORE, GMS_CORE, GSF)
}
