// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.persona.flavor

/**
 * The **one extra input** NoporIS adds to the shared provisioning flow: which *flavor*
 * the single second persona takes. Everything else — the managed-profile provisioning,
 * the lifecycle, the profile-scoped wipe — is the shared DPC (`android-common`); the
 * flavor only selects **which post-provisioning policy set** the DPC applies. It does
 * NOT fork the provisioning path (see the mechanism design, §3.1 / §4).
 *
 * ## The two worlds (mechanism design §0)
 * - [CLEAN] — a Porog-style **hardened, GMS-free** persona. This *is* Porog's container;
 *   NoporIS just adds the "second persona" framing, the switcher, and the guarded
 *   crossing around it. Reuses the shared `LockdownPolicy.applyBaseline()`.
 * - [GOOGLE_PLAY] — a managed profile where Google Play + GMS are enabled and the user
 *   signs in a Google account. It quarantines Google's phone-home into a *separate FBE
 *   boundary* so it does not sit next to wallet keys. **This is the LESS-private side by
 *   construction** — it phones home to Google. Separation and convenience, not privacy.
 *   The in-product labeling that says so lives in `android-bridge/persona/play/`
 *   (Dev N-play), never silently omitted.
 *
 * ## Fail-closed default (mirrors the gate-store `normalize()` contract)
 * The chosen flavor crosses the profile boundary as a wire tag in the provisioning
 * admin-extras bundle. If that tag is **missing, unknown, or malformed**, we default to
 * the **MORE-private** flavor ([CLEAN]) — never silently to the less-private Google-Play
 * side. "Anything not explicitly the less-private side is the safe side." A corrupt or
 * absent flavor can never silently stand up a phone-home persona.
 */
enum class PersonaFlavor(val wireTag: String) {

    /** Hardened, GMS-free (== Porog's container). The safe default. */
    CLEAN("clean"),

    /** Google-Play + GMS enabled in-profile. The LESS-private side, labelled as such. */
    GOOGLE_PLAY("google-play"),

    ;

    companion object {

        /** The fail-closed default: the more-private flavor. */
        val SAFE_DEFAULT: PersonaFlavor = CLEAN

        /** The admin-extras key the flavor tag travels under across the profile boundary. */
        const val EXTRA_FLAVOR_TAG: String = "labs.postern.persona.FLAVOR"

        /**
         * Parse a wire tag to a flavor, **fail-closed**. Pure (no Android types) so the
         * fail-closed behaviour is unit-testable on a plain JVM. Any input that is not an
         * exact, known tag collapses to [SAFE_DEFAULT] ([CLEAN]) — the less-private side
         * is *only* ever selected by an exact, explicit `"google-play"`.
         */
        fun fromWireTag(tag: String?): PersonaFlavor =
            PersonaFlavor.entries.firstOrNull { it.wireTag == tag } ?: SAFE_DEFAULT
    }
}
