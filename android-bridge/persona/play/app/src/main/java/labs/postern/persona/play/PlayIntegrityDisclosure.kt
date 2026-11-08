// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Postern Labs
package labs.postern.persona.play

/**
 * Honest handling of **Google Play Integrity** on the Play persona.
 *
 * ## The licensing / integrity rule this file exists to honour
 * NoporIS does **NOT circumvent SafetyNet / Play Integrity.** There is no
 * spoofing, no bootloader-lock faking, no verdict tampering anywhere in this
 * module. Instead we **disclose** what a verdict actually means, honestly:
 *
 *  - Play Integrity is an **OPTIONAL** device-integrity signal, **never a hard
 *    gate** inside NoporIS. NoporIS does not require, fake, or defeat it.
 *  - A verdict reads the **whole device's** state (bootloader lock, verified
 *    boot, TEE) — **not** the persona. It "attests the phone, not the workspace."
 *  - `MEETS_STRONG_INTEGRITY` needs a locked bootloader + a Google-certified
 *    image; it **excludes custom-ROM / rooted / de-Googled users by design**, and
 *    NoporIS says so rather than trying to satisfy it dishonestly.
 *  - If a third-party app the user installs checks Integrity, that is between the
 *    user, that app, and Google — NoporIS neither helps pass nor helps bypass it.
 *
 * This class produces only *disclosure copy* + an honest classification of a
 * verdict Google returned; it never manufactures a verdict. The
 * request/attestation plumbing (Play Integrity API token exchange) is a seam
 * owned elsewhere and is intentionally NOT implemented here.
 *
 * **Status: SCAFFOLD · DESIGN ONLY · UNAUDITED.** Never run on a device.
 */
object PlayIntegrityDisclosure {

    /**
     * The honest, load-bearing sentence about Integrity on this persona. Pinned;
     * surfaces may show it verbatim. (The full "less-private" card copy is owned
     * by the labeling module in `android-bridge/config/`, Dev N-labeling; this is
     * only the Integrity-specific clause it can reuse.)
     */
    const val DISCLOSURE: String =
        "Play Integrity, if an app checks it, reads your WHOLE device's state " +
            "(bootloader lock, verified boot, TEE) — not this persona. NoporIS treats " +
            "it as an optional signal, never a gate, and never spoofs or bypasses it. " +
            "STRONG will fail on rooted / de-Googled / custom-ROM devices, by design."

    /** How much a returned verdict actually tells you — never inflated. */
    enum class DeviceIntegrityTier {
        /** No verdict obtained (the default). NoporIS proceeds anyway — not a gate. */
        UNKNOWN,

        /** Basic device recognition only. */
        MEETS_BASIC_INTEGRITY,

        /** Passes normal device integrity (a genuine, unrooted Android device). */
        MEETS_DEVICE_INTEGRITY,

        /** Passes STRONG (locked bootloader + certified image + hardware-backed).
         *  Reflects the DEVICE, not the NoporIS persona. */
        MEETS_STRONG_INTEGRITY,
    }

    /**
     * Classify a verdict Google returned into an honest tier. Input is the set of
     * device-recognition labels from the Play Integrity response
     * (`deviceIntegrity.deviceRecognitionVerdict`). We never fabricate a tier:
     * an empty / missing verdict is [DeviceIntegrityTier.UNKNOWN], and NoporIS
     * carries on regardless (Integrity is not a gate here).
     */
    fun classify(deviceRecognitionVerdict: Set<String>): DeviceIntegrityTier = when {
        "MEETS_STRONG_INTEGRITY" in deviceRecognitionVerdict -> DeviceIntegrityTier.MEETS_STRONG_INTEGRITY
        "MEETS_DEVICE_INTEGRITY" in deviceRecognitionVerdict -> DeviceIntegrityTier.MEETS_DEVICE_INTEGRITY
        "MEETS_BASIC_INTEGRITY" in deviceRecognitionVerdict -> DeviceIntegrityTier.MEETS_BASIC_INTEGRITY
        else -> DeviceIntegrityTier.UNKNOWN
    }

    /**
     * NoporIS **never** gates on Integrity: whatever the tier, the persona still
     * runs. This function exists to make that promise explicit and testable — it
     * always returns true. (Report the tier honestly in the UI; do not act on it.)
     */
    @Suppress("UNUSED_PARAMETER")
    fun isPersonaAllowed(tier: DeviceIntegrityTier): Boolean = true
}
