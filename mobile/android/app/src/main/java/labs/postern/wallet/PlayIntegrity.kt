package labs.postern.wallet

/**
 * Honest Play Integrity integration — a **second, independent** device-integrity
 * signal layered on top of Key Attestation ([StrongBoxKey]). It is NOT the trust
 * anchor: the cryptographic anchor is Key Attestation, which works even where Play
 * Integrity is unavailable (no GMS / microG).
 *
 * ## The four hard honesty rails (non-negotiable)
 * 1. **Obtain, never spoof.** Porog requests the token via Google's
 *    `StandardIntegrityManager`; it NEVER fabricates `MEETS_STRONG_INTEGRITY` or
 *    any verdict. The realistic outcome on a stock certified phone is DEVICE
 *    integrity; STRONG legitimately FAILS on unlocked-bootloader / custom-ROM /
 *    rooted devices — the very users who want Porog. That failure is *by Google's
 *    design*, disclosed plainly, never worked around.
 * 2. **Decode server-side only.** The raw token is opaque here and is handed
 *    straight to the server ([TokenResult.Obtained.rawToken]); a client-decoded
 *    verdict is never trusted. This class deliberately has NO token-decode path.
 * 3. **"No token" = absence of a signal, NOT failure.** microG / Google-free
 *    devices cannot produce a token at all → [TokenResult.NoProvider]. Porog must
 *    fall back to Key Attestation as the sole anchor and must NOT hard-exclude the
 *    device. Play Integrity is a signal; it is never a hard gate.
 * 4. **Nominative use only.** "Play Integrity" / "Google Play" name the API; they
 *    never imply Google's endorsement or certification of Porog.
 *
 * SCAFFOLD · DESIGN ONLY · UNAUDITED · UNTESTED-until-device. The real
 * STRONG/DEVICE/BASIC verdict is establishable ONLY on a real device with Play
 * services (Tier C); an emulator cannot substantiate it.
 *
 * Requires the Play Integrity client dependency (Dev 5 adds to the version
 * catalog): `com.google.android.play:integrity` — see the class TODO.
 */
object PlayIntegrity {

    /** The outcome of a token request — a raw token, an honest absence, or an error. */
    sealed interface TokenResult {
        /**
         * A token was obtained. [rawToken] is opaque and MUST be sent to the
         * server for decode/verification — never trusted client-side.
         */
        data class Obtained(val rawToken: String) : TokenResult

        /**
         * No Play Integrity provider on this device (microG / no GMS). This is an
         * **absence of signal**, not a failure — fall back to Key Attestation and
         * do NOT exclude the device.
         */
        data object NoProvider : TokenResult

        /** The request reached a provider but errored (network / API). */
        data class Error(val reason: String) : TokenResult
    }

    /**
     * Request a Play Integrity token bound to [requestHash] (a server-issued,
     * per-request hash — typically the same fresh nonce used as the Key-Attestation
     * challenge, so both proofs bind to one session). [cloudProjectNumber] is the
     * Play-console project the token is minted for. Result delivered to [onResult].
     *
     * Contract: on any device without a provider this returns
     * [TokenResult.NoProvider] (absence of signal), NEVER a synthesized verdict.
     * Blocking work runs off the main thread inside the client; the callback may
     * arrive on a background thread.
     *
     * IMPLEMENTATION (Dev 5 must add `com.google.android.play:integrity` to the
     * catalog before this compiles). The shape is:
     * ```
     * val mgr = IntegrityManagerFactory.createStandard(context)          // or create(context)
     * mgr.prepareIntegrityToken(
     *         PrepareIntegrityTokenRequest.builder()
     *             .setCloudProjectNumber(cloudProjectNumber).build())
     *     .addOnSuccessListener { provider ->
     *         provider.request(
     *                 StandardIntegrityTokenRequest.builder()
     *                     .setRequestHash(requestHash).build())
     *             .addOnSuccessListener { onResult(TokenResult.Obtained(it.token())) } // token = OPAQUE → server
     *             .addOnFailureListener { onResult(classify(it)) }
     *     }
     *     .addOnFailureListener { onResult(classify(it)) }   // API-unavailable ⇒ NoProvider
     * ```
     * `classify` maps `IntegrityServiceException` API-unavailable / no-GMS codes to
     * [TokenResult.NoProvider], everything else to [TokenResult.Error]. The token is
     * NEVER decoded here.
     */
    fun requestToken(
        requestHash: String,
        cloudProjectNumber: Long,
        onResult: (TokenResult) -> Unit,
    ) {
        // Fail-closed honest placeholder until the Play Integrity client dep is
        // wired (Dev 5). Returning NoProvider models the microG/no-GMS path — an
        // absence of signal, never a fabricated pass. No client-side decode exists
        // in this class by design.
        onResult(TokenResult.NoProvider)
    }
}
