// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.container.attest

/**
 * The hardware tier a Keystore key was **actually** attested at — the honest
 * "report the tier you got, never upgrade" surface.
 *
 * StrongBox → TEE is a *graceful fallback*, never a silent promotion: if the
 * device has no discrete HSM, [StrongBoxAttestationGateway] catches
 * `StrongBoxUnavailableException` and generates a TEE-backed key instead, and it
 * reports [TEE] — it never claims [STRONGBOX] for a key that isn't in one. The
 * on-device tier label here is only *provisional*; the authoritative security
 * level is whatever the **server-side** Rust verifier
 * (`crates/postern-seal-companion/src/mobile.rs`, `SecurityLevel`) reads out of
 * the attested `KeyDescription`. A local self-report is never a trust claim.
 *
 * ## Honest boundary (repo-enforced qualifier)
 * A genuine [STRONGBOX] tier means: a P-256 key provably resident in the phone's
 * discrete HSM, on a device whose verified-boot / patch state is as reported.
 * It is a **key-attested device, not a measured-boot workspace** — it attests the
 * PHONE, not Porog's workspace code or contents. StrongBox is a **classical P-256**
 * HSM: it attests the device and wraps the post-quantum wallet key *at rest*; it
 * does NOT hold or sign the Falcon‖ML-DSA key. Attestation raises the RBAC bar; it
 * never replaces wallet-key auth.
 *
 * SCAFFOLD · DESIGN ONLY · UNAUDITED · UNTESTED-until-VM/device.
 * `SecurityLevel=2` StrongBox is provable ONLY on real hardware (Pixel 3+ / some
 * Samsung) — an emulator has no discrete HSM and will (correctly) fall back.
 */
enum class AttestationTier {
    /** Discrete StrongBox HSM (`SecurityLevel=2`). Device-only; never on emulator. */
    STRONGBOX,

    /** Trusted Execution Environment (`SecurityLevel=1`) — the graceful fallback. */
    TEE,

    /**
     * No hardware-backed key available (software keymaster, or key generation
     * failed). Attestation was attempted and produced nothing trustworthy — an
     * absence of hardware backing, reported honestly, never masked as a pass.
     */
    NONE,
}

/**
 * The evidence a single attestation attempt produced, carried across the A↔C
 * wire to a verifier. [chainDer] is **leaf-first DER** (index 0 = the attested
 * leaf), exactly what `verify_key_attestation` consumes; [tier] is the *provisional,
 * on-device* tier the fallback actually reached (authoritative tier comes from the
 * verifier). [nonce] is echoed for the verifier's freshness/anti-replay check.
 *
 * An empty [chainDer] with tier [AttestationTier.NONE] is the honest "no evidence"
 * outcome — never a fabricated chain.
 */
data class AttestationEvidence(
    val tier: AttestationTier,
    val chainDer: List<ByteArray>,
    val nonce: ByteArray,
) {
    /** True only when a hardware-backed chain was actually produced. */
    val hasEvidence: Boolean get() = tier != AttestationTier.NONE && chainDer.isNotEmpty()

    // data class with ByteArray members — override equals/hashCode by identity of
    // the meaningful fields (content compare) so accidental structural equality on
    // raw arrays isn't relied upon.
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AttestationEvidence) return false
        if (tier != other.tier) return false
        if (!nonce.contentEquals(other.nonce)) return false
        if (chainDer.size != other.chainDer.size) return false
        return chainDer.indices.all { chainDer[it].contentEquals(other.chainDer[it]) }
    }

    override fun hashCode(): Int {
        var result = tier.hashCode()
        result = 31 * result + nonce.contentHashCode()
        result = 31 * result + chainDer.sumOf { it.contentHashCode() }
        return result
    }
}
