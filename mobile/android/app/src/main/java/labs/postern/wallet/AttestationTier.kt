package labs.postern.wallet

import android.security.keystore.StrongBoxUnavailableException

/**
 * Wallet-side StrongBox→TEE fallback orchestration — the honest "report the tier
 * you actually got, never upgrade" surface over [StrongBoxKey].
 *
 * [attest] asks [StrongBoxKey] for a discrete-HSM key first; if the device has no
 * StrongBox chip the Keystore throws `StrongBoxUnavailableException`, which we catch
 * and retry with the TEE-backed spec — reporting [Tier.TEE], never [Tier.STRONGBOX].
 * The tier reported here is **provisional/local**: it is only what the on-device
 * builder requested succeeded at. The AUTHORITATIVE security level is whatever the
 * server-side Rust verifier (`crates/postern-seal-companion/src/mobile.rs`,
 * `SecurityLevel`) reads out of the attested `KeyDescription` over the chain we emit.
 *
 * HONEST LIMIT: a genuine StrongBox tier attests the **phone** (key-attested device,
 * NOT a measured-boot workspace). StrongBox is classical P-256 — it attests + wraps
 * the post-quantum wallet key at rest; it does not hold or sign the Falcon‖ML-DSA
 * key. See mobile/README.md.
 *
 * SCAFFOLD · DESIGN ONLY · UNAUDITED · UNTESTED-until-VM/device. StrongBox
 * (`SecurityLevel=2`) is provable ONLY on real hardware (Pixel 3+ / some Samsung);
 * an emulator has no discrete HSM and correctly falls back.
 */
object AttestationTier {

    /** The tier a key was ACTUALLY generated at. Reported, never upgraded. */
    enum class Tier {
        /** Discrete StrongBox HSM (`SecurityLevel=2`). Device-only. */
        STRONGBOX,

        /** Trusted Execution Environment (`SecurityLevel=1`) — graceful fallback. */
        TEE,

        /** No hardware-backed key produced — absence of backing, reported honestly. */
        NONE,
    }

    /**
     * The evidence one attestation attempt produced. [chainDer] is **leaf-first
     * DER** — the exact wire input the mobile verifier consumes; an empty list with
     * [tier] == [Tier.NONE] is the honest "no evidence" outcome (never fabricated).
     */
    data class Result(val tier: Tier, val chainDer: List<ByteArray>)

    /**
     * Generate an attested key over [nonce] at the best available tier.
     * StrongBox → TEE → NONE, reporting the tier actually reached.
     *
     * Blocking (Keystore key generation) — call off the main thread.
     */
    fun attest(nonce: ByteArray, requireUserAuth: Boolean = true): Result {
        // 1. Discrete StrongBox HSM.
        try {
            StrongBoxKey.generateAttestedKey(nonce, requireUserAuth)
            return Result(Tier.STRONGBOX, StrongBoxKey.attestationChainDer())
        } catch (_: StrongBoxUnavailableException) {
            // Graceful fallback to TEE — not a failure.
        } catch (_: Throwable) {
            return Result(Tier.NONE, emptyList())
        }

        // 2. TEE fallback — report TEE, never re-label as StrongBox.
        return try {
            StrongBoxKey.generateTeeFallbackKey(nonce, requireUserAuth)
            Result(Tier.TEE, StrongBoxKey.attestationChainDer())
        } catch (_: Throwable) {
            Result(Tier.NONE, emptyList())
        }
    }
}
