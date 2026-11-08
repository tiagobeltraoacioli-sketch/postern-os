package labs.postern.wallet

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.Certificate

/**
 * StrongBox-backed Keystore key + Android Key Attestation — the mobile form of
 * the **Postern Seal**.
 *
 * The generated EC P-256 key lives in the device's discrete hardware security
 * module (StrongBox). Its X.509 certificate chain (from [getCertificateChain])
 * roots in Google's attestation CA and BINDS: verified-boot state, OS patch
 * level, the app that owns the key, and — crucially — the verifier **nonce** we
 * pass as the attestation challenge. A node/verifier runs
 * `bloch::attestation::verify` with the `mobile` backend over that chain,
 * echoing the nonce it issued (via `getattestation`).
 *
 * HONEST LIMIT (see mobile/README.md + docs/specs/POSTERN-CONTAINER.md):
 * StrongBox is a CLASSICAL P-256 HSM. It does NOT hold the post-quantum
 * (Falcon‖ML-DSA) wallet key IN hardware. Its role is (a) attest the device/app
 * to a verifier, and (b) protect the PQ key material AT REST by wrapping it with
 * this hardware key. The PQ signing itself happens in the Rust core, in RAM
 * (zeroized on drop). Light-client role only — never a miner.
 *
 * The StrongBox→TEE **graceful fallback** ("report the tier you actually got,
 * never upgrade") is orchestrated in [AttestationTier]; this object exposes the
 * two raw builders ([generateAttestedKey] StrongBox, [generateTeeFallbackKey]
 * TEE) plus [attestationChainDer] (the A↔C wire) and [clear] (rotate the alias
 * before re-attesting with a fresh nonce).
 */
object StrongBoxKey {

    private const val KEY_ALIAS = "postern-wallet-wrap"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"

    /**
     * Generate (or replace) the StrongBox-backed key, attesting over [nonce].
     *
     * @param nonce the verifier/node challenge to echo into the attestation.
     * @param requireUserAuth gate key use behind device unlock / biometric.
     * @return the attestation certificate chain — the proof to hand a verifier.
     */
    fun generateAttestedKey(
        nonce: ByteArray,
        requireUserAuth: Boolean = true,
    ): Array<Certificate> {
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setIsStrongBoxBacked(true)                 // discrete HSM (falls back handled by caller)
            .setUserAuthenticationRequired(requireUserAuth)
            .setAttestationChallenge(nonce)             // echoes the node/verifier nonce
            .build()

        val kpg = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEYSTORE,
        )
        kpg.initialize(spec)
        kpg.generateKeyPair()
        return getCertificateChain()
    }

    /**
     * The Key-Attestation X.509 chain for the wrapping key — the Postern Seal
     * proof a verifier checks. Empty if no key has been generated yet.
     */
    fun getCertificateChain(): Array<Certificate> {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return ks.getCertificateChain(KEY_ALIAS) ?: emptyArray()
    }

    /**
     * The attestation chain as **leaf-first DER blobs** — the exact wire input
     * the `mobile` verifier backend consumes
     * (`crates/postern-seal-companion/src/mobile.rs::verify_key_attestation`,
     * feature `mobile-attest`). This is the A↔C seam: the container ships this
     * list out to a node/verifier, which checks it to a pinned Google
     * attestation root and returns a `Verdict`.
     *
     * HONEST LIMIT: this proves the **phone** (key-attested device state + app
     * identity), NOT the workspace. It is key-attested device, not
     * measured-boot workspace — design only, UNAUDITED, no security claim.
     *
     * The verifier expects index 0 = the leaf (the attested wrapping key), each
     * cert signed by the next, terminating at (or under) the pinned Google root.
     */
    fun attestationChainDer(): List<ByteArray> =
        getCertificateChain().map { it.encoded }

    /** Whether a wrapping key already exists in the Keystore. */
    fun exists(): Boolean {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return ks.containsAlias(KEY_ALIAS)
    }

    /**
     * Delete the current key so the next [generateAttestedKey] mints a fresh
     * attestation. Required before re-attesting with a new verifier nonce: a
     * Keystore entry's `attestationChallenge` is fixed at generation time, so a
     * new session nonce needs a new key. No-op if no key exists.
     */
    fun clear() {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (ks.containsAlias(KEY_ALIAS)) ks.deleteEntry(KEY_ALIAS)
    }

    /**
     * Some low-cost devices lack a StrongBox HSM. Callers that catch
     * `StrongBoxUnavailableException` from [generateAttestedKey] should retry
     * with this weaker, TEE-backed spec (`setIsStrongBoxBacked(false)`).
     */
    fun generateTeeFallbackKey(nonce: ByteArray, requireUserAuth: Boolean = true): Array<Certificate> {
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setIsStrongBoxBacked(false)                // TEE, not the discrete HSM — weaker guarantee
            .setUserAuthenticationRequired(requireUserAuth)
            .setAttestationChallenge(nonce)
            .build()
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        kpg.initialize(spec)
        kpg.generateKeyPair()
        return getCertificateChain()
    }
}
