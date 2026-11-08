// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.container.attest

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec

/**
 * The real [AttestationGateway]: it generates a hardware-backed EC P-256 key in
 * the device Keystore that attests over a verifier nonce, with a **graceful
 * StrongBox→TEE fallback**, and forwards the resulting chain to a server-side
 * verifier for the authoritative [AttestationGateway.Verdict].
 *
 * ## StrongBox → TEE fallback ("report the tier you got, never upgrade")
 * [attest] first asks for a discrete-HSM (`setIsStrongBoxBacked(true)`) key. On a
 * device with no StrongBox chip the Keystore throws `StrongBoxUnavailableException`;
 * we catch it and retry with a TEE-backed spec, and we report [AttestationTier.TEE].
 * We NEVER report [AttestationTier.STRONGBOX] for a key that fell back — the local
 * tier is only a provisional hint; the authoritative security level is whatever the
 * server-side Rust verifier reads out of the attested `KeyDescription`.
 *
 * ## Verification is server-side
 * The Google attestation roots, current-RKP-rotation pinning, and the fail-closed
 * field checks live in `crates/postern-seal-companion/src/mobile.rs`
 * (`verify_key_attestation`, feature `mobile-attest`), run **off-device** — the
 * phone holds no trust anchor. [verify] hands the leaf-first DER chain + nonce to a
 * [Verifier] seam and relays its verdict. With no verifier wired it fails closed to
 * [AttestationGateway.Verdict.Unavailable], never a fabricated pass.
 *
 * ## Honest boundary (repo-enforced)
 * A [AttestationTier.STRONGBOX] result proves the **phone** — a key-attested
 * device, **not a measured-boot workspace**. StrongBox is classical P-256: it
 * attests the device and wraps the PQ wallet key at rest; it does not hold or sign
 * the Falcon‖ML-DSA key. Attestation raises the RBAC bar; it never replaces
 * wallet-key auth, and a failed/absent tier degrades posture — it never
 * hard-excludes a device.
 *
 * SCAFFOLD · DESIGN ONLY · UNAUDITED · UNTESTED-until-VM/device. `SecurityLevel=2`
 * StrongBox is provable ONLY on real hardware (Pixel 3+ / some Samsung); an
 * emulator has no discrete HSM and will (correctly) fall back to TEE/software.
 *
 * @param verifier the server-side verify seam. Defaults to [Verifier.None] —
 *   fail-closed until a real verifier client is injected.
 * @param keyAlias Keystore alias for the attested key.
 * @param requireUserAuth gate key use behind device unlock / biometric.
 */
class StrongBoxAttestationGateway(
    private val verifier: Verifier = Verifier.None,
    private val keyAlias: String = DEFAULT_ALIAS,
    private val requireUserAuth: Boolean = true,
) : AttestationGateway {

    /**
     * The server-side verify seam. An implementation forwards the chain + nonce
     * to the `postern-seal-companion` mobile backend and returns its verdict; it
     * MUST NOT trust anything client-decoded. [None] is the fail-closed default.
     */
    fun interface Verifier {
        fun verify(evidence: AttestationEvidence): AttestationGateway.Verdict

        companion object {
            /** No verifier wired → fail closed to Unavailable (never a pass). */
            val None: Verifier = Verifier { AttestationGateway.Verdict.Unavailable }
        }
    }

    override fun attest(nonce: ByteArray): AttestationEvidence {
        // 1. Try the discrete StrongBox HSM.
        try {
            generateKey(nonce, strongBox = true)
            return AttestationEvidence(AttestationTier.STRONGBOX, chainDer(), nonce)
        } catch (_: StrongBoxUnavailableException) {
            // Fall through to the TEE tier — a graceful fallback, not a failure.
        } catch (_: Throwable) {
            return AttestationEvidence(AttestationTier.NONE, emptyList(), nonce)
        }

        // 2. TEE fallback. Report TEE — never upgrade the label back to StrongBox.
        return try {
            generateKey(nonce, strongBox = false)
            AttestationEvidence(AttestationTier.TEE, chainDer(), nonce)
        } catch (_: Throwable) {
            AttestationEvidence(AttestationTier.NONE, emptyList(), nonce)
        }
    }

    override fun verify(evidence: AttestationEvidence): AttestationGateway.Verdict {
        if (!evidence.hasEvidence) return AttestationGateway.Verdict.Unavailable
        return verifier.verify(evidence)
    }

    /** Generate (or replace) the attested key with the requested backing. */
    private fun generateKey(nonce: ByteArray, strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setIsStrongBoxBacked(strongBox)
            .setUserAuthenticationRequired(requireUserAuth)
            .setAttestationChallenge(nonce) // echoes the verifier nonce (freshness)
            .build()
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        kpg.initialize(spec)
        kpg.generateKeyPair()
    }

    /** The attestation chain as **leaf-first DER** — the A↔C wire input. */
    private fun chainDer(): List<ByteArray> {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val chain = ks.getCertificateChain(keyAlias) ?: return emptyList()
        return chain.map { it.encoded }
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val DEFAULT_ALIAS = "porog-container-attest"
    }
}
