// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.container.attest

/**
 * The **A↔attest seam**: the only surface across which this DPC/provisioning tree
 * talks to attestation. Per the dev breakdown, the seam is exactly
 * **"nonce in → cert chain out → verdict/tier back"** — and nothing more.
 *
 * - **Dev 1 / A-lead (DPC tree)** owns provisioning + lifecycle and merely *calls*
 *   this interface at the right moment — see [onProfileOwnerEstablished], the
 *   single method the DPC fires after enrollment.
 * - **Dev 4 / A-attest (this tree)** owns the real implementation
 *   ([StrongBoxAttestationGateway]): StrongBox/TEE key generation with
 *   `setAttestationChallenge(nonce)`, and the mobile Key-Attestation *verify*
 *   backend in `postern-seal-companion` (`mobile-attest`: parse the X.509 chain,
 *   pin current Google roots, check verified-boot / patch / app-id + nonce).
 *
 * ## The A↔C wire (stable)
 * [AttestationEvidence.chainDer] is **leaf-first DER**, index 0 = the attested
 * leaf, each cert signed by the next, terminating at/under a pinned Google root.
 * The Rust `verify_key_attestation(chain_der, expected)` consumes exactly that and
 * returns `Verdict::{Genuine, Mismatch(reason), Unverified(reason)}`. Keep this
 * structure stable — it is the only cross-boundary data shape.
 *
 * ## Honest boundary
 * Attestation here proves the **phone** (a hardware-backed key on a device whose
 * verified-boot state / patch level / app identity are as reported, nonce echoed
 * for freshness). It does **NOT** measure the **workspace**: key-attested device,
 * not measured-boot workspace. StrongBox is classical P-256 — no PQ key in
 * hardware. Verification is authoritative **server-side only** (Google roots +
 * current-RKP-rotation pinning live off-device). Attestation raises the RBAC bar;
 * it never replaces wallet-key auth, and it never hard-excludes a device — a
 * failed/absent tier is degraded posture, reported honestly.
 *
 * SCAFFOLD · DESIGN ONLY · UNAUDITED · UNTESTED-until-VM/device.
 */
interface AttestationGateway {

    /**
     * The verdict surfaced to the UI. Deliberately opaque about cert internals —
     * this tree does not interpret chains, it only relays the verifier's result.
     * Mirrors the Rust `Verdict` (Genuine / Mismatch / Unverified) plus a local
     * [Unavailable] for "no evidence / no verifier reachable".
     */
    sealed interface Verdict {
        /** Verifier returned Genuine at the reported [tier] (never upgraded). */
        data class Trusted(val tier: AttestationTier) : Verdict

        /** Verifier returned a named Mismatch/Unverified (fail-closed reason). */
        data class Rejected(val reason: String) : Verdict

        /** Attestation not attempted, no hardware key, or no verifier reachable. */
        data object Unavailable : Verdict
    }

    /**
     * Generate a hardware-backed key that attests over [nonce], with a graceful
     * StrongBox→TEE fallback, and return the [AttestationEvidence] (leaf-first
     * DER chain + the tier actually reached). Never fabricates a chain: on failure
     * it returns [AttestationTier.NONE] with an empty chain.
     */
    fun attest(nonce: ByteArray): AttestationEvidence

    /**
     * Ask the (server-side) verifier for a [Verdict] over previously produced
     * [evidence]. The authoritative Google-rooted check runs off-device; an
     * on-device implementation forwards the chain + nonce and relays the result.
     */
    fun verify(evidence: AttestationEvidence): Verdict

    /**
     * **The attestation kick Dev 1 calls from `onProfileOwnerEstablished`.**
     *
     * Signature (the seam contract handed to Dev 1):
     * ```
     * gateway.onProfileOwnerEstablished(nonce: ByteArray): Verdict
     * ```
     * where `nonce` is the fresh verifier/node challenge (freshness / anti-replay).
     * It composes [attest] (nonce → chain) then [verify] (chain → verdict) and
     * returns the [Verdict] for the UI. Contract for Dev 1:
     * - **Best-effort, never throws** to the caller — any failure is caught and
     *   surfaced as [Verdict.Rejected]/[Verdict.Unavailable], not an exception.
     * - **Never gates provisioning.** A non-[Verdict.Trusted] result is degraded
     *   posture to display/log; it must not abort profile setup.
     * - **Off the main thread.** Key generation + the verifier round-trip block;
     *   Dev 1 should call this from a background/IO context.
     */
    fun onProfileOwnerEstablished(nonce: ByteArray): Verdict =
        try {
            verify(attest(nonce))
        } catch (t: Throwable) {
            Verdict.Rejected("attestation kick failed: ${t.javaClass.simpleName}")
        }

    companion object {
        /**
         * The NO-OP stub the scaffold links against until the real gateway is
         * wired. Honest by construction: it attests nothing ([AttestationTier.NONE])
         * and reports [Verdict.Unavailable] — it NEVER fabricates a trusted verdict.
         */
        val NoOp: AttestationGateway = object : AttestationGateway {
            override fun attest(nonce: ByteArray): AttestationEvidence =
                AttestationEvidence(AttestationTier.NONE, emptyList(), nonce)

            override fun verify(evidence: AttestationEvidence): Verdict = Verdict.Unavailable
        }
    }
}
