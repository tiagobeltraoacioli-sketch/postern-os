// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.container.dpc

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.util.Log
import labs.postern.common.profile.dpc.ManagedProfileAdminReceiver
import labs.postern.container.attest.AttestationGateway
import labs.postern.container.attest.StrongBoxAttestationGateway
import java.security.SecureRandom
import java.util.concurrent.Executors

/**
 * The Porog **Device Policy Controller (DPC)**. Registered in the manifest with
 * `BIND_DEVICE_ADMIN`, it becomes **profile owner** of the managed profile created
 * by `ACTION_PROVISION_MANAGED_PROFILE` (the self-enrolled, no-root, no-EMM path).
 *
 * The generic enrollment sequence — name the profile, apply post-provisioning
 * policy, enable the profile — lives in the shared [ManagedProfileAdminReceiver]
 * (android-common), so Porog and NoporIS do **not** fork a second DPC. Porog
 * supplies exactly two things here: the profile name, and — in the single
 * [onProfileOwnerEstablished] extension point — its **hardening**: the baseline
 * lockdown ([LockdownPolicy.applyBaseline]). That hardening is what makes Porog the
 * hardened "door"; it stays Porog-only and never leaks into the shared module or
 * into NoporIS's deliberately less-private persona.
 *
 * ## Honest trust boundary (keep it verbatim on every surface)
 * This makes Porog the profile owner of a second Android user — real per-profile
 * FBE + SELinux isolation. It attests the **phone**, not the **workspace**:
 * hardened, not anonymous; key-attested, not measured-boot. A rooted /
 * kernel-compromised host defeats the whole boundary; only Postern OS Mobile
 * (measured boot) addresses that, and this is **NEVER "Postern OS."**
 *
 * **Status: SCAFFOLD · DESIGN ONLY · UNAUDITED.** Never provisioned on hardware.
 */
class PosternDeviceAdminReceiver : ManagedProfileAdminReceiver() {

    companion object {
        private const val TAG = "PorogDpc"

        /** The admin component name, for building provisioning intents / DPM calls. */
        fun componentName(context: Context): ComponentName =
            ComponentName(context, PosternDeviceAdminReceiver::class.java)

        // User-facing profile name. "Porog" (PROPOSED, pending trademark clearance).
        private const val PROFILE_NAME = "Porog"

        /** Attestation-challenge nonce size (bytes). 256-bit freshness. */
        private const val NONCE_BYTES = 32
    }

    override fun profileName(context: Context): String = PROFILE_NAME

    /**
     * Porog's post-provisioning policy: the baseline lockdown (screenshots off, IME
     * allowlist, cross-profile off, unknown sources blocked). This is the ONLY
     * hardening in the DPC path, and it is intentionally Porog-only — the shared
     * skeleton applies none. The Tor always-on VPN and the postern-policy consent
     * gate are Dev A-workspace's to wire; LockdownPolicy exposes those as
     * clearly-labeled seams, not silent gaps.
     *
     * Runs after Porog is confirmed profile owner and the profile is named, and
     * before the profile is enabled — identical ordering to the pre-extraction
     * scaffold.
     */
    override fun onProfileOwnerEstablished(
        context: Context,
        dpm: DevicePolicyManager,
        admin: ComponentName,
    ) {
        // 1. Porog's own hardening baseline (screenshots off, IME allowlist,
        //    cross-profile off, unknown sources blocked, separate work challenge
        //    required). Runs inline: it must land BEFORE the profile is enabled.
        LockdownPolicy(context, admin).applyBaseline()

        // 2. SEAM (Dev 3) — cross-profile reconciler FIRST reconcile. Reads the gate
        //    state (files/porog-gate/state.json) and maps the host-proven kernel's
        //    directives onto DPM cross-profile calls; idempotent. The baseline above
        //    already set the default-deny copy-paste restriction, so the reconciler
        //    is authoritative from an all-deny floor (documented semantic coordination
        //    with Dev 3). Wrapped so a reconcile hiccup never aborts enrollment.
        //    Real seam signature (Dev 3 owns the class) — UNTESTED-until-VM:
        //      class CrossProfileReconciler(Context, DevicePolicyManager, ComponentName) {
        //          fun reconcile(trigger: Trigger): Decision   // Trigger.PROVISIONING here
        //      }
        runCatching {
            CrossProfileReconciler(context, dpm, admin)
                .reconcile(CrossProfileReconciler.Trigger.PROVISIONING)
        }.onFailure { Log.w(TAG, "cross-profile first reconcile failed (non-fatal)", it) }

        // 2b. Arm the in-process gate-state observer from its long-lived host (this
        //     DPC process). It lives as long as the process does; the explicit
        //     GateStateWriter broadcast + the BOOT_COMPLETED reconcile cover the
        //     not-running case, so a dead observer is only ever a DELAYED reconcile,
        //     never a laxer policy. ensureStarted never throws.
        BridgeStateObserver.ensureStarted(context)

        // 3. SEAM (Dev 4) — StrongBox attestation kick (nonce → chain → verdict).
        //    Key generation can be slow, so it is dispatched OFF the broadcast thread
        //    to avoid blocking profile-enable / an ANR; it is not a precondition for a
        //    usable profile. Honest by construction: the NoOp/Unavailable path never
        //    fabricates a trusted verdict. This attests the PHONE, not the workspace —
        //    key-attested device, not a measured-boot workspace.
        kickAttestation()

        // NOTE(Dev 2): the in-profile onboarding hand-off (prompt the user to set the
        // separate work challenge, render the honest attestation verdict/tier) is the
        // UI surface owned by Dev 2; this receiver only kicks the work.
    }

    /**
     * Fire-and-forget StrongBox attestation on enrollment, off the broadcast thread.
     *
     * Orchestrated here over the stable [AttestationGateway] seam interface; the
     * concrete [StrongBoxAttestationGateway] (StrongBox with a TEE fallback) is
     * supplied by Dev 4. We generate a fresh nonce, obtain the attested cert chain,
     * ask the verifier for a [AttestationGateway.Verdict], and log it honestly. The
     * user-facing surface is Dev 2's; the real verify backend is
     * `postern-seal-companion` (Dev 4). All failures are swallowed to a logged,
     * non-fatal Unavailable — enrollment never depends on attestation succeeding.
     *
     * **UNTESTED-until-device.** The emulator's keymaster is software, so on VM this
     * yields `Tier.TEE`/`NONE`, never `STRONGBOX` — a correct, honest result, not a bug.
     */
    private fun kickAttestation() {
        Executors.newSingleThreadExecutor().execute {
            // Real seam (Dev 4) — UNTESTED-until-VM. The gateway's
            // onProfileOwnerEstablished(nonce) is best-effort and NEVER throws:
            // it composes attest()+verify() internally and returns a Verdict
            // (Trusted/Rejected/Unavailable). We just supply a fresh nonce and log.
            val gateway: AttestationGateway = StrongBoxAttestationGateway()
            val verdict: AttestationGateway.Verdict =
                gateway.onProfileOwnerEstablished(freshNonce())
            // Report the tier we ACTUALLY got — never assume STRONGBOX.
            Log.i(TAG, "enrollment attestation verdict = $verdict (attests the phone, not the workspace)")
        }
    }

    /** A cryptographically-fresh attestation challenge nonce (256-bit). */
    private fun freshNonce(): ByteArray =
        ByteArray(NONCE_BYTES).also { SecureRandom().nextBytes(it) }
}
