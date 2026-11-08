// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.container.dpc

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.os.UserManager

/**
 * The **baseline** lockdown policy applied once Postern becomes profile owner
 * (called from [PosternDeviceAdminReceiver.onProfileProvisioningComplete]).
 *
 * Scope split (per the A1 decision record + the 10-dev breakdown):
 * - **Owned here (A-lead):** the provisioning-hygiene baseline that belongs with
 *   *becoming profile owner* — screen capture off, an IME allowlist, cross-profile
 *   sharing off, unknown-sources blocked, and requiring a **separate work challenge**
 *   ([WorkChallengePolicy.require]) so the Panic Lock's CE-key eviction is meaningful.
 * - **A clearly-labeled seam, NOT implemented here (A-workspace):** the **Tor
 *   always-on lockdown VPN** (`setAlwaysOnVpnPackage(admin, "org.torproject.android",
 *   lockdown = true)`) plus leak/kill-switch testing, and the `postern-policy`
 *   consent kernel that drives per-toggle bridges. We surface the call site so the
 *   gap is honest, not silent.
 *
 * ## Honest limit
 * These toggles are enforced by the Android framework + kernel, not by Postern's
 * code. They are exactly as strong as the profile boundary — a rooted host ignores
 * all of them. Hardened, not anonymous.
 *
 * **Status: SCAFFOLD · DESIGN ONLY · UNAUDITED.** Never applied on a device.
 */
class LockdownPolicy(
    private val context: Context,
    private val admin: ComponentName,
) {
    private val dpm: DevicePolicyManager =
        context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager

    /** Apply the baseline the moment we own the profile. Idempotent by intent. */
    fun applyBaseline() {
        disableScreenCapture()
        blockCrossProfileSharing()
        blockUnknownSources()
        restrictInputMethods(permittedImePackages = emptyList()) // empty ⇒ system IMEs only.

        // Require a SEPARATE work challenge (distinct profile lock ⇒ distinct CE key).
        // This is the precondition that makes the Panic Lock's CE-key eviction
        // meaningful (porog-01 §2.1; a shared/unified lock has no separate CE key to
        // evict) — without it, "lock" degrades to a device lock. Porog-only
        // hardening; stating the requirement here, the in-profile onboarding surface
        // (Dev 2) drives the user to actually set it via
        // WorkChallengePolicy.newSetWorkChallengeIntent(). UNTESTED-until-VM/device.
        WorkChallengePolicy(context, admin).require()

        // ── SEAM (Dev A-workspace) — NOT wired here ─────────────────────────────
        // Always-on Tor lockdown VPN + kill-switch/leak testing, and the
        // postern-policy consent gate. Intentionally left as a documented seam:
        //
        //   dpm.setAlwaysOnVpnPackage(admin, ORBOT_PACKAGE, /* lockdownEnabled = */ true)
        //
        // Wiring Orbot, verifying no traffic escapes the tunnel, and gating the
        // bridges through postern-policy is A-workspace's milestone (A4), not A2.
    }

    /** Malicious-screenshot / screen-recorder mitigation inside the profile. */
    private fun disableScreenCapture() {
        dpm.setScreenCaptureDisabled(admin, true)
    }

    /**
     * Restrict IMEs to a keylogger-resistant allowlist. An empty list restricts to
     * the system IMEs only (the safe default); a non-empty list additionally
     * permits the named packages.
     */
    private fun restrictInputMethods(permittedImePackages: List<String>) {
        // null would permit ALL IMEs; we pass a concrete list to enforce the allowlist.
        dpm.setPermittedInputMethods(admin, permittedImePackages)
    }

    /** No shared clipboard/contacts/notifications unless the user later opts in. */
    private fun blockCrossProfileSharing() {
        // Do not add cross-profile intent filters; keep the default-off posture and
        // explicitly disallow cross-profile copy/paste where the platform allows.
        dpm.addUserRestriction(admin, UserManager.DISALLOW_CROSS_PROFILE_COPY_PASTE)
    }

    /** Block sideloading inside the container; the install path is Postern Store. */
    private fun blockUnknownSources() {
        dpm.addUserRestriction(admin, UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES)
    }
}
