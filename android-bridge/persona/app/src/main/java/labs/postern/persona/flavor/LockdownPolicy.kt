// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.persona.flavor

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.os.UserManager

/**
 * **The CLEAN persona's baseline hardening — persona-local by `android-common`'s design.**
 *
 * `COMMON-INTERFACE.md` optimistically listed `LockdownPolicy` under
 * `labs.postern.common.dpc` as "reused as-is". The shared module **as landed deliberately
 * does the opposite**: its README states hardening *"stays in each product"* — the shared
 * DPC skeleton applies **no** policy of its own, and Porog's `LockdownPolicy.applyBaseline()`
 * remains in `android-container/`. There is therefore no shared baseline class to import.
 *
 * Per COMMON-INTERFACE.md's divergence rule — *"a thin adapter in this tree ... never a fork
 * of the DPC"* — this is the persona-local baseline. It is the **generic, hardening-free
 * subset** of Porog's baseline (the product-neutral `DevicePolicyManager` calls), reproduced
 * here because the shared module intentionally does not vend it:
 *
 *  - screen capture off,
 *  - IME restricted to the system allowlist,
 *  - cross-profile copy/paste disallowed,
 *  - unknown-sources (sideload) install disallowed.
 *
 * It intentionally **omits** Porog's `WorkChallengePolicy.require()` step: that separate-work-
 * challenge requirement is Porog-app-specific hardening (it underpins Porog's Panic-Lock
 * CE-key eviction), not part of the generic managed-profile baseline, and NoporIS does not
 * claim that Porog-specific capability on the persona. The CLEAN flavor is "Porog-style"
 * hardening applied to a persona, honestly labelled — not a bit-for-bit re-derivation of the
 * Porog app's full policy.
 *
 * ## Honest limit (verbatim from the shared boundary)
 * These toggles are enforced by the Android framework + kernel, not by NoporIS. They are
 * exactly as strong as the managed-profile boundary — a rooted / kernel-compromised host
 * ignores all of them. Hardened separation, not anonymity, and never "Postern OS."
 *
 * **Status: SCAFFOLD · DESIGN ONLY · UNAUDITED.** Never applied on a device.
 */
class LockdownPolicy(
    private val context: Context,
    private val admin: ComponentName,
) {
    private val dpm: DevicePolicyManager =
        context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager

    /** Apply the baseline the moment we own the CLEAN persona's profile. Idempotent by intent. */
    fun applyBaseline() {
        disableScreenCapture()
        restrictInputMethodsToSystem()
        blockCrossProfileSharing()
        blockUnknownSources()
    }

    /** Malicious-screenshot / screen-recorder mitigation inside the profile. */
    private fun disableScreenCapture() {
        dpm.setScreenCaptureDisabled(admin, true)
    }

    /** Empty allowlist ⇒ system IMEs only (a null list would permit ALL IMEs). */
    private fun restrictInputMethodsToSystem() {
        dpm.setPermittedInputMethods(admin, emptyList())
    }

    /** Keep the default-off cross-profile posture and disallow cross-profile copy/paste. */
    private fun blockCrossProfileSharing() {
        dpm.addUserRestriction(admin, UserManager.DISALLOW_CROSS_PROFILE_COPY_PASTE)
    }

    /** Block sideloading inside the clean persona. */
    private fun blockUnknownSources() {
        dpm.addUserRestriction(admin, UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES)
    }
}
