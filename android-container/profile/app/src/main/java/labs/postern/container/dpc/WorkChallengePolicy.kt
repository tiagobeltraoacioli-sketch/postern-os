// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.container.dpc

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build

/**
 * The Porog **separate work challenge** policy — the piece that makes Panic Lock's
 * CE-key eviction meaningful.
 *
 * ## Why this is load-bearing (not cosmetic)
 * The Panic Lock ([ContainerProfileManager.panicLock] /
 * `lockNow(FLAG_EVICT_CREDENTIAL_ENCRYPTION_KEY)`) only *seals* anything if the
 * profile has its **own** credential-encryption key — i.e. a **separate work
 * challenge** distinct from the device lock. If the profile shares the device's
 * unified challenge, there is no separate CE key to evict and "Panic Lock" silently
 * degrades to a device lock. This class closes that gap: at enrollment it
 * **requires** a work-profile lock of at least medium complexity, and offers the
 * intent to **prompt** the user to set one — the precondition for a real Panic Lock
 * (`porog-01` §2.1), not decoration.
 *
 * This is Porog-only hardening (it never leaks into the shared `android-common`
 * core or into NoporIS). It is wired from [LockdownPolicy.applyBaseline].
 *
 * ## What each call does
 * - [require] sets the *minimum acceptable* profile-lock strength as profile owner:
 *   `setRequiredPasswordComplexity(PASSWORD_COMPLEXITY_MEDIUM)` on API 31+ (the modern
 *   coarse API), falling back to `setPasswordQuality(PASSWORD_QUALITY_NUMERIC_COMPLEX)`
 *   on API 30. It states the requirement; it does not itself create a lock.
 * - [isSatisfied] reports whether the profile currently satisfies that requirement
 *   (`isActivePasswordSufficient`), so the UI can honestly show whether a real
 *   separate CE key exists yet (see [shouldPrompt] for the pure decision).
 * - [newSetWorkChallengeIntent] returns `ACTION_SET_NEW_PASSWORD` for the onboarding
 *   UI to launch so the user actually sets the profile lock; the framework owns that
 *   UI and we never handle the secret.
 *
 * ## Honest limit
 * These are Android-framework password requirements, enforced by the platform, not
 * by Porog. The user must actually *set* the separate challenge (the platform shows
 * `ACTION_SET_NEW_PASSWORD`); until they do, the profile falls back to the unified
 * lock and Panic Lock cannot evict a separate CE key — an honest limitation to
 * surface in the UI (Dev 2), never to paper over. Complexity floors are advisory to
 * the framework, OEM keyguards vary, and a rooted / kernel-compromised host defeats
 * the whole boundary. Hardened, not anonymous.
 *
 * **Status: SCAFFOLD · DESIGN ONLY · UNAUDITED · UNTESTED-until-VM/device.** Never
 * applied on hardware; the password-complexity APIs are exercised only from a real
 * profile-owner context.
 */
class WorkChallengePolicy(
    private val context: Context,
    private val admin: ComponentName,
) {
    private val dpm: DevicePolicyManager =
        context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager

    /**
     * **Require** a separate work challenge of at least medium complexity. Idempotent
     * by intent — re-applying the same requirement is a no-op at the platform level;
     * the user still sets the actual lock via [newSetWorkChallengeIntent].
     *
     * - **API 31+ (S):** `setRequiredPasswordComplexity(PASSWORD_COMPLEXITY_MEDIUM)`,
     *   the modern, bucketed requirement.
     * - **API 30 (R) fallback:** the deprecated but still-honored
     *   `setPasswordQuality(PASSWORD_QUALITY_NUMERIC_COMPLEX)`. We deliberately keep
     *   the fallback rather than raise `minSdk`, so R devices still get a real
     *   separate challenge.
     *
     * Runs in profile-owner context (from `onProfileOwnerEstablished`).
     * **UNTESTED-until-VM/device.**
     */
    fun require() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            // API 31+ coarse complexity bucket — the recommended modern surface.
            dpm.setRequiredPasswordComplexity(DevicePolicyManager.PASSWORD_COMPLEXITY_MEDIUM)
        } else {
            // R fallback: no bucketed complexity API yet. NUMERIC_COMPLEX forces a
            // non-trivial PIN (no repeating/ordered sequences) as the separate lock.
            @Suppress("DEPRECATION")
            dpm.setPasswordQuality(admin, DevicePolicyManager.PASSWORD_QUALITY_NUMERIC_COMPLEX)
        }
    }

    /**
     * Whether a separate work challenge that meets the required complexity is
     * **currently set** — i.e. a real separate work challenge (and CE key) exists.
     * Best-effort read of profile-owner password sufficiency. The UI must consult
     * this before implying the Panic Lock can seal anything: `false` ⇒ a Panic Lock
     * would only be a device lock, an honest limitation to surface, not paper over.
     * Used to decide whether the user still needs to be prompted (see [shouldPrompt]).
     *
     * `false` when no sufficient separate challenge exists yet, or when the read
     * cannot be performed. **UNTESTED-until-VM/device.**
     */
    fun isSatisfied(): Boolean =
        runCatching {
            @Suppress("DEPRECATION")
            dpm.isActivePasswordSufficient
        }.getOrDefault(false)

    /**
     * The intent that drives the user to set/upgrade the separate work challenge.
     * The caller (the in-profile onboarding surface — Dev 2) starts it from an
     * Activity; a `BroadcastReceiver` context cannot. Kept as a factory so this
     * policy stays Activity-agnostic. The framework owns the credential-entry UI;
     * we never handle the secret.
     */
    fun newSetWorkChallengeIntent(): Intent = Intent(DevicePolicyManager.ACTION_SET_NEW_PASSWORD)

    companion object {
        /**
         * **Pure** gate: should we prompt the user to set the separate work
         * challenge? Factored out so it is JVM-unit-testable with no Android device.
         * Prompt exactly when the challenge is [required] and not yet [satisfied].
         */
        @JvmStatic
        fun shouldPrompt(required: Boolean, satisfied: Boolean): Boolean =
            required && !satisfied
    }
}
