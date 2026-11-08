// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Postern Labs
package labs.postern.persona.play

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context

/**
 * The **Google-Play flavor** post-provisioning policy — flavor B of NoporIS's one
 * second persona (Mechanism-Design §3.3). It is the sibling of the clean flavor's
 * `LockdownPolicy` (in `android-container`, Dev N-lead's Porog scaffold): the
 * *same* self-enrolled managed-profile DPC, a *different* post-provisioning policy
 * set. NoporIS does **not** fork a second DPC — this class is applied by the shared
 * profile-owner receiver (consumed from `android-common`; NOT edited here) when the
 * user picked the Google-Play flavor at provisioning.
 *
 * What it does, and *only* this:
 *  1. `enableSystemApp(admin, pkg)` for the Play Store + GMS anchors **inside the
 *     managed profile only**, gated deny-by-default through [GmsPackages.ALLOWLIST].
 *     This **un-hides** stock system apps the certified device already ships — it
 *     redistributes nothing (see [GmsPackages]).
 *  2. Asserts the **NO-wallet-keys** invariant for this side ([WalletKeyExclusion]).
 *  3. Leaves cross-persona sharing **OFF** — the Play persona must never see the
 *     clean persona's data. This class opens no bridge; the switcher/bridge panel
 *     is the persona-root's job (Dev N-persona), deny-by-default.
 *
 * ## Honest boundary — the load-bearing rails (keep verbatim on every surface)
 * The Google-Play persona is the **LESS-PRIVATE side, by construction**: GMS phones
 * home. NoporIS sells **separation + convenience, NOT privacy** on this side, and
 * cannot make a Google-Android persona private. It is an app on **stock Android —
 * NEVER "Postern OS."** The profile's FBE + SELinux boundary is real
 * (`EnforcementMode::KernelBoundary`), but a **rooted / kernel-compromised host
 * defeats it**. The user brings **their own Google account** and installs from Play
 * themselves — a self-enrolled non-EMM DPC **cannot** silently add accounts or push
 * apps, and NoporIS does not try to (honest limit, this is Play-in-a-profile, NOT
 * *Managed* Google Play).
 *
 * The "less-private" in-product labeling copy is owned by the labeling module
 * (`android-bridge/config/`, Dev N-labeling); this class references it as a seam
 * rather than duplicating the strings.
 *
 * **Status: SCAFFOLD · DESIGN ONLY · UNAUDITED.** Never applied on a device.
 */
class PlayFlavorPolicy(
    private val context: Context,
    private val admin: ComponentName,
) {
    private val dpm: DevicePolicyManager =
        context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager

    /** Outcome of enabling one system app: what was requested and whether the gate allowed it. */
    data class EnableResult(val pkg: String, val enabled: Boolean, val reason: String)

    /**
     * Apply the Google-Play flavor. MUST be called as **profile owner INSIDE the
     * managed profile** (from the shared receiver's `onProfileProvisioningComplete`
     * for the Play flavor). Order matters: prove the no-wallet-keys invariant
     * *before* enabling anything Google.
     *
     * @param observedKeyAliases Keystore aliases seen in this profile (real build:
     *   `KeyStore.aliases()`), for the wallet-exclusion self-check.
     * @param observedPackages packages present in this profile (real build:
     *   profile-scoped `PackageManager`), for the same check.
     * @return the per-package enable results (for honest logging / UI), all from
     *   the deny-by-default gate.
     */
    fun apply(
        observedKeyAliases: List<String> = emptyList(),
        observedPackages: List<String> = emptyList(),
    ): List<EnableResult> {
        // 1. Fail-closed: NO wallet keys/packages on the Google side. Hard stop.
        WalletKeyExclusion.assertClean(observedKeyAliases, observedPackages)

        // 2. Un-hide the Play/GMS system apps, deny-by-default through the allowlist.
        val results = GmsPackages.ALLOWLIST.map { pkg ->
            if (mayEnable(pkg)) {
                enableSystemApp(pkg)
                EnableResult(pkg, enabled = true, reason = "on Play/GMS allowlist; not wallet-owned")
            } else {
                EnableResult(pkg, enabled = false, reason = "denied by policy gate")
            }
        }

        // 3. Cross-persona sharing stays OFF (inherited default). We add no
        //    cross-profile intent filter, no clipboard/contacts bridge. The user
        //    must open each bridge on purpose via the persona-root panel.
        //    (No call here == the deny-by-default posture; documented, not silent.)

        // NOTE (honest limit): we do NOT sign in a Google account and do NOT push
        // apps — a self-enrolled non-EMM DPC cannot, and NoporIS will not pretend
        // to. The user signs in and installs from Play themselves. That hand-off UX
        // is the persona-root's onboarding seam (Dev N-persona), not this class.
        return results
    }

    /**
     * The deny-by-default gate for `enableSystemApp`. Mirrors `mayEnableSystemApp`
     * in `policy/play-flavor-policy.mjs`: allow only if on the Play/GMS allowlist
     * AND not wallet-owned. Public for the switcher/preflight to reuse.
     */
    fun mayEnable(pkg: String?): Boolean =
        pkg != null &&
            !WalletKeyExclusion.isWalletOwnedPackage(pkg) &&
            GmsPackages.ALLOWLIST.contains(pkg)

    /**
     * `enableSystemApp` un-hides a system app **already present** on a certified
     * device, **within this managed profile only**. If the package is absent (a
     * de-Googled ROM), the platform call is a no-op and NoporIS plants nothing —
     * the user's microG / GApps / vanilla choice is theirs, never bundled by us.
     */
    private fun enableSystemApp(pkg: String) {
        // Guarded so a de-Googled device (package genuinely absent) is a clean no-op
        // rather than an exception — we enable what exists, redistribute nothing.
        runCatching { dpm.enableSystemApp(admin, pkg) }
    }
}
