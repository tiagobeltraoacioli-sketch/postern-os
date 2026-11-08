// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Postern Labs
package labs.postern.persona.play

/**
 * The **"NO wallet keys on the Google side"** invariant, as code.
 *
 * The whole point of the Play flavor is that GMS lives in *its own* FBE boundary,
 * **not next to the wallet** (Mechanism-Design §3.3). So the Google-Play persona
 * must never carry Postern wallet / seal / signer packages, nor any StrongBox /
 * Keystore key material for them. This class is the fail-closed guard that a
 * self-check (and policy apply) uses to *prove* that, rather than merely assume it.
 *
 * The canonical deny-lists + `walletExclusionViolations` live in the node-testable
 * `policy/play-flavor-policy.mjs`; this mirrors them for the Kotlin side.
 *
 * ## Honest enforcement boundary
 * This is an in-process check — `EnforcementMode::ByConstruction` in
 * `crates/postern-policy` terms: *"integrity by construction: a userland,
 * in-process check, not an OS sandbox or kernel boundary."* The real separation
 * between wallet and Google is the **profile's FBE + SELinux boundary** (kernel);
 * this guard only makes the intended absence *checkable* and fail-closed. A
 * rooted host defeats both. Never round this up to the kernel boundary's strength.
 *
 * **Status: SCAFFOLD · DESIGN ONLY · UNAUDITED.** Never run on a device.
 */
object WalletKeyExclusion {

    /** Package-name prefixes that carry Postern wallet / container / signer code. */
    val FORBIDDEN_PACKAGE_PREFIXES: List<String> = listOf(
        "labs.postern.wallet",
        "labs.postern.container",
        "labs.postern.signer",
    )

    /** Keystore alias prefixes for wallet / seal / signer key material. */
    val FORBIDDEN_KEY_ALIAS_PREFIXES: List<String> = listOf(
        "postern.wallet.",
        "postern.seal.",
        "postern.signer.",
    )

    /** A single detected violation of the no-wallet-keys invariant. */
    data class Violation(val kind: Kind, val value: String) {
        enum class Kind { PACKAGE, KEY_ALIAS }
    }

    fun isWalletOwnedPackage(pkg: String?): Boolean =
        pkg != null && FORBIDDEN_PACKAGE_PREFIXES.any { pkg == it || pkg.startsWith("$it.") || pkg.startsWith(it) }

    fun isWalletKeyAlias(alias: String?): Boolean =
        alias != null && FORBIDDEN_KEY_ALIAS_PREFIXES.any { alias.startsWith(it) }

    /**
     * Given the Keystore aliases and installed packages observed **inside the
     * Play profile**, return every violation. An empty list means the invariant
     * holds. Callers treat any non-empty result as a **hard stop** — the Play
     * flavor is misconfigured and must not be enabled.
     *
     * In a real build the inputs come from `KeyStore.aliases()` (the profile's
     * AndroidKeyStore) and `PackageManager.getInstalledPackages()` *scoped to the
     * managed profile*. Here they are passed in so the logic is pure + testable.
     */
    fun violations(keyAliases: List<String>, packages: List<String>): List<Violation> =
        keyAliases.filter(::isWalletKeyAlias).map { Violation(Violation.Kind.KEY_ALIAS, it) } +
            packages.filter(::isWalletOwnedPackage).map { Violation(Violation.Kind.PACKAGE, it) }

    /** Fail-closed assertion for policy apply: throw if any wallet material is present. */
    fun assertClean(keyAliases: List<String>, packages: List<String>) {
        val bad = violations(keyAliases, packages)
        check(bad.isEmpty()) {
            "Google-Play persona must carry NO wallet keys/packages, found: $bad"
        }
    }
}
