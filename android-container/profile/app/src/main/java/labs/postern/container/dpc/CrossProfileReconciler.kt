// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.container.dpc

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.UriPermission
import android.os.Build
import android.os.UserManager
import org.json.JSONObject
import java.io.File

/**
 * **Porog A3 cross-profile reconciler** — the enforcement heart of the
 * work↔personal boundary. It reads the deny-by-default consent state written by
 * the ONE writer ([GateStateWriter] → `files/porog-gate/state.json`,
 * managed-profile FBE-private), runs the SAME fail-closed decision the
 * host-proven kernel proves (`apps/porog-crossprofile/reconcile-kernel.mjs`),
 * and makes the live [DevicePolicyManager] policy match it — **idempotently and
 * convergently**.
 *
 * ## Reader/writer split (design porog-03 §3.1)
 * This class is a PURE READER of the gate state. It **never writes grant state**;
 * the only self-write the enforcement side may perform is engaging the
 * kill-switch toward *more closed* — that lives in [GateStateWriter.engageKillSwitch],
 * not here. Running this twice is a no-op; running it after a crash re-derives
 * policy purely from the state file.
 *
 * ## THE ONE KOTLIN DECISION PATH (anti-drift rail)
 * The macOS host cannot run Kotlin and the emulator cannot run node, so the
 * fail-closed decision exists in exactly TWO places, no more:
 *   1. the authoritative, node-tested `reconcile-kernel.mjs` (the spec of record;
 *      `node apps/porog-crossprofile/test-reconcile.mjs` keeps it green), and
 *   2. this single Kotlin port ([decide]), pinned to the kernel by the committed
 *      golden vectors (`apps/porog-crossprofile/golden-vectors.json`, emitted by
 *      `export-vectors.mjs`) and the plain-JVM `CrossProfileReconcilerParityTest`.
 * There is deliberately NO second Kotlin port anywhere in this app: the former
 * `labs.postern.container.crossprofile` package (which coerced a stringified
 * version via `optInt` — schema laundering the kernel forbids — ignored the
 * per-crossing `open` gate, and shipped an empty package allowlist) was deleted.
 * Any change to the `.mjs` MUST regenerate the vectors and keep the parity test
 * green in the same commit.
 *
 * ## Honest bounds (verbatim — keep on every surface)
 * - Porog is a **key-attested device, NOT a measured-boot workspace**. It attests
 *   the phone, never the workspace; NEVER "Postern OS."
 * - The DPC governs **only the managed profile it owns**. It cannot police the
 *   personal side after data crosses, and it **cannot un-send bytes already
 *   copied** — closing a crossing stops FUTURE flows and revokes LIVE grants only.
 * - The URI-grant revoke is **best-effort**: the DPC can enumerate and release
 *   only the *persisted* content:// permissions it holds or granted
 *   (ContentResolver persisted/outgoing tables). Transient grants held by other
 *   apps are not enumerable from here; they expire with their task/reboot. This
 *   is disclosed, not hidden.
 * - These toggles are Android framework policy, only as strong as the kernel under
 *   them; a rooted/compromised host defeats the whole boundary.
 *
 * **Status: SCAFFOLD · DESIGN ONLY · UNAUDITED · UNTESTED-until-VM.**
 * No Android SDK on the macOS host — this compiles only on the Linux+Nix VM and
 * its behaviour is proven only on the T1 emulator (§6.3) and a real device (§6).
 * The [decide] half runs on a plain JVM (see CrossProfileReconcilerParityTest).
 */
class CrossProfileReconciler(
    private val context: Context,
    private val dpm: DevicePolicyManager,
    private val admin: ComponentName,
) {
    /** Resolve the DPM from the context when the caller does not already hold it. */
    constructor(context: Context, admin: ComponentName) : this(
        context,
        context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager,
        admin,
    )

    /** What kicked this reconcile — recorded verbatim in the audit log. */
    enum class Trigger { PROVISIONING, BOOT, STATE_CHANGE, KILL_SWITCH }

    private val audit = CrossProfileAuditLog(context)

    // ── Public entry point ─────────────────────────────────────────────────────

    /**
     * Read the gate state, decide the fail-closed directive set, apply it to the
     * live DPM policy idempotently, and append the transition to the local audit
     * log. Never throws on a missing/corrupt state file — a read/parse failure is
     * an input, and the input for "no readable, consented, non-killed state" is
     * **full-deny**. Returns the [Decision] that was applied (for tests/logging).
     */
    fun reconcile(trigger: Trigger): Decision {
        val decision = decide(readStateOrNull())
        apply(decision)
        audit.record(trigger, decision)
        return decision
    }

    // ── State file (pure reader; app-private, FBE-encrypted, never telemetry) ───

    /** `files/porog-gate/state.json` under the DPC's managed-profile-private dir. */
    private fun stateFile(): File = File(File(context.filesDir, GATE_DIR), STATE_FILE)

    private fun readStateOrNull(): JSONObject? = try {
        val f = stateFile()
        if (!f.isFile) null else JSONObject(f.readText())
    } catch (_: Throwable) {
        // Unparseable / unreadable / truncated => treated as absent => full-deny.
        null
    }

    // ── Applying the decision to the live DPM policy (idempotent + convergent) ──

    /**
     * Make the framework match [decision]. Convergent by construction: every
     * cross-profile intent filter is cleared and re-installed from scratch, and the
     * standing allowlists are REPLACED with the decided sets (empty = closed), so
     * there is no additive drift — a crossing the state no longer names is gone
     * after the next reconcile. All calls are wrapped fail-closed: an exception on
     * any single policy leaves the more-restrictive prior state, never a laxer one.
     */
    private fun apply(decision: Decision) {
        applyIntentFilters(decision.intentFilters)
        applyUserRestriction(UserManager.DISALLOW_CROSS_PROFILE_COPY_PASTE, decision.copyPasteDisallowed)
        applyShareIntoManagedRestriction(decision.shareIntoManagedProfileDisallowed)
        applyCalendarPackages(decision.calendarPackages)
        applyConnectedAppPackages(decision.connectedAppPackages)
        applyContactsPolicy(decision.contactsPolicy.open)
        applyUriGrantRevocation(decision.revokeOutstandingUriGrants)
    }

    private fun applyIntentFilters(directives: List<IntentDirective>) = failClosed {
        // No framework API lists installed filters, so converge by clear-then-add.
        dpm.clearCrossProfileIntentFilters(admin)
        for (d in directives) {
            for (filter in intentFiltersFor(d.capability)) {
                dpm.addCrossProfileIntentFilter(admin, filter, d.flags)
            }
        }
    }

    /**
     * The narrow, per-capability actions a crossing installs. Kept deliberately
     * tight (design §2: "exactly one narrow filter"). The precise action set is a
     * policy detail the T1 emulator + real device settle; documented, not silent.
     */
    private fun intentFiltersFor(capability: String): List<IntentFilter> = when (capability) {
        "files" -> listOf(
            IntentFilter(Intent.ACTION_SEND),
            IntentFilter(Intent.ACTION_SEND_MULTIPLE),
        )
        "intents" -> listOf(IntentFilter(Intent.ACTION_VIEW))
        else -> emptyList()
    }

    private fun applyUserRestriction(key: String, on: Boolean) = failClosed {
        if (on) dpm.addUserRestriction(admin, key) else dpm.clearUserRestriction(admin, key)
    }

    /**
     * `DISALLOW_SHARE_INTO_MANAGED_PROFILE` is a PARENT restriction — set via the
     * parent instance. Availability varies by OEM/API; guarded + fail-closed (on
     * error the inbound door stays as-is, never forced open).
     */
    private fun applyShareIntoManagedRestriction(on: Boolean) = failClosed {
        val parent = dpm.getParentProfileInstance(admin)
        if (on) parent.addUserRestriction(admin, DISALLOW_SHARE_INTO_MANAGED_PROFILE)
        else parent.clearUserRestriction(admin, DISALLOW_SHARE_INTO_MANAGED_PROFILE)
    }

    /** setCrossProfileCalendarPackages(admin, Set) — API 30+ (minSdk 30). */
    private fun applyCalendarPackages(packages: Set<String>) = failClosed {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            dpm.setCrossProfileCalendarPackages(admin, packages)
        }
        // < R: API absent => calendar crossing simply never applies (fail-closed).
    }

    /** setCrossProfilePackages(admin, Set) — API 30+ (minSdk 30). */
    private fun applyConnectedAppPackages(packages: Set<String>) = failClosed {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            dpm.setCrossProfilePackages(admin, packages)
        }
    }

    /**
     * Contacts / caller-ID. API 34+ uses the PackagePolicy-based access policies;
     * older levels use the deprecated boolean disablers. Fail-closed: on any level
     * where the intended API is absent, apply the MOST restrictive available call.
     */
    @Suppress("DEPRECATION")
    private fun applyContactsPolicy(open: Boolean) = failClosed {
        if (Build.VERSION.SDK_INT >= 34) {
            // open  => empty BLOCKLIST  (nothing blocked => parent may access).
            // closed => empty ALLOWLIST (nothing allowed => fully partitioned).
            val policy = if (open) {
                android.app.admin.PackagePolicy(android.app.admin.PackagePolicy.PACKAGE_POLICY_BLOCKLIST, emptySet())
            } else {
                android.app.admin.PackagePolicy(android.app.admin.PackagePolicy.PACKAGE_POLICY_ALLOWLIST, emptySet())
            }
            dpm.setManagedProfileContactsAccessPolicy(policy)
            dpm.setManagedProfileCallerIdAccessPolicy(policy)
        } else {
            // Legacy booleans: disabled = !open. Fail-closed when open is false.
            dpm.setCrossProfileContactsSearchDisabled(admin, !open)
            dpm.setCrossProfileCallerIdDisabled(admin, !open)
        }
    }

    /**
     * Best-effort revoke of outstanding content:// URI grants on every full-deny /
     * kill (kernel directive `revokeOutstandingUriGrants`). HONEST BOUND: the DPC
     * can enumerate and release only the *persisted* URI permissions it holds
     * (incoming) or granted (outgoing) — there is no framework API to enumerate
     * transient grants held by other apps; those expire with their task/reboot.
     * Fail-closed: a failure here leaves policy no laxer (the filters/allowlists
     * above are already cleared on the same deny path).
     */
    private fun applyUriGrantRevocation(revoke: Boolean) = failClosed {
        if (!revoke) return@failClosed
        val resolver = context.contentResolver
        for (perm in resolver.outgoingPersistedUriPermissions) {
            failClosed { resolver.releasePersistableUriPermission(perm.uri, grantModeFlags(perm)) }
        }
        for (perm in resolver.persistedUriPermissions) {
            failClosed { resolver.releasePersistableUriPermission(perm.uri, grantModeFlags(perm)) }
        }
    }

    private fun grantModeFlags(perm: UriPermission): Int {
        var flags = 0
        if (perm.isReadPermission) flags = flags or Intent.FLAG_GRANT_READ_URI_PERMISSION
        if (perm.isWritePermission) flags = flags or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
        return flags
    }

    /** Run a DPM mutation; swallow failures so a laxer state can never leak in. */
    private inline fun failClosed(block: () -> Unit) {
        try {
            block()
        } catch (_: Throwable) {
            // Intentionally swallowed: a failed policy call leaves the prior (more
            // restrictive baseline) intact. Never rethrow into the reconcile loop.
        }
    }

    // ── Value types ─────────────────────────────────────────────────────────────

    data class IntentDirective(val capability: String, val direction: String, val flags: Int)

    /**
     * The contacts crossing is enforced by setManagedProfile*AccessPolicy — a
     * POLICY over the whole contacts surface, not a package allowlist. Mirrors the
     * kernel's `contactsPolicy { open, direction }`; direction is advisory (a
     * record of user intent), the OS policy itself is not per-direction.
     */
    data class ContactsPolicy(val open: Boolean, val direction: String)

    /**
     * The applied cross-profile decision. Mirrors the kernel's directive object,
     * flattened for the DPM surface (package-backed standing caps split into their
     * concrete allowlists). `open == false` is the fail-closed full-deny result.
     * Field-by-field parity with the kernel's `reconcile()` output is pinned by
     * the committed golden vectors (see CrossProfileReconcilerParityTest).
     */
    data class Decision(
        val open: Boolean,
        val cleared: Boolean,
        val reason: String,
        val intentFilters: List<IntentDirective>,
        val calendarPackages: Set<String>,
        val connectedAppPackages: Set<String>,
        val contactsPolicy: ContactsPolicy,
        val copyPasteDisallowed: Boolean,
        val clipboardDirection: String,
        val shareIntoManagedProfileDisallowed: Boolean,
        val revokeOutstandingUriGrants: Boolean,
    )

    companion object {
        const val SCHEMA_ID = "postern.porog-gate.state"
        const val SCHEMA_VERSION = 1

        /** Honesty rail: Porog attests the PHONE, never the workspace. Pinned. */
        const val TIER = "key-attested-device"

        const val GATE_DIR = "porog-gate"
        const val STATE_FILE = "state.json"

        /** Parent restriction (framework constant name; string-guarded for API skew). */
        const val DISALLOW_SHARE_INTO_MANAGED_PROFILE = "no_sharing_into_profile"

        private val USER_MEDIATED_CAPS = listOf("intents", "files", "clipboard")
        private val STANDING_CAPS = listOf("contacts", "calendar", "connectedApp")
        private val CROSSING_KEYS = USER_MEDIATED_CAPS + STANDING_CAPS
        private val DIRECTIONS = setOf("none", "p2w", "w2p", "both")

        /**
         * A valid Android package name for the ONE-package allowlist caps: dotted
         * identifier, conservative charset — the kernel's `PKG_RE`, character for
         * character. Anything else (missing, empty, single label, junk) normalises
         * to null, which keeps the crossing CLOSED (nothing to allowlist).
         */
        private val PKG_RE = Regex("^[a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z][a-zA-Z0-9_]*)+$")

        // ── The decision (single Kotlin port of reconcile-kernel.mjs) ──────────
        // Kept in the companion so it is a pure, Context-free function testable on
        // a plain JVM against the committed golden vectors.

        /**
         * Fail-closed decision. Order mirrors the kernel exactly:
         *  1. schema/version not EXACTLY ours  => full-deny (unknown blob).
         *  2. kill-switch engaged              => clear ALL, re-impose restrictions.
         *  3. consent not accepted             => default-deny.
         *  4. per-crossing: install ONLY when `open == true` AND direction is real;
         *     standing caps also require the stronger standing consent; package-backed
         *     standing caps (calendar/connectedApp) need one VALID named package.
         * Reason strings are the kernel's, verbatim, so the parity test can compare
         * every field the [Decision] carries.
         */
        fun decide(input: JSONObject?): Decision {
            // Strict identity checks — opt(), never optString()/optInt(), so no type
            // coercion can launder a foreign blob (a stringified "1" version, a
            // number where the schema id belongs) into a recognised one. The kernel
            // compares with `===`; `equals` on the raw opt() value is the JVM twin.
            // (Version is numeric-identity like JS: 1 and 1.0 are the same number.)
            val version = input?.opt("version")
            if (
                input == null ||
                input.opt("schema") != SCHEMA_ID ||
                version !is Number || version.toDouble() != SCHEMA_VERSION.toDouble()
            ) {
                return fullDeny("unknown or mismatched schema/version — full-deny")
            }

            val consent = input.optJSONObject("consent") ?: JSONObject()
            val killSwitch = input.optJSONObject("killSwitch") ?: JSONObject()

            if (killSwitch.opt("engaged") == true) {
                return fullDeny(
                    "kill-switch engaged — all cross-profile bridges cleared and copy/paste re-disallowed",
                    cleared = true,
                )
            }
            if (consent.opt("accepted") != true) return fullDeny("consent not accepted — default-deny")
            val standing = consent.opt("standing") == true

            val crossings = input.optJSONObject("crossings") ?: JSONObject()
            val intentFilters = mutableListOf<IntentDirective>()
            val calendarPackages = linkedSetOf<String>()
            val connectedAppPackages = linkedSetOf<String>()
            var contactsPolicy = ContactsPolicy(open = false, direction = "none")
            var clipboardDirection = "none"

            for (cap in CROSSING_KEYS) {
                val c = crossings.optJSONObject(cap) ?: continue
                val direction = asDirection(c.opt("direction"))
                // `open` is the primary deny gate; omitted => inherit from direction
                // (backward compat), explicit false => forced closed (fail-closed).
                val open = if (c.has("open")) c.opt("open") == true else direction != "none"
                if (!open || direction == "none") continue
                if (cap in STANDING_CAPS && !standing) continue

                when (cap) {
                    "intents", "files" ->
                        intentFilters += IntentDirective(cap, direction, directionFlags(direction))
                    "clipboard" -> clipboardDirection = direction
                    // contacts is a POLICY toggle over the whole contacts surface,
                    // not a package allowlist — carries its (advisory) direction.
                    "contacts" -> contactsPolicy = ContactsPolicy(open = true, direction = direction)
                    "calendar" -> asPackage(c.opt("package"))?.let { calendarPackages += it }
                    "connectedApp" -> asPackage(c.opt("package"))?.let { connectedAppPackages += it }
                }
            }

            val inboundOpen = intentFilters.any {
                (it.capability == "files" || it.capability == "intents") &&
                    (it.direction == "p2w" || it.direction == "both")
            }

            return Decision(
                open = true,
                cleared = false,
                reason = "consented — cross-profile directives reconciled",
                intentFilters = intentFilters,
                calendarPackages = calendarPackages,
                connectedAppPackages = connectedAppPackages,
                contactsPolicy = contactsPolicy,
                copyPasteDisallowed = clipboardDirection == "none",
                clipboardDirection = clipboardDirection,
                shareIntoManagedProfileDisallowed = !inboundOpen,
                // Grants stand while consented; nothing to revoke on the open path.
                revokeOutstandingUriGrants = false,
            )
        }

        private fun fullDeny(reason: String, cleared: Boolean = false) = Decision(
            open = false,
            cleared = cleared,
            reason = reason,
            intentFilters = emptyList(),
            calendarPackages = emptySet(),
            connectedAppPackages = emptySet(),
            contactsPolicy = ContactsPolicy(open = false, direction = "none"),
            copyPasteDisallowed = true,
            clipboardDirection = "none",
            shareIntoManagedProfileDisallowed = true,
            // Inbound-share block imposed; outstanding content:// grants revoked.
            // On a full-deny we always close the inbound door and revoke — fail-closed.
            revokeOutstandingUriGrants = true,
        )

        /** direction => addCrossProfileIntentFilter flags (kernel DIRECTION_FLAGS). */
        private fun directionFlags(direction: String): Int = when (direction) {
            "p2w" -> DevicePolicyManager.FLAG_PARENT_CAN_ACCESS_MANAGED
            "w2p" -> DevicePolicyManager.FLAG_MANAGED_CAN_ACCESS_PARENT
            "both" -> DevicePolicyManager.FLAG_PARENT_CAN_ACCESS_MANAGED or
                DevicePolicyManager.FLAG_MANAGED_CAN_ACCESS_PARENT
            else -> 0
        }

        private fun asDirection(v: Any?): String =
            if (v is String && v in DIRECTIONS) v else "none"

        private fun asPackage(v: Any?): String? =
            if (v is String && PKG_RE.matches(v)) v else null
    }
}
