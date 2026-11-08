// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.container.dpc

import android.content.Context
import android.content.Intent
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * **Porog A3 gate-state writer — the ONE writer** of
 * `files/porog-gate/state.json` (design porog-03 §3.1 reader/writer split).
 *
 * The consent UI calls [write] with a complete, schema-shaped state blob; the
 * enforcement side owns exactly ONE self-write, [engageKillSwitch], and it moves
 * the state strictly toward *more closed* (kill-switch on) — never toward open.
 * Everything else in this app is a PURE READER ([CrossProfileReconciler],
 * [BridgeStateReceiver], [BridgeStateObserver], [CrossProfileAuditLog] writes
 * only `audit.log`). No other class may write the state file or send the
 * state-changed signal — that single-writer rail is what makes "the file is the
 * state" true.
 *
 * ## Write protocol (atomic + signalled)
 *  1. **Verify the pins** — refuse (no write, no signal) unless the blob carries
 *     EXACTLY our `schema`/`version`, `tier == "key-attested-device"`, and
 *     `sealedWallet.preserved == true`, with the schema's required objects
 *     present (`consent`, `killSwitch`, `crossings`). The writer never stamps
 *     pins onto a foreign blob — re-labelling would be schema laundering; a blob
 *     that is not already honestly ours does not get written.
 *  2. **Atomic persist** — write to `state.json.tmp` in the same dir, `fsync`,
 *     then `rename(2)` over `state.json`. A crash mid-write leaves either the
 *     old complete file or a stray tmp — never a torn `state.json`. (And even a
 *     torn file is safe: the reader treats unparseable as absent ⇒ full-deny.)
 *  3. **Signal** — send [BridgeStateReceiver.ACTION_BRIDGE_STATE_CHANGED] with
 *     `setPackage(context.packageName)`: app-internal only, deliverable to our
 *     manifest receiver (exported=false) across processes, invisible to third
 *     parties. The in-process [BridgeStateObserver] complements it.
 *
 * ## What this writer canNOT do (honest bounds)
 * - It cannot open anything by itself: opening still requires the reconciler to
 *   re-derive policy from the written state through the fail-closed kernel port.
 * - It cannot recall bytes that already crossed; engaging the kill-switch stops
 *   FUTURE crossings and revokes live grants only (see the reconciler's
 *   best-effort URI-grant revoke and its documented limits).
 * - Shape reference: `apps/porog-crossprofile/gate-state.schema.json`. This
 *   writer checks the load-bearing pins, not full JSON-Schema validation — the
 *   reader normalises fail-closed regardless, so an invalid field can only ever
 *   collapse toward deny, never toward open.
 *
 * **Status: SCAFFOLD · DESIGN ONLY · UNAUDITED · UNTESTED-until-VM.**
 * No Android SDK on this host; compile-correct by inspection only.
 */
class GateStateWriter(private val context: Context) {

    /**
     * Persist a complete consent state written by the consent UI, then signal the
     * reconciler. Returns false (nothing written, nothing signalled) when the blob
     * fails the pin check or the atomic write fails. Never throws.
     */
    fun write(state: JSONObject): Boolean {
        if (!pinsVerified(state)) return false
        val ok = atomicPersist(state.toString(2) + "\n")
        if (ok) signalStateChanged()
        return ok
    }

    /**
     * The ONE enforcement-side self-write: engage the kill-switch (more-closed
     * only). Preserves the rest of a readable, recognised state; if the current
     * file is absent, foreign, or corrupt it writes a fresh fully-safe default
     * state with the kill-switch engaged — every branch lands on full-deny.
     * The consent UI / quick-settings tile call this; nothing here can ever
     * flip the state toward open. Returns false only if even the fail-closed
     * write could not be persisted (the reader then full-denies on the old or
     * torn file anyway). Never throws.
     */
    fun engageKillSwitch(): Boolean {
        val base = readRecognizedOrNull() ?: defaultDenyState()
        base.put(
            "killSwitch",
            JSONObject().put("engaged", true).put("engagedAtIso", nowIso()),
        )
        val ok = atomicPersist(base.toString(2) + "\n")
        if (ok) signalStateChanged()
        return ok
    }

    // ── Pins (verify, never stamp) ──────────────────────────────────────────────

    /**
     * The same strict identity checks the decision port makes — opt(), never a
     * coercing accessor, numeric identity for version — plus the pinned honesty
     * rails. A blob failing any of these is refused, not "fixed".
     */
    private fun pinsVerified(state: JSONObject): Boolean {
        val version = state.opt("version")
        return state.opt("schema") == CrossProfileReconciler.SCHEMA_ID &&
            version is Number &&
            version.toDouble() == CrossProfileReconciler.SCHEMA_VERSION.toDouble() &&
            state.opt("tier") == CrossProfileReconciler.TIER &&
            state.optJSONObject("sealedWallet")?.opt("preserved") == true &&
            state.optJSONObject("consent") != null &&
            state.optJSONObject("killSwitch") != null &&
            state.optJSONObject("crossings") != null
    }

    /** Current state, only if it parses AND passes the pin check; else null. */
    private fun readRecognizedOrNull(): JSONObject? = try {
        val f = stateFile()
        if (!f.isFile) null
        else JSONObject(f.readText()).takeIf { pinsVerified(it) }
    } catch (_: Throwable) {
        null
    }

    /**
     * The fully-safe state (kernel `defaultState()` shape, per
     * gate-state.schema.json): not consented, every crossing closed with
     * direction "none", kill-switch clear, tier + sealedWallet pinned.
     */
    private fun defaultDenyState(): JSONObject = JSONObject().apply {
        put("schema", CrossProfileReconciler.SCHEMA_ID)
        put("version", CrossProfileReconciler.SCHEMA_VERSION)
        put("tier", CrossProfileReconciler.TIER)
        put("lang", "en")
        put("consent", JSONObject().apply {
            put("accepted", false)
            put("scope", "session")
            put("acceptedAtIso", JSONObject.NULL)
            put("standing", false)
        })
        put("killSwitch", JSONObject().apply {
            put("engaged", false)
            put("engagedAtIso", JSONObject.NULL)
        })
        put("crossings", JSONObject().apply {
            for (cap in listOf("intents", "files", "clipboard", "contacts")) {
                put(cap, JSONObject().put("open", false).put("direction", "none"))
            }
            for (cap in listOf("calendar", "connectedApp")) {
                put(cap, JSONObject().put("open", false).put("direction", "none")
                    .put("package", JSONObject.NULL))
            }
        })
        put("sealedWallet", JSONObject().put("preserved", true))
    }

    // ── Atomic persist (tmp + fsync + rename) ───────────────────────────────────

    private fun gateDir(): File = File(context.filesDir, CrossProfileReconciler.GATE_DIR)

    private fun stateFile(): File = File(gateDir(), CrossProfileReconciler.STATE_FILE)

    private fun atomicPersist(text: String): Boolean = try {
        val dir = gateDir()
        dir.mkdirs()
        val tmp = File(dir, TMP_FILE)
        FileOutputStream(tmp).use { out ->
            out.write(text.toByteArray(Charsets.UTF_8))
            out.flush()
            out.fd.sync() // durable before it can become visible
        }
        if (tmp.renameTo(stateFile())) {
            true
        } else {
            tmp.delete() // never leave a stray that could confuse a later rename
            false
        }
    } catch (_: Throwable) {
        false
    }

    // ── Signal (app-internal only) ──────────────────────────────────────────────

    /**
     * The explicit, process-independent state-change signal. `setPackage` keeps it
     * inside this app (the manifest receiver is exported=false); no third party
     * can observe or forge it through this path.
     */
    private fun signalStateChanged() {
        try {
            context.sendBroadcast(
                Intent(BridgeStateReceiver.ACTION_BRIDGE_STATE_CHANGED)
                    .setPackage(context.packageName),
            )
        } catch (_: Throwable) {
            // The observer/boot paths re-derive policy anyway; a lost signal is a
            // delay, never a laxer policy.
        }
    }

    private fun nowIso(): String {
        val fmt = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)
        fmt.timeZone = TimeZone.getTimeZone("UTC")
        return fmt.format(Date())
    }

    companion object {
        /** Same-directory temp name; renamed over [CrossProfileReconciler.STATE_FILE]. */
        const val TMP_FILE = "state.json.tmp"
    }
}
