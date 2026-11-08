// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.container.dpc

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * **Porog A3 cross-profile audit log** — a local, managed-profile-private,
 * append-only record of every cross-profile policy **transition** the reconciler
 * applies (design porog-03 §3.5).
 *
 * ## What it can and CANNOT see (honest bound — keep verbatim)
 * This logs *that the boundary was configured to allow X, and when* — a filter
 * installed/cleared, a restriction toggled, an allowlist changed, the kill-switch
 * engaged. It does **NOT** and **CANNOT** log each individual file the user then
 * shares or each clipboard paste: those are mediated by the framework AFTER the
 * grant, below the DPC's visibility. The audit proves the **policy shape over
 * time**, never a byte-level record of what actually crossed.
 *
 * ## Privacy posture
 * - **Local only. Never telemetry.** No network, ever. The file lives in the DPC's
 *   FBE-encrypted, app-private dir and never leaves the device.
 * - **Append-only** (opened in append mode); one JSON object per line (JSONL).
 * - Bounded: rotates by truncation past [MAX_LINES] so it cannot grow unbounded on
 *   a device (keeps the newest entries; this is a diagnostics log, not evidence).
 *
 * **Status: SCAFFOLD · DESIGN ONLY · UNAUDITED · UNTESTED-until-VM.**
 */
class CrossProfileAuditLog(private val context: Context) {

    private fun logFile(): File =
        File(File(context.filesDir, GATE_DIR), LOG_FILE)

    /**
     * Append one transition entry. Records the trigger, the fail-closed reason, and
     * a compact summary of the resulting boundary **shape** — NOT any user payload.
     * The summary is drawn only from the canonical [CrossProfileReconciler.Decision]
     * decided + applied by the reconciler: capability + direction of each installed
     * cross-profile intent filter / package allowlist entry, and the clipboard /
     * copy-paste / contacts / inbound-share posture. It never contains a filename, a
     * clipboard value, a contact, or any other byte that crossed — those are
     * framework-mediated below the DPC's visibility (see class kdoc). Never throws:
     * an audit-write failure must not break enforcement.
     */
    fun record(trigger: CrossProfileReconciler.Trigger, decision: CrossProfileReconciler.Decision) {
        try {
            val entry = JSONObject().apply {
                put("ts", nowIso())
                put("trigger", trigger.name)
                put("open", decision.open)
                put("cleared", decision.cleared)
                put("reason", decision.reason)
                put("intentFilters", JSONArray().apply {
                    for (f in decision.intentFilters) {
                        put(JSONObject().put("capability", f.capability).put("direction", f.direction))
                    }
                })
                put("calendarPackages", JSONArray(decision.calendarPackages.toList()))
                put("connectedAppPackages", JSONArray(decision.connectedAppPackages.toList()))
                put("contactsPolicy", JSONObject()
                    .put("open", decision.contactsPolicy.open)
                    .put("direction", decision.contactsPolicy.direction))
                put("copyPasteDisallowed", decision.copyPasteDisallowed)
                put("clipboardDirection", decision.clipboardDirection)
                put("shareIntoManagedProfileDisallowed", decision.shareIntoManagedProfileDisallowed)
                put("revokeOutstandingUriGrants", decision.revokeOutstandingUriGrants)
            }
            val f = logFile()
            f.parentFile?.mkdirs()
            f.appendText(entry.toString() + "\n")
            rotateIfNeeded(f)
        } catch (_: Throwable) {
            // Diagnostics only — never let an audit failure break the reconcile.
        }
    }

    /** Read back the log lines (newest last). Diagnostics/tests only. */
    fun readLines(): List<String> = try {
        val f = logFile()
        if (f.isFile) f.readLines().filter { it.isNotBlank() } else emptyList()
    } catch (_: Throwable) {
        emptyList()
    }

    private fun rotateIfNeeded(f: File) {
        try {
            val lines = f.readLines()
            if (lines.size > MAX_LINES) {
                f.writeText(lines.takeLast(MAX_LINES).joinToString("\n") + "\n")
            }
        } catch (_: Throwable) {
            // best-effort rotation
        }
    }

    private fun nowIso(): String {
        val fmt = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)
        fmt.timeZone = TimeZone.getTimeZone("UTC")
        return fmt.format(Date())
    }

    companion object {
        const val GATE_DIR = "porog-gate"
        const val LOG_FILE = "audit.log"
        const val MAX_LINES = 2000
    }
}
