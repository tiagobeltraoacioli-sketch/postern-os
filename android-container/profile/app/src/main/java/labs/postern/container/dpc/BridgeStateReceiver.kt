// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.container.dpc

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.FileObserver
import java.io.File

/**
 * **Porog A3 bridge state-change trigger.** Re-runs the [CrossProfileReconciler]
 * whenever the boundary could have drifted from the consent state (design
 * porog-03 §3.3 triggers), so the framework policy is re-derived purely from the
 * gate state and never left stale.
 *
 * It handles two trigger classes:
 *  1. **Boot** — `ACTION_BOOT_COMPLETED`, delivered inside the managed profile
 *     once it unlocks. Policy is re-applied from scratch on every boot
 *     (convergent; survives a crash/reboot).
 *  2. **State-change** — the explicit [ACTION_BRIDGE_STATE_CHANGED] broadcast
 *     that [GateStateWriter] (the sole writer) sends right after it atomically
 *     rewrites `files/porog-gate/state.json`. This is the reliable,
 *     process-independent signal; the [BridgeStateObserver] below is the
 *     in-process complement.
 *
 * ## Why there is deliberately NO `LOCKED_BOOT_COMPLETED` branch
 * The gate state lives in credential-encrypted (CE) `filesDir`, which is
 * unreadable before the user unlocks — and this receiver is not
 * `directBootAware`, so the system would never deliver that broadcast to it
 * anyway. Handling it here was dead code pretending to run earlier than it
 * could. The window is fail-closed without it: the persisted lockdown baseline
 * (default-deny copy/paste etc.) survives reboot as retained DPM policy, and
 * the `BOOT_COMPLETED` reconcile re-derives everything the moment the profile
 * unlocks. Before unlock, nothing can read the state — and nothing opens.
 *
 * ## Reader-only
 * This never writes grant state — it only asks the reconciler to make policy
 * match whatever the ([GateStateWriter]-written) state currently says.
 * Fail-closed: if the state file is missing/corrupt at trigger time, the
 * reconciler applies full-deny.
 *
 * ## Manifest (registered in AndroidManifest.xml — keep in lock-step)
 * ```xml
 * <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
 *
 * <receiver
 *     android:name=".dpc.BridgeStateReceiver"
 *     android:exported="false">
 *     <intent-filter>
 *         <action android:name="android.intent.action.BOOT_COMPLETED" />
 *         <action android:name="labs.postern.container.action.BRIDGE_STATE_CHANGED" />
 *     </intent-filter>
 * </receiver>
 * ```
 * `exported="false"` — the system still delivers the protected `BOOT_COMPLETED`
 * broadcast to non-exported receivers, and [GateStateWriter] targets
 * [ACTION_BRIDGE_STATE_CHANGED] at this package with `setPackage`, so the
 * signal crosses processes but never leaves the app. Third parties can no
 * longer poke the reconciler (they could only ever cause an extra fail-closed
 * re-derive, but there is no reason to leave that door open).
 *
 * **Status: SCAFFOLD · DESIGN ONLY · UNAUDITED · UNTESTED-until-VM.**
 */
class BridgeStateReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val trigger = when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED -> CrossProfileReconciler.Trigger.BOOT
            ACTION_BRIDGE_STATE_CHANGED -> CrossProfileReconciler.Trigger.STATE_CHANGE
            else -> return // ignore anything we did not register for
        }
        // Any broadcast proves the DPC process is alive: (re-)arm the in-process
        // observer so subsequent writes re-reconcile even if a signal is lost.
        BridgeStateObserver.ensureStarted(context)
        val admin = PosternDeviceAdminReceiver.componentName(context)
        try {
            CrossProfileReconciler(context, admin).reconcile(trigger)
        } catch (_: Throwable) {
            // A trigger must never crash the profile; the reconciler is itself
            // fail-closed, but guard the broadcast entry point too.
        }
    }

    companion object {
        /**
         * Explicit state-change signal [GateStateWriter] (the sole sender) emits
         * after each atomic state write, always with `setPackage` (app-internal).
         */
        const val ACTION_BRIDGE_STATE_CHANGED = "labs.postern.container.action.BRIDGE_STATE_CHANGED"
    }
}

/**
 * In-process [FileObserver] on `files/porog-gate/` that re-reconciles the moment
 * [GateStateWriter] rewrites the state file — the `FileObserver` option named in
 * design §3.3. Complements [BridgeStateReceiver]'s explicit broadcast: it covers
 * writes while the DPC process is alive; the broadcast covers the cross-process /
 * not-running case, and boot covers everything else.
 *
 * ## Its real, honest host lifecycle
 * A `FileObserver` needs a live process to keep watching — it is NOT a
 * standalone lifecycle component and Android gives a DPC no immortal process.
 * So the contract is: [ensureStarted] arms ONE app-wide observer whenever the
 * DPC process is known to be running — kicked from
 * [PosternDeviceAdminReceiver.onProfileOwnerEstablished] (enrollment) and from
 * every [BridgeStateReceiver] delivery — and it dies with the process. That is
 * the strongest guarantee a DPC process can honestly make; the broadcast + boot
 * triggers close the gap, and a missed event is only ever a DELAYED reconcile,
 * never a laxer policy (the policy converges on the next trigger).
 *
 * Watches `MOVED_TO` because [GateStateWriter] lands atomically via rename;
 * `CLOSE_WRITE`/`CREATE`/`DELETE` cover any non-canonical writer or a cleared
 * file — all of which converge, fail-closed, through the same reconcile.
 *
 * **Status: SCAFFOLD · DESIGN ONLY · UNAUDITED · UNTESTED-until-VM.**
 */
class BridgeStateObserver private constructor(
    private val context: Context,
    dir: File,
) : FileObserver(dir, CLOSE_WRITE or MOVED_TO or CREATE or DELETE) {

    override fun onEvent(event: Int, path: String?) {
        // Only react to changes to the state file itself (rename lands as
        // MOVED_TO with the destination name).
        if (path != null && path != CrossProfileReconciler.STATE_FILE) return
        val admin = PosternDeviceAdminReceiver.componentName(context)
        try {
            CrossProfileReconciler(context, admin)
                .reconcile(CrossProfileReconciler.Trigger.STATE_CHANGE)
        } catch (_: Throwable) {
            // Never let a filesystem event crash the host process.
        }
    }

    companion object {
        @Volatile
        private var active: BridgeStateObserver? = null

        /**
         * Arm the single app-wide observer for the life of this process (no-op if
         * already armed). Safe to call from any trigger path; never throws — a
         * failure to arm only delays reconciles until the next broadcast/boot.
         */
        fun ensureStarted(context: Context) {
            if (active != null) return
            synchronized(this) {
                if (active != null) return
                try {
                    val app = context.applicationContext
                    // The watched dir must exist before FileObserver init, or the
                    // watch is silently inert.
                    val dir = File(app.filesDir, CrossProfileReconciler.GATE_DIR)
                    dir.mkdirs()
                    active = BridgeStateObserver(app, dir).also { it.startWatching() }
                } catch (_: Throwable) {
                    // Fail-open on the WATCH only, never on policy: the explicit
                    // broadcast and boot triggers still re-derive fail-closed.
                }
            }
        }
    }
}
