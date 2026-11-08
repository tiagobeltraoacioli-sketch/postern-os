// modules/terem.js — Terem: the QEMU/QMP guest-runtime POC (frontend half).
// Backed by the REAL terem_create / terem_start / terem_qmp / terem_status /
// terem_stop / terem_destroy Tauri commands (desktop/src-tauri/src/terem.rs —
// UNAUDITED POC) whenever a backend is present. There is deliberately NO
// preview engine here: a local stub that pretends a guest VM is running would
// be exactly the overclaim this repo bans, so without a backend every surface
// renders the honest empty/preview state instead of a fabricated guest.
// QEMU is opt-in and user-fetched: this app never downloads, ships, or links
// QEMU — the user installs it and supplies the binary paths, keeping the
// GPL-licensed QEMU process at mere-aggregation distance (see
// docs/os-portal-v2/LICENSE-DECISION.md). The terem_* commands are registered
// #[cfg(unix)]-only in main.rs (QMP rides a unix-domain socket), so a Windows
// build honestly reports them unavailable instead of half-working.
(function () {
  "use strict";
  const P = window.Postern, UI = P.ui, api = P.api;

  // Mirror of terem.rs's QMP_ALLOWED_COMMANDS — the UI only ever OFFERS
  // allowlisted verbs, and the backend re-checks the same allowlist
  // fail-closed before a byte reaches the socket (defense in depth, not
  // trust in this front-end list).
  const QMP_ALLOWED = ["query-status", "query-name", "query-version", "qom-list", "system_powerdown"];

  const NO_BACKEND_HINT = "Terem has no preview engine on purpose — a simulated running guest would be an overclaim. Connect the Tauri backend on a unix host (macOS/Linux) to drive a real, user-installed QEMU.";
  const NO_BACKEND_MSG = "no backend — Terem never fakes a VM; this action needs the Tauri backend on a unix host";

  // terem-log event stream (QEMU's own stderr + lifecycle markers emitted by
  // terem.rs) — the buffer survives route changes, same shape as node-log.
  const logBuf = [];
  const MAX_LINES = 1000;
  let logEl = null;
  api.listen("terem-log", (e) => {
    const line = String(e.payload);
    logBuf.push(line);
    if (logBuf.length > MAX_LINES) logBuf.splice(0, logBuf.length - MAX_LINES);
    if (logEl && logEl.isConnected) appendLine(logEl, line);
  });
  function appendLine(el, line) {
    const span = document.createElement("span");
    span.textContent = line + "\n";
    el.appendChild(span);
    while (el.childNodes.length > MAX_LINES) el.removeChild(el.firstChild);
    el.scrollTop = el.scrollHeight;
  }

  P.register({
    id: "terem",
    title: "Terem",
    short: "Terem",
    desc: "One headless QEMU guest over an allowlisted QMP control plane — UNAUDITED POC, not a security control.",
    group: "Operate",
    order: 4,
    live: () => api.isReal("terem_status"),
    icon: `<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="12" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M10 7.5l4.5 2.5-4.5 2.5z" fill="currentColor"/><path d="M8 20h8" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>`,

    render(root) {
      const live = api.isReal("terem_status");
      root.innerHTML = `
        <div class="stack">
          <div class="callout callout-warn">
            <strong>UNAUDITED POC — a guest runtime, not a security control.</strong>
            Terem drives ONE headless QEMU guest over its QMP socket, with an <strong>allowlisted</strong>
            QMP passthrough (no libvirt, no raw monitor escape hatch).
            ${live
              ? UI.liveBadge("live · terem (QEMU/QMP POC) — UNAUDITED")
              : UI.stubBadge("no backend — Terem never fakes a VM")}
            <p class="note" style="margin:8px 0 0">
              QEMU is <strong>opt-in and user-fetched</strong>: this app never downloads, ships, or links QEMU —
              you install it yourself and point Terem at the binaries, so the GPL-licensed QEMU process stays
              mere aggregation, never shipped (see docs/os-portal-v2/LICENSE-DECISION.md).
              No VM boots in CI or tests. Running a guest is <strong>not attestation</strong> and
              <strong>not Seal-covered</strong> — os_roothash never describes what runs inside this guest.
              The terem_* commands are <strong>unix-only</strong> (QMP rides a unix socket), so a
              Windows build honestly reports them unavailable.
            </p>
          </div>

          <section class="card">
            <div class="card-head"><h2>Guest status</h2><div class="spacer"></div>
              <button class="btn btn-ghost btn-sm" id="tm-refresh">refresh</button>
            </div>
            <div id="tm-status">${live
              ? UI.loadingState("querying terem_status…")
              : UI.emptyState("No backend — guest status unavailable.", NO_BACKEND_HINT)}</div>
          </section>

          <div class="grid2">
            <section class="card">
              <div class="card-head"><h2>Define guest (create disk)</h2></div>
              <p class="note">Creates a fresh qcow2 disk with your own <code>qemu-img</code> and defines it as
                the one guest v1 manages. Refuses to overwrite an existing file; call Destroy before redefining.</p>
              <div class="field-row">
                <label class="field"><span>qemu-img binary (user-installed)</span>
                  <input id="tm-qemuimg" class="mono" placeholder="qemu-img or /opt/homebrew/bin/qemu-img"></label>
                <label class="field"><span>Disk path (new .qcow2)</span>
                  <input id="tm-disk" class="mono" placeholder="/path/to/guest.qcow2"></label>
                <label class="field"><span>Size (MB)</span>
                  <input id="tm-size" type="number" value="512" min="1"></label>
              </div>
              <div class="actions">
                <button class="btn btn-primary" id="tm-create">Create + define</button>
                <span class="result-line muted" id="tm-createres"></span>
              </div>
            </section>

            <section class="card">
              <div class="card-head"><h2>Start / stop / destroy</h2></div>
              <div class="field-row">
                <label class="field"><span>qemu-system-x86_64 binary (user-installed)</span>
                  <input id="tm-qemu" class="mono" placeholder="qemu-system-x86_64 or an absolute path"></label>
              </div>
              <div class="field-row">
                <label class="field"><span>Kernel (optional, direct boot)</span>
                  <input id="tm-kernel" class="mono" placeholder="/path/to/bzImage"></label>
                <label class="field"><span>Initrd (optional)</span>
                  <input id="tm-initrd" class="mono" placeholder="/path/to/initramfs"></label>
                <label class="field"><span>Kernel append (optional)</span>
                  <input id="tm-append" class="mono" placeholder="console=ttyS0"></label>
              </div>
              <div class="actions">
                <button class="btn btn-primary" id="tm-start">▶ Start guest</button>
                <button class="btn" id="tm-stop">■ Stop</button>
                <button class="btn btn-danger" id="tm-destroy" title="Deletes ONLY the qcow2 disk Terem created (plus its derived QMP-socket/serial-log files) — the host disk is never touched.">Destroy</button>
                <span class="result-line muted" id="tm-lcres"></span>
              </div>
            </section>
          </div>

          <section class="card">
            <div class="card-head"><h2>QMP passthrough (allowlisted)</h2></div>
            <p class="note">Only these exact verbs are offered — and the backend re-checks the same allowlist
              fail-closed before anything touches the socket. Raw QMP (human-monitor-command, drive_add,
              blockdev-add, device hot-plug, migrate…) is deliberately not available from anywhere in this app.</p>
            <div class="actions">
              <label class="field"><span>Command</span>
                <select id="tm-qmpcmd">${QMP_ALLOWED.map((c) => `<option value="${c}">${c}</option>`).join("")}</select></label>
              <button class="btn" id="tm-qmpgo" style="align-self:flex-end">Send</button>
            </div>
            <pre class="json-view" id="tm-qmpout" style="max-height:200px">—</pre>
          </section>

          <section class="card">
            <div class="card-head"><h2>Guest log (terem-log)</h2><div class="spacer"></div>
              <button class="btn btn-ghost btn-sm" id="tm-clear">clear</button>
            </div>
            <pre class="logview" id="tm-log" style="height:220px"></pre>
          </section>

          ${UI.privacyCaveat()}
        </div>`;

      // hydrate the log buffer
      logEl = UI.qs("#tm-log", root);
      logBuf.forEach((l) => appendLine(logEl, l));
      UI.qs("#tm-clear", root).addEventListener("click", () => {
        logBuf.length = 0;
        logEl.textContent = "";
      });

      // ── status card: real terem_status only; honest empty state otherwise ─
      const statusBox = UI.qs("#tm-status", root);
      const refresh = async () => {
        if (!live) {
          statusBox.innerHTML = UI.emptyState("No backend — guest status unavailable.", NO_BACKEND_HINT);
          return;
        }
        try {
          const st = await api.invoke("terem_status");
          const defined = !!(st && st.defined);
          const running = !!(st && st.running);
          statusBox.innerHTML = `
            <div class="stats">
              <div class="stat"><b>${defined ? "yes" : "no"}</b><span>defined</span></div>
              <div class="stat"><b>${running ? "running" : "stopped"}</b><span>state</span></div>
              <div class="stat"><b>${running && st.pid != null ? UI.esc(st.pid) : "—"}</b><span>pid</span></div>
            </div>`;
        } catch (e) {
          // Includes the honest Windows path: an unregistered unix-only
          // command rejects, and that rejection is shown, not papered over.
          statusBox.innerHTML = UI.errorState(e);
        }
      };
      UI.qs("#tm-refresh", root).addEventListener("click", refresh);
      if (live) refresh();
      // Poll while the pane is attached to the document. Chained setTimeout
      // (not setInterval) so a detached pane stops on its own; onHide also
      // clears the pending timer.
      const schedule = () => {
        this._timer = setTimeout(async () => {
          if (!root.isConnected) return;
          await refresh();
          schedule();
        }, 3000);
      };
      if (live && root.isConnected) schedule();

      // ── create / define ────────────────────────────────────────────────
      UI.qs("#tm-create", root).addEventListener("click", async () => {
        const res = UI.qs("#tm-createres", root);
        if (!live) { UI.setResult(res, NO_BACKEND_MSG, "err"); return; }
        const qemuImgBinary = UI.qs("#tm-qemuimg", root).value.trim();
        const diskPath = UI.qs("#tm-disk", root).value.trim();
        const sizeMb = parseInt(UI.qs("#tm-size", root).value, 10);
        if (!qemuImgBinary || !diskPath || !(sizeMb > 0)) {
          UI.setResult(res, "qemu-img path, disk path and a size > 0 MB are required", "err");
          return;
        }
        UI.setResult(res, "creating qcow2…", "muted");
        try {
          await api.invoke("terem_create", { qemuImgBinary, diskPath, sizeMb });
          UI.setResult(res, `✓ guest defined — new qcow2 at ${diskPath}`, "ok");
          refresh();
        } catch (e) { UI.setResult(res, `✖ ${e}`, "err"); }
      });

      // ── start / stop / destroy ─────────────────────────────────────────
      UI.qs("#tm-start", root).addEventListener("click", async () => {
        const res = UI.qs("#tm-lcres", root);
        if (!live) { UI.setResult(res, NO_BACKEND_MSG, "err"); return; }
        const qemuBinary = UI.qs("#tm-qemu", root).value.trim();
        if (!qemuBinary) { UI.setResult(res, "qemu-system-x86_64 path is required (user-installed)", "err"); return; }
        const kernelPath = UI.qs("#tm-kernel", root).value.trim() || null;
        const initrdPath = UI.qs("#tm-initrd", root).value.trim() || null;
        const kernelAppend = UI.qs("#tm-append", root).value.trim() || null;
        UI.setResult(res, "starting guest…", "muted");
        try {
          const pid = await api.invoke("terem_start", { qemuBinary, kernelPath, initrdPath, kernelAppend });
          UI.setResult(res, `✓ guest started (pid ${pid}) — QEMU's stderr streams into the log below`, "ok");
          refresh();
        } catch (e) { UI.setResult(res, `✖ ${e}`, "err"); }
      });

      UI.qs("#tm-stop", root).addEventListener("click", async () => {
        const res = UI.qs("#tm-lcres", root);
        if (!live) { UI.setResult(res, NO_BACKEND_MSG, "err"); return; }
        UI.setResult(res, "stopping guest…", "muted");
        try {
          await api.invoke("terem_stop");
          UI.setResult(res, "✓ guest stopped — definition kept, start again anytime", "ok");
          refresh();
        } catch (e) { UI.setResult(res, `✖ ${e}`, "err"); }
      });

      UI.qs("#tm-destroy", root).addEventListener("click", async () => {
        const res = UI.qs("#tm-lcres", root);
        if (!live) { UI.setResult(res, NO_BACKEND_MSG, "err"); return; }
        UI.setResult(res, "destroying guest…", "muted");
        try {
          await api.invoke("terem_destroy");
          UI.setResult(res, "✓ guest destroyed — Terem deleted only its own qcow2/socket/log files", "ok");
          refresh();
        } catch (e) { UI.setResult(res, `✖ ${e}`, "err"); }
      });

      // ── allowlisted QMP passthrough ────────────────────────────────────
      UI.qs("#tm-qmpgo", root).addEventListener("click", async () => {
        const out = UI.qs("#tm-qmpout", root);
        if (!live) { out.innerHTML = UI.emptyState("No backend — QMP passthrough unavailable.", NO_BACKEND_HINT); return; }
        const cmd = UI.qs("#tm-qmpcmd", root).value;
        if (!QMP_ALLOWED.includes(cmd)) { out.innerHTML = UI.errorState(`'${cmd}' is not on the QMP allowlist`); return; }
        out.innerHTML = UI.loadingState(`qmp ${cmd}…`);
        try {
          const r = await api.invoke("terem_qmp", { cmd, args: {} });
          out.textContent = JSON.stringify(r, null, 2);
        } catch (e) { out.innerHTML = UI.errorState(e); }
      });
    },

    onHide() {
      if (this._timer) { clearTimeout(this._timer); this._timer = null; }
      logEl = null;
    },
  });
})();
