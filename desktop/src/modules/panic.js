// modules/panic.js — Panic Lock (postern-panic): one action seals the vault
// and evicts keys + secrets from RAM. Denial of access, not destruction.
// Wired to the real `panic` Tauri command (postern-panic) when a backend is
// present; falls back to the labeled preview vault engine otherwise. The panic
// action itself is triggered globally via P.doPanic(). (Unaudited crate.)
(function () {
  "use strict";
  const P = window.Postern, UI = P.ui, api = P.api;

  P.register({
    id: "panic",
    title: "Panic Lock",
    desc: "Instant re-lock — keys evicted from memory, ciphertext at rest, nothing destroyed.",
    group: "Protect",
    order: 2,
    live: () => api.isReal("panic"),
    icon: `<svg viewBox="0 0 24 24"><path d="M12 3l9 16H3z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M12 10v4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/><circle cx="12" cy="16.8" r=".5" fill="currentColor"/></svg>`,

    render(root) {
      root.innerHTML = `
        <div class="stack">
          <section class="card">
            <div class="card-head"><h2>Panic Lock</h2><div class="spacer"></div>
              ${api.isReal("panic")
                ? UI.liveBadge("live · postern-panic — instant re-lock (unaudited)")
                : UI.stubBadge("preview — backend pending")}
            </div>
            <div class="grid2">
              <div>
                <div class="stats">
                  <div class="stat"><b id="pn-state">—</b><span>vault state</span></div>
                  <div class="stat"><b id="pn-count">—</b><span>sealed items</span></div>
                </div>
                <div class="actions">
                  <button class="btn btn-danger" id="pn-panic" style="font-size:15px;padding:10px 20px">⬢ PANIC — seal now</button>
                </div>
                <p class="note" id="pn-hint"></p>
              </div>
              <div class="callout">
                <strong>What it does.</strong> One call seals every secret back to ciphertext and evicts the
                key and all decrypted material from RAM. What remains on disk is <strong>unreadable but
                intact</strong> — the legitimate owner reopens later by re-deriving the key from the
                passphrase (or a TEE re-auth on device).
                <ul>
                  <li>Protects a theft / coercion victim by <strong>denial of access</strong>.</li>
                  <li>Destroys <strong>nothing</strong> — it cannot be misused to destroy evidence.</li>
                  <li>The destructive-erase variant is deliberately deferred (see the Deadbolt spec).</li>
                </ul>
              </div>
            </div>
          </section>

          <section class="card">
            <div class="card-head"><h2>Recover</h2></div>
            <p class="note">After a panic, everything is exactly where it was — sealed. Unlock in the Vault module with your passphrase.</p>
            <div class="actions">
              <button class="btn" id="pn-govault">Open Vault →</button>
            </div>
          </section>

          ${UI.privacyCaveat()}
        </div>`;

      const sync = (v) => {
        const stateEl = UI.qs("#pn-state", root);
        stateEl.textContent = !v.exists ? "NONE" : v.unlocked ? "OPEN" : "SEALED";
        stateEl.style.color = v.unlocked ? "var(--warn)" : "var(--ok)";
        UI.qs("#pn-count", root).textContent = v.unlocked ? v.count : "•••";
        UI.qs("#pn-panic", root).disabled = !v.unlocked;
        UI.qs("#pn-hint", root).textContent = !v.exists
          ? "No vault exists yet — create one in the Vault module."
          : v.unlocked
            ? "The vault is open — secrets and key are in memory. Panic seals instantly."
            : "Already sealed. Nothing is in memory.";
      };
      api.invoke("vault_status").then(sync).catch((e) => {
        UI.qs("#pn-hint", root).innerHTML = UI.errorState(e);
      });

      UI.qs("#pn-panic", root).addEventListener("click", () => P.doPanic());
      UI.qs("#pn-govault", root).addEventListener("click", () => P.navigate("vault"));

      this._unsub = P.onState((s) => { if (root.isConnected) sync(s.vault); });
    },

    onHide() { if (this._unsub) { this._unsub(); this._unsub = null; } },
  });
})();
