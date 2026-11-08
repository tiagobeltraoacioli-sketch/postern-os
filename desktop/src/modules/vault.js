// modules/vault.js — Postern Vault: secrets sealed at rest.
// Wired to the real core (postern-vault: Argon2id + XChaCha20-Poly1305) via the
// vault_* Tauri commands whenever a backend is present (see
// desktop/src-tauri/src/main.rs — vault_status/create/unlock/lock/list/get/put/
// remove/discard, backed by the `postern-vault` crate, native Rust, no wasm
// needed; plus vault_keychain_enable / vault_unlock_keychain /
// vault_keychain_forget behind the opt-in `vault-keychain` cargo feature —
// keychain controls render ONLY when the backend's vault_status carries a
// `keychain` object, and its verbatim honesty text — "SOFTWARE convenience,
// not hardware protection … not a TEE until real hardware — UNAUDITED" —
// renders wherever the controls do; no preview engine fakes an OS keychain).
// When no Tauri backend is present (e.g. iterating on the UI in a
// plain browser), it falls back to api.js's preview engine, which ALSO probes
// globalThis.PosternSDK and seals with that same real Argon2id + XChaCha20-
// Poly1305 primitive via wasm when a host has loaded it, or the honestly
// labeled classical PBKDF2 stand-in otherwise. The backing is chosen by
// api.isReal(); the UI is unchanged. (The real crate is unaudited — no
// "secure/audited" claim is made here.)
(function () {
  "use strict";
  const P = window.Postern, UI = P.ui, api = P.api;

  P.register({
    id: "vault",
    title: "Vault",
    desc: "Secrets sealed at rest — one Postern seal (XChaCha20-Poly1305 · Argon2id).",
    group: "Protect",
    order: 1,
    live: () => api.isReal("vault_status"),
    icon: `<svg viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="2" fill="none" stroke="currentColor" stroke-width="1.6"/><circle cx="12" cy="12" r="3.6" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M12 8.4V6.5M12 17.5v-1.9M15.6 12h1.9M6.5 12h1.9" stroke="currentColor" stroke-width="1.4"/></svg>`,

    async render(root) {
      root.innerHTML = UI.loadingState("reading vault status…");
      let st;
      try { st = await api.invoke("vault_status"); }
      catch (e) {
        root.innerHTML = `<div class="stack">${UI.errorState(e)}${UI.privacyCaveat()}</div>`;
        return;
      }
      root.innerHTML = `
        <div class="stack">
          <div class="callout callout-brass">
            <strong>One seal to audit.</strong> Every Postern product seals with the same primitive
            (XChaCha20-Poly1305 AEAD, Argon2id KDF — <span class="mono">postern-core</span>).
            ${api.isReal("vault_status")
              ? UI.liveBadge("live · postern-vault (Argon2id + XChaCha20-Poly1305) — unaudited")
              : UI.stubBadge(st.cipher ? `preview engine: ${st.cipher} — Tauri backend pending` : "preview engine: WebCrypto AES-GCM + PBKDF2 — backend pending")}
            <p class="note" style="margin:8px 0 0">Honest limits: <strong>unaudited</strong>, and
            <strong>not a TEE until real hardware</strong> — while unlocked, the key and secrets live
            in ordinary process RAM; no hardware isolation is claimed.</p>
          </div>
          <section class="card" id="vt-body"></section>

          ${UI.privacyCaveat()}
        </div>`;
      this.renderBody(UI.qs("#vt-body", root), st);

      this._unsub = P.onState(async (s) => {
        if (!root.isConnected) return;
        const body = UI.qs("#vt-body", root);
        if (body && body.dataset.locked !== String(!s.vault.unlocked)) {
          this.renderBody(body, s.vault);
        }
      });
    },

    onHide() { if (this._unsub) { this._unsub(); this._unsub = null; } },

    async renderBody(body, st) {
      body.dataset.locked = String(!st.unlocked);

      // OS-keychain unlock (opt-in `vault-keychain` cargo feature). Only the
      // REAL backend reports a `keychain` object in vault_status — the
      // preview engine never does, so no keychain UI is ever faked in a
      // plain-browser preview. HONESTY: kc.honesty is the backend's verbatim
      // "SOFTWARE convenience, not hardware protection … not a TEE until real
      // hardware — UNAUDITED" text; it is rendered wherever keychain unlock
      // is offered and must never be dropped or paraphrased here.
      const kc = st.keychain || null;

      if (!st.unlocked) {
        body.innerHTML = `
          <div class="locked-box">
            <svg viewBox="0 0 24 24"><rect x="6" y="10" width="12" height="9" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M8.5 10V7.5a3.5 3.5 0 017 0V10" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>
            <strong>${st.exists ? "Vault sealed" : "No vault yet"}</strong>
            <span class="muted">${st.exists
              ? "Ciphertext at rest. Enter the passphrase to derive the key and open it."
              : "Create a vault — the key is derived from your passphrase and never stored."}</span>
            <label class="field" style="width:min(320px,100%)"><span>Passphrase</span>
              <input id="vt-pass" type="password" autocomplete="off"></label>
            <div class="actions" style="margin-top:6px">
              <button class="btn btn-primary" id="vt-open">${st.exists ? "Unlock" : "Create vault"}</button>
              ${st.exists && kc && kc.available && kc.enrolled
                ? `<button class="btn" id="vt-kc-unlock">Unlock with OS keychain</button>` : ""}
              ${st.exists ? `<button class="btn btn-ghost btn-sm" id="vt-discard">discard vault…</button>` : ""}
            </div>
            ${st.exists && kc && kc.available && kc.enrolled
              ? `<p class="note muted" style="max-width:420px">${UI.esc(kc.honesty || "")}</p>` : ""}
            <p class="result-line muted" id="vt-err"></p>
          </div>`;

        const go = async () => {
          const pass = UI.qs("#vt-pass", body).value;
          const errEl = UI.qs("#vt-err", body);
          UI.setResult(errEl, "deriving key…", "muted");
          try {
            const ns = await api.invoke(st.exists ? "vault_unlock" : "vault_create", { passphrase: pass });
            UI.toast(st.exists ? "Vault unlocked" : "Vault created", "ok");
            P.setState({ vault: ns });
            this.renderBody(body, ns);
          } catch (e) { UI.setResult(errEl, `${e}`, "err"); }
        };
        UI.qs("#vt-open", body).addEventListener("click", go);
        UI.qs("#vt-pass", body).addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
        UI.qs("#vt-pass", body).focus();
        const kcUnlock = UI.qs("#vt-kc-unlock", body);
        if (kcUnlock) kcUnlock.addEventListener("click", async () => {
          const errEl = UI.qs("#vt-err", body);
          UI.setResult(errEl, "unlocking with the OS-keychain key…", "muted");
          try {
            const ns = await api.invoke("vault_unlock_keychain");
            UI.toast("Vault unlocked (OS keychain — software convenience, not hardware)", "ok");
            P.setState({ vault: ns });
            this.renderBody(body, ns);
          } catch (e) { UI.setResult(errEl, `${e}`, "err"); }
        });
        const disc = UI.qs("#vt-discard", body);
        if (disc) disc.addEventListener("click", async () => {
          if (!confirm("Discard the sealed vault? The ciphertext (and everything in it) is deleted. This cannot be undone.")) return;
          await api.invoke("vault_discard");
          const ns = await api.invoke("vault_status");
          P.setState({ vault: ns });
          this.renderBody(body, ns);
        });
        return;
      }

      // unlocked
      let names;
      try { names = await api.invoke("vault_list"); }
      catch (e) {
        // A lock/panic can race between vault_status and vault_list — fail
        // closed to the error state instead of leaving a blank pane.
        body.innerHTML = UI.errorState(e);
        return;
      }
      body.innerHTML = `
        <div class="card-head"><h2>Secrets</h2><div class="spacer"></div>
          <span class="badge badge-ok">unlocked · ${names.length} item${names.length === 1 ? "" : "s"}</span>
          <button class="btn btn-sm" id="vt-lock">🔒 Lock</button>
        </div>
        <div class="actions" style="margin-top:0">
          <input id="vt-name" class="input" style="width:180px" placeholder="name (e.g. github-token)">
          <input id="vt-secret" class="input mono" style="flex:1;min-width:160px" placeholder="secret value" type="password">
          <button class="btn btn-primary" id="vt-add">Seal in</button>
        </div>
        <div class="entry-list" id="vt-list" style="margin-top:14px">
          ${names.length ? "" : UI.emptyState("Nothing sealed yet.", "Every write re-seals the vault to disk immediately.")}
        </div>
        ${kc ? `
        <div class="callout" style="margin-top:14px">
          <strong>OS-keychain unlock</strong> — opt-in convenience, off by default.
          ${kc.available
            ? (kc.enrolled
              ? `<div class="actions" style="margin-top:6px">
                   <span class="badge badge-warn">enabled — vault key stored in the OS login keychain</span>
                   <button class="btn btn-sm" id="vt-kc-forget">Forget keychain key</button>
                 </div>`
              : `<div class="actions" style="margin-top:6px">
                   <button class="btn btn-sm" id="vt-kc-enable">Enable keychain unlock</button>
                 </div>`)
            : `<p class="note muted" style="margin:6px 0 0">Unavailable here — this build has no reachable
               OS-keychain backend (needs the <span class="mono">vault-keychain</span> cargo feature and a
               reachable macOS Keychain / freedesktop Secret Service). Passphrase unlock only.</p>`}
          <p class="note muted" style="margin:8px 0 0">${UI.esc(kc.honesty || "")}</p>
        </div>` : ""}
        <p class="result-line muted" id="vt-err" style="margin-top:8px"></p>`;

      const list = UI.qs("#vt-list", body);
      for (const name of names) {
        const row = document.createElement("div");
        row.className = "entry";
        row.innerHTML = `
          <span class="e-name">${UI.esc(name)}</span>
          <span class="e-secret">••••••••••••</span>
          <button class="btn btn-ghost btn-sm" data-act="reveal">reveal</button>
          <button class="btn btn-ghost btn-sm" data-act="copy">copy</button>
          <button class="btn btn-ghost btn-sm" data-act="remove" style="color:var(--crit)">remove</button>`;
        const secretEl = UI.qs(".e-secret", row);
        row.addEventListener("click", async (e) => {
          const act = e.target?.dataset?.act;
          if (!act) return;
          try {
            if (act === "reveal") {
              if (secretEl.classList.contains("revealed")) {
                secretEl.classList.remove("revealed");
                secretEl.textContent = "••••••••••••";
                e.target.textContent = "reveal";
              } else {
                secretEl.textContent = await api.invoke("vault_get", { name });
                secretEl.classList.add("revealed");
                e.target.textContent = "hide";
              }
            } else if (act === "copy") {
              UI.copy(await api.invoke("vault_get", { name }), "Secret copied");
            } else if (act === "remove") {
              await api.invoke("vault_remove", { name });
              row.remove();
              P.setState({ vault: await api.invoke("vault_status") });
              UI.toast(`'${name}' removed and vault re-sealed`, "ok");
            }
          } catch (err) { UI.toast(`${err}`, "err"); }
        });
        list.appendChild(row);
      }

      UI.qs("#vt-add", body).addEventListener("click", async () => {
        const name = UI.qs("#vt-name", body).value.trim();
        const secret = UI.qs("#vt-secret", body).value;
        const errEl = UI.qs("#vt-err", body);
        if (!name || !secret) { UI.setResult(errEl, "name + secret required", "err"); return; }
        try {
          await api.invoke("vault_put", { name, secret });
          UI.toast(`'${name}' sealed`, "ok");
          const ns = await api.invoke("vault_status");
          P.setState({ vault: ns });
          this.renderBody(body, ns);
        } catch (e) { UI.setResult(errEl, `${e}`, "err"); }
      });

      UI.qs("#vt-lock", body).addEventListener("click", async () => {
        await api.invoke("vault_lock");
        const ns = await api.invoke("vault_status");
        P.setState({ vault: ns });
        this.renderBody(body, ns);
      });

      // Keychain enable/forget (buttons exist only when the backend reported
      // a keychain object AND the matching state — see the kc note above).
      const kcEnable = UI.qs("#vt-kc-enable", body);
      if (kcEnable) kcEnable.addEventListener("click", async () => {
        try {
          const ns = await api.invoke("vault_keychain_enable");
          UI.toast("Keychain unlock enabled — the vault key now sits in the OS login keychain (software convenience, not hardware)", "warn");
          P.setState({ vault: ns });
          this.renderBody(body, ns);
        } catch (e) { UI.setResult(UI.qs("#vt-err", body), `${e}`, "err"); }
      });
      const kcForget = UI.qs("#vt-kc-forget", body);
      if (kcForget) kcForget.addEventListener("click", async () => {
        try {
          const ns = await api.invoke("vault_keychain_forget");
          UI.toast("Keychain key forgotten — the next unlock needs the passphrase again", "ok");
          P.setState({ vault: ns });
          this.renderBody(body, ns);
        } catch (e) { UI.setResult(UI.qs("#vt-err", body), `${e}`, "err"); }
      });
    },
  });
})();
