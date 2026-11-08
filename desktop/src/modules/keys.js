// modules/keys.js — Postern Keys: passkey / FIDO2 authenticator core.
// Backed by the REAL keys_create / keys_list / keys_sign / keys_remove Tauri
// commands (postern-keys) whenever a backend is present — an UNAUDITED
// SOFTWARE authenticator: ES256 private keys live in app RAM, NOT a hardware
// key, and not TEE-sealed (the vault itself is not a TEE until real
// hardware). Without a backend, the labeled preview engine does REAL ES256
// (ECDSA P-256, WebCrypto) signing with the key kept in localStorage.
(function () {
  "use strict";
  const P = window.Postern, UI = P.ui, api = P.api;

  P.register({
    id: "keys",
    title: "Keys",
    desc: "Passkeys — one ES256 credential per relying party, private key sealed in the vault.",
    group: "Protect",
    order: 3,
    live: () => api.isReal("keys_create"),
    icon: `<svg viewBox="0 0 24 24"><circle cx="8.5" cy="12" r="4.5" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M13 12h8M18 12v3.5M21 12v2.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>`,

    async render(root) {
      const live = api.isReal("keys_create");
      root.innerHTML = `
        <div class="stack">
          <section class="card">
            <div class="card-head"><h2>Create a passkey</h2><div class="spacer"></div>
              ${live
                ? UI.liveBadge("live · postern-keys — UNAUDITED software authenticator")
                : UI.stubBadge("preview — key stored locally, not TEE-sealed")}
            </div>
            <div class="actions" style="margin-top:0">
              <label class="field" style="flex:1;min-width:200px"><span>Relying party (site)</span>
                <input id="ky-rp" class="mono" placeholder="github.com"></label>
              <button class="btn btn-primary" id="ky-create" style="align-self:flex-end">Create credential</button>
            </div>
            <p class="result-line muted" id="ky-err"></p>
            <p class="note"><strong>UNAUDITED software authenticator</strong> — ES256 private keys live
            in app RAM while in use (<strong>not a hardware key</strong>; the vault is not a TEE until
            real hardware). WebAuthn ES256 (P-256) is classical by ecosystem necessity: relying parties
            don't accept PQ passkeys yet.</p>
          </section>

          <section class="card">
            <div class="card-head"><h2>Credentials</h2><div class="spacer"></div><span class="muted mono" id="ky-count"></span></div>
            <div class="entry-list" id="ky-list"></div>
          </section>

          <section class="card">
            <div class="card-head"><h2>Test an assertion</h2></div>
            <p class="note">Sign a fresh challenge with a credential and verify the signature locally — the full authenticate roundtrip.</p>
            <div class="actions" style="margin-top:8px">
              <select id="ky-cred" class="input" style="min-width:220px"></select>
              <button class="btn" id="ky-sign">Issue challenge &amp; sign</button>
            </div>
            <div class="kv" style="margin-top:10px">
              <div class="kv-row"><span class="k">challenge</span><span class="v" id="ky-chal">—</span></div>
              <div class="kv-row"><span class="k">signature</span><span class="v" id="ky-sig">—</span></div>
              <div class="kv-row"><span class="k">verified</span><span class="v" id="ky-ver">—</span></div>
            </div>
          </section>

          ${UI.privacyCaveat()}
        </div>`;

      const refresh = async () => {
        const list = UI.qs("#ky-list", root);
        list.innerHTML = UI.loadingState("listing credentials…");
        let creds;
        try { creds = await api.invoke("keys_list"); }
        catch (e) { list.innerHTML = UI.errorState(e); return; }
        UI.qs("#ky-count", root).textContent = `${creds.length} credential${creds.length === 1 ? "" : "s"}`;
        list.innerHTML = creds.length ? "" : UI.emptyState("No passkeys yet.", "Create one above — one ES256 credential per relying party.");
        const sel = UI.qs("#ky-cred", root);
        sel.innerHTML = creds.map((c) => `<option value="${UI.esc(c.credentialId)}">${UI.esc(c.rpId)} · ${UI.esc(c.credentialId.slice(0, 8))}…</option>`).join("");
        for (const c of creds) {
          const row = document.createElement("div");
          row.className = "entry";
          row.innerHTML = `
            <span class="e-name">${UI.esc(c.rpId)}</span>
            <span class="e-secret" title="public key (raw P-256)">${UI.esc(UI.shortHex(c.publicKey, 12))} · sign count ${c.signCount}</span>
            <button class="btn btn-ghost btn-sm" data-act="copy">copy pubkey</button>
            <button class="btn btn-ghost btn-sm" data-act="remove" style="color:var(--crit)">remove</button>`;
          row.addEventListener("click", async (e) => {
            const act = e.target?.dataset?.act;
            if (act === "copy") UI.copy(c.publicKey, "Public key copied");
            if (act === "remove") {
              await api.invoke("keys_remove", { credentialId: c.credentialId });
              refresh();
            }
          });
          list.appendChild(row);
        }
      };
      await refresh();

      UI.qs("#ky-create", root).addEventListener("click", async () => {
        const errEl = UI.qs("#ky-err", root);
        try {
          const c = await api.invoke("keys_create", { rpId: UI.qs("#ky-rp", root).value });
          UI.toast(`Passkey created for ${c.rpId}`, "ok");
          UI.qs("#ky-rp", root).value = "";
          UI.setResult(errEl, "", "muted");
          refresh();
        } catch (e) { UI.setResult(errEl, `${e}`, "err"); }
      });

      UI.qs("#ky-sign", root).addEventListener("click", async () => {
        const credentialId = UI.qs("#ky-cred", root).value;
        if (!credentialId) { UI.toast("Create a credential first", "warn"); return; }
        const challenge = UI.randHex(32);
        UI.qs("#ky-chal", root).textContent = UI.shortHex(challenge, 14);
        try {
          const r = await api.invoke("keys_sign", { credentialId, challenge });
          UI.qs("#ky-sig", root).textContent = UI.shortHex(r.signature, 16);
          const v = UI.qs("#ky-ver", root);
          v.textContent = r.verifiedLocally ? `✓ valid (sign count ${r.signCount})` : "✖ INVALID";
          v.style.color = r.verifiedLocally ? "var(--ok)" : "var(--crit)";
          refresh();
        } catch (e) { UI.toast(`${e}`, "err"); }
      });
    },
  });
})();
