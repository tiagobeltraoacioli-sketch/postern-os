// modules/courier.js — Postern Courier: post-quantum sealed file drop over Tor.
// Backed by the REAL courier_generate_recipient / courier_seal / courier_open
// Tauri commands (postern-courier — UNAUDITED) whenever a backend is present.
// The TRANSPORT is still mock/local either way: no live onion round trip yet
// (you hand the sealed payload over yourself) — hardened, not anonymous.
// Without a backend, the labeled preview engine seals with a real (but
// classical) ECDH-P256 + AES-GCM KEM instead of the hybrid ML-KEM-1024 +
// X25519 (HKDF combiner) + XChaCha20-Poly1305.
(function () {
  "use strict";
  const P = window.Postern, UI = P.ui, api = P.api;

  let sendFile = null; // {name, bytesB64, size}

  P.register({
    id: "courier",
    title: "Courier",
    desc: "Person-to-person sealed drop — PQ payload seal inside the Tor tunnel, no server.",
    group: "Transmit",
    order: 1,
    live: () => api.isReal("courier_seal"),
    icon: `<svg viewBox="0 0 24 24"><path d="M3 8l9 5 9-5" fill="none" stroke="currentColor" stroke-width="1.6"/><rect x="3" y="5" width="18" height="14" rx="2" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>`,

    render(root) {
      const live = api.isReal("courier_seal");
      root.innerHTML = `
        <div class="stack">
          <div class="callout callout-brass">
            <strong>Harvest-now-decrypt-later is the threat.</strong> The payload is sealed with
            hybrid ML-KEM-1024 + X25519 + XChaCha20-Poly1305 <em>inside</em> the Tor tunnel — a recorded circuit
            yields nothing, even to a future quantum adversary.
            ${live
              ? UI.liveBadge("live · postern-courier (hybrid ML-KEM-1024 + X25519 · XChaCha20-Poly1305) — UNAUDITED")
              : UI.stubBadge("preview KEM: ECDH-P256 (classical) — no backend loaded")}
            <p class="note" style="margin:8px 0 0"><strong>UNAUDITED</strong>, and the transport is
            <strong>mock/local</strong> — no live onion round trip yet: you hand the sealed payload to
            the recipient yourself. That makes this <strong>hardened, not anonymous</strong>.</p>
          </div>

          <div class="grid2">
            <section class="card">
              <div class="card-head"><h2>Receive</h2></div>
              <p class="note">1 · Generate a drop identity. Share the <strong>public key</strong> with the sender; keep the secret key here.</p>
              <div class="actions">
                <button class="btn btn-primary" id="cr-gen">Generate drop identity</button>
              </div>
              <div class="kv" id="cr-ident" style="display:none">
                <div class="kv-row"><span class="k">public key</span><span class="v accent" id="cr-pub">—</span><button class="copy-btn" id="cr-copypub">copy</button></div>
                <div class="kv-row"><span class="k">secret key</span><span class="v" id="cr-sec-masked">••••••••••••••••</span></div>
              </div>
              <p class="note" style="margin-top:14px">2 · Paste the sealed payload the sender gives you, and open it.</p>
              <label class="field"><span>Sealed payload (JSON)</span>
                <textarea id="cr-sealed-in" rows="4" placeholder='{"v":"postern-courier…"}'></textarea></label>
              <div class="actions">
                <button class="btn" id="cr-open">Open payload</button>
                <span class="result-line muted" id="cr-openres"></span>
              </div>
            </section>

            <section class="card">
              <div class="card-head"><h2>Send</h2></div>
              <label class="field"><span>Recipient public key</span>
                <input id="cr-to" class="mono" placeholder="base64 public key from the recipient"></label>
              <div class="dropzone" id="cr-drop" tabindex="0" role="button" aria-label="choose a file to seal" style="margin-top:12px">
                <input type="file" id="cr-file">
                <strong id="cr-fname">Drop a file here</strong>
                <span id="cr-fmeta">or click to choose — it is scrubbed-by-default and sealed locally</span>
              </div>
              <div class="actions">
                <button class="btn btn-primary" id="cr-seal" disabled>Seal payload</button>
                <span class="result-line muted" id="cr-sealres"></span>
              </div>
              <div id="cr-out" class="hidden">
                <label class="field"><span>Sealed payload — hand this to the recipient</span>
                  <textarea id="cr-sealed-out" rows="4" readonly></textarea></label>
                <div class="actions">
                  <button class="btn btn-sm" id="cr-copyout">copy</button>
                  <button class="btn btn-sm" id="cr-dlout">download .postern</button>
                </div>
              </div>
            </section>
          </div>

          <section class="card">
            <div class="card-head"><h2>Live drop over Tor</h2><div class="spacer"></div>${UI.stubBadge("onion transport backend pending — seal/open above may be live, this is not")}</div>
            <p class="note">The real product hosts the sealed payload on an <strong>ephemeral onion service</strong> (postern-tor) — you stay online during the transfer; no server, no account, no mailbox. Honest limits: the onion <em>address</em> crypto is classical (the PQ wrap covers the payload, not circuit metadata) and endpoint traffic analysis remains possible.</p>
            <div class="actions">
              <button class="btn" disabled title="Requires the postern-tor onion-service backend command">⧉ Host ephemeral onion drop</button>
              <span class="muted">requires backend</span>
            </div>
          </section>

          ${UI.privacyCaveat()}
        </div>`;

      let secret = null;

      UI.qs("#cr-gen", root).addEventListener("click", async () => {
        const btn = UI.qs("#cr-gen", root);
        btn.disabled = true;
        try {
          const r = await api.invoke("courier_generate_recipient");
          secret = r.secret;
          UI.qs("#cr-ident", root).style.display = "";
          UI.qs("#cr-pub", root).textContent = r.public;
          UI.qs("#cr-copypub", root).onclick = () => UI.copy(r.public, "Public key copied");
          UI.toast("Drop identity generated — secret key held in memory", "ok");
        } catch (e) {
          // Never fail silently: surface the backend/preview error instead of
          // leaving a dead button and an empty identity card.
          UI.setResult(UI.qs("#cr-openres", root), `✖ could not generate drop identity: ${e}`, "err");
          UI.toast(`Drop identity failed: ${e}`, "err");
        }
        btn.disabled = false;
      });

      const drop = UI.qs("#cr-drop", root);
      UI.wireDropzone(drop, UI.qs("#cr-file", root), async (file) => {
        const buf = new Uint8Array(await file.arrayBuffer());
        sendFile = { name: file.name, size: file.size, bytesB64: UI.toB64(buf) };
        UI.qs("#cr-fname", root).textContent = file.name;
        UI.qs("#cr-fmeta", root).textContent = `${UI.fmtBytes(file.size)} — ready to seal`;
        UI.qs("#cr-seal", root).disabled = false;
      });

      UI.qs("#cr-seal", root).addEventListener("click", async () => {
        const res = UI.qs("#cr-sealres", root);
        const to = UI.qs("#cr-to", root).value.trim();
        if (!to) { UI.setResult(res, "recipient public key required", "err"); return; }
        if (!sendFile) { UI.setResult(res, "choose a file first", "err"); return; }
        UI.setResult(res, "sealing…", "muted");
        try {
          const sealed = await api.invoke("courier_seal", {
            recipientPublic: to, bytesB64: sendFile.bytesB64, name: sendFile.name,
          });
          const json = JSON.stringify(sealed);
          UI.qs("#cr-out", root).classList.remove("hidden");
          UI.qs("#cr-sealed-out", root).value = json;
          UI.qs("#cr-copyout", root).onclick = () => UI.copy(json, "Sealed payload copied");
          UI.qs("#cr-dlout", root).onclick = () => UI.download(sendFile.name + ".postern", json, "application/json");
          UI.setResult(res, `✓ sealed ${UI.fmtBytes(sendFile.size)} — only the recipient's secret key opens it`, "ok");
        } catch (e) { UI.setResult(res, `✖ ${e}`, "err"); }
      });

      UI.qs("#cr-open", root).addEventListener("click", async () => {
        const res = UI.qs("#cr-openres", root);
        if (!secret) { UI.setResult(res, "generate a drop identity first (its secret key opens payloads)", "err"); return; }
        let sealed;
        try { sealed = JSON.parse(UI.qs("#cr-sealed-in", root).value); }
        catch { UI.setResult(res, "not valid payload JSON", "err"); return; }
        UI.setResult(res, "opening…", "muted");
        try {
          const out = await api.invoke("courier_open", { recipientSecret: secret, sealed });
          UI.download(out.name, UI.fromB64(out.bytesB64));
          UI.setResult(res, `✓ opened — downloaded '${out.name}'`, "ok");
        } catch (e) { UI.setResult(res, `✖ ${e}`, "err"); }
      });
    },
  });
})();
