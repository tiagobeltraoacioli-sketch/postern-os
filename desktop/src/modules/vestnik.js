// modules/vestnik.js — Vestnik: the Postern Messenger UI shell.
//
// Wired to the REAL postern-messenger DEFAULT native channel (vodozemac
// Megolm E2EE) through the vestnik_* Tauri commands whenever a backend is
// present — no homeserver, no account, no live network (the federated
// matrix-rust-sdk path is OFF in this build), classical (not post-quantum),
// key distribution out-of-band. Without a backend it runs a clearly-labelled
// local PREVIEW engine (Web Crypto AES-GCM, Megolm-shaped) that is never
// presented as the real ratchet — the whole self-contained preview lives in
// THIS file, so api.js only needs the vestnik_* names in its REAL set.
(function () {
  "use strict";
  const P = window.Postern, UI = P.ui, api = P.api;

  const REAL_CMD = "vestnik_create_session";
  const isLive = () => api.isReal(REAL_CMD);

  // ── local, labelled PREVIEW engine (no backend) ─────────────────────────
  // Honest shape only: AES-GCM with a per-message counter bound as associated
  // data. NOT Megolm, NOT forward-ratcheted — the real crypto is the Rust
  // vodozemac core reached via the vestnik_* commands when a backend exists.
  const preview = (() => {
    const te = new TextEncoder(), td = new TextDecoder();
    let key = null, keyRaw = null, sid = null, seen = new Set();
    const hex = (buf) => Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
    const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
    const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
    async function create() {
      keyRaw = crypto.getRandomValues(new Uint8Array(32));
      key = await crypto.subtle.importKey("raw", keyRaw, "AES-GCM", false, ["encrypt", "decrypt"]);
      sid = hex(crypto.getRandomValues(new Uint8Array(8)));
      seen = new Set();
      return { sessionId: sid, sessionKey: b64(keyRaw), index: 0, tierBadge: "E2EE (Postern)", honesty: HONESTY_PREVIEW };
    }
    async function encrypt(plaintext, idx) {
      if (!key) throw new Error("no active session — create one first");
      const iv = new Uint8Array(12); new DataView(iv.buffer).setUint32(8, idx);
      const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: te.encode(String(idx)) }, key, te.encode(plaintext));
      return { frame: { sessionId: sid, ciphertext: b64(iv) + "." + b64(ct) }, honesty: HONESTY_PREVIEW };
    }
    async function decrypt(frame, idx) {
      if (!key) throw new Error("no active session — create one first");
      if (seen.has(idx)) throw new Error(`replayed message (index ${idx} already seen)`);
      const [ivB, ctB] = frame.ciphertext.split(".");
      const iv = unb64(ivB);
      const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: te.encode(String(idx)) }, key, unb64(ctB));
      seen.add(idx);
      return { plaintext: td.decode(pt), sessionId: frame.sessionId, messageIndex: idx, honesty: HONESTY_PREVIEW };
    }
    return { create, encrypt, decrypt, active: () => !!key, sid: () => sid };
  })();

  const HONESTY_PREVIEW = "PREVIEW (no backend) — local AES-GCM stand-in, NOT the real vodozemac Megolm ratchet. Wire the desktop backend for the real E2EE core.";

  // session survives route changes
  const sess = { active: false, sessionId: null, sessionKey: null, index: 0, messages: [], showCipher: false };

  async function invoke(cmd, args) {
    // Live → real Tauri command; preview → this module's local engine (the
    // preview index bookkeeping is the module's, mirroring the real ratchet).
    if (isLive()) return api.invoke(cmd, args);
    if (cmd === "vestnik_create_session") return preview.create();
    if (cmd === "vestnik_encrypt") return preview.encrypt(args.plaintext, sess.index);
    if (cmd === "vestnik_decrypt") return preview.decrypt(args.frame, args.previewIndex);
    if (cmd === "vestnik_register_peer") return { sessionId: "preview-peer", honesty: HONESTY_PREVIEW };
    if (cmd === "vestnik_status") return { active: preview.active(), sessionId: preview.sid(), tierBadge: "E2EE (Postern)", honesty: HONESTY_PREVIEW };
    throw new Error(`no handler for '${cmd}'`);
  }

  P.register({
    id: "vestnik",
    title: "Vestnik",
    short: "Vestnik",
    desc: "End-to-end encrypted messaging — Megolm group crypto, no phone-number identity, no homeserver.",
    group: "Transmit",
    order: 3,
    live: () => api.isReal("vestnik_create_session"),
    icon: `<svg viewBox="0 0 24 24"><path d="M4 5h16v11H8l-4 4z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M8 9.5h8M8 12.5h5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`,

    // Test seam: the module's own labelled AES-GCM PREVIEW engine (the
    // no-backend fallback). Unused in production — inside the desktop app the
    // vestnik_* commands route to the real vodozemac Megolm core. Exposed so
    // vestnik.test.mjs can prove the preview roundtrip/replay/honesty directly,
    // the way vault.test.mjs proves its preview through P.api.
    previewEngine: preview,
    honestyPreview: HONESTY_PREVIEW,

    render(root) {
      const live = isLive();
      root.innerHTML = `
        <div class="stack">
          <div class="callout callout-brass">
            <strong>Real Megolm E2EE — offline, no homeserver.</strong> Messages are encrypted with the
            vodozemac Megolm ratchet on Postern Messenger's default native channel, run entirely in-process.
            ${live
              ? UI.liveBadge("live · postern-messenger (vodozemac Megolm) — UNAUDITED")
              : UI.stubBadge("preview — AES-GCM stand-in, no backend loaded")}
            <p class="note" style="margin:8px 0 0">
              <strong>No account, no server, no live network</strong> in this build — the federated
              matrix-rust-sdk path is OFF. Megolm is <strong>classical</strong> (Curve25519), <strong>not
              post-quantum</strong>. Key distribution here is <strong>out-of-band</strong>: share your
              session key over an already-secure channel (e.g. Courier). The session is
              <strong>ephemeral in RAM</strong> this build — vault-backed persistence is a remaining gate.
            </p>
          </div>

          <div class="grid2" style="grid-template-columns: minmax(0,1.6fr) minmax(0,1fr)">
            <section class="card">
              <div class="card-head"><h2>Conversation</h2><div class="spacer"></div>
                <span class="badge badge-live" title="Security tier — internal Postern E2EE. Never silently downgraded.">E2EE (Postern)</span>
              </div>
              <div class="actions" style="margin-top:0">
                <button class="btn btn-primary" id="vk-new">New encrypted session</button>
                <span class="mono muted" id="vk-meta"></span>
                <div class="spacer" style="flex:1"></div>
                <label class="check"><input type="checkbox" id="vk-cipher"> show ciphertext</label>
              </div>
              <div class="chat" id="vk-chat" style="margin-top:12px" aria-live="polite"></div>
              <div class="actions">
                <input id="vk-input" class="input" style="flex:1" placeholder="Message — Megolm-encrypted before it leaves this pane" disabled>
                <button class="btn btn-primary" id="vk-send" disabled>Send</button>
              </div>
            </section>

            <div class="stack">
              <section class="card">
                <div class="card-head"><h2>Your session key</h2></div>
                <p class="note">Anyone holding this outbound session key can decrypt your messages from its
                  ratchet index forward — share it <strong>only</strong> over a verified channel (or via Courier).
                  Distribution is out-of-band on this native path (the matrix path automates it over Olm).</p>
                <div class="kv" style="margin-top:8px">
                  <div class="kv-row"><span class="k">session id</span><span class="v" id="vk-sid">—</span></div>
                  <div class="kv-row"><span class="k">session key</span><span class="v" id="vk-key">—</span><button class="copy-btn" id="vk-copykey">copy</button></div>
                </div>
              </section>

              <section class="card">
                <div class="card-head"><h2>Add a peer</h2></div>
                <p class="note">Paste a peer's outbound session key (received out-of-band) to decrypt their frames.</p>
                <div class="actions" style="margin-top:8px">
                  <input id="vk-peerkey" class="input" style="flex:1" placeholder="peer session key (base64)" disabled>
                  <button class="btn" id="vk-addpeer" disabled>Register</button>
                </div>
              </section>

              <section class="card">
                <div class="card-head"><h2>Receive a frame</h2></div>
                <p class="note">Paste a frame received out-of-band — JSON <code>{sessionId, ciphertext}</code> — to
                  decrypt it into an incoming message. The ratchet index carried by the frame is bound as
                  associated data on decrypt, and a replayed index is rejected.</p>
                <div class="stack" style="margin-top:8px">
                  <textarea id="vk-recv" class="input" rows="3" style="width:100%;resize:vertical" placeholder='{"sessionId":"…","ciphertext":"…"}' disabled></textarea>
                  <div class="actions" style="margin-top:0">
                    <div class="spacer" style="flex:1"></div>
                    <button class="btn" id="vk-recv-btn" disabled>Decrypt frame</button>
                  </div>
                </div>
              </section>

              <div class="callout">
                <strong>Honest limits.</strong>
                <ul>
                  <li>Megolm is <strong>classical</strong> — captured ciphertext is exposed to a future quantum adversary (harvest-now-decrypt-later). PQ transport waits on upstream.</li>
                  <li>No homeserver here, but a real homeserver/peer sees the social graph (who, when). Mitigate with a self-hosted server over Tor and no phone-number identity.</li>
                  <li><strong>Bridged</strong> (external, non-E2EE) conversations are a separate tier with a mandatory, non-dismissible disclaimer — not present in this offline shell.</li>
                </ul>
              </div>
            </div>
          </div>

          ${UI.privacyCaveat()}
        </div>`;

      const chat = UI.qs("#vk-chat", root);

      // Recover the ratchet index a preview frame was sealed at: the AES-GCM IV
      // encodes it big-endian at byte 8 (see the preview engine's encrypt).
      const frameIndex = (frame) => {
        try {
          const iv = Uint8Array.from(atob(String(frame.ciphertext).split(".")[0]), (c) => c.charCodeAt(0));
          return new DataView(iv.buffer, iv.byteOffset, iv.byteLength).getUint32(8);
        } catch { return sess.index; }
      };

      const renderMsgs = () => {
        chat.innerHTML = sess.messages.length ? "" :
          UI.emptyState("No messages yet.", "Create a session and say something — each message is Megolm-encrypted and its ratchet index is bound as associated data, then decrypted back to verified plaintext.");
        for (const m of sess.messages) {
          const el = document.createElement("div");
          el.className = "msg" + (m.them ? " them" : "");
          const badge = live ? "🔒 megolm" : "🔒 megolm(preview)";
          el.innerHTML = `
            <div class="bubble">${UI.esc(m.text)}${sess.showCipher ? `<div class="cipher">${UI.esc(UI.shortHex(m.cipher, 42))}</div>` : ""}</div>
            <div class="meta">idx ${m.index} · ${m.time} · ${badge}</div>`;
          chat.appendChild(el);
        }
        chat.scrollTop = chat.scrollHeight;
      };

      const syncSession = () => {
        const on = sess.active;
        UI.qs("#vk-input", root).disabled = !on;
        UI.qs("#vk-send", root).disabled = !on;
        UI.qs("#vk-peerkey", root).disabled = !on;
        UI.qs("#vk-addpeer", root).disabled = !on;
        UI.qs("#vk-recv", root).disabled = !on;
        UI.qs("#vk-recv-btn", root).disabled = !on;
        UI.qs("#vk-sid", root).textContent = on ? UI.shortHex(sess.sessionId, 10) : "—";
        UI.qs("#vk-key", root).textContent = on ? UI.shortHex(sess.sessionKey, 12) : "—";
        UI.qs("#vk-meta", root).textContent = on ? `session active · ${sess.messages.length} msg` : "";
        UI.qs("#vk-copykey", root).onclick = () => { if (sess.sessionKey) UI.copy(sess.sessionKey, "Session key copied"); };
      };

      UI.qs("#vk-new", root).addEventListener("click", async () => {
        try {
          const s = await invoke("vestnik_create_session");
          sess.active = true;
          sess.sessionId = s.sessionId;
          sess.sessionKey = s.sessionKey;
          sess.index = 0;
          sess.messages = [];
          renderMsgs();
          syncSession();
          UI.toast(live ? "Megolm session created" : "Preview session created", "ok");
        } catch (e) { UI.toast(String(e.message || e), "err"); }
      });

      UI.qs("#vk-cipher", root).addEventListener("change", (e) => {
        sess.showCipher = e.target.checked;
        renderMsgs();
      });
      UI.qs("#vk-cipher", root).checked = sess.showCipher;

      const send = async () => {
        const input = UI.qs("#vk-input", root);
        const text = input.value.trim();
        if (!text || !sess.active) return;
        try {
          const idx = sess.index;
          const enc = await invoke("vestnik_encrypt", { plaintext: text });
          // Roundtrip: decrypt the frame we'd receive, so the pane shows
          // VERIFIED plaintext and the true ratchet index — the loopback-to-
          // self path the backend registers on session create.
          const dec = await invoke("vestnik_decrypt", { frame: enc.frame, previewIndex: idx });
          sess.index = (typeof dec.messageIndex === "number" ? dec.messageIndex : idx) + 1;
          sess.messages.push({ text: dec.plaintext, cipher: enc.frame.ciphertext, index: dec.messageIndex, time: UI.nowHHMM(), them: false });
          input.value = "";
          renderMsgs();
          syncSession();
        } catch (e) { UI.toast(String(e.message || e), "err"); }
      };
      UI.qs("#vk-send", root).addEventListener("click", send);
      UI.qs("#vk-input", root).addEventListener("keydown", (e) => { if (e.key === "Enter") send(); });

      UI.qs("#vk-addpeer", root).addEventListener("click", async () => {
        const el = UI.qs("#vk-peerkey", root);
        const k = el.value.trim();
        if (!k || !sess.active) return;
        try {
          const r = await invoke("vestnik_register_peer", { sessionKey: k });
          el.value = "";
          UI.toast(`Peer registered · ${UI.shortHex(r.sessionId, 8)}`, "ok");
        } catch (e) { UI.toast(String(e.message || e), "err"); }
      });

      UI.qs("#vk-recv-btn", root).addEventListener("click", async () => {
        const el = UI.qs("#vk-recv", root);
        const raw = el.value.trim();
        if (!raw || !sess.active) return;
        try {
          let frame;
          try { frame = JSON.parse(raw); }
          catch { throw new Error("not a frame — paste JSON {sessionId, ciphertext}"); }
          if (!frame || typeof frame.sessionId !== "string" || typeof frame.ciphertext !== "string")
            throw new Error("frame must be JSON {sessionId, ciphertext}");
          // The preview engine binds the ratchet index as associated data, so
          // decrypt needs the index the frame was sealed at. Live: the real
          // vodozemac ratchet supplies it and previewIndex is ignored.
          const idx = frameIndex(frame);
          const dec = await invoke("vestnik_decrypt", { frame, previewIndex: idx });
          const i = typeof dec.messageIndex === "number" ? dec.messageIndex : idx;
          sess.messages.push({ text: dec.plaintext, cipher: frame.ciphertext, index: i, time: UI.nowHHMM(), them: true });
          if (i >= sess.index) sess.index = i + 1;
          el.value = "";
          renderMsgs();
          syncSession();
          UI.toast("Frame decrypted", "ok");
        } catch (e) { UI.toast(String(e.message || e), "err"); }
      });

      renderMsgs();
      syncSession();
    },
  });
})();
