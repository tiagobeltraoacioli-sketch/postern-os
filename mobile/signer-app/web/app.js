// SPDX-License-Identifier: MIT OR Apache-2.0
//
// app.js — the framework-free reference UI for the phone-as-signer flow.
//
// It renders the phone side and drives `postern-mobile-signer` through the Node
// bridge (POST /api). It never signs or decodes anything itself: it asks the
// engine for the WYSIWYS prompt and the signature. Honesty is carried on screen
// (UNBOOTED image, software keystore, per-sign presence, not a hardware wallet).
"use strict";

(function () {
  const $ = (id) => document.getElementById(id);
  const show = (id, on) => ($(id).hidden = !on);

  let state = { paired: false, session: null, kind: "login", prompt: null, method: "biometric", mode: "unknown" };

  // ── API glue ────────────────────────────────────────────────────────────────
  async function api(cmd) {
    const res = await fetch("/api", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(cmd),
    });
    return res.json();
  }

  function toast(msg, kind) {
    const t = document.createElement("div");
    t.className = "toast" + (kind ? " " + kind : "");
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 3200);
  }

  const esc = (s) =>
    String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

  // Deterministic 6-digit reference SAS from the derived session (display only —
  // the real SAS comes from the PQ-hybrid pairing ceremony).
  async function sasFromSession(hex) {
    const bytes = new Uint8Array(hex.match(/../g).map((h) => parseInt(h, 16)));
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
    let n = 0;
    for (let i = 0; i < 3; i++) n = (n << 8) | digest[i];
    return String(n % 1000000).padStart(6, "0");
  }

  // A 16-byte hex session id derived from the desktop QR payload (so pairing and
  // SAS are tied together in the reference).
  async function sessionFromQr(text) {
    const enc = new TextEncoder().encode("postern:ref-session:" + (text || "default-desktop"));
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", enc));
    return Array.from(digest.slice(0, 16)).map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  // ── Mode badge ────────────────────────────────────────────────────────────────
  async function detectMode() {
    try {
      const m = await fetch("/mode").then((r) => r.json());
      state.mode = m.mode;
      const badge = $("mode-badge");
      badge.className = "mode " + (m.mode === "engine" ? "mode-engine" : "mode-preview");
      badge.textContent = m.mode === "engine" ? "engine: real signer" : "preview: NOTHING signed";
      $("foot-mode").textContent = m.mode === "engine" ? "real postern-mobile-signer" : "preview — build signer-cli for real signatures";
    } catch (_) {
      $("mode-badge").textContent = "bridge offline";
    }
  }

  // ── STEP 1 — pairing ───────────────────────────────────────────────────────────
  let pendingSession = null;

  $("btn-pair").addEventListener("click", async () => {
    const qr = $("qr-input").value.trim();
    pendingSession = await sessionFromQr(qr);
    const sas = await sasFromSession(pendingSession);
    $("sas-digits").textContent = sas.replace(/(\d{3})(\d{3})/, "$1 $2");
    show("sas-box", true);
    show("paired-card", false);
  });

  $("btn-sas-abort").addEventListener("click", () => {
    show("sas-box", false);
    pendingSession = null;
    toast("Pairing aborted — SAS mismatch means a possible interceptor.", "err");
  });

  $("btn-sas-ok").addEventListener("click", async () => {
    const peer = $("peer-name").value.trim() || "desktop";
    const testnet = $("network").value === "testnet";
    const out = await api({ cmd: "init", session_hex: pendingSession, peer, testnet });
    if (!out.ok) return toast(out.error || "init failed", "err");
    state.paired = true;
    state.session = out.session_hex;
    $("p-peer").textContent = out.peer;
    $("p-addr").textContent = out.address;
    $("p-session").textContent = out.session_hex;
    show("paired-card", true);
    show("sas-box", false);
    show("s-request", true);
    if (out.mode === "preview") toast("Paired in PREVIEW — no engine, nothing will be signed.", "err");
    else toast("Paired. The key lives here on the phone.", "ok");
  });

  // ── STEP 2 — desktop simulator ───────────────────────────────────────────────
  document.querySelectorAll(".tab").forEach((tab) =>
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      state.kind = tab.dataset.kind;
      show("sim-login", state.kind === "login");
      show("sim-transfer", state.kind === "transfer");
    })
  );

  $("btn-send").addEventListener("click", async () => {
    if (!state.paired) return toast("pair a desktop first", "err");
    let reqOut;
    if (state.kind === "login") {
      reqOut = await api({ cmd: "request_login", org: $("r-org").value.trim() || "acme", user: $("r-user").value.trim() || "alice" });
    } else {
      reqOut = await api({
        cmd: "request_transfer",
        to_address: $("t-to").value.trim(),
        amount: Number($("t-amt").value || 0),
        fee: Number($("t-fee").value || 0),
      });
    }
    if (!reqOut.ok) return toast(reqOut.error || "request failed", "err");

    // Feed the genuine frame to the phone engine → WYSIWYS prompt.
    const rf = await api({ cmd: "receive_frame", frame_hex: reqOut.frame_hex });
    if (!rf.ok) return toast(rf.error || "receive_frame failed", "err");
    state.prompt = rf.prompt;
    renderApproval(rf.prompt);
  });

  // ── STEP 3 — approval card ───────────────────────────────────────────────────
  function tierHeadline(tier) {
    return {
      SilentReadOnly: "Read-only — no signature, no key use.",
      SingleTap: "Low-stakes — this signature can't move funds.",
      ExplicitReview: "Irreversible — review carefully before you confirm.",
    }[tier] || "";
  }

  function renderApproval(p) {
    show("s-request", false);
    show("s-approve", true);
    show("s-result", false);
    const isTransfer = p.can_move_funds;
    const singleTap = p.tier === "SingleTap";
    $("approve-card").innerHTML = `
      <span class="tier-badge tier-${esc(p.tier)}"><span class="tier-dot"></span>${esc(p.tier)}</span>
      <div class="tier-headline">${esc(tierHeadline(p.tier))}</div>
      <div class="wysiwys">${esc(p.sentence)}</div>
      <div class="fund-flag ${isTransfer ? "move" : "nomove"}">
        ${isTransfer ? "⚠ This can MOVE FUNDS — spends are irreversible." : "✓ This cannot move funds."}
      </div>
      <div class="kv"><span>Approve for</span><b>${esc(p.peer_device)}</b></div>
      <div class="frag">
        <div class="frag-label">Confirmation fragment — must match the desktop, else decline</div>
        <div class="frag-val">${esc(p.confirmation_fragment)}</div>
      </div>
      <div class="disclosure">${esc(p.disclosure)}</div>

      <div class="presence">
        <div class="presence-label">Per-sign user presence (no blanket auto-approve)</div>
        <div class="seg" id="seg-method">
          <button data-m="biometric" class="on">Biometric</button>
          <button data-m="device_pin">Device PIN</button>
        </div>
      </div>

      ${
        singleTap
          ? `<div class="grant-row">Optional: reduce prompts for logins to this org for
               <input id="grant-mins" type="number" value="22" min="1" max="1440" /> min
               <button class="btn ghost" id="btn-grant" style="width:auto;margin:0;padding:6px 10px">Set grant</button></div>`
          : ""
      }

      <button class="btn primary" id="btn-approve">Confirm presence &amp; sign</button>
      ${singleTap ? `<button class="btn ghost" id="btn-tap">Single-tap (if grant covers it)</button>` : ""}
      <button class="btn danger" id="btn-decline">Decline</button>
      <div class="dim" style="font-size:11px;margin-top:8px">req-nonce ${esc(p.req_nonce_hex.slice(0, 20))}…</div>
    `;

    document.querySelectorAll("#seg-method button").forEach((b) =>
      b.addEventListener("click", () => {
        document.querySelectorAll("#seg-method button").forEach((x) => x.classList.remove("on"));
        b.classList.add("on");
        state.method = b.dataset.m;
      })
    );

    if (singleTap) {
      $("btn-grant").addEventListener("click", async () => {
        const mins = Number($("grant-mins").value || 22);
        const g = await api({ cmd: "set_login_grant", org: $("r-org").value.trim() || "acme", expires_at_unix: Math.floor(Date.now() / 1000) + mins * 60 });
        if (g.ok) toast("Grant set — single-tap now allowed for this org (revocable).", "ok");
      });
      $("btn-tap").addEventListener("click", async () => {
        const out = await api({ cmd: "approve_single_tap", now_unix: Math.floor(Date.now() / 1000) });
        renderResult(out, "single-tap");
      });
    }

    $("btn-approve").addEventListener("click", async () => {
      const out = await api({ cmd: "approve", req_nonce_hex: p.req_nonce_hex, method: state.method });
      renderResult(out, "presence");
    });
    $("btn-decline").addEventListener("click", async () => {
      const out = await api({ cmd: "decline" });
      renderResult(out, "decline");
    });
  }

  // ── Result ───────────────────────────────────────────────────────────────────
  function renderResult(out, how) {
    show("s-approve", false);
    show("s-result", true);
    let html = "";
    if (!out.ok) {
      html = `<span class="result-badge declined">refused</span>
        <div class="wysiwys">${esc(out.error || "the engine refused (fail-closed)")}</div>`;
    } else if (out.declined) {
      html = `<span class="result-badge declined">declined</span>
        <div class="dim">Nothing was signed. The replay guard did not advance — as if the request never arrived.</div>`;
    } else if (out.preview || out.signature_hex == null) {
      html = `<span class="result-badge preview">preview — NOT signed</span>
        <div class="wysiwys">${esc(out.note || "No engine built. No key, no signature.")}</div>
        <div class="dim">Build <code>signer-cli</code> to produce a real hybrid Falcon‖ML-DSA signature here.</div>`;
    } else {
      html = `<span class="result-badge ok">approved &amp; signed (${esc(how)})</span>
        <div class="kv"><span>desktop matched the approval</span><b>${out.matched ? "yes" : "no"}</b></div>
        <div class="kv"><span>counter</span><b>${esc(out.counter)}</b></div>
        <div class="presence-label" style="margin-top:10px">signed payload digest</div>
        <div class="sig">${esc(out.payload_digest_hex)}</div>
        <div class="presence-label" style="margin-top:10px">hybrid signature (public)</div>
        <div class="sig">${esc(out.signature_hex)}</div>
        <div class="presence-label" style="margin-top:10px">identity public key (public)</div>
        <div class="sig">${esc(out.public_key_hex)}</div>`;
    }
    $("result-card").innerHTML = html;
  }

  $("btn-again").addEventListener("click", () => {
    show("s-result", false);
    show("s-request", true);
  });

  detectMode();
})();
