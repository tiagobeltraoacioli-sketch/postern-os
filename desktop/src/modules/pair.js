// SPDX-License-Identifier: MIT OR Apache-2.0
// modules/pair.js — Phone-as-signer, the DESKTOP REQUESTER side (v1).
//
// The desktop holds NO wallet key. It runs the QR + SAS pairing ceremony with a
// phone, composes a wallet-LOGIN challenge, and asks the paired phone to sign it
// (the key stays on the phone). Approved logins become scoped, expiring,
// revocable postern-policy grants shown in a live list.
//
// Every claim on screen is meant to be literally true: this protects the KEY
// (on the phone), not the desktop session; it is software signing, not a
// hardware wallet; it is local-first with no cloud; and it is unaudited scaffold.
(function () {
  "use strict";
  const P = window.Postern, UI = P.ui, api = P.api;

  P.register({
    id: "pair",
    title: "Phone-as-Signer",
    short: "Phone Signer",
    desc: "Pair your phone and approve logins there — the key lives on the phone; this desktop holds none.",
    group: "Protect",
    order: 5,
    // "live" whenever the pairing backend is wired; the sign step is honestly
    // a request to the phone either way.
    live: () => api.isReal("pair_begin"),
    icon: `<svg viewBox="0 0 24 24"><rect x="7" y="2.5" width="10" height="19" rx="2" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M10 18.5h4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/><path d="M9.5 8.5l2 2 3.5-3.6" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>`,

    render(root) {
      const backend = api.isReal("pair_begin");
      root.innerHTML = `
        <div class="stack">
          <div class="callout callout-brass">
            <strong>This protects the key, not this session.</strong>
            The wallet key lives on your <em>phone</em>; this desktop holds <strong>none</strong>.
            Signing happens on the phone in <strong>software</strong> — this is <strong>not a hardware
            wallet</strong>, and a compromised (rooted/jailbroken/malware) phone can still steal the key.
            Pairing trusts the other device <em>on your say-so</em>; Postern cannot verify the peer is
            genuine. Local-only — no cloud, no account, no server. Unaudited beta scaffold.
            The coin (BLCH) is <strong>not a security</strong>.
            ${backend ? UI.liveBadge("pairing backend wired · phone leg simulated") : UI.stubBadge("browser preview — no backend")}
          </div>

          <div class="callout callout-warn">
            <strong>v1 is LOGIN-ONLY.</strong> The only shipped flow is a wallet-<em>login</em> signature
            (domain <span class="mono">consiglio:wallet-login:v1</span>). The value-transfer flow is a
            <strong>reference demo</strong>, not a v1 path. Even on the live backend, the
            <strong>phone leg is simulated</strong> here — there is no real phone signing over the LAN yet.
          </div>

          <!-- ── 1 · Pairing ceremony ──────────────────────────────────── -->
          <section class="card">
            <div class="card-head"><h2>1 · Pair a phone</h2><div class="spacer"></div>
              <span class="badge badge-info">QR + SAS · mandatory</span>
            </div>
            <p class="note">Show this QR and <strong>scan it with your phone</strong> (the phone is the
              trust root doing the verifying). The phone pins the desktop's <em>ephemeral channel key</em>
              off the glass. Then compare the <strong>6-digit SAS</strong> on both screens — if they
              differ, <strong>someone may be intercepting you: abort.</strong>
              LAN discovery is visible to your local network.</p>
            <div class="field-row">
              <label class="field"><span>LAN hint (mDNS / host:port — optional)</span>
                <input id="pr-lan" class="mono" placeholder="mdns://_postern._tcp.local"></label>
              <div class="actions" style="align-items:flex-end">
                <button class="btn btn-primary" id="pr-begin">Begin pairing</button>
                <button class="btn btn-ghost" id="pr-cancel" hidden>Cancel</button>
              </div>
            </div>
            <div id="pr-cere" hidden style="margin-top:14px">
              <div class="grid2">
                <div style="text-align:center">
                  <div id="pr-qr" class="qr-box" aria-label="Pairing QR"></div>
                  <div class="note" style="margin-top:6px">Ephemeral channel key — no wallet key exists here.</div>
                </div>
                <div>
                  <label class="field"><span>Fingerprint (pinned by the phone · TOFU)</span>
                    <div class="mono pr-val" id="pr-fp"></div></label>
                  <label class="field" style="margin-top:8px"><span>QR payload</span>
                    <div class="mono pr-val small" id="pr-payload"></div></label>
                  <div class="callout callout-warn" style="margin-top:10px">
                    <strong>Confirm on the phone.</strong> In a real pairing the phone scans, runs the
                    hybrid-KEM handshake, and shows its own SAS. Compare it with the value below —
                    they must match exactly.
                  </div>
                  <div class="actions" style="margin-top:8px">
                    <label class="field" style="flex:1"><span>Nickname for this device</span>
                      <input id="pr-nick" placeholder="Tiago's phone"></label>
                    <button class="btn" id="pr-confirm" style="align-self:flex-end">${backend ? "Simulate phone scan" : "Simulate phone (preview)"}</button>
                  </div>
                  <div id="pr-sas" class="sas-box" hidden></div>
                </div>
              </div>
            </div>
          </section>

          <!-- ── Paired devices ────────────────────────────────────────── -->
          <section class="card">
            <div class="card-head"><h2>Paired devices</h2><div class="spacer"></div>
              <button class="btn btn-sm btn-ghost" id="pr-refresh-pairs">refresh</button></div>
            <div id="pr-pairs" class="pair-list"></div>
          </section>

          <!-- ── 2 · Wallet-login request ──────────────────────────────── -->
          <section class="card">
            <div class="card-head"><h2>2 · Request a wallet-login signature</h2><div class="spacer"></div>
              <span class="badge badge-info">WYSIWYS · desktop holds no key</span></div>
            <p class="note">The desktop composes a <strong>domain-separated login transcript</strong>
              (<span class="mono">consiglio:wallet-login:v1</span>) and asks the paired phone to sign it.
              The phone parses the bytes itself and shows what it is signing — <em>this signature can only
              be a login, never a payment.</em></p>
            <div class="field-row">
              <label class="field"><span>Organisation</span><input id="pr-org" placeholder="acme"></label>
              <label class="field"><span>User</span><input id="pr-user" placeholder="alice"></label>
              <label class="field"><span>Paired device</span><select id="pr-session"></select></label>
              <div class="actions" style="align-items:flex-end">
                <button class="btn btn-primary" id="pr-req">Request signature</button>
              </div>
            </div>
            <div id="pr-req-card" hidden style="margin-top:12px"></div>
          </section>

          <!-- ── 3 · Grants ────────────────────────────────────────────── -->
          <section class="card">
            <div class="card-head"><h2>3 · Grants</h2><div class="spacer"></div>
              <button class="btn btn-sm btn-ghost" id="pr-refresh-grants">refresh</button></div>
            <p class="note">Every approved login is a <strong>time-boxed, revocable</strong> grant,
              re-checked fail-closed at each boundary. Silence defaults to deny.</p>
            <div id="pr-grants" class="grant-list"></div>
            <p class="note" id="pr-enforce" style="margin-top:8px"></p>
          </section>

          <div class="callout">
            <strong>Honest limits.</strong> A compromised endpoint (A5) defeats this: ring-0 on the phone
            reads the key from RAM and can forge the approval card. Pairing authenticates a device key,
            not that the software is genuine; a coerced user can pair an attacker's device. The channel is
            hybrid post-quantum (X25519 ‖ ML-KEM-1024) with a classical X25519 hedge — ML-KEM is
            pre-1.0 and unaudited. Nothing here is built for or proven on hardware.
          </div>

          ${UI.privacyCaveat()}
        </div>`;

      let pending = null; // { qr, fingerprint, nonce } from pair_begin

      // ── QR render (self-contained; dark-on-light for scanning) ──────────
      function renderQR(el, text) {
        try {
          el.innerHTML = window.PosternQR ? window.PosternQR.toSVG(text) : "";
          if (!window.PosternQR) throw new Error("no encoder");
        } catch (e) {
          el.innerHTML = `<div class="note">QR unavailable — scan the payload text below instead.</div>`;
        }
      }

      // ── pairing ceremony ────────────────────────────────────────────────
      UI.qs("#pr-begin", root).addEventListener("click", async () => {
        try {
          const lanHint = UI.qs("#pr-lan", root).value.trim();
          const nickname = UI.qs("#pr-nick", root).value.trim() || "phone";
          const r = await api.invoke("pair_begin", { lanHint, nickname });
          pending = r;
          UI.qs("#pr-cere", root).hidden = false;
          UI.qs("#pr-cancel", root).hidden = false;
          UI.qs("#pr-fp", root).textContent = r.fingerprint;
          UI.qs("#pr-payload", root).textContent = r.qr;
          renderQR(UI.qs("#pr-qr", root), r.qr);
          UI.qs("#pr-sas", root).hidden = true;
        } catch (e) { UI.toast(`${e}`, "err"); }
      });

      UI.qs("#pr-cancel", root).addEventListener("click", async () => {
        try { await api.invoke("pair_cancel"); } catch { /* ignore */ }
        pending = null;
        UI.qs("#pr-cere", root).hidden = true;
        UI.qs("#pr-cancel", root).hidden = true;
      });

      UI.qs("#pr-confirm", root).addEventListener("click", async () => {
        if (!pending) { UI.toast("start pairing first", "err"); return; }
        // The phone scans the QR, runs the ML-KEM-1024‖X25519 handshake, and returns
        // its PairingInit over the LAN leg. Preview stand-in: a faked PairingInit so
        // the ceremony is exercisable; the live path awaits the LAN transport + phone.
        const pairingInitHex = UI.randHex(1600);
        try {
          // Step 1: derive the KEM-bound SAS from the phone's reply.
          const resp = await api.invoke("pair_respond", { pairingInitHex });
          const box = UI.qs("#pr-sas", root);
          box.hidden = false;
          box.innerHTML = `
            <div class="sas-label">Compare this SAS on BOTH screens</div>
            <div class="sas-digits mono">${UI.esc(resp.sas)}</div>
            <div class="note">${UI.esc(resp.note)}</div>`;
          // Step 2: the fail-closed human gate. In the scaffold we confirm inline;
          // a refusal (userConfirmed:false) persists NOTHING.
          const r = await api.invoke("pair_confirm", { userConfirmed: true });
          UI.toast(`Paired “${r.nickname}” — SAS ${r.sas}`, "ok");
          await refreshPairs();
          await refreshSessions();
        } catch (e) { UI.toast(`${e}`, "err"); }
      });

      // ── paired devices list ─────────────────────────────────────────────
      async function refreshPairs() {
        const el = UI.qs("#pr-pairs", root);
        try {
          const { pairings } = await api.invoke("pair_list");
          if (!pairings.length) { el.innerHTML = UI.emptyState("No paired devices yet.", "Begin pairing above — the phone is the trust root."); return; }
          el.innerHTML = "";
          for (const p of pairings) {
            const row = document.createElement("div");
            row.className = "pair-row" + (p.revoked ? " revoked" : "");
            row.innerHTML = `
              <div class="pair-main">
                <strong>${UI.esc(p.nickname)}</strong>
                <span class="badge ${p.revoked ? "badge-crit" : "badge-ok"}">${p.revoked ? "revoked" : "paired"}</span>
              </div>
              <div class="pair-meta mono">peer ${UI.esc(p.peerFingerprint)} · SAS ${UI.esc(p.sas)}</div>
              <div class="pair-actions">
                ${p.revoked ? "" : `<button class="btn btn-sm btn-danger" data-unpair="${p.id}">Unpair / revoke</button>`}
              </div>`;
            el.appendChild(row);
          }
          UI.qsa("[data-unpair]", el).forEach((b) =>
            b.addEventListener("click", async () => {
              try {
                const r = await api.invoke("pair_unpair", { id: Number(b.dataset.unpair) });
                UI.toast(`Unpaired ${r.revokedDevice} — its grants revoked`, "ok");
                await refreshPairs(); await refreshSessions(); await refreshGrants();
              } catch (e) { UI.toast(`${e}`, "err"); }
            }));
        } catch (e) { el.innerHTML = UI.errorState(e); }
      }

      async function refreshSessions() {
        const sel = UI.qs("#pr-session", root);
        try {
          const { pairings } = await api.invoke("pair_list");
          const live = pairings.filter((p) => !p.revoked);
          sel.innerHTML = live.length
            ? live.map((p) => `<option value="${p.id}">${UI.esc(p.nickname)}</option>`).join("")
            : `<option value="">— pair a device first —</option>`;
        } catch { sel.innerHTML = `<option value="">—</option>`; }
      }

      // ── wallet-login request ────────────────────────────────────────────
      UI.qs("#pr-req", root).addEventListener("click", async () => {
        const org = UI.qs("#pr-org", root).value.trim();
        const user = UI.qs("#pr-user", root).value.trim();
        const sessionId = Number(UI.qs("#pr-session", root).value || 0);
        if (!org || !user) { UI.toast("org and user are required", "err"); return; }
        if (!sessionId) { UI.toast("pair a phone first", "err"); return; }
        try {
          const req = await api.invoke("login_request", { org, user, sessionId });
          const card = UI.qs("#pr-req-card", root);
          card.hidden = false;
          card.innerHTML = `
            <div class="signreq">
              <div class="signreq-head"><strong>Sign-request sent to the phone</strong>
                <span class="badge badge-info">#${req.id} · counter ${req.counter}</span></div>
              <p class="signreq-summary">${UI.esc(req.summary)}</p>
              <div class="sr-kv mono">
                <span>domain</span><span>${UI.esc(req.domain)}</span>
                <span>transcript</span><span>${UI.esc(UI.shortHex(req.transcript, 12))}</span>
                <span>req-nonce</span><span>${UI.esc(UI.shortHex(req.reqNonce, 10))}</span>
              </div>
              <p class="note">${UI.esc(req.note)}</p>
              <p class="note"><strong>Phone leg is simulated.</strong> There is no real phone signing over
                the LAN yet — the button below sends a <em>stand-in</em> approval frame. On the live backend
                that stand-in will NOT pass signature verification, so it mints no grant (fail closed); it is
                not a working phone approval.</p>
              <div class="actions">
                <button class="btn btn-primary" id="pr-approve" data-id="${req.id}">${backend ? "Simulate phone approval (won’t verify)" : "Approve on phone (preview)"}</button>
                <button class="btn btn-ghost" id="pr-rej" data-id="${req.id}">Reject</button>
                <label class="field" style="max-width:150px"><span>grant minutes</span>
                  <input id="pr-mins" type="number" value="22" min="1" max="1440"></label>
              </div>
              <div id="pr-approve-res" class="result-line muted"></div>
            </div>`;
          UI.qs("#pr-approve", card).addEventListener("click", async () => {
            const minutes = Number(UI.qs("#pr-mins", card).value || 22);
            try {
              // The phone returns a sealed Approval frame over the LAN leg; the
              // backend opens it, matches it, and VERIFIES the hybrid signature
              // before minting (F-3). Preview stand-in: a faked approval frame.
              const approvalFrameHex = UI.randHex(2048);
              const g = await api.invoke("login_complete", { id: req.id, approvalFrameHex, minutes });
              UI.setResult(UI.qs("#pr-approve-res", card),
                `✓ ${g.note} (grant #${g.grantId}, scope ${g.scope}, expires ${g.expiry})`, "ok");
              await refreshGrants();
            } catch (e) { UI.setResult(UI.qs("#pr-approve-res", card), `✖ ${e}`, "err"); }
          });
          UI.qs("#pr-rej", card).addEventListener("click", async () => {
            try { await api.invoke("login_reject", { id: req.id }); UI.toast("request rejected", "ok"); card.hidden = true; }
            catch (e) { UI.toast(`${e}`, "err"); }
          });
        } catch (e) { UI.toast(`${e}`, "err"); }
      });

      // ── grants list ─────────────────────────────────────────────────────
      async function refreshGrants() {
        const el = UI.qs("#pr-grants", root);
        try {
          const { grants, enforcement } = await api.invoke("grants_list");
          UI.qs("#pr-enforce", root).textContent = `Enforcement: ${enforcement}`;
          if (!grants.length) { el.innerHTML = UI.emptyState("No grants yet — approve a login above."); return; }
          el.innerHTML = "";
          for (const g of grants) {
            const mins = Math.floor(g.remainingSecs / 60), secs = g.remainingSecs % 60;
            const live = g.allow;
            const row = document.createElement("div");
            row.className = "grant-row" + (live ? "" : " dead");
            row.innerHTML = `
              <div class="grant-main">
                <strong>${UI.esc(g.scope)}</strong>
                <span class="badge ${live ? "badge-ok" : "badge-crit"}">${live ? "active" : (g.revoked ? "revoked" : "expired")}</span>
              </div>
              <div class="grant-meta">${UI.esc(g.subject)} · ${live ? `${mins}m ${secs}s left` : UI.esc(g.reason || "denied")}</div>
              <div class="grant-actions">
                ${g.revoked ? "" : `<button class="btn btn-sm btn-danger" data-revoke="${g.id}">Revoke</button>`}
              </div>`;
            el.appendChild(row);
          }
          UI.qsa("[data-revoke]", el).forEach((b) =>
            b.addEventListener("click", async () => {
              try { await api.invoke("grant_revoke", { id: Number(b.dataset.revoke) }); UI.toast("grant revoked", "ok"); await refreshGrants(); }
              catch (e) { UI.toast(`${e}`, "err"); }
            }));
        } catch (e) { el.innerHTML = UI.errorState(e); }
      }

      UI.qs("#pr-refresh-pairs", root).addEventListener("click", refreshPairs);
      UI.qs("#pr-refresh-grants", root).addEventListener("click", refreshGrants);

      // live-tick the grants countdown while this module is visible
      this._tick = setInterval(() => { if (P.state.route === "pair") refreshGrants(); }, 5000);

      refreshPairs();
      refreshSessions();
      refreshGrants();
    },

    onHide() { if (this._tick) { clearInterval(this._tick); this._tick = null; } },
  });
})();
