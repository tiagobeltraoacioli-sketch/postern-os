// modules/seal.js — Postern Seal Companion: the product thesis, visible.
// Self-audit ("is THIS device the genuine build?") + peer-verify ("is THAT
// device genuine?"). No backing Tauri command yet → preview mirrors the
// postern-seal-companion API; the verdict is honestly capped at UNVERIFIED
// because the PQ signature check and posture probes need the backend.
(function () {
  "use strict";
  const P = window.Postern, UI = P.ui, api = P.api;

  P.register({
    id: "seal",
    title: "Seal Companion",
    short: "Seal",
    desc: "Trust but verify — attest this device, and verify any Postern device before trusting it.",
    group: "Verify",
    order: 1,
    live: () => api.isReal("seal_self_audit"),
    icon: `<svg viewBox="0 0 24 24"><path d="M12 2 L21 7 v10 L12 22 L3 17 V7 Z" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M9 12l2.2 2.2L15.5 9.8" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>`,

    render(root) {
      root.innerHTML = `
        <div class="stack">
          <div class="seal-hero" id="sl-hero">
            <svg viewBox="0 0 24 24"><path d="M12 2 L21 7 v10 L12 22 L3 17 V7 Z" fill="none" stroke="currentColor" stroke-width="1.3"/><path d="M12 7 L16.5 9.5 v5 L12 17 L7.5 14.5 v-5 Z" fill="currentColor" opacity=".85"/></svg>
            <div>
              <div class="sh-verdict warn" id="sl-verdict">SEAL · UNVERIFIED</div>
              <p id="sl-verdict-note">Run a self-audit to compare this device against the published attested build. In preview, the verdict is honestly capped at UNVERIFIED — the roothash read, posture probes and Falcon‖ML-DSA check need the backend.</p>
            </div>
          </div>

          <div class="grid2">
            <section class="card">
              <div class="card-head"><h2>Self-audit</h2><div class="spacer"></div>
                ${api.isReal("seal_self_audit") ? UI.liveBadge() : UI.stubBadge("preview — probes need backend")}
              </div>
              <p class="note">Does <strong>this device</strong> run the genuine, unmodified Postern build? Compares the running <span class="mono">os_roothash</span> (dm-verity) to the published attested image, plus local posture checks.</p>
              <div class="actions">
                <button class="btn btn-primary" id="sl-audit">Run self-audit</button>
              </div>
              <div class="audit-list" id="sl-items" style="margin-top:12px"></div>
            </section>

            <section class="card">
              <div class="card-head"><h2>Peer-verify</h2><div class="spacer"></div>
                ${UI.stubBadge("structural checks only in preview")}
              </div>
              <p class="note">Before trusting <strong>another</strong> Postern device — sending a vault secret, pairing the wallet, trusting a messenger contact — verify the attestation it presents, bound to a fresh nonce <em>you</em> issued.</p>
              <div class="actions" style="margin-top:8px">
                <button class="btn" id="sl-challenge">1 · Issue fresh challenge</button>
                <span class="v mono" id="sl-nonce" style="color:var(--brass);font-size:12px"></span>
              </div>
              <label class="field" style="margin-top:10px"><span>2 · Peer's attestation report (JSON)</span>
                <textarea id="sl-report" rows="4" placeholder='{"os_roothash":"…","nonce":"…","signature":"…"}'></textarea></label>
              <label class="field" style="margin-top:10px"><span>3 · Expected os_roothash (published attested image)</span>
                <input id="sl-expected" class="mono" placeholder="hex roothash from the published build"></label>
              <div class="actions">
                <button class="btn btn-primary" id="sl-verify">Verify report</button>
              </div>
              <div class="audit-list" id="sl-checks" style="margin-top:12px"></div>
              <p class="result-line muted" id="sl-vres"></p>
            </section>
          </div>

          <div class="callout">
            <strong>Honest limits.</strong> Attestation proves the <em>build</em>, not the absence of a kernel
            0-day or a coerced user. Mobile attestation ultimately chains to the vendor CA (a stated trust
            dependency). Peer-verify is only sound with a fresh, single-use challenge.
          </div>

          ${UI.privacyCaveat()}
        </div>`;

      const drawItems = (el, items) => {
        el.innerHTML = "";
        for (const it of items) {
          const cls = it.status === "pass" || it.ok === true ? "badge-ok"
            : it.status === "fail" || it.ok === false ? "badge-crit" : "badge-warn";
          const label = it.status ?? (it.ok === true ? "pass" : it.ok === false ? "FAIL" : "unknown");
          const row = document.createElement("div");
          row.className = "audit-item";
          row.innerHTML = `
            <span class="a-name">${UI.esc(it.name)}</span>
            <span class="a-detail" title="${UI.esc(it.detail)}">${UI.esc(it.detail)}</span>
            <span class="badge ${cls}">${UI.esc(label)}</span>`;
          el.appendChild(row);
        }
      };

      UI.qs("#sl-audit", root).addEventListener("click", async () => {
        const btn = UI.qs("#sl-audit", root);
        btn.disabled = true;
        btn.textContent = "auditing…";
        try {
          const r = await api.invoke("seal_self_audit");
          drawItems(UI.qs("#sl-items", root), r.items);
          const v = UI.qs("#sl-verdict", root);
          if (r.verdict === "genuine") {
            v.textContent = "SEAL · GENUINE";
            v.className = "sh-verdict ok";
            P.setState({ seal: { verdict: "genuine", preview: !api.isReal("seal_self_audit") } });
          } else if (r.verdict === "compromised") {
            v.textContent = "SEAL · COMPROMISED";
            v.className = "sh-verdict crit";
            P.setState({ seal: { verdict: "compromised", preview: !api.isReal("seal_self_audit") } });
          } else {
            v.textContent = "SEAL · UNVERIFIED";
            v.className = "sh-verdict warn";
            P.setState({ seal: { verdict: "unverified", preview: true } });
          }
        } catch (e) { UI.toast(`${e}`, "err"); }
        btn.disabled = false;
        btn.textContent = "Run self-audit";
      });

      let challenge = null;
      UI.qs("#sl-challenge", root).addEventListener("click", async () => {
        try {
          challenge = await api.invoke("seal_issue_challenge");
          UI.qs("#sl-nonce", root).textContent = UI.shortHex(challenge, 12);
          UI.copy(challenge, "Challenge copied — send it to the peer");
        } catch (e) {
          UI.setResult(UI.qs("#sl-vres", root), `✖ could not issue challenge: ${e}`, "err");
        }
      });

      UI.qs("#sl-verify", root).addEventListener("click", async () => {
        const res = UI.qs("#sl-vres", root);
        if (!challenge) { UI.setResult(res, "issue a fresh challenge first (step 1)", "err"); return; }
        let report;
        try { report = JSON.parse(UI.qs("#sl-report", root).value); }
        catch { UI.setResult(res, "report is not valid JSON", "err"); return; }
        const expected = { os_roothash: UI.qs("#sl-expected", root).value.trim(), challenge };
        if (!expected.os_roothash) { UI.setResult(res, "expected roothash required", "err"); return; }
        try {
          const r = await api.invoke("seal_verify_report", { report, expected });
          drawItems(UI.qs("#sl-checks", root), r.checks);
          const good = r.verdict.startsWith("Genuine");
          UI.setResult(res, `verdict: ${r.verdict}${r.preview ? " (preview — PQ signature not checked)" : ""}`, good ? "ok" : "err");
        } catch (e) { UI.setResult(res, `✖ ${e}`, "err"); }
      });

      // reflect stored verdict on entry
      const cur = P.state.seal;
      if (cur.verdict === "genuine") {
        UI.qs("#sl-verdict", root).textContent = "SEAL · GENUINE";
        UI.qs("#sl-verdict", root).className = "sh-verdict ok";
      }
    },
  });
})();
