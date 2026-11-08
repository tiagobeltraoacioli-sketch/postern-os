// modules/hygiene.js — Postern Hygiene: metadata scrub-by-default.
// Backed by the REAL `hygiene_scrub` Tauri command (postern-hygiene,
// desktop/src-tauri/src/hygiene.rs) whenever a backend is present — fails
// closed on unsupported formats, UNAUDITED. Without a backend it falls back
// to the labeled preview engine (api.js): JPEG scrub is REAL (metadata
// segments actually removed, cleaned file downloadable); OOXML/PDF show the
// exact fields the Rust core strips.
(function () {
  "use strict";
  const P = window.Postern, UI = P.ui, api = P.api;

  P.register({
    id: "hygiene",
    title: "Hygiene",
    desc: "Scrub document metadata by default — author, company, timestamps never leave.",
    group: "Transmit",
    order: 3,
    live: () => api.isReal("hygiene_scrub"),
    icon: `<svg viewBox="0 0 24 24"><path d="M7 3h7l4 4v14H7z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M14 3v4h4" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M9.5 13l5 5M14.5 13l-5 5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>`,

    render(root) {
      const live = api.isReal("hygiene_scrub");
      root.innerHTML = `
        <div class="stack">
          <div class="callout callout-brass">
            <strong>Metadata is the leak nobody fixes.</strong> Office files carry the author,
            <span class="mono">lastModifiedBy</span>, company and timestamps; photos carry EXIF GPS.
            Postern's rule: <strong>scrub by default</strong> — the provenance seal is a separate
            opt-in, because a provenance trail can de-anonymize.
            <p class="note" style="margin:8px 0 0"><strong>UNAUDITED</strong> reference core, and it
            <strong>fails closed</strong>: an unsupported or unparseable file is rejected outright —
            it is never passed through and presented as "cleaned".</p>
          </div>

          <section class="card">
            <div class="card-head"><h2>Scrub a file</h2><div class="spacer"></div>
              ${live
                ? UI.liveBadge("live · postern-hygiene — fails closed, unaudited")
                : UI.stubBadge("preview — JPEG scrub real · OOXML/PDF simulated report")}
            </div>
            <div class="dropzone" id="hy-drop" tabindex="0" role="button" aria-label="choose a file to scrub">
              <input type="file" id="hy-file" accept=".docx,.xlsx,.pptx,.odt,.ods,.odp,.pdf,.jpg,.jpeg">
              <strong>Drop a document or photo here</strong>
              <span>.docx · .xlsx · .pptx · ODF · .pdf · .jpg</span>
            </div>
            <div id="hy-report" class="hidden" style="margin-top:16px">
              <div class="card-head" style="margin-bottom:10px"><h2 id="hy-title">Report</h2><div class="spacer"></div><span id="hy-badge"></span></div>
              <div class="entry-list" id="hy-items"></div>
              <div class="actions">
                <button class="btn btn-primary hidden" id="hy-dl">Download cleaned file</button>
                <span class="result-line muted" id="hy-note"></span>
              </div>
            </div>
            <p class="result-line muted" id="hy-err" style="margin-top:8px"></p>
          </section>

          <section class="card">
            <div class="card-head"><h2>Prove / seal (opt-in)</h2><div class="spacer"></div>${UI.stubBadge("backend pending")}</div>
            <p class="note">After scrubbing, you can <em>opt in</em> to seal the clean file: SHAKE-256 digest signed with Falcon‖ML-DSA — a verifiable "this exact document, untampered" proof. Off by default: a provenance trail can de-anonymize.</p>
            <div class="actions">
              <button class="btn" disabled title="Requires the postern-hygiene seal backend command">◈ Seal cleaned document</button>
              <span class="muted">requires backend</span>
            </div>
          </section>

          ${UI.privacyCaveat()}
        </div>`;

      UI.wireDropzone(UI.qs("#hy-drop", root), UI.qs("#hy-file", root), async (file) => {
        const errEl = UI.qs("#hy-err", root);
        UI.setResult(errEl, "scrubbing…", "muted");
        try {
          const buf = new Uint8Array(await file.arrayBuffer());
          const rep = await api.invoke("hygiene_scrub", { name: file.name, bytesB64: UI.toB64(buf) });
          UI.setResult(errEl, "", "muted");

          UI.qs("#hy-report", root).classList.remove("hidden");
          UI.qs("#hy-title", root).textContent = `${file.name} — ${rep.kind.toUpperCase()}`;
          UI.qs("#hy-badge", root).innerHTML = rep.real
            ? `<span class="badge badge-ok">scrubbed locally — real</span>`
            : `<span class="badge badge-stub">SIMULATED REPORT — real scrub needs backend</span>`;

          const items = UI.qs("#hy-items", root);
          items.innerHTML = rep.removed.length ? "" : UI.emptyState("Nothing to remove — already clean.");
          for (const r of rep.removed) {
            const row = document.createElement("div");
            row.className = "entry";
            row.innerHTML = `<span class="e-name" style="width:auto;color:var(--crit)">✕</span>
              <span class="e-secret">${UI.esc(r)}</span>
              <span class="badge ${rep.real ? "badge-ok" : "badge-warn"}">${rep.real ? "removed" : "would remove"}</span>`;
            items.appendChild(row);
          }

          const dl = UI.qs("#hy-dl", root);
          if (rep.real && rep.cleanedB64) {
            dl.classList.remove("hidden");
            dl.onclick = () => UI.download(file.name.replace(/(\.\w+)$/, ".clean$1"), UI.fromB64(rep.cleanedB64), file.type || "image/jpeg");
          } else {
            dl.classList.add("hidden");
          }
          UI.qs("#hy-note", root).textContent = rep.note;
        } catch (e) {
          UI.setResult(errEl, `✖ ${e}`, "err");
          UI.qs("#hy-report", root).classList.add("hidden");
        }
      });
    },
  });
})();
