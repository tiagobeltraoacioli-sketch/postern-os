// modules/quarantine.js — Postern Quarantine: inbound-document safety.
// The MIRROR of Hygiene: Hygiene protects what you SEND, Quarantine protects
// what you RECEIVE. An untrusted file is neutralised by rebuilding it from its
// rendered content — images are decoded to raw pixels and re-encoded to a
// clean PNG; PDFs are rendered page-by-page (pure-Rust `hayro`) and rebuilt
// into a flat, metadata-free PDF. Backed by the REAL `quarantine_rebuild`
// Tauri command (postern-quarantine, desktop/src-tauri/src/quarantine.rs)
// whenever a backend is present — fails closed on office/unknown magic,
// UNAUDITED.
//
// Deliberately NO preview engine: a local browser stub that pretended to
// "sanitise" a file without the real pixel/render round-trip would be exactly
// the overclaim this repo bans (and worse for a SECURITY tool — a user would
// trust an un-neutralised file). So without a backend the pane renders the
// honest disabled state and every action refuses, rather than faking a clean
// file. The HONEST caveat rides on every surface: the PDF render runs
// IN-PROCESS with NO OS-level containment (no out-of-process sandbox, no
// Landlock/seccomp around the renderer, no wall-clock timeout); the image
// path's Landlock confinement is Linux-only and best-effort.
(function () {
  "use strict";
  const P = window.Postern, UI = P.ui, api = P.api;

  const NO_BACKEND_HINT = "Quarantine has no preview engine on purpose — a browser stub that pretended to sanitise a file without the real pixel/render round-trip would be an overclaim, and dangerous for a security tool. Connect the Tauri backend to rebuild a real, neutralised file.";
  const NO_BACKEND_MSG = "no backend — Quarantine never fakes a rebuild; this needs the Tauri backend";

  P.register({
    id: "quarantine",
    title: "Quarantine",
    desc: "Neutralise an untrusted inbound file by rebuilding it from pixels — macros, scripts, trackers and metadata never survive.",
    group: "Protect",
    order: 6,
    live: () => api.isReal("quarantine_rebuild"),
    icon: `<svg viewBox="0 0 24 24"><path d="M12 3l7 3v5c0 4.2-2.9 7.7-7 9-4.1-1.3-7-4.8-7-9V6z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M9 12l2 2 4-4" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>`,

    render(root) {
      const live = api.isReal("quarantine_rebuild");
      root.innerHTML = `
        <div class="stack">
          <div class="callout callout-brass">
            <strong>The file you receive is the attack.</strong> A booby-trapped PDF or image targets
            <em>your</em> viewer — a macro, a script, an exploit in the parser. Postern's rule for inbound
            files: <strong>rebuild from pixels</strong> — the original structure, and anything riding in it,
            never reaches your viewer. Images become a clean PNG; PDFs are rendered and re-emitted as a flat,
            metadata-free PDF. The text layer is <strong>destroyed by design</strong> (pixels only; OCR to
            recover text is lossy) — what is not carried over cannot carry a payload.
            ${live
              ? UI.liveBadge("live · postern-quarantine — in-process render, no OS containment, unaudited")
              : UI.stubBadge("no backend — Quarantine never fakes a rebuild")}
            <p class="note" style="margin:8px 0 0"><strong>UNAUDITED · NOT exploit-proof.</strong> This is
            <strong>NOT</strong> a sandbox. The PDF render runs <strong>IN-PROCESS</strong>, in this app's
            address space — the same attack surface as the image decode: pure Rust (which removes the classic
            C-parser memory-unsafety class, not logic bugs or resource exhaustion), but with
            <strong>no out-of-process containment, no Landlock/seccomp around the renderer, and no wall-clock
            timeout</strong>. The image path's Landlock confinement is <strong>Linux-only and best-effort</strong>
            (macOS/Windows are unsandboxed). It also <strong>fails closed</strong>: office documents
            (.docx/.xlsx/.pptx, legacy OLE2) are rejected here — that path would spawn a user-installed
            LibreOffice, which this app deliberately does not do — and an unsupported or unparseable file is
            never passed through and presented as "clean".</p>
          </div>

          <section class="card">
            <div class="card-head"><h2>Rebuild an inbound file</h2><div class="spacer"></div>
              ${live
                ? UI.liveBadge("live · postern-quarantine — fails closed, unaudited")
                : UI.stubBadge("no backend — needs the Tauri backend")}
            </div>
            ${live
              ? `<div class="dropzone" id="qz-drop" tabindex="0" role="button" aria-label="choose an inbound file to rebuild">
                   <input type="file" id="qz-file" accept=".png,.jpg,.jpeg,.pdf">
                   <strong>Drop an untrusted image or PDF here</strong>
                   <span>.png · .jpg · .pdf — rebuilt from pixels, downloaded clean</span>
                 </div>`
              : UI.emptyState("No backend — nothing is rebuilt here.", NO_BACKEND_HINT)}
            <div id="qz-report" class="hidden" style="margin-top:16px">
              <div class="card-head" style="margin-bottom:10px"><h2 id="qz-title">Report</h2><div class="spacer"></div><span id="qz-badge"></span></div>
              <div class="entry-list" id="qz-items"></div>
              <div class="actions">
                <button class="btn btn-primary hidden" id="qz-dl">Download rebuilt file</button>
                <span class="result-line muted" id="qz-note"></span>
              </div>
              <p class="note" id="qz-sandbox" style="margin:8px 0 0"></p>
            </div>
            <p class="result-line muted" id="qz-err" style="margin-top:8px"></p>
          </section>

          ${UI.privacyCaveat()}
        </div>`;

      if (!live) return; // no preview engine — honest disabled state, nothing wired

      UI.wireDropzone(UI.qs("#qz-drop", root), UI.qs("#qz-file", root), async (file) => {
        const errEl = UI.qs("#qz-err", root);
        UI.setResult(errEl, "rebuilding from pixels…", "muted");
        try {
          const buf = new Uint8Array(await file.arrayBuffer());
          const rep = await api.invoke("quarantine_rebuild", { name: file.name, bytesB64: UI.toB64(buf) });
          UI.setResult(errEl, "", "muted");

          const isImage = rep.kind === "image";
          const outExt = isImage ? ".png" : ".pdf";
          const outMime = isImage ? "image/png" : "application/pdf";

          UI.qs("#qz-report", root).classList.remove("hidden");
          UI.qs("#qz-title", root).textContent = `${file.name} — rebuilt as ${rep.kind.toUpperCase()}`;
          UI.qs("#qz-badge", root).innerHTML = rep.real
            ? `<span class="badge badge-ok">rebuilt locally — real</span>`
            : `<span class="badge badge-stub">SIMULATED — real rebuild needs backend</span>`;

          // The rebuild deliberately keeps only pixels; state plainly what was
          // destroyed rather than pretending to enumerate the removed payload.
          const items = UI.qs("#qz-items", root);
          items.innerHTML = "";
          const destroyed = isImage
            ? ["Original file container + all metadata (EXIF/XMP/ICC/…) — output is a fresh PNG from the pixels alone"]
            : ["Text layer, fonts, links, forms, actions", "/JavaScript, /OpenAction, /AA — scripts and auto-actions", "/EmbeddedFiles — attachments", "/Metadata, /Info, trailer /ID — document metadata", "All compression filters — streams are raw pixels"];
          for (const d of destroyed) {
            const row = document.createElement("div");
            row.className = "entry";
            row.innerHTML = `<span class="e-name" style="width:auto;color:var(--crit)">✕</span>
              <span class="e-secret">${UI.esc(d)}</span>
              <span class="badge badge-ok">destroyed</span>`;
            items.appendChild(row);
          }

          const dl = UI.qs("#qz-dl", root);
          if (rep.real && rep.cleanedB64) {
            dl.classList.remove("hidden");
            dl.onclick = () => UI.download(file.name.replace(/(\.\w+)$/, `.clean${outExt}`), UI.fromB64(rep.cleanedB64), outMime);
          } else {
            dl.classList.add("hidden");
          }
          UI.qs("#qz-note", root).textContent = rep.note;
          // Surface the REAL sandbox status verbatim — Landlock story for the
          // image path, honest "no OS-level containment" for the PDF path.
          UI.qs("#qz-sandbox", root).textContent = `Containment: ${rep.sandbox}`;
        } catch (e) {
          UI.setResult(errEl, `✖ ${e}`, "err");
          UI.qs("#qz-report", root).classList.add("hidden");
        }
      });
    },
  });
})();
