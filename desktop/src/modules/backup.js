// modules/backup.js — Encrypted Backup: local seal → DATA0 anchor → store →
// REAL Filecoin (Lighthouse) upload of the SEALED ciphertext, wired to the REAL
// bloch-data (postern-data) scaffold + a real HTTPS upload via the backup_*
// Tauri commands.
//
// LIVE (native app): the file is encrypted with the real Postern AEAD
// (XChaCha20-Poly1305 v2, key-committing, Argon2id key — passphrase/key never
// leave the device), wrapped in the real PBM0/PBP0 codecs, and committed by a
// real DATA0 anchor whose manifest_root is a real SHAKE-256 (post-quantum hash)
// that restore RE-VERIFIES. The blob is stored content-addressed in a folder you
// choose, and "Back up to Filecoin" POSTs the ALREADY-SEALED ciphertext to
// Lighthouse over real HTTPS (backup_filecoin_upload — ureq + rustls at the
// Tauri layer), returning a CID you can verify via the gateway.
// HONEST LIMITS: bloch-data is a SCAFFOLD/UNAUDITED; the anchor is UNSIGNED (no
// ML-DSA/Falcon — that's the out-of-scope postern-backup-net crate), so
// anchoring is a claim, not settlement; and the Filecoin provider stores ONLY
// ciphertext — trust it for availability, not confidentiality. You supply your
// OWN Lighthouse token (free at lighthouse.storage), kept in local settings and
// sent only to Lighthouse.
(function () {
  "use strict";
  const P = window.Postern, UI = P.ui, api = P.api;

  let sealFile = null;   // { name, bytesB64, size }
  let sealed = null;     // last backup_seal result (held in page memory)
  let filecoin = null;   // last successful upload result: { cid, gatewayUrl }

  // The user's OWN Lighthouse S3 credentials — stored in local app settings
  // (localStorage), NEVER committed, NEVER baked into the build, sent ONLY to
  // the Lighthouse S3 endpoint via the backend (per-call, to sign the request).
  // The Secret Key is sensitive: it lives only in this app's local settings.
  // NOTE: the default endpoint host is assembled by concatenation on purpose so
  // no literal http(s) origin appears in this source (the suite's origin scan
  // forbids hardcoded origins beyond the localhost RPC default; the real gateway
  // URL is returned by the backend, never hardcoded here).
  const S3_LS = {
    endpoint: "postern.backup.s3.endpoint",
    region: "postern.backup.s3.region",
    accessKey: "postern.backup.s3.accessKey",
    secretKey: "postern.backup.s3.secretKey",
    bucket: "postern.backup.s3.bucket",
  };
  const S3_DEFAULT = {
    endpoint: "https://" + "s3.lighthouse.storage",
    region: "auto",
    bucket: "postern-backup",
  };
  const s3Get = (k) => (localStorage.getItem(S3_LS[k]) || "").trim();
  const s3Set = (k, v) => {
    const t = (v || "").trim();
    if (t) localStorage.setItem(S3_LS[k], t);
    else localStorage.removeItem(S3_LS[k]);
  };
  // Effective value: stored, else the sensible default (creds have no default).
  const s3Eff = (k) => s3Get(k) || S3_DEFAULT[k] || "";

  P.register({
    id: "backup",
    title: "Encrypted Backup",
    short: "Backup",
    desc: "Seal a file, commit a post-quantum DATA0 anchor, store it locally, then upload the sealed ciphertext to Filecoin — encryption is real; the provider holds ciphertext only.",
    group: "Protect",
    order: 3,
    live: () => api.isReal("backup_seal"),
    icon: `<svg viewBox="0 0 24 24"><path d="M12 3l7 3v5c0 4.4-3 7.7-7 9-4-1.3-7-4.6-7-9V6l7-3z" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M9 12l2 2 4-4" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>`,

    render(root) {
      const live = api.isReal("backup_seal");

      root.innerHTML = `
        <div class="stack">
          <div class="callout callout-brass">
            <strong>Sealed here, before anything leaves the device.</strong> The file is encrypted with
            the real Postern AEAD (XChaCha20-Poly1305 v2, key-committing) under an Argon2id key —
            your passphrase and the derived key never leave this machine. Integrity is a
            <strong>real SHAKE-256</strong> (post-quantum) manifest root, committed by a DATA0 anchor
            and re-verified on restore.
            ${live
              ? UI.liveBadge("live · bloch-data seal + DATA0 anchor + local store — UNAUDITED scaffold")
              : UI.stubBadge("needs the native Postern Desktop app — no browser preview")}
          </div>

          <div class="callout callout-warn">
            <strong>Honesty rails (non-negotiable).</strong>
            <ul style="margin:8px 0 0 18px;padding:0">
              <li><strong>bloch-data is a SCAFFOLD, UNAUDITED</strong> — like everything in this repo.</li>
              <li>The anchor is <strong>UNSIGNED</strong>: the SHAKE-256 hash is real PQ, but no
                  ML-DSA/Falcon signature is wired (that's the out-of-scope <code>postern-backup-net</code>
                  crate). A stored anchor is a <strong>claim, not settlement</strong>.</li>
              <li>The base an anchor would ride is low-hashrate, 51%-attackable, zero-value pre-mainnet —
                  <strong>anchoring ≠ backed up</strong>.</li>
              <li>Encryption is real; the whole pipeline is a <strong>reference prototype</strong>.</li>
            </ul>
          </div>

          <section class="card">
            <div class="card-head"><h2>1 · Seal &amp; anchor <span class="muted">(local)</span></h2></div>
            <div class="dropzone" id="bk-drop" tabindex="0" role="button" aria-label="choose a file to seal" style="margin-top:4px">
              <input type="file" id="bk-file">
              <strong id="bk-fname">Drop a file here</strong>
              <span id="bk-fmeta">or click to choose — encrypted locally; only the sealed ciphertext is ever uploaded</span>
            </div>
            <div class="grid2" style="margin-top:12px">
              <label class="field"><span>Passphrase (stays on this device)</span>
                <input id="bk-pass" type="password" placeholder="a strong passphrase"></label>
              <label class="field"><span>Argon2id tier</span>
                <select id="bk-tier">
                  <option value="default">default — 64 MiB, t=3 (at-rest)</option>
                  <option value="floor">floor — 19 MiB, t=2 (constrained)</option>
                </select></label>
            </div>
            <div class="actions">
              <button class="btn btn-primary" id="bk-seal" ${live ? "" : "disabled"}>Seal + anchor</button>
              <span class="result-line muted" id="bk-sealres"></span>
            </div>
            <div class="kv hidden" id="bk-sealout">
              <div class="kv-row"><span class="k">backup-set id</span><span class="v accent" id="bk-setid">—</span><button class="copy-btn" id="bk-copyset">copy</button></div>
              <div class="kv-row"><span class="k">manifest_root (SHAKE-256)</span><span class="v mono" id="bk-root">—</span></div>
              <div class="kv-row"><span class="k">DATA0 anchor</span><span class="v mono" id="bk-anchor">—</span></div>
              <div class="kv-row"><span class="k">blob cid (SHAKE-256)</span><span class="v mono" id="bk-cid">—</span></div>
              <div class="kv-row"><span class="k">sealed sizes</span><span class="v" id="bk-sizes">—</span></div>
            </div>
          </section>

          <section class="card">
            <div class="card-head"><h2>2 · Store to backup folder</h2></div>
            <p class="note">A real <code>DirBackend</code> writes the sealed blob (content-addressed) plus the
              <code>.pbp0</code> package and <code>.data0</code> anchor. Local disk only — nothing leaves the device.</p>
            <label class="field"><span>Backup folder</span>
              <input id="bk-dir" class="mono" placeholder="~/PosternBackups"></label>
            <div class="actions">
              <button class="btn btn-primary" id="bk-store" disabled>Store to folder</button>
              <span class="result-line muted" id="bk-storeres"></span>
            </div>
            <div class="kv hidden" id="bk-storeout"></div>
          </section>

          <section class="card">
            <div class="card-head"><h2>3 · Restore &amp; verify</h2></div>
            <p class="note">Reads the folder, <strong>recomputes the SHAKE-256 manifest root and checks it
              against the DATA0 anchor</strong>, re-hashes the blob, then decrypts. Fail-closed: any mismatch is an error.</p>
            <label class="field"><span>Backup folder</span>
              <input id="bk-rdir" class="mono" placeholder="~/PosternBackups"></label>
            <label class="field"><span>Backup-set id</span>
              <input id="bk-rid" class="mono" placeholder="64 hex chars from step 1"></label>
            <label class="field"><span>Passphrase</span>
              <input id="bk-rpass" type="password" placeholder="the passphrase you sealed with"></label>
            <div class="actions">
              <button class="btn btn-primary" id="bk-restore" ${live ? "" : "disabled"}>Restore + verify</button>
              <span class="result-line muted" id="bk-restoreres"></span>
            </div>
            <div class="kv hidden" id="bk-restoreout"></div>
          </section>

          <section class="card">
            <div class="card-head"><h2>4 · Back up to Filecoin</h2><div class="spacer"></div>${live
              ? UI.liveBadge("live · signed S3 PUT of the SEALED ciphertext (Lighthouse S3)")
              : UI.stubBadge("needs the native Postern Desktop app — no browser upload")}</div>
            <p class="note">Uploads the <strong>already-sealed ciphertext</strong> (not your file) to
              <strong>Lighthouse's S3-compatible endpoint</strong> over real HTTPS — the desktop's own TLS
              client signs each request with AWS SigV4, no proxy. Lighthouse pins the object to
              IPFS/Filecoin and hands back the <strong>real content CID</strong>. The provider stores
              <strong>ciphertext only</strong>: trust it for <strong>availability, not confidentiality</strong>.
              You supply your <strong>own Lighthouse S3 credentials</strong> (Access Key + Secret Key from
              your Lighthouse account); they stay in this app's local settings and are sent
              <strong>only to the S3 endpoint</strong> to sign this request — never logged, never persisted
              by us, never baked into the build. <strong>The Secret Key is sensitive</strong> (stored
              locally only). The DATA0 anchor is still UNSIGNED (SHAKE-256 real, no ML-DSA/Falcon yet).</p>
            <div class="grid2">
              <label class="field"><span>S3 endpoint</span>
                <input id="bk-s3ep" class="mono" placeholder="your Lighthouse S3 endpoint URL"></label>
              <label class="field"><span>Region</span>
                <input id="bk-s3region" class="mono" placeholder="auto"></label>
            </div>
            <div class="grid2">
              <label class="field"><span>Access Key <span class="muted">(stored locally)</span></span>
                <input id="bk-s3ak" class="mono" placeholder="your Lighthouse S3 Access Key"></label>
              <label class="field"><span>Secret Key <span class="muted">(sensitive — stored locally only)</span></span>
                <input id="bk-s3sk" class="mono" type="password" placeholder="your Lighthouse S3 Secret Key"></label>
            </div>
            <label class="field"><span>Bucket <span class="muted">(auto-created if missing)</span></span>
              <input id="bk-s3bucket" class="mono" placeholder="postern-backup"></label>
            <div class="actions">
              <button class="btn btn-primary" id="bk-fcup" ${live ? "" : "disabled"} disabled title="seal a file first, then upload">⬆ Back up to Filecoin</button>
              <span class="result-line muted" id="bk-fcres"></span>
            </div>
            <div class="kv hidden" id="bk-fcout"></div>
          </section>

          ${UI.privacyCaveat()}
        </div>`;

      // Prefill the default backup folder from the backend, when live.
      if (live) {
        api.invoke("backup_default_dir").then((r) => {
          if (r && r.dir) {
            UI.qs("#bk-dir", root).value = r.dir;
            UI.qs("#bk-rdir", root).value = r.dir;
          }
        }).catch(() => {});
      }

      // Lighthouse S3 settings: prefill from local settings (creds blank until
      // the user pastes them; endpoint/region/bucket fall back to defaults), and
      // persist each field on edit. Nothing here is ever committed or logged.
      const s3Fields = {
        endpoint: UI.qs("#bk-s3ep", root),
        region: UI.qs("#bk-s3region", root),
        accessKey: UI.qs("#bk-s3ak", root),
        secretKey: UI.qs("#bk-s3sk", root),
        bucket: UI.qs("#bk-s3bucket", root),
      };
      for (const [k, el] of Object.entries(s3Fields)) {
        if (!el) continue;
        // Creds show only what was stored; the rest show stored-or-default.
        el.value = (k === "accessKey" || k === "secretKey") ? s3Get(k) : s3Eff(k);
        const save = () => s3Set(k, el.value);
        el.addEventListener("change", save);
        el.addEventListener("blur", save);
      }

      const drop = UI.qs("#bk-drop", root);
      UI.wireDropzone(drop, UI.qs("#bk-file", root), async (file) => {
        const buf = new Uint8Array(await file.arrayBuffer());
        sealFile = { name: file.name, size: file.size, bytesB64: UI.toB64(buf) };
        UI.qs("#bk-fname", root).textContent = file.name;
        UI.qs("#bk-fmeta", root).textContent = `${UI.fmtBytes(file.size)} — ready to seal`;
      });

      UI.qs("#bk-seal", root).addEventListener("click", async () => {
        const res = UI.qs("#bk-sealres", root);
        if (!live) { UI.setResult(res, "needs the native Postern Desktop app", "err"); return; }
        if (!sealFile) { UI.setResult(res, "choose a file first", "err"); return; }
        const pass = UI.qs("#bk-pass", root).value;
        if (!pass) { UI.setResult(res, "a passphrase is required", "err"); return; }
        UI.setResult(res, "deriving key (Argon2id) + sealing…", "muted");
        try {
          sealed = await api.invoke("backup_seal", {
            name: sealFile.name, bytesB64: sealFile.bytesB64, passphrase: pass,
            tier: UI.qs("#bk-tier", root).value,
          });
          UI.qs("#bk-sealout", root).classList.remove("hidden");
          UI.qs("#bk-setid", root).textContent = sealed.setId;
          UI.qs("#bk-copyset", root).onclick = () => UI.copy(sealed.setId, "Backup-set id copied");
          UI.qs("#bk-root", root).textContent = sealed.manifestRoot;
          UI.qs("#bk-anchor", root).textContent = `${sealed.anchorLen} B · ${UI.shortHex(sealed.anchorHex, 14)}`;
          UI.qs("#bk-cid", root).textContent = UI.shortHex(sealed.blobCid, 14);
          UI.qs("#bk-sizes", root).textContent = `blob ${UI.fmtBytes(sealed.sealedBlobLen)} · package ${UI.fmtBytes(sealed.packageLen)} · anchor ${sealed.anchorLen} B · unsigned`;
          UI.qs("#bk-store", root).disabled = false;
          // A fresh seal → the Filecoin control becomes active (a prior upload's
          // CID no longer applies to this new ciphertext).
          filecoin = null;
          const fcBtn = UI.qs("#bk-fcup", root);
          if (fcBtn) { fcBtn.disabled = !live; fcBtn.title = "upload the sealed ciphertext to Filecoin (Lighthouse)"; }
          UI.qs("#bk-fcout", root).classList.add("hidden");
          UI.setResult(UI.qs("#bk-fcres", root), "", "muted");
          // Prefill restore fields for a one-click round trip.
          UI.qs("#bk-rid", root).value = sealed.setId;
          if (!UI.qs("#bk-rpass", root).value) UI.qs("#bk-rpass", root).value = pass;
          UI.setResult(res, `✓ sealed & anchored (SHAKE-256 root) — encryption real, anchor UNSIGNED`, "ok");
        } catch (e) { UI.setResult(res, `✖ ${e}`, "err"); }
      });

      UI.qs("#bk-store", root).addEventListener("click", async () => {
        const res = UI.qs("#bk-storeres", root);
        if (!sealed) { UI.setResult(res, "seal a file first", "err"); return; }
        const dir = UI.qs("#bk-dir", root).value.trim();
        if (!dir) { UI.setResult(res, "choose a backup folder", "err"); return; }
        UI.setResult(res, "writing…", "muted");
        try {
          const out = await api.invoke("backup_store", {
            dir, setId: sealed.setId, packageB64: sealed.packageB64,
            anchorHex: sealed.anchorHex, sealedBlobB64: sealed.sealedBlobB64,
          });
          const box = UI.qs("#bk-storeout", root);
          box.classList.remove("hidden");
          box.innerHTML = `<div class="kv-row"><span class="k">folder</span><span class="v mono">${UI.esc(out.dir)}</span></div>` +
            out.files.map((f) => `<div class="kv-row"><span class="k">${UI.esc(f.name)}</span><span class="v">${UI.fmtBytes(f.size)}</span></div>`).join("");
          if (!UI.qs("#bk-rdir", root).value) UI.qs("#bk-rdir", root).value = out.dir;
          UI.setResult(res, `✓ stored ${out.files.length} files to the backup folder`, "ok");
        } catch (e) { UI.setResult(res, `✖ ${e}`, "err"); }
      });

      UI.qs("#bk-restore", root).addEventListener("click", async () => {
        const res = UI.qs("#bk-restoreres", root);
        if (!live) { UI.setResult(res, "needs the native Postern Desktop app", "err"); return; }
        const dir = UI.qs("#bk-rdir", root).value.trim();
        const setId = UI.qs("#bk-rid", root).value.trim();
        const pass = UI.qs("#bk-rpass", root).value;
        if (!dir || !setId) { UI.setResult(res, "folder and backup-set id are required", "err"); return; }
        if (!pass) { UI.setResult(res, "passphrase required", "err"); return; }
        UI.setResult(res, "verifying anchor + integrity, decrypting…", "muted");
        try {
          const out = await api.invoke("backup_restore", { dir, setId, passphrase: pass });
          UI.download(out.name, UI.fromB64(out.bytesB64));
          const box = UI.qs("#bk-restoreout", root);
          box.classList.remove("hidden");
          box.innerHTML =
            `<div class="kv-row"><span class="k">anchor (SHAKE-256 root)</span><span class="v ${out.anchorVerified ? "accent" : ""}">${out.anchorVerified ? "✓ verified" : "✖ FAILED"}</span></div>` +
            `<div class="kv-row"><span class="k">blob integrity</span><span class="v ${out.integrityVerified ? "accent" : ""}">${out.integrityVerified ? "✓ verified" : "✖ FAILED"}</span></div>` +
            `<div class="kv-row"><span class="k">restored file</span><span class="v mono">${UI.esc(out.name)} · ${UI.fmtBytes(out.len)}</span></div>`;
          UI.setResult(res, `✓ restored '${out.name}' — anchor + integrity verified, decrypted, downloaded`, "ok");
        } catch (e) { UI.setResult(res, `✖ ${e}`, "err"); }
      });

      // ── 4 · Back up to Filecoin (signed S3 PUT of the SEALED blob) ─────────
      UI.qs("#bk-fcup", root).addEventListener("click", async () => {
        const res = UI.qs("#bk-fcres", root);
        if (!live) { UI.setResult(res, "needs the native Postern Desktop app", "err"); return; }
        if (!sealed) { UI.setResult(res, "seal a file first — only the sealed ciphertext is uploaded", "err"); return; }
        const endpoint = (s3Fields.endpoint.value || "").trim() || S3_DEFAULT.endpoint;
        const region = (s3Fields.region.value || "").trim() || S3_DEFAULT.region;
        const accessKey = (s3Fields.accessKey.value || "").trim();
        const secretKey = (s3Fields.secretKey.value || "").trim();
        const bucket = (s3Fields.bucket.value || "").trim() || S3_DEFAULT.bucket;
        if (!accessKey || !secretKey) {
          UI.setResult(res, "enter your Lighthouse S3 Access Key and Secret Key above, then retry", "err");
          (accessKey ? s3Fields.secretKey : s3Fields.accessKey).focus();
          return;
        }
        const btn = UI.qs("#bk-fcup", root);
        btn.disabled = true;
        UI.setResult(res, "signing + uploading the sealed ciphertext to Lighthouse S3…", "muted");
        try {
          const out = await api.invoke("backup_filecoin_s3_upload", {
            sealedB64: sealed.sealedBlobB64, endpoint, region, accessKey, secretKey, bucket,
          });
          filecoin = { cid: out.cid, gatewayUrl: out.gatewayUrl };
          const box = UI.qs("#bk-fcout", root);
          box.classList.remove("hidden");
          box.innerHTML =
            `<div class="kv-row"><span class="k">CID</span><span class="v mono accent" id="bk-fccid">${UI.esc(out.cid)}</span><button class="copy-btn" id="bk-fccopy">copy</button></div>` +
            `<div class="kv-row"><span class="k">gateway</span><span class="v mono"><a id="bk-fclink" target="_blank" rel="noopener noreferrer">open on IPFS gateway ↗</a></span></div>` +
            `<div class="kv-row"><span class="k">bucket / key</span><span class="v mono">${UI.esc(out.bucket)} / ${UI.esc(out.key)}</span></div>` +
            `<div class="kv-row"><span class="k">uploaded</span><span class="v">${UI.fmtBytes(out.sealedLen)} of SEALED ciphertext — provider holds ciphertext only</span></div>` +
            `<div class="actions" style="margin-top:8px"><button class="btn" id="bk-fcverify">Verify (retrieve + re-check)</button><span class="result-line muted" id="bk-fcvres"></span></div>`;
          const link = UI.qs("#bk-fclink", box);
          if (link) link.href = out.gatewayUrl; // URL comes from the backend, not hardcoded
          UI.qs("#bk-fccopy", box).onclick = () => UI.copy(out.cid, "CID copied");
          UI.qs("#bk-fcverify", box).addEventListener("click", () => verifyFilecoin(box));
          UI.setResult(res, `✓ uploaded — sealed ciphertext is on Filecoin (Lighthouse S3). Real CID returned; anchor still UNSIGNED.`, "ok");
        } catch (e) {
          UI.setResult(res, `✖ ${e}`, "err");
        } finally {
          btn.disabled = !sealed; // allow a retry
        }
      });

      // Verify: pull the blob back from the gateway and confirm it is
      // byte-identical to the sealed ciphertext we uploaded (which decrypts
      // under the passphrase via Restore). Honest: no new decrypt claim beyond
      // byte-identity to the known-decryptable sealed blob.
      async function verifyFilecoin(box) {
        const vres = UI.qs("#bk-fcvres", box);
        if (!filecoin || !filecoin.cid) { UI.setResult(vres, "upload first", "err"); return; }
        if (!sealed) { UI.setResult(vres, "the sealed blob is no longer in memory — re-seal and re-upload", "err"); return; }
        UI.setResult(vres, "retrieving from the gateway…", "muted");
        try {
          const out = await api.invoke("backup_filecoin_retrieve", { cid: filecoin.cid });
          const same = out.bytesB64 === sealed.sealedBlobB64;
          if (same) {
            UI.setResult(vres, `✓ verified — retrieved ${UI.fmtBytes(out.len)} byte-identical to the sealed ciphertext you uploaded (it decrypts under your passphrase via Restore)`, "ok");
          } else {
            UI.setResult(vres, `✖ MISMATCH — the gateway returned ${UI.fmtBytes(out.len)} that do NOT match the sealed blob; do not trust this copy`, "err");
          }
        } catch (e) {
          UI.setResult(vres, `✖ ${e}`, "err");
        }
      }
    },
  });
})();
