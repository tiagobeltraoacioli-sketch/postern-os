// modules/wallet.js — Postern Wallet: post-quantum hybrid wallet (Falcon‖ML-DSA),
// diversified addresses, send/sign. Wired to REAL Tauri commands:
// wallet_generate / wallet_from_mnemonic / wallet_address_at / wallet_send / rpc.
(function () {
  "use strict";
  const P = window.Postern, UI = P.ui, api = P.api;

  // The active wallet's mnemonic — kept in memory only, never persisted.
  let mnemonic = null;
  let rotIndex = 0;
  // An imported bloch-cli SIMPLE keystore: { json, password, address }. Kept in
  // memory only (the json is the user's own ciphertext; the password stays here
  // just for the session so re-signing a send doesn't re-prompt). A simple
  // keystore is a raw keypair with NO seed, so diversified-address rotation is
  // unavailable — spend goes through wallet_keystore_send, not wallet_send.
  let imported = null;

  P.register({
    id: "wallet",
    title: "Wallet",
    desc: "Post-quantum hybrid wallet — generate, receive on diversified addresses, send. Zero-value testnet.",
    group: "Advanced · testnet (zero value)",
    order: 2,
    live: () => api.isReal("wallet_generate"),
    icon: `<svg viewBox="0 0 24 24"><rect x="3" y="6" width="18" height="13" rx="2" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M3 9.5h18" stroke="currentColor" stroke-width="1.6"/><circle cx="17" cy="14.5" r="1.2" fill="currentColor"/></svg>`,

    render(root) {
      const live = api.isReal("wallet_generate");
      const s = P.state.settings;
      root.innerHTML = `
        <div class="stack">
          <div class="callout callout-warn">
            <strong>Zero-value testnet.</strong> This wallet operates on a pre-mainnet,
            <strong>unaudited</strong> prototype network — coins have <strong>no value</strong> and
            can vanish in a chain reset. Do not treat anything here as money.
          </div>
          <div class="grid2">
            <section class="card">
              <div class="card-head"><h2>Keys</h2><div class="spacer"></div>
                ${live ? UI.liveBadge("live · walletcore") : UI.stubBadge("preview — simulated derivation")}
              </div>
              <div class="actions">
                <button class="btn btn-primary" id="wl-gen">Generate new wallet</button>
                <label class="check"><input id="wl-testnet" type="checkbox" ${s.testnet ? "checked" : ""}> testnet</label>
              </div>
              <div class="kv" style="margin-top:12px">
                <div class="kv-row"><span class="k">address</span><span class="v accent" id="wl-addr">—</span><button class="copy-btn" id="wl-copyaddr">copy</button></div>
                <div class="kv-row"><span class="k">pubkey</span><span class="v" id="wl-pub">—</span></div>
              </div>
              <div class="mnemonic hidden" id="wl-mnbox">
                <strong>⚠ Write this seed down — shown once, kept only in memory.</strong>
                <code id="wl-mn"></code>
              </div>
              <details style="margin-top:12px">
                <summary class="muted" style="cursor:pointer">Restore from a seed phrase</summary>
                <label class="field" style="margin-top:10px"><span>Seed phrase</span>
                  <textarea id="wl-restore" rows="2" placeholder="word1 word2 …"></textarea></label>
                <div class="actions"><button class="btn" id="wl-dorestore">Restore</button></div>
              </details>
              <details style="margin-top:12px" id="wl-import-details">
                <summary class="muted" style="cursor:pointer">Import a bloch-cli <code>wallet.json</code></summary>
                <p class="note" style="margin-top:8px">Reads the protocol CLI's own encrypted keystore
                  (<code>bloch-cli newwallet</code> = <em>simple</em>, or <code>newseed</code> = <em>HD</em>).
                  Decryption + the address round-trip run through the <code>bloch</code> crate itself, so a
                  successful import means the recovered address is byte-identical to what the CLI wrote.
                  Your keystore file and password never leave this machine.</p>
                <div class="actions" style="margin-top:6px">
                  <label class="check"><input type="radio" name="wl-imp-kind" id="wl-imp-simple" checked> simple</label>
                  <label class="check"><input type="radio" name="wl-imp-kind" id="wl-imp-hd"> HD (24-word)</label>
                </div>
                <label class="field" style="margin-top:8px"><span>wallet.json file</span>
                  <input id="wl-imp-file" type="file" accept=".json,application/json"></label>
                <label class="field" style="margin-top:8px"><span>Keystore password</span>
                  <input id="wl-imp-pass" type="password" autocomplete="off"></label>
                <div id="wl-imp-hdonly" class="hidden">
                  <label class="field" style="margin-top:8px"><span>24-word mnemonic (HD only)</span>
                    <textarea id="wl-imp-mn" rows="2" placeholder="word1 word2 …"></textarea></label>
                  <label class="field" style="margin-top:8px"><span>BIP39 passphrase (HD, optional)</span>
                    <input id="wl-imp-pp" type="password" autocomplete="off"></label>
                </div>
                <div class="actions" style="margin-top:8px"><button class="btn" id="wl-imp-go">Import &amp; verify</button></div>
                <div class="entry-list hidden" id="wl-imp-hdlist" style="margin-top:8px"></div>
                <p class="result-line muted" id="wl-imp-res"></p>
              </details>
              <p class="result-line muted" id="wl-keyerr"></p>
            </section>

            <section class="card">
              <div class="card-head"><h2>Receive</h2><div class="spacer"></div>
                <span class="badge badge-brass">P4 · never reuse addresses</span>
              </div>
              <p class="note">Each receive gets a fresh, unlinkable diversified address derived from the same seed. Rotate one per payment.</p>
              <div class="actions">
                <button class="btn" id="wl-rotate">＋ New receiving address</button>
                <span class="mono muted" id="wl-rotidx"></span>
              </div>
              <div class="kv-row" style="margin-top:8px">
                <span class="v accent" id="wl-rotaddr" style="flex:1">—</span>
                <button class="copy-btn" id="wl-copyrot">copy</button>
              </div>
              <div class="actions" style="margin-top:16px">
                <button class="btn" id="wl-balance">↻ Refresh balance</button>
                <b class="mono" id="wl-bal" style="font-size:17px;color:var(--brass)">—</b>
                <span class="muted">sats</span>
              </div>
              <p class="result-line muted" id="wl-balerr"></p>
              <p class="note muted" id="wl-trust" style="margin-top:6px"></p>
            </section>
          </div>

          <section class="card">
            <div class="card-head"><h2>Send</h2><div class="spacer"></div>
              ${api.isReal("wallet_send") && api.isReal("rpc") ? UI.liveBadge("live · signed on-device") : UI.stubBadge("preview")}
            </div>
            <div class="field-row">
              <label class="field" style="grid-column:span 2"><span>Destination</span>
                <input id="wl-to" class="mono" placeholder="bloch1…"></label>
              <label class="field"><span>Amount (sats)</span><input id="wl-amount" type="number" min="1"></label>
              <label class="field"><span>Fee</span>
                <select id="wl-fee">
                  <option value="medium">medium</option>
                  <option value="next">next block</option>
                  <option value="slow">slow</option>
                </select></label>
            </div>
            <div class="actions">
              <button class="btn btn-primary" id="wl-send">Sign &amp; send</button>
              <span class="result-line muted" id="wl-sendres"></span>
            </div>
            <p class="note">Built, signed (Falcon‖ML-DSA hybrid) and broadcast from this device via the node's RPC — keys never leave the machine.</p>
          </section>

          ${UI.privacyCaveat()}
        </div>`;

      const err = (id, msg) => UI.setResult(UI.qs("#" + id, root), msg || "", msg ? "err" : "muted");
      // Show which node this wallet trusts for reads + broadcast (keys stay local).
      const trustEl = UI.qs("#wl-trust", root);
      if (trustEl) trustEl.textContent = `Connected via: ${P.rpcTrustLabel()} · change in Node → Connection.`;
      const testnet = () => UI.qs("#wl-testnet", root).checked;
      UI.qs("#wl-testnet", root).addEventListener("change", () => {
        P.state.settings.testnet = testnet(); P.saveSettings();
      });

      const showWallet = (w) => {
        UI.qs("#wl-addr", root).textContent = w.address;
        UI.qs("#wl-pub", root).textContent = UI.shortHex(w.pubkey, 16);
        UI.qs("#wl-pub", root).title = w.pubkey;
        rotIndex = 0;
        UI.qs("#wl-rotaddr", root).textContent = "—";
        UI.qs("#wl-rotidx", root).textContent = "";
      };

      // A seed-phrase wallet (generate/restore) and an imported simple keystore
      // are mutually exclusive as the "active" spender — loading one clears the
      // other so the send path is never ambiguous.
      const useMnemonicWallet = (w) => { imported = null; showWallet(w); };

      UI.qs("#wl-gen", root).addEventListener("click", async () => {
        err("wl-keyerr");
        try {
          const w = await api.invoke("wallet_generate", { testnet: testnet() });
          mnemonic = w.mnemonic;
          useMnemonicWallet(w);
          UI.qs("#wl-mn", root).textContent = w.mnemonic;
          UI.qs("#wl-mnbox", root).classList.remove("hidden");
        } catch (e) { err("wl-keyerr", `${e}`); }
      });

      UI.qs("#wl-dorestore", root).addEventListener("click", async () => {
        err("wl-keyerr");
        const phrase = UI.qs("#wl-restore", root).value.trim();
        try {
          const w = await api.invoke("wallet_from_mnemonic", { phrase, testnet: testnet() });
          mnemonic = phrase;
          useMnemonicWallet(w);
          UI.qs("#wl-mnbox", root).classList.add("hidden");
          UI.qs("#wl-restore", root).value = "";
          UI.toast("Wallet restored", "ok");
        } catch (e) { err("wl-keyerr", `${e}`); }
      });

      // ── Import a bloch-cli wallet.json ────────────────────────────────
      const impRes = UI.qs("#wl-imp-res", root);
      const isHd = () => UI.qs("#wl-imp-hd", root).checked;
      const toggleHd = () => UI.qs("#wl-imp-hdonly", root).classList.toggle("hidden", !isHd());
      UI.qs("#wl-imp-simple", root).addEventListener("change", toggleHd);
      UI.qs("#wl-imp-hd", root).addEventListener("change", toggleHd);

      const readFileText = (input) => new Promise((resolve, reject) => {
        const f = input.files && input.files[0];
        if (!f) { reject(new Error("choose a wallet.json file first")); return; }
        const r = new FileReader();
        r.onload = () => resolve(String(r.result || ""));
        r.onerror = () => reject(new Error("could not read the selected file"));
        r.readAsText(f);
      });

      UI.qs("#wl-imp-go", root).addEventListener("click", async () => {
        const btn = UI.qs("#wl-imp-go", root);
        const hdList = UI.qs("#wl-imp-hdlist", root);
        hdList.classList.add("hidden");
        hdList.innerHTML = "";
        UI.setResult(impRes, "reading + decrypting keystore…", "muted");
        btn.disabled = true;
        try {
          const json = await readFileText(UI.qs("#wl-imp-file", root));
          const password = UI.qs("#wl-imp-pass", root).value;
          if (!password) throw new Error("keystore password required");
          if (isHd()) {
            const phrase = UI.qs("#wl-imp-mn", root).value.trim();
            const passphrase = UI.qs("#wl-imp-pp", root).value;
            if (!phrase) throw new Error("HD wallets need their 24-word mnemonic to open");
            const r = await api.invoke("wallet_import_hd", { json, mnemonic: phrase, passphrase, password });
            // HD import is view/verify/receive only. Show the first address as the
            // active receive address; spend an HD wallet by restoring its mnemonic
            // in the seed-phrase flow above.
            imported = null;
            mnemonic = null;
            const first = r.addresses[0];
            UI.qs("#wl-addr", root).textContent = first ? first.address : "—";
            UI.qs("#wl-pub", root).textContent = "—";
            rotIndex = 0;
            UI.qs("#wl-rotaddr", root).textContent = "—";
            UI.qs("#wl-rotidx", root).textContent = "";
            hdList.classList.remove("hidden");
            hdList.innerHTML = r.addresses.map((a) =>
              `<div class="entry"><span class="e-name mono">#${a.index}</span>` +
              `<span class="v accent" style="flex:1">${UI.esc(a.address)}</span>` +
              `<span class="muted">${UI.esc(a.label || "")}</span></div>`).join("");
            UI.setResult(impRes, `✓ HD wallet imported & verified — ${r.addresses.length} address(es), ${r.network}. Round-trip OK. To spend, restore the 24-word seed above.`, "ok");
            UI.toast("HD wallet.json imported (verified)", "ok");
          } else {
            const r = await api.invoke("wallet_import_keystore", { json, password });
            imported = { json, password, address: r.address };
            mnemonic = null;
            showWallet({ address: r.address, pubkey: r.pubkey });
            UI.setResult(impRes, `✓ simple keystore imported & verified — ${r.network}. Round-trip OK. You can receive and send from this address.`, "ok");
            UI.toast("Keystore imported (verified) — spendable", "ok");
          }
        } catch (e) {
          UI.setResult(impRes, `✖ ${e.message || e}`, "err");
        }
        btn.disabled = false;
      });

      UI.qs("#wl-copyaddr", root).addEventListener("click", () => {
        const a = UI.qs("#wl-addr", root).textContent;
        if (a !== "—") UI.copy(a, "Address copied");
      });
      UI.qs("#wl-copyrot", root).addEventListener("click", () => {
        const a = UI.qs("#wl-rotaddr", root).textContent;
        if (a !== "—") UI.copy(a, "Address copied");
      });

      UI.qs("#wl-rotate", root).addEventListener("click", async () => {
        if (imported) { err("wl-keyerr", "diversified rotation needs a seed phrase — an imported simple keystore is a single raw keypair with no seed. Restore a mnemonic to rotate."); return; }
        if (!mnemonic) { err("wl-keyerr", "generate or restore a wallet first"); return; }
        // FAIL CLOSED when address-at-index is not REAL. Under the browser
        // backend this command is deliberately unregistered — the WASM core has
        // no index-derivation op (keypair_from_mnemonic takes no index) — so
        // api.invoke() would fall through to the preview engine and hand back a
        // DIFFERENT wallet's address (observed: core address bloch1t4de0…, preview
        // rotation tbloch1q5wp…, not even the same address format) while this pane
        // shows a live badge. Presenting that as "your rotation address" is how a
        // user ends up publishing an address they cannot spend from.
        if (!api.isReal("wallet_address_at")) {
          err("wl-keyerr", "diversified rotation is not available in this build: deriving an address at an index needs the native app (the browser crypto core has no index-derivation op). Your main address above is real and safe to use.");
          return;
        }
        rotIndex += 1;
        try {
          const addr = await api.invoke("wallet_address_at", { mnemonic, testnet: testnet(), index: rotIndex });
          UI.qs("#wl-rotaddr", root).textContent = addr;
          UI.qs("#wl-rotidx", root).textContent = `index ${rotIndex}`;
        } catch (e) { err("wl-keyerr", `${e}`); }
      });

      UI.qs("#wl-balance", root).addEventListener("click", async () => {
        const addr = UI.qs("#wl-addr", root).textContent;
        if (addr === "—") { err("wl-balerr", "no wallet loaded"); return; }
        err("wl-balerr");
        try {
          // Read-only — the address is public; no key/mnemonic is ever sent.
          const r = await P.rpc("getbalance", [addr]);
          if (r && r.error) throw new Error(JSON.stringify(r.error));
          const b = r ? r.result : undefined;
          UI.qs("#wl-bal", root).textContent = UI.fmtNum(typeof b === "number" ? b : b?.balance ?? b?.confirmed);
        } catch (e) {
          err("wl-balerr", `balance: ${e.message || e} — ${P.rpcReachHint()}`);
        }
      });

      UI.qs("#wl-send", root).addEventListener("click", async () => {
        const res = UI.qs("#wl-sendres", root);
        if (!mnemonic && !imported) { UI.setResult(res, "generate, restore, or import a wallet first", "err"); return; }
        const to = UI.qs("#wl-to", root).value.trim();
        const amount = parseInt(UI.qs("#wl-amount", root).value, 10);
        if (!to) { UI.setResult(res, "destination + amount required", "err"); return; }
        if (!Number.isInteger(amount) || amount <= 0) {
          UI.setResult(res, "amount must be a whole number of sats greater than 0", "err");
          return;
        }
        const btn = UI.qs("#wl-send", root);
        btn.disabled = true;
        UI.setResult(res, "building, signing, broadcasting…", "muted");
        try {
          // Two real signers: an imported simple keystore spends its raw keypair
          // (wallet_keystore_send — same getutxos→build→broadcast flow bloch-cli
          // uses); a seed-phrase wallet spends via wallet_send.
          // Signing is LOCAL (native/postern-vault); the RPC only carries the
          // already-signed tx (sendrawtransaction) + a getutxos read. allowCustom
          // is set only for a user-confirmed custom endpoint (backend fail-close).
          const fee = UI.qs("#wl-fee", root).value;
          const allowCustom = P.rpcAllowCustom();
          const txid = imported
            ? await api.invoke("wallet_keystore_send", {
                json: imported.json, password: imported.password,
                rpcUrl: P.rpcUrl(), to, amount, fee, allowCustom,
              })
            : await api.invoke("wallet_send", {
                rpcUrl: P.rpcUrl(), mnemonic, testnet: testnet(),
                to, amount, fee, allowCustom,
              });
          UI.setResult(res, `✓ txid ${UI.shortHex(txid, 12)}`, "ok");
          UI.toast("Transaction broadcast", "ok");
        } catch (e) {
          UI.setResult(res, `✖ ${e}`, "err");
        }
        btn.disabled = false;
      });
    },
  });
})();
