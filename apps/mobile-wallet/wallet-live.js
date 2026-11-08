/* ============================================================================
   Postern Wallet — mobile · LIVE layer
   ============================================================================
   Turns the reference-prototype UI into a REAL post-quantum wallet:

     • real keys + real hybrid Falcon‖ML-DSA signatures, from the WASM build of
       the node's own bloch-crypto (bloch_wallet_wasm.wasm)
     • real Bloch addresses (byte-identical to bloch-cli / the node)
     • real balance + broadcast against a live Bloch node over JSON-RPC
     • an encrypted keystore in IndexedDB (Argon2id + XChaCha20-Poly1305); the
       seed / key is NEVER stored in plaintext. (AES-256-GCM is used only on the
       bloch-cli import path, where the on-disk format is fixed.)
     • import of an existing bloch-cli wallet.json (simple keypair / founder.json)
       or newseed HD wallet

   HONEST LIMITS (shown to the user, on purpose):
     • UNAUDITED beta. No security audit. Do not trust it with value.
     • The coin BLOCH carries NO value claim.
     • The base chain is small and 51%-attackable today.
     • This is a browser SOFTWARE keystore — NOT the phone's Secure Enclave /
       StrongBox. Decrypted key material is briefly in JS/WASM memory while
       signing. A compromised browser or device can read it.

   This file is self-contained (no imports) and touches the existing inline
   scripts only through the exposed globalThis.WALLET seam + capture-phase event
   interception, so it never invalidates their CSP hashes.
   ============================================================================ */
(function () {
  "use strict";

  // ── configuration ─────────────────────────────────────────────────────────
  // Live Bloch node (JSON-RPC 2.0), reached via the SAME-ORIGIN `/rpc` proxy — a
  // Cloudflare Pages Function that forwards reads + already-signed
  // `sendrawtransaction` bytes to the CANONICAL node over HTTPS (keys never leave
  // this tab). Same-origin means no mixed-content and no CSP host to allow beyond
  // 'self'. Repointing is still possible for a local/custom node.
  const DEFAULT_RPC = "/rpc";
  const LS_RPC = "postern-wallet.rpc";
  const WASM_URL = "bloch_wallet_wasm.wasm";
  const DB_NAME = "postern-wallet";
  const DB_STORE = "keystore";
  const DB_KEY = "current";
  const WARN_KEY = "postern-wallet.warned.v1";

  const W = globalThis.WALLET; // the pure core (SHA3, parseCoins, validateAddress…)

  // ── tiny DOM helpers ───────────────────────────────────────────────────────
  const $ = (s) => document.querySelector(s);
  const el = (tag, cls, html) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (html != null) e.innerHTML = html;
    return e;
  };
  const txt = (tag, cls, t) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (t != null) e.textContent = t;
    return e;
  };
  function toast(m) {
    const t = $("#toast");
    if (!t) { return; }
    t.textContent = m;
    t.classList.add("show");
    setTimeout(() => t.classList.remove("show"), 2200);
  }

  // ════════════════════════════════════════════════════════════════════════
  // WASM core: loader + minimal WASI shim + string marshalling
  // ════════════════════════════════════════════════════════════════════════
  const Core = (function () {
    let ex = null,
      mem = null;
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    // The module needs 5 wasi_snapshot_preview1 functions. It does NO real IO;
    // only random_get is meaningfully used (OS CSPRNG for fresh mnemonics + the
    // Falcon hedged-signing nonce). The rest are satisfied with safe stubs.
    function wasiShim() {
      const view = () => new DataView(mem.buffer);
      return {
        wasi_snapshot_preview1: {
          random_get: (ptr, len) => {
            crypto.getRandomValues(new Uint8Array(mem.buffer, ptr, len));
            return 0;
          },
          environ_sizes_get: (cptr, sptr) => {
            const v = view();
            v.setUint32(cptr, 0, true);
            v.setUint32(sptr, 0, true);
            return 0;
          },
          environ_get: () => 0,
          fd_write: (fd, iovs, n, nwritten) => {
            // Tally the bytes but write nothing (no stdout in the browser).
            const v = view();
            let total = 0;
            for (let i = 0; i < n; i++) total += v.getUint32(iovs + i * 8 + 4, true);
            v.setUint32(nwritten, total, true);
            return 0;
          },
          proc_exit: (code) => {
            throw new Error("wallet core aborted (proc_exit " + code + ")");
          },
        },
      };
    }

    async function init() {
      if (ex) return;
      const resp = await fetch(WASM_URL);
      if (!resp.ok) throw new Error("failed to load wallet core (" + resp.status + ")");
      let instance;
      const shim = wasiShim();
      if (WebAssembly.instantiateStreaming) {
        try {
          ({ instance } = await WebAssembly.instantiateStreaming(resp.clone(), shim));
        } catch (_) {
          const bytes = await resp.arrayBuffer();
          ({ instance } = await WebAssembly.instantiate(bytes, shim));
        }
      } else {
        const bytes = await resp.arrayBuffer();
        ({ instance } = await WebAssembly.instantiate(bytes, shim));
      }
      ex = instance.exports;
      mem = ex.memory;
    }

    // bw_call(method, args) -> parsed JSON (throws on wasm error result).
    function call(method, args) {
      const mb = encoder.encode(method);
      const ab = encoder.encode(JSON.stringify(args || {}));
      const mp = ex.bw_alloc(mb.length);
      new Uint8Array(mem.buffer, mp, mb.length).set(mb);
      const ap = ex.bw_alloc(ab.length);
      new Uint8Array(mem.buffer, ap, ab.length).set(ab);
      const rp = ex.bw_call(mp, mb.length, ap, ab.length);
      const dv = new DataView(mem.buffer);
      const ok = dv.getUint8(rp);
      const len = dv.getUint32(rp + 1, true);
      const payload = decoder.decode(new Uint8Array(mem.buffer, rp + 5, len));
      ex.bw_free(rp, 5 + len);
      ex.bw_free(mp, mb.length);
      ex.bw_free(ap, ab.length);
      if (!ok) throw new Error(payload);
      return JSON.parse(payload);
    }

    return { init, call, ready: () => !!ex };
  })();

  // ════════════════════════════════════════════════════════════════════════
  // JSON-RPC to a live Bloch node (read balance/UTXOs, broadcast)
  // ════════════════════════════════════════════════════════════════════════
  const Rpc = {
    endpoint() {
      return (localStorage.getItem(LS_RPC) || DEFAULT_RPC).trim();
    },
    setEndpoint(u) {
      localStorage.setItem(LS_RPC, String(u || "").trim());
    },
    async post(method, params, timeoutMs) {
      const ctrl = new AbortController();
      const to = setTimeout(() => ctrl.abort(), timeoutMs || 20000);
      let r;
      try {
        r = await fetch(this.endpoint(), {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: params || [] }),
          signal: ctrl.signal,
          cache: "no-store",
          mode: "cors",
        });
      } finally {
        clearTimeout(to);
      }
      if (!r.ok) throw new Error("node HTTP " + r.status);
      const j = await r.json();
      if (j && j.error != null) throw new Error("node error: " + JSON.stringify(j.error));
      return j ? j.result : undefined;
    },
    async getHeight() {
      const r = await this.post("getblockcount", []);
      return typeof r === "number" ? r : r && r.height;
    },
    async getBalanceSats(address) {
      const r = await this.post("getbalance", [address]);
      if (r && typeof r.satoshis === "number") return r.satoshis;
      if (typeof r === "number") return r;
      return 0;
    },
    async getUtxos(address) {
      const r = await this.post("getutxos", [address]);
      const list = (r && r.utxos) || [];
      return list.map((u) => ({ txid: u.txid, index: u.index | 0, value: u.value | 0 }));
    },
    async broadcast(rawHex) {
      return this.post("sendrawtransaction", [rawHex]);
    },
  };

  // ════════════════════════════════════════════════════════════════════════
  // Encrypted keystore in IndexedDB (the sealed blob only; never plaintext)
  // ════════════════════════════════════════════════════════════════════════
  const Store = {
    _db: null,
    open() {
      if (this._db) return Promise.resolve(this._db);
      return new Promise((res, rej) => {
        const req = indexedDB.open(DB_NAME, 1);
        req.onupgradeneeded = () => {
          req.result.createObjectStore(DB_STORE);
        };
        req.onsuccess = () => {
          this._db = req.result;
          res(this._db);
        };
        req.onerror = () => rej(req.error);
      });
    },
    async put(record) {
      const db = await this.open();
      return new Promise((res, rej) => {
        const tx = db.transaction(DB_STORE, "readwrite");
        tx.objectStore(DB_STORE).put(record, DB_KEY);
        tx.oncomplete = () => res();
        tx.onerror = () => rej(tx.error);
      });
    },
    async get() {
      const db = await this.open();
      return new Promise((res, rej) => {
        const tx = db.transaction(DB_STORE, "readonly");
        const rq = tx.objectStore(DB_STORE).get(DB_KEY);
        rq.onsuccess = () => res(rq.result || null);
        rq.onerror = () => rej(rq.error);
      });
    },
    async clear() {
      const db = await this.open();
      return new Promise((res, rej) => {
        const tx = db.transaction(DB_STORE, "readwrite");
        tx.objectStore(DB_STORE).delete(DB_KEY);
        tx.oncomplete = () => res();
        tx.onerror = () => rej(tx.error);
      });
    },
  };

  // ════════════════════════════════════════════════════════════════════════
  // Session: the unlocked secret + address, held only in memory
  // ════════════════════════════════════════════════════════════════════════
  const Session = {
    unlocked: false,
    address: null,
    network: null, // "testnet" | "mainnet"
    testnet: true,
    secret: null, // { kind:"mnemonic", mnemonic } | { kind:"keys", private_key_hex, public_key_hex, address }
    publicKeyHex: null,
    mnemonic: null,
    balanceSats: 0,
    height: null,

    lock() {
      this.unlocked = false;
      this.secret = null;
      this.mnemonic = null;
    },
    // Build the sign args for the core from the in-memory secret.
    signArgs(to, amountSats, feeSats, utxos) {
      const base = { to, amount_sats: String(amountSats), fee_sats: String(feeSats), utxos };
      if (this.secret.kind === "mnemonic") {
        return {
          method: "build_and_sign_tx_from_mnemonic",
          args: Object.assign({ mnemonic: this.secret.mnemonic, testnet: this.testnet }, base),
        };
      }
      return {
        method: "build_and_sign_tx",
        args: Object.assign(
          {
            secret_hex: this.secret.private_key_hex,
            public_hex: this.secret.public_key_hex,
            address: this.secret.address,
          },
          base
        ),
      };
    },
  };

  // ════════════════════════════════════════════════════════════════════════
  // Apply the unlocked wallet to the existing prototype UI
  // ════════════════════════════════════════════════════════════════════════
  function applyToUI() {
    Session.unlocked = true;
    // Make the prototype's address helpers return the REAL address, so the
    // Balance/Receive/copy surfaces (which call W.demoAddress) show it.
    if (W) {
      W.demoAddress = function () {
        return Session.address;
      };
      if (Session.mnemonic) {
        const words = Session.mnemonic.split(/\s+/);
        W.demoMnemonic = function () {
          return words;
        };
      }
    }
    // Network badge reflects the wallet's real network (not the demo toggle).
    const netName = $("#netName");
    if (netName) netName.textContent = Session.network;
    const badge = $("#netBadge");
    if (badge) badge.classList.toggle("testnet", Session.testnet);
    // Public key on the Keys screen.
    if (Session.publicKeyHex && $("#pubKey")) {
      const pk = Session.publicKeyHex;
      $("#pubKey").textContent = pk.slice(0, 16) + "…" + pk.slice(-8) + " (" + pk.length / 2 + " B)";
    }
    // Receive placeholder input hint → real address prefix.
    const sendTo = $("#sendTo");
    if (sendTo) sendTo.placeholder = (Session.testnet ? "bloch1t…" : "bloch1q…") + " recipient address";

    setAddressUI();
    refreshBalance();
    startRefreshLoop();
  }

  function setAddressUI() {
    const a = Session.address;
    if ($("#balAddr")) $("#balAddr").textContent = a.slice(0, 12) + "…" + a.slice(-8);
  }

  let refreshTimer = null;
  function startRefreshLoop() {
    if (refreshTimer) clearInterval(refreshTimer);
    refreshTimer = setInterval(() => {
      if (Session.unlocked) refreshBalance();
    }, 15000);
  }

  async function refreshBalance() {
    try {
      const [sats, height] = await Promise.all([
        Rpc.getBalanceSats(Session.address).catch(() => null),
        Rpc.getHeight().catch(() => null),
      ]);
      if (sats != null) {
        Session.balanceSats = sats;
        if ($("#balAmt")) $("#balAmt").innerHTML = W.fmtCoins(sats) + '<span class="unit">BLOCH</span>';
      }
      if (height != null) {
        Session.height = height;
        if ($("#height")) $("#height").textContent = Number(height).toLocaleString("en-US");
      }
      const note = $("#liveConnNote");
      if (sats == null && height == null) {
        if ($("#height")) $("#height").textContent = "node unreachable";
        if (note) {
          note.className = "note warn mt";
          note.innerHTML =
            "<strong>Node unreachable.</strong> The live layer could not reach " +
            "<span class='mono'>" + escapeHtml(Rpc.endpoint()) + "</span>. Showing " +
            "last-known values; you can repoint the node in the unlock screen.";
        }
      } else if (note) {
        // Honest live status: real data is coming from the configured node.
        note.className = "note mt";
        note.innerHTML =
          "<strong>Live.</strong> Balance and block height are read from " +
          "<span class='mono'>" + escapeHtml(Rpc.endpoint()) + "</span> over JSON-RPC. " +
          "A send here signs a real hybrid PQ transaction and broadcasts it. " +
          "Unaudited beta — browser software keystore, no value claim.";
      }
    } catch (_) {
      /* leave last-known values */
    }
  }

  // ════════════════════════════════════════════════════════════════════════
  // Overlay UI (onboarding / unlock / create / import) — self-contained DOM
  // ════════════════════════════════════════════════════════════════════════
  const Overlay = {
    root: null,
    show(node) {
      if (!this.root) {
        this.root = el("div", "pw-overlay");
        this.root.setAttribute(
          "style",
          "position:fixed;inset:0;z-index:9999;overflow:auto;-webkit-overflow-scrolling:touch;" +
            "background:var(--bg,#0d0f12);color:var(--fg,#e9edf1);padding:22px 18px 40px;"
        );
        document.body.appendChild(this.root);
      }
      this.root.innerHTML = "";
      const wrap = el("div");
      wrap.setAttribute("style", "max-width:460px;margin:0 auto;");
      wrap.appendChild(node);
      this.root.appendChild(wrap);
      this.root.scrollTop = 0;
      this.root.style.display = "block";
    },
    hide() {
      if (this.root) this.root.style.display = "none";
    },
  };

  function h(title, sub) {
    const box = el("div");
    box.appendChild(txt("h2", null, title)).setAttribute("style", "margin:.2em 0 .1em;font-size:1.25rem");
    if (sub) {
      const p = txt("p", "small dim", sub);
      p.setAttribute("style", "margin:.2em 0 1em;opacity:.8");
      box.appendChild(p);
    }
    return box;
  }
  function button(label, primary) {
    const b = txt("button", "btn" + (primary ? " primary" : ""), label);
    b.setAttribute("style", "display:block;width:100%;margin:.4em 0;padding:.85em;font-size:1rem;border-radius:12px");
    return b;
  }
  function input(placeholder, type) {
    const i = el("input", "in mono");
    i.type = type || "text";
    i.placeholder = placeholder || "";
    i.autocomplete = "off";
    i.spellcheck = false;
    i.setAttribute("style", "width:100%;margin:.35em 0;padding:.75em;border-radius:10px");
    return i;
  }
  function note(kind, html) {
    const n = el("div", "note " + (kind || ""), html);
    n.setAttribute(
      "style",
      "margin:.6em 0;padding:.7em .8em;border-radius:10px;font-size:.82rem;line-height:1.45;" +
        "border:1px solid rgba(255,255,255,.14)"
    );
    return n;
  }

  const HONEST_LIMITS =
    "<strong>Unaudited beta — a real wallet, not a safe one.</strong> No security " +
    "audit. The coin <b>BLOCH</b> has no value claim. The base chain is small and " +
    "51%-attackable today. This is a browser <b>software</b> keystore — <b>not</b> " +
    "your phone's Secure Enclave / StrongBox; decrypted keys briefly live in " +
    "browser memory while signing. Don't store anything you can't afford to lose.";

  // ── first screen: onboard or unlock ────────────────────────────────────────
  async function boot() {
    // Wire the About screen's live-core note if present.
    try {
      await Core.init();
    } catch (e) {
      return Overlay.show(
        (function () {
          const b = h("Wallet core failed to load", "The WebAssembly crypto core could not start.");
          b.appendChild(note("warn", String(e.message || e)));
          const retry = button("Retry", true);
          retry.onclick = () => location.reload();
          b.appendChild(retry);
          return b;
        })()
      );
    }

    const rec = await Store.get().catch(() => null);
    if (rec && rec.sealed) return screenUnlock(rec);
    return screenWelcome();
  }

  function screenWelcome() {
    const b = h("Postern Wallet", "Post-quantum wallet — real Falcon‖ML-DSA keys.");
    b.appendChild(note("warn", HONEST_LIMITS));

    const netRow = el("div");
    netRow.setAttribute("style", "display:flex;gap:.5em;margin:.6em 0");
    let testnet = true;
    const mkNet = (label, tn) => {
      const bt = txt("button", "btn sm", label);
      bt.setAttribute("style", "flex:1;padding:.6em;border-radius:10px;opacity:" + (tn === testnet ? "1" : ".55"));
      bt.onclick = () => {
        testnet = tn;
        mkNet && paint();
      };
      return bt;
    };
    let paint;
    (paint = function () {
      netRow.innerHTML = "";
      const a = mkNet("testnet", true),
        c = mkNet("mainnet", false);
      netRow.appendChild(txt("span", "small dim", "Network:")).setAttribute("style", "align-self:center;margin-right:.3em");
      netRow.appendChild(a);
      netRow.appendChild(c);
    })();
    b.appendChild(netRow);

    const create = button("Create a new wallet", true);
    create.onclick = () => screenCreate(testnet);
    const imp = button("Import a wallet.json");
    imp.onclick = () => screenImport(testnet);
    b.appendChild(create);
    b.appendChild(imp);

    b.appendChild(rpcRow());
    Overlay.show(b);
  }

  function rpcRow() {
    const wrap = el("div");
    wrap.setAttribute("style", "margin-top:1.2em");
    wrap.appendChild(txt("div", "small dim", "Node RPC endpoint (JSON-RPC 2.0)"));
    const i = input("https://node…/", "url");
    i.value = Rpc.endpoint();
    i.oninput = () => Rpc.setEndpoint(i.value);
    wrap.appendChild(i);
    wrap.appendChild(
      note(
        "",
        "Balance and broadcast use this node over HTTPS. Point it at any Bloch " +
          "node you trust. A plain-<code>http://</code> node won't work from an " +
          "https page (mixed content) — it needs HTTPS or a same-origin proxy."
      )
    );
    return wrap;
  }

  // ── create new wallet ───────────────────────────────────────────────────────
  function screenCreate(testnet) {
    const b = h("Create wallet", "Generating a 24-word recovery phrase.");
    let mnemonic;
    try {
      mnemonic = Core.call("new_mnemonic", { words: 24 }).mnemonic;
    } catch (e) {
      b.appendChild(note("warn", "keygen failed: " + e.message));
      Overlay.show(b);
      return;
    }
    const derived = Core.call("wallet_from_mnemonic", { mnemonic, testnet });

    b.appendChild(
      note(
        "warn",
        "<strong>Write these 24 words down, in order, offline.</strong> They are " +
          "the ONLY backup of this wallet. Anyone with them controls the funds. " +
          "This screen shows them once."
      )
    );
    const grid = el("div");
    grid.setAttribute("style", "display:grid;grid-template-columns:1fr 1fr;gap:.3em .8em;margin:.6em 0;font-family:monospace");
    mnemonic.split(/\s+/).forEach((w, i) => {
      const cell = el("div");
      cell.setAttribute("style", "padding:.3em .5em;background:rgba(255,255,255,.05);border-radius:8px");
      cell.appendChild(txt("span", null, i + 1 + ". ")).setAttribute("style", "opacity:.5");
      cell.appendChild(document.createTextNode(w));
      grid.appendChild(cell);
    });
    b.appendChild(grid);

    const copy = button("Copy phrase");
    copy.onclick = () => navigator.clipboard && navigator.clipboard.writeText(mnemonic).then(() => toast("Phrase copied"));
    b.appendChild(copy);

    const addrNote = note("", "Address: <span class='mono'>" + derived.address + "</span>");
    b.appendChild(addrNote);

    const chk = el("label");
    chk.setAttribute("style", "display:flex;gap:.5em;align-items:flex-start;margin:.8em 0;font-size:.9rem");
    const cb = el("input");
    cb.type = "checkbox";
    chk.appendChild(cb);
    chk.appendChild(txt("span", null, "I've written down my 24 words and understand they can't be recovered if lost."));
    b.appendChild(chk);

    const cont = button("Set a passphrase to encrypt this wallet", true);
    cont.disabled = true;
    cb.onchange = () => (cont.disabled = !cb.checked);
    cont.onclick = () =>
      screenSetPassphrase({
        kind: "mnemonic",
        secret: { kind: "mnemonic", mnemonic },
        meta: {
          kind: "mnemonic",
          address: derived.address,
          network: testnet ? "testnet" : "mainnet",
          public_key_hex: derived.public_key_hex,
        },
        testnet,
      });
    b.appendChild(cont);

    const back = button("← back");
    back.onclick = () => screenWelcome();
    b.appendChild(back);
    Overlay.show(b);
  }

  // ── import wallet.json ──────────────────────────────────────────────────────
  function screenImport(testnetHint) {
    const b = h("Import wallet.json", "A bloch-cli wallet: simple keypair, founder.json, or a newseed HD wallet.");
    b.appendChild(
      note(
        "warn",
        "<strong>A wallet.json holds your key material</strong> (encrypted with its " +
          "own password). Treat the file like a private key. Importing decrypts it " +
          "and re-encrypts the key into THIS browser's keystore."
      )
    );

    const file = el("input");
    file.type = "file";
    file.accept = ".json,application/json";
    file.setAttribute("style", "display:block;margin:.5em 0");
    const jsonArea = el("textarea", "in mono");
    jsonArea.placeholder = "…or paste the wallet JSON here";
    jsonArea.setAttribute("style", "width:100%;height:110px;margin:.4em 0;padding:.6em;border-radius:10px;font-size:.75rem");
    file.onchange = () => {
      const f = file.files[0];
      if (!f) return;
      const r = new FileReader();
      r.onload = () => (jsonArea.value = String(r.result || ""));
      r.readAsText(f);
    };
    b.appendChild(file);
    b.appendChild(jsonArea);

    const filePw = input("wallet.json password", "password");
    b.appendChild(txt("div", "small dim", "wallet.json password"));
    b.appendChild(filePw);

    // HD-only fields (mnemonic + optional passphrase), shown only for HD files.
    const hdWrap = el("div");
    hdWrap.style.display = "none";
    const mnem = input("24-word mnemonic (HD wallet only)");
    const hdPass = input("HD passphrase (optional)");
    hdWrap.appendChild(txt("div", "small dim", "HD mnemonic"));
    hdWrap.appendChild(mnem);
    hdWrap.appendChild(txt("div", "small dim", "HD passphrase (blank if none)"));
    hdWrap.appendChild(hdPass);
    b.appendChild(hdWrap);

    const status = note("", "");
    status.style.display = "none";
    b.appendChild(status);

    function detectHd() {
      try {
        const v = JSON.parse(jsonArea.value);
        return v && v.format === "hd-wallet-v1";
      } catch (_) {
        return false;
      }
    }
    jsonArea.oninput = () => {
      hdWrap.style.display = detectHd() ? "block" : "none";
    };

    const doImport = button("Decrypt & import", true);
    doImport.onclick = () => {
      status.style.display = "block";
      status.innerHTML = "Decrypting… (Argon2id, may take a second)";
      // let the UI paint before the heavy Argon2.
      setTimeout(() => {
        try {
          let res;
          const isHd = detectHd();
          if (isHd) {
            res = Core.call("import_hd_wallet", {
              json: jsonArea.value,
              mnemonic: mnem.value.trim(),
              passphrase: hdPass.value,
              password: filePw.value,
            });
          } else {
            res = Core.call("import_simple_wallet", { json: jsonArea.value, password: filePw.value });
          }
          const primary = res.keys[0];
          const testnet = res.network === "testnet";
          status.className = "note ok";
          status.innerHTML = "Imported <span class='mono'>" + primary.address + "</span>";
          const secret = {
            kind: "keys",
            private_key_hex: primary.private_key_hex,
            public_key_hex: primary.public_key_hex,
            address: primary.address,
          };
          const meta = {
            kind: res.kind,
            address: primary.address,
            network: res.network,
            public_key_hex: primary.public_key_hex,
          };
          // HD wallets carry a mnemonic (for display) too.
          if (res.mnemonic) secret.mnemonic_display = res.mnemonic;
          const cont = button("Set a passphrase to encrypt this wallet in the browser", true);
          cont.onclick = () => screenSetPassphrase({ kind: "keys", secret, meta, testnet, mnemonic: res.mnemonic || null });
          b.appendChild(cont);
          doImport.disabled = true;
        } catch (e) {
          status.className = "note warn";
          status.innerHTML = "Import failed: " + escapeHtml(e.message);
        }
      }, 40);
    };
    b.appendChild(doImport);

    const back = button("← back");
    back.onclick = () => screenWelcome();
    b.appendChild(back);
    Overlay.show(b);
  }

  // ── set app passphrase, seal, save, unlock ─────────────────────────────────
  function screenSetPassphrase(payload) {
    const b = h("Encrypt your wallet", "A passphrase (Argon2id + XChaCha20-Poly1305) locks this wallet in the browser.");
    const p1 = input("passphrase (min 8 chars)", "password");
    const p2 = input("confirm passphrase", "password");
    b.appendChild(p1);
    b.appendChild(p2);
    const status = note("", "");
    status.style.display = "none";
    b.appendChild(status);

    const save = button("Encrypt & open wallet", true);
    save.onclick = () => {
      if (p1.value.length < 8) return fail("passphrase must be at least 8 characters");
      if (p1.value !== p2.value) return fail("passphrases do not match");
      status.style.display = "block";
      status.className = "note";
      status.textContent = "Encrypting…";
      setTimeout(async () => {
        try {
          const plaintext = JSON.stringify(payload.secret);
          const sealed = JSON.stringify(Core.call("keystore_seal", { plaintext, passphrase: p1.value }));
          await Store.put({ sealed, meta: payload.meta });
          // populate session and open
          openSession(payload.secret, payload.meta, payload.mnemonic || (payload.secret && payload.secret.mnemonic) || null);
        } catch (e) {
          fail(e.message);
        }
      }, 40);
    };
    function fail(m) {
      status.style.display = "block";
      status.className = "note warn";
      status.textContent = m;
    }
    b.appendChild(save);
    Overlay.show(b);
  }

  // ── unlock existing ─────────────────────────────────────────────────────────
  function screenUnlock(rec) {
    const b = h("Unlock wallet", rec.meta.address ? rec.meta.address : "");
    const addr = rec.meta.address;
    if (addr) {
      const a = note("", "Wallet: <span class='mono'>" + addr.slice(0, 14) + "…" + addr.slice(-8) + "</span> · " + rec.meta.network);
      b.appendChild(a);
    }
    const pw = input("passphrase", "password");
    b.appendChild(pw);
    const status = note("", "");
    status.style.display = "none";
    b.appendChild(status);

    const unlock = button("Unlock", true);
    const doUnlock = () => {
      status.style.display = "block";
      status.className = "note";
      status.textContent = "Decrypting…";
      setTimeout(() => {
        try {
          const opened = Core.call("keystore_open", { blob: rec.sealed, passphrase: pw.value });
          const secret = JSON.parse(opened.plaintext);
          openSession(secret, rec.meta, secret.mnemonic || secret.mnemonic_display || null);
        } catch (e) {
          status.className = "note warn";
          status.textContent = "Wrong passphrase";
        }
      }, 40);
    };
    unlock.onclick = doUnlock;
    pw.onkeydown = (e) => {
      if (e.key === "Enter") doUnlock();
    };
    b.appendChild(unlock);

    const forget = button("Forget this wallet");
    forget.onclick = async () => {
      if (confirm("Remove this wallet from this browser? You can only restore it from its recovery phrase or wallet.json.")) {
        await Store.clear();
        screenWelcome();
      }
    };
    b.appendChild(forget);
    b.appendChild(rpcRow());
    Overlay.show(b);
  }

  function openSession(secret, meta, mnemonic) {
    Session.secret = secret;
    Session.address = meta.address;
    Session.network = meta.network;
    Session.testnet = meta.network === "testnet";
    Session.publicKeyHex = meta.public_key_hex || (secret && secret.public_key_hex) || null;
    Session.mnemonic = mnemonic || null;
    Overlay.hide();
    applyToUI();
    maybeShowFirstRunWarning();
    toast("Wallet unlocked");
  }

  function maybeShowFirstRunWarning() {
    if (localStorage.getItem(WARN_KEY)) return;
    localStorage.setItem(WARN_KEY, "1");
    // Non-blocking honest banner via the existing toast + a persistent note in About.
    toast("Unaudited beta — no real value; keys live in the browser.");
  }

  // ════════════════════════════════════════════════════════════════════════
  // Real SEND: intercept the prototype's "Review & sign" in capture phase
  // ════════════════════════════════════════════════════════════════════════
  document.addEventListener(
    "click",
    function (e) {
      const btn = e.target.closest && e.target.closest("#sendReview");
      if (!btn || !Session.unlocked) return; // let the demo handle it pre-unlock
      e.preventDefault();
      e.stopImmediatePropagation();
      startRealSend();
    },
    true
  );

  function readSendInputs() {
    const to = ($("#sendTo").value || "").trim();
    let amt, fee, err = null;
    try {
      amt = W.parseCoins($("#sendAmt").value || "0");
    } catch (x) {
      err = "amount: " + x.message;
    }
    try {
      fee = W.parseCoins($("#sendFee").value || "0.0001");
    } catch (x) {
      err = err || "fee: " + x.message;
    }
    if (!to) err = err || "enter a recipient address";
    else {
      try {
        W.validateAddress(to, Session.testnet);
      } catch (x) {
        err = err || "address " + x.message;
      }
    }
    if (!err && amt <= 0) err = "amount must be greater than zero";
    return { to, amt, fee, err };
  }

  async function startRealSend() {
    const s = readSendInputs();
    if (s.err) {
      toast(s.err);
      return;
    }
    // WYSIWYS confirm — show exactly what will be signed & broadcast.
    const b = h("Confirm — this is irreversible", null);
    b.appendChild(
      note(
        "warn",
        "You are about to <b>sign and broadcast</b> a real transaction on <b>" +
          Session.network +
          "</b>. There is no undo."
      )
    );
    const kv = (k, v) => {
      const row = el("div");
      row.setAttribute("style", "display:flex;justify-content:space-between;gap:1em;margin:.35em 0;font-size:.9rem");
      row.appendChild(txt("span", "dim", k));
      const val = txt("span", "mono", v);
      val.setAttribute("style", "text-align:right;word-break:break-all");
      row.appendChild(val);
      return row;
    };
    b.appendChild(kv("from", Session.address));
    b.appendChild(kv("to", s.to));
    b.appendChild(kv("amount", W.fmtCoins(s.amt) + " BLOCH"));
    b.appendChild(kv("fee", W.fmtCoins(s.fee) + " BLOCH"));
    b.appendChild(kv("network", Session.network));
    b.appendChild(
      note(
        "",
        "Signature: real hybrid <b>Falcon-1024 ‖ ML-DSA-65</b>. The signing key is " +
          "decrypted in this browser only for the moment it signs."
      )
    );
    const status = note("", "");
    status.style.display = "none";
    b.appendChild(status);

    const confirm = button("Sign & broadcast", true);
    confirm.onclick = async () => {
      confirm.disabled = true;
      status.style.display = "block";
      status.className = "note";
      status.textContent = "Fetching UTXOs from the node…";
      try {
        const utxos = await Rpc.getUtxos(Session.address);
        if (!utxos.length) throw new Error("no spendable UTXOs at this address (balance is 0 or unconfirmed)");
        status.textContent = "Signing (hybrid PQ)…";
        const { method, args } = Session.signArgs(s.to, s.amt, s.fee, utxos);
        const signed = await new Promise((res, rej) =>
          setTimeout(() => {
            try {
              res(Core.call(method, args));
            } catch (x) {
              rej(x);
            }
          }, 30)
        );
        status.textContent = "Broadcasting…";
        await Rpc.broadcast(signed.raw_hex);
        status.className = "note ok";
        status.innerHTML = "Broadcast accepted · txid <span class='mono'>" + signed.txid_hex + "</span>";
        confirm.textContent = "Done";
        refreshBalance();
        const done = button("Back to wallet");
        done.onclick = () => Overlay.hide();
        b.appendChild(done);
      } catch (e) {
        status.className = "note warn";
        status.textContent = "Failed: " + e.message;
        confirm.disabled = false;
      }
    };
    b.appendChild(confirm);
    const cancel = button("Cancel");
    cancel.onclick = () => Overlay.hide();
    b.appendChild(cancel);
    Overlay.show(b);
  }

  // A small "Lock / switch wallet" affordance appended to the About screen.
  function installLockButton() {
    const about = $("#scr-about");
    if (!about) return;
    const wrap = el("div");
    wrap.setAttribute("style", "margin:1.2em 0");
    const lock = button("Lock / switch wallet");
    lock.onclick = async () => {
      Session.lock();
      const rec = await Store.get();
      if (rec) screenUnlock(rec);
      else screenWelcome();
    };
    wrap.appendChild(lock);
    about.appendChild(wrap);
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  // ── go ──────────────────────────────────────────────────────────────────────
  function main() {
    installLockButton();
    boot().catch((e) => {
      console.error(e);
      toast("wallet init error: " + (e && e.message));
    });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", main);
  else main();
})();
