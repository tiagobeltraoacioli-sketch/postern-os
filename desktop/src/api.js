// api.js — Postern front-end API layer.
//
// One rule, enforced here and surfaced in the UI: a call either goes to a REAL
// backend command, or it runs on a clearly-labeled local PREVIEW engine.
// A preview is never presented as live — modules ask `api.isReal(cmd)` and show
// the stub badge whenever it's false.
//
// THREE backends can sit behind this one seam (api.backendKind says which):
//   'tauri'   — the native desktop app: window.__TAURI__.core.invoke routes to
//               the Rust commands listed below. The full command surface.
//   'browser' — the Postern PWA: window.PosternBrowser (browser/registry.js,
//               loaded BEFORE this file) carries commands something REAL has
//               registered — the wallet_* set against the WASM build of the
//               node's own bloch-crypto (browser/core.js + browser/wallet.js,
//               golden-vector-gated), and the read-only same-origin /rpc proxy.
//               A command is real here ONLY if it is registered; registration
//               only happens after the real capability proved itself, so an
//               unregistered command falls through to its labelled preview.
//   'preview' — neither: every command runs on the preview engines below.
//
// Real commands (desktop/src-tauri/src/main.rs):
//   node_start, node_stop, node_status, rpc, rpc_tor,
//   wallet_generate, wallet_from_mnemonic, wallet_address_at, wallet_send,
//   vault_status/create/unlock/lock/list/get/put/remove/discard (postern-vault),
//   vault_keychain_enable / vault_unlock_keychain / vault_keychain_forget
//   (opt-in `vault-keychain` cargo feature — SOFTWARE convenience, not
//   hardware protection; built without the feature they return an honest
//   "not built with keychain support" error),
//   panic (postern-panic — instant re-lock, key + secrets evicted from RAM),
//   hygiene_scrub (postern-hygiene — fails closed, unaudited),
//   courier_generate_recipient/courier_seal/courier_open (postern-courier —
//   unaudited; transport is still mock/local, no live onion round trip),
//   keys_create/keys_list/keys_sign/keys_remove (postern-keys — unaudited
//   software authenticator, keys in app RAM, not a hardware key),
//   terem_create/start/qmp/status/stop/destroy (terem.rs — QEMU/QMP guest
//   POC, unaudited, unix-only, allowlisted QMP; deliberately NO preview
//   engine: a faked "running guest" would be an overclaim),
//   vestnik_recipient_init/session_store/session_load/session_open
//   (vestnik.rs — vault-custodied courier recipient secret + opaque sealed
//   SavedSession blob; deliberately NO preview engine: a faked vault
//   custody would be an overclaim),
//   vestnik_matrix_status/vestnik_login/vestnik_session_seal/vestnik_restore/
//   vestnik_sync_once/vestnik_rooms/vestnik_send/vestnik_logout
//   (vestnik_client.rs — the matrix client behind the opt-in `vestnik-matrix`
//   cargo feature; registered always, a no-feature build returns the clean
//   "not built with matrix support" error and status reports built:false;
//   deliberately NO preview engine: a faked matrix client would be an
//   overclaim)
// Everything else (seal_*) has no
// backend command yet → preview engine below (or an honest throw). When there is no Tauri backend,
// `isReal` asks the browser-backend registry (window.PosternBrowser) instead;
// commands it has NOT registered fall back to their labeled preview engines
// exactly as before. `hasBackend` keeps meaning "Tauri present". The vault
// preview engine additionally probes globalThis.PosternSDK (the same
// postern-sdk wasm seam the browser front-ends use) and seals with the REAL
// Argon2id + XChaCha20-Poly1305 core when it's present, instead of always
// falling back to the classical PBKDF2 stand-in — see the VAULT preview
// engine block below for the honest, fail-closed dispatch rule.
(function () {
  "use strict";

  const P = window.Postern;
  const UI = P.ui;

  const T = window.__TAURI__;
  const hasBackend = !!(T && T.core && typeof T.core.invoke === "function");
  const REAL = new Set([
    "node_start", "node_stop", "node_status", "rpc", "rpc_tor",
    "wallet_generate", "wallet_from_mnemonic", "wallet_address_at", "wallet_send",
    // Import a bloch-cli wallet.json (walletjson.rs). REAL interop only — these
    // decrypt with the `bloch` crate's own keystore readers. In the browser
    // backend the SAME crate does the decrypt via the WASM core
    // (browser/wallet.js registers them, golden-vector-gated); with neither
    // backend, isReal() is false and the preview handlers below throw a clear
    // "needs a real backend" error rather than faking a decrypt.
    "wallet_import_keystore", "wallet_import_hd", "wallet_keystore_send",
    // Vault (postern-vault) + Panic (postern-panic) — real cores wired in.
    "vault_status", "vault_create", "vault_unlock", "vault_lock",
    "vault_list", "vault_get", "vault_put", "vault_remove", "vault_discard",
    // OS-keychain unlock (opt-in `vault-keychain` cargo feature). The three
    // commands are ALWAYS registered by the backend: built without the
    // feature they return a clean "not built with keychain support" error
    // (never a silent no-op), and vault_status's keychain object reports
    // available:false — so the pane only shows keychain controls when the
    // backend really has a reachable OS keychain. HONESTY: a SOFTWARE
    // convenience, not hardware protection — see KEYCHAIN_HONESTY in
    // desktop/src-tauri/src/vault.rs (rendered verbatim by the pane).
    // Deliberately NO preview engine: a faked OS keychain would be an
    // overclaim, so without a backend the pane shows no keychain UI at all.
    "vault_keychain_enable", "vault_unlock_keychain", "vault_keychain_forget",
    "panic",
    // Phone-as-signer — desktop requester side (pairing, wallet-login, grants).
    "pair_begin", "pair_respond", "pair_confirm", "pair_cancel", "pair_list", "pair_unpair",
    "login_request", "login_complete", "login_reject", "grants_list", "grant_revoke",
    // Folded cores registered by the backend lane in generate_handler!
    // (desktop/src-tauri/src/main.rs). All UNAUDITED reference cores; the
    // preview engines below become the no-backend (plain browser) fallback.
    "hygiene_scrub",
    // Quarantine (postern-quarantine) — the MIRROR of hygiene (receive side):
    // an untrusted image/PDF is rebuilt from pixels into a clean PNG / flat
    // metadata-free PDF. Registered by the backend lane in generate_handler!.
    // HONESTY: the PDF render runs IN-PROCESS with NO OS-level containment
    // (no out-of-process sandbox, no Landlock/seccomp around the renderer, no
    // wall-clock timeout); the image path's Landlock confinement is
    // Linux-only + best-effort. Fails closed on office/unknown magic.
    // Deliberately NO preview engine below: a faked sanitised file would be
    // an overclaim (and dangerous for a security tool), so without a backend
    // the pane renders disabled and any invoke throws honestly.
    "quarantine_rebuild",
    "courier_generate_recipient", "courier_seal", "courier_open",
    "keys_create", "keys_list", "keys_sign", "keys_remove",
    // Vestnik — the in-process Megolm shell commands (vestnik_create_session /
    // register_peer / encrypt / decrypt / status) were REMOVED from the backend
    // when vestnik.rs became the sealed-session CUSTODY layer and the matrix
    // client moved to vestnik_client.rs (both claimed further down). Claiming
    // them here was an overclaim against a generate_handler! that no longer
    // registers them — the panes.test.mjs REAL-set/backend-mirror gate caught
    // it. The vestnik.js pane keeps its own clearly-labelled AES-GCM PREVIEW
    // engine, which is exactly what it falls back to when isReal() is false.
    // Encrypted Backup — the LOCAL Postern → Filecoin user-backup path
    // (backup.rs) wired to the real bloch-data (data/postern-data) SCAFFOLD.
    // backup_seal encrypts a file with the real Postern AEAD (XChaCha20-
    // Poly1305 v2, key-committing) under an Argon2id key — passphrase/key never
    // leave the device — and commits a real (UNSIGNED) DATA0 anchor whose
    // manifest_root is a real SHAKE-256; backup_store writes it content-
    // addressed to a user-chosen folder (real DirBackend); backup_restore
    // re-verifies the SHAKE-256 anchor + blob integrity, then decrypts.
    // backup_filecoin_upload POSTs the already-SEALED ciphertext to Lighthouse
    // over REAL HTTPS at the Tauri layer (the desktop's ureq + rustls client —
    // NOT bloch-data::LiveBackend, whose hand-rolled HTTP has no in-crate TLS);
    // backup_filecoin_retrieve fetches it back from the gateway for a
    // byte-identity verify. HONESTY: bloch-data is UNAUDITED scaffold; anchor is
    // UNSIGNED (no ML-DSA/Falcon — out-of-scope postern-backup-net), so anchoring
    // is a claim, not settlement; ONLY Postern-sealed CIPHERTEXT is uploaded (the
    // provider is trusted for availability, not confidentiality) and the user
    // supplies their OWN Lighthouse token, sent only to Lighthouse, per-call,
    // never logged or persisted. Deliberately NO preview engine: encrypting/
    // anchoring/restoring/uploading for real needs the native app, so with no
    // backend isReal() is false and the pane disables its actions with a clear
    // "needs the native app" note rather than faking a seal or an upload.
    // backup_filecoin_s3_upload is the PRIMARY Filecoin path: a signed PUT to
    // Lighthouse's S3-compatible endpoint (minimal in-tree SigV4 at the Tauri
    // layer) that returns the real IPFS/Filecoin CID from the object's
    // x-amz-meta-cid metadata. The user supplies their OWN Lighthouse S3
    // credentials (Access/Secret key), stored ONLY in local settings and sent
    // per-call, never logged/persisted/baked-in. backup_filecoin_upload (the
    // IPFS bearer add) stays as a labeled fallback — it TIMES OUT on some
    // networks, which is why S3 is the default.
    "backup_default_dir", "backup_seal", "backup_store", "backup_restore",
    "backup_filecoin_s3_upload", "backup_filecoin_upload", "backup_filecoin_retrieve",
    // Terem — QEMU/QMP guest-runtime POC registered by the backend lane in
    // generate_handler! (desktop/src-tauri/src/main.rs, #[cfg(unix)]-gated:
    // QMP rides a unix socket, so a Windows build honestly rejects these).
    // UNAUDITED POC, and deliberately WITHOUT a preview engine below — with
    // no backend the Terem pane renders the honest empty state instead of
    // fabricating a running guest.
    "terem_create", "terem_start", "terem_qmp", "terem_status", "terem_stop", "terem_destroy",
    // Vestnik — desktop CUSTODY of the Matrix sealed session, registered by
    // the backend in generate_handler! (desktop/src-tauri/src/vestnik.rs).
    // HONESTY: the recipient secret is a vault entry (requires an UNLOCKED
    // vault, fails closed when locked; software seal, not a TEE until real
    // hardware) and sealed-at-rest covers the SavedSession blob ONLY.
    // Deliberately NO preview engine: a faked vault custody would be an
    // overclaim, so without a backend these throw.
    "vestnik_recipient_init", "vestnik_session_store", "vestnik_session_load", "vestnik_session_open",
    // Vestnik matrix client (desktop/src-tauri/src/vestnik_client.rs).
    // HONESTY: registered ALWAYS, but the client only exists behind the
    // opt-in `vestnik-matrix` cargo feature — built without it every command
    // returns a clean "not built with matrix support (rebuild with
    // --features vestnik-matrix)" error (never a silent no-op), and
    // vestnik_matrix_status reports { built:false, … } so the pane gates on
    // REAL capability (the vault-keychain available:false pattern), never on
    // registration alone. In a vestnik-matrix build a homeserver is
    // contacted ONLY when the user acts (login/sync/send) — never in CI,
    // never at app startup; the homeserver sees the social graph (no Tor
    // wiring); Megolm/Olm is classical, not post-quantum; the SDK's sqlite
    // store passphrase is SDK-layer only. Deliberately NO preview engine:
    // a faked matrix client would be an overclaim, so without a backend
    // these throw.
    "vestnik_matrix_status", "vestnik_login", "vestnik_session_seal", "vestnik_restore",
    "vestnik_sync_once", "vestnik_rooms", "vestnik_send", "vestnik_logout",
  ]);

  // ── event bus (real Tauri events + preview emissions share it) ──────────
  const busListeners = {};
  function busEmit(evt, payload) {
    (busListeners[evt] || []).forEach((f) => { try { f({ payload }); } catch (e) { console.error(e); } });
  }

  // Browser backend (browser/registry.js, loaded before this file in the PWA).
  // Only consulted when there is NO Tauri backend — the native app's commands
  // always win. An absent or empty registry means plain preview, as ever.
  const browserHas = (cmd) =>
    !hasBackend && !!(window.PosternBrowser && window.PosternBrowser.has(cmd));

  const api = (P.api = {
    hasBackend, // Tauri present — the native app (unchanged meaning)
    // Which backend answers real commands right now. 'browser' requires at
    // least one actually-registered browser command; registration is gated on
    // the real capability (wasm golden vector, /rpc), so this never overclaims.
    get backendKind() {
      if (hasBackend) return "tauri";
      const B = window.PosternBrowser;
      return B && B.list().length > 0 ? "browser" : "preview";
    },
    isReal: (cmd) => (hasBackend && REAL.has(cmd)) || browserHas(cmd),

    async invoke(cmd, args = {}) {
      if (hasBackend && REAL.has(cmd)) return T.core.invoke(cmd, args);
      if (browserHas(cmd)) return window.PosternBrowser.call(cmd, args);
      const h = preview[cmd];
      if (!h) throw new Error(`no handler for '${cmd}'`);
      return h(args);
    },

    listen(evt, cb) {
      (busListeners[evt] = busListeners[evt] || []).push(cb);
      if (hasBackend && T.event && typeof T.event.listen === "function") {
        T.event.listen(evt, cb).catch(() => {});
      }
    },
  });

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  // ═════════════════════════════════════════════════════════════════════
  // PREVIEW ENGINES — every function below is a stub. Honest, local, and
  // labeled in the UI. Data shapes mirror the real Rust cores' public APIs.
  // ═════════════════════════════════════════════════════════════════════
  const preview = {};

  // ── preview node + chain simulation ─────────────────────────────────────
  const simNode = {
    running: false, pid: null, height: 12873, peers: 0, mempool: 2, timer: null,
    blocks: [], // recent simulated blocks, newest first
  };
  function simBlock(height) {
    return {
      height,
      hash: UI.randHex(32),
      time: Math.floor(Date.now() / 1000),
      txs: 1 + Math.floor(Math.random() * 5),
      size: 900 + Math.floor(Math.random() * 4200),
      miner: "bloch1q" + UI.randHex(8),
    };
  }
  function simTick() {
    if (!simNode.running) return;
    // mempool churn
    simNode.mempool = Math.max(0, simNode.mempool + (Math.random() < 0.5 ? 1 : -1));
    simNode.peers = 6 + Math.floor(Math.random() * 5);
    if (Math.random() < 0.45) {
      simNode.height += 1;
      const b = simBlock(simNode.height);
      simNode.blocks.unshift(b);
      simNode.blocks.length = Math.min(simNode.blocks.length, 40);
      busEmit("node-log", `[preview] ⛏ block ${b.height} sealed — ${b.txs} tx, ${b.size} B, hash ${b.hash.slice(0, 16)}…`);
    } else if (Math.random() < 0.3) {
      busEmit("node-log", `[preview] net: ${simNode.peers} peers, mempool ${simNode.mempool}`);
    }
  }

  preview.node_start = async ({ binary, rpcPort }) => {
    if (simNode.running) throw "node already running";
    simNode.running = true;
    simNode.pid = 40000 + Math.floor(Math.random() * 9999);
    if (!simNode.blocks.length) {
      for (let i = 0; i < 12; i++) simNode.blocks.push(simBlock(simNode.height - i));
    }
    busEmit("node-log", `[preview] ▶ SIMULATED node started (binary '${binary}', rpc :${rpcPort}) — no Tauri backend in this preview; nothing was spawned.`);
    simNode.timer = setInterval(simTick, 2000);
    return simNode.pid;
  };

  preview.node_stop = async () => {
    if (!simNode.running) throw "node not running";
    simNode.running = false;
    clearInterval(simNode.timer);
    busEmit("node-log", "[preview] ■ simulated node stopped");
  };

  preview.node_status = async () => ({ running: simNode.running, pid: simNode.pid });

  // ── preview JSON-RPC (mirrors the node's method names) ──────────────────
  preview.rpc = async ({ method, params }) => {
    await sleep(120 + Math.random() * 180);
    if (!simNode.running) throw `rpc ${method}: connection refused (preview — start the simulated node first)`;
    const ok = (result) => ({ jsonrpc: "2.0", id: 1, result });
    switch (method) {
      case "getnetworkinfo":
        return ok({ blocks: simNode.height, peers: simNode.peers, mempool: simNode.mempool, network: "testnet (preview)" });
      case "getblockcount":
        return ok(simNode.height);
      case "getrecentblocks":
        return ok(simNode.blocks.slice(0, Math.min(params?.[0] ?? 15, 40)));
      case "getblockbyheight": {
        const h = Number(params?.[0]);
        const b = simNode.blocks.find((x) => x.height === h) || simBlock(h);
        return ok(b);
      }
      case "getblock": {
        const b = simNode.blocks.find((x) => x.hash === params?.[0]);
        if (!b) throw "block not found (preview only tracks recent simulated blocks)";
        return ok(b);
      }
      case "getbalance":
      case "getaddressinfo": {
        const addr = String(params?.[0] || "");
        let acc = 0;
        for (const c of addr) acc = (acc * 31 + c.charCodeAt(0)) >>> 0;
        const balance = acc % 5_000_000;
        return ok(method === "getbalance" ? balance : { address: addr, balance, utxos: 1 + (acc % 4), txs: 2 + (acc % 9) });
      }
      case "getdaginfo":
        return ok({ tips: 1 + Math.floor(Math.random() * 3), blue_score: simNode.height, k: 8 });
      case "getchainstats":
        return ok({ height: simNode.height, difficulty: (3.2 + Math.random()).toFixed(4), hashrate: `${(84 + Math.random() * 9).toFixed(1)} kH/s`, supply: simNode.height * 50 });
      case "getpeers":
        return ok(Array.from({ length: simNode.peers }, (_, i) => ({ addr: `[preview-peer-${i}].onion:8646`, latency_ms: 40 + Math.floor(Math.random() * 400) })));
      default:
        throw `rpc ${method}: method not simulated in preview`;
    }
  };

  preview.rpc_tor = async ({ endpoint, method, params }) => {
    // Simulated Arti bootstrap: first call is slow, later calls reuse "circuits".
    if (!preview._torReady) {
      P.setState({ tor: "bootstrapping" });
      busEmit("node-log", "[preview] tor: simulating Arti bootstrap…");
      await sleep(2200);
      preview._torReady = true;
    }
    P.setState({ tor: "ready" });
    busEmit("node-log", `[preview] tor: simulated circuit → ${endpoint} (${method})`);
    return preview.rpc({ method, params });
  };

  // ── preview wallet (deterministic from mnemonic; NOT the real derivation) ─
  const WORDS = ("abandon anchor arch armor atlas autumn basalt beacon birch bloom bolt border bridge canyon cedar chorus cipher citadel cliff comet copper coral crest crystal delta drift dusk ember falcon fern flint forge fossil garnet glacier granite grove harbor hollow horizon ink iron isle jade juniper keel kestrel lantern ledge linen lunar maple marble meadow mesa mica midnight moss north oak obsidian onyx opal orbit osprey oxide pearl pike pine prairie quarry quartz raven reef ridge river rune russet saber sage sequoia shale shore silver slate solstice sparrow spruce steel summit thicket thorn tide timber trellis tundra umber vale vault violet walnut wharf willow winter zenith").split(" ");
  const CHARSET = "qpzry9x8gf2tvdw0s3jn54kh6ce7mua";

  async function seedFromPhrase(phrase) {
    return UI.sha256(UI.utf8("postern-preview:" + phrase.trim().toLowerCase()));
  }
  async function previewAddress(phrase, testnet, index) {
    const seed = await seedFromPhrase(phrase + "/" + index);
    let s = "";
    for (let i = 0; i < 32; i++) s += CHARSET[seed[i] % CHARSET.length];
    return (testnet ? "tbloch1q" : "bloch1q") + s;
  }

  preview.wallet_generate = async ({ testnet }) => {
    const idx = crypto.getRandomValues(new Uint32Array(12));
    const mnemonic = Array.from(idx, (v) => WORDS[v % WORDS.length]).join(" ");
    const address = await previewAddress(mnemonic, testnet, 0);
    const pubkey = UI.toHex(await seedFromPhrase("pk:" + mnemonic));
    return { mnemonic, address, pubkey };
  };

  preview.wallet_from_mnemonic = async ({ phrase, testnet }) => {
    if (!phrase || phrase.trim().split(/\s+/).length < 12) throw "mnemonic must have at least 12 words";
    return {
      address: await previewAddress(phrase, testnet, 0),
      pubkey: UI.toHex(await seedFromPhrase("pk:" + phrase)),
    };
  };

  preview.wallet_address_at = async ({ mnemonic, testnet, index }) =>
    previewAddress(mnemonic, testnet, index);

  preview.wallet_send = async ({ to, amount }) => {
    await sleep(500);
    if (!simNode.running) throw "wallet send: node unreachable (preview — start the simulated node first)";
    if (!/^t?bloch1/.test(to)) throw "invalid address (preview expects bloch1…/tbloch1…)";
    simNode.mempool += 1;
    const txid = UI.toHex(await UI.sha256(UI.utf8(`tx:${to}:${amount}:${Date.now()}`)));
    busEmit("node-log", `[preview] tx accepted to mempool — ${txid.slice(0, 16)}… (${amount} sats)`);
    return txid;
  };

  // Import a bloch-cli wallet.json: NO honest preview. Decrypting a real
  // Argon2id/AES-256-GCM keystore and re-deriving the address to prove the
  // round-trip requires the `bloch` crate — natively, or via the browser
  // backend's WASM core (which registers these commands for real when it
  // loads). This preview fallback only runs when NEITHER is available, and it
  // throws a clear message instead of faking a decrypt.
  const importNeedsBackend = async () => {
    throw "Importing a bloch-cli wallet.json needs the native Postern Desktop app or the Postern PWA's WASM wallet core (not loaded here) — the preview engine cannot decrypt a real keystore.";
  };
  preview.wallet_import_keystore = importNeedsBackend;
  preview.wallet_import_hd = importNeedsBackend;
  preview.wallet_keystore_send = importNeedsBackend;

  // ═════════════════════════════════════════════════════════════════════
  // VAULT preview engine. This only ever runs when hasBackend is false (no
  // Tauri backend — e.g. iterating on the UI in a plain browser): inside the
  // real desktop app, vault_* is in REAL above and routes straight to the
  // native postern-vault Tauri commands (Argon2id + XChaCha20-Poly1305,
  // unaudited Rust — see desktop/src-tauri/src/main.rs), which this preview
  // engine never touches and cannot fake.
  //
  // Adopts the ONE postern-sdk wiring seam (globalThis.PosternSDK): the
  // Tauri webview has no CSP restriction, so if a build has loaded the wasm
  // core anyway (e.g. a relaxed-CSP dev shell without the native commands
  // wired up), the preview seals with that SAME REAL Argon2id + XChaCha20-
  // Poly1305 primitive instead of the classical stand-in. Absent that, we
  // keep the honest labeled stand-in: PBKDF2-SHA-256 (310k it.) → AES-256-
  // GCM. Dispatch is on the stored record's OWN kdf tag, never on current
  // seam state — a real-core vault can never be silently opened (or
  // downgraded) by the stand-in path. Sealed blob persists in localStorage;
  // unlocked entries live in memory.
  // ═════════════════════════════════════════════════════════════════════
  const VAULT_LS = "postern.preview.vault";
  const VAULT_AAD = "postern.desktop.vault.v1";
  const VAULT_KDF_STANDIN = "PBKDF2-SHA-256";
  const VAULT_KDF_REAL = "Argon2id-postern-sdk";
  const vaultMem = { key: null, entries: null, real: false }; // evicted on lock/panic

  const vaultSdk = () => (globalThis.PosternSDK && globalThis.PosternSDK.__postern) ? globalThis.PosternSDK : null;
  const vaultKdfReal = () => { const s = vaultSdk(); return !!(s && s.kdf && s.kdf.available); };

  async function vaultDeriveKeyStandin(passphrase, saltBytes) {
    const km = await crypto.subtle.importKey("raw", UI.utf8(passphrase), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: saltBytes, iterations: 310000, hash: "SHA-256" },
      km, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }
  async function vaultPersist() {
    // write-through: every mutation re-seals to disk, so panic() only has to evict RAM
    const stored = JSON.parse(localStorage.getItem(VAULT_LS));
    const pt = UI.utf8(JSON.stringify(vaultMem.entries));
    if (vaultMem.real) {                                    // REAL postern-sdk core path
      const blob = vaultSdk().kdf.seal(vaultMem.key, UI.utf8(VAULT_AAD), pt);
      localStorage.setItem(VAULT_LS, JSON.stringify({ kdf: VAULT_KDF_REAL, salt: stored.salt, blob: UI.toB64(blob) }));
      return;
    }
    const iv = UI.randBytes(12);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: UI.utf8(VAULT_AAD) }, vaultMem.key, pt));
    localStorage.setItem(VAULT_LS, JSON.stringify({ kdf: VAULT_KDF_STANDIN, salt: stored.salt, iv: UI.toB64(iv), ct: UI.toB64(ct) }));
  }
  function vaultCipherLabel() {                             // what actually sealed the current blob (honest, independent of live seam state)
    const stored = JSON.parse(localStorage.getItem(VAULT_LS) || "null");
    if (!stored) return null;
    return stored.kdf === VAULT_KDF_REAL
      ? "XChaCha20-Poly1305 (real Argon2id, via postern-sdk)"
      : "AES-256-GCM (PBKDF2-SHA-256 stand-in)";
  }
  function vaultState() {
    return {
      exists: !!localStorage.getItem(VAULT_LS),
      unlocked: !!vaultMem.key,
      count: vaultMem.entries ? Object.keys(vaultMem.entries).length : 0,
      cipher: vaultCipherLabel(),
    };
  }
  function vaultBroadcast() { P.setState({ vault: vaultState() }); }

  preview.vault_status = async () => vaultState();

  preview.vault_create = async ({ passphrase }) => {
    if (localStorage.getItem(VAULT_LS)) throw "a vault already exists — unlock it or discard it first";
    if (!passphrase || passphrase.length < 8) throw "passphrase must have at least 8 characters";
    if (vaultKdfReal()) {
      const s = vaultSdk();
      const salt = s.kdf.generateSalt();
      vaultMem.key = s.kdf.deriveKey(UI.utf8(passphrase), salt);
      vaultMem.real = true;
      vaultMem.entries = {};
      localStorage.setItem(VAULT_LS, JSON.stringify({ kdf: VAULT_KDF_REAL, salt: UI.toB64(salt), blob: "" }));
    } else {
      const salt = UI.randBytes(16);
      vaultMem.key = await vaultDeriveKeyStandin(passphrase, salt);
      vaultMem.real = false;
      vaultMem.entries = {};
      localStorage.setItem(VAULT_LS, JSON.stringify({ kdf: VAULT_KDF_STANDIN, salt: UI.toB64(salt), iv: "", ct: "" }));
    }
    await vaultPersist();
    vaultBroadcast();
    return vaultState();
  };

  preview.vault_unlock = async ({ passphrase }) => {
    const stored = JSON.parse(localStorage.getItem(VAULT_LS) || "null");
    if (!stored) throw "no vault exists yet";
    if (stored.kdf === VAULT_KDF_REAL) {                    // sealed by the real core — never downgrade
      if (!vaultKdfReal()) throw "this vault was sealed by the real postern-sdk Argon2id core, which isn't loaded here — open it inside a host shell that installs globalThis.PosternSDK.";
      const s = vaultSdk();
      try {
        const key = s.kdf.deriveKey(UI.utf8(passphrase), UI.fromB64(stored.salt));
        const pt = s.kdf.open(key, UI.utf8(VAULT_AAD), UI.fromB64(stored.blob));
        vaultMem.key = key; vaultMem.real = true;
        vaultMem.entries = JSON.parse(UI.utf8dec(pt));
      } catch (e) {
        if (/postern-sdk|host shell/.test(String(e))) throw e;
        throw "wrong passphrase (AEAD authentication failed)";
      }
      vaultBroadcast();
      return vaultState();
    }
    // PBKDF2-SHA-256 stand-in (also the legacy no-AAD format written before this seam existed)
    const key = await vaultDeriveKeyStandin(passphrase, UI.fromB64(stored.salt));
    try {
      const params = { name: "AES-GCM", iv: UI.fromB64(stored.iv) };
      if (stored.kdf) params.additionalData = UI.utf8(VAULT_AAD); // legacy blobs (no kdf tag) had no AAD
      const pt = await crypto.subtle.decrypt(params, key, UI.fromB64(stored.ct));
      vaultMem.key = key; vaultMem.real = false;
      vaultMem.entries = JSON.parse(UI.utf8dec(new Uint8Array(pt)));
    } catch {
      throw "wrong passphrase (AEAD authentication failed)";
    }
    vaultBroadcast();
    return vaultState();
  };

  preview.vault_lock = async () => {
    if (vaultMem.real && vaultMem.key && typeof vaultMem.key.free === "function") { try { vaultMem.key.free(); } catch {} }
    vaultMem.key = null;
    vaultMem.entries = null;
    vaultMem.real = false;
    vaultBroadcast();
    return vaultState();
  };

  /** Panic Lock (postern-panic mirror): instant re-lock. Evicts key + secrets
      from memory; ciphertext at rest is untouched — nothing destroyed. */
  preview.panic = preview.vault_lock;

  preview.vault_list = async () => {
    if (!vaultMem.key) throw "vault is locked";
    return Object.keys(vaultMem.entries).sort();
  };
  preview.vault_get = async ({ name }) => {
    if (!vaultMem.key) throw "vault is locked";
    if (!(name in vaultMem.entries)) throw `no secret '${name}'`;
    return vaultMem.entries[name];
  };
  preview.vault_put = async ({ name, secret }) => {
    if (!vaultMem.key) throw "vault is locked";
    vaultMem.entries[name] = secret;
    await vaultPersist();
    vaultBroadcast();
  };
  preview.vault_remove = async ({ name }) => {
    if (!vaultMem.key) throw "vault is locked";
    delete vaultMem.entries[name];
    await vaultPersist();
    vaultBroadcast();
  };
  preview.vault_discard = async () => {
    if (vaultMem.real && vaultMem.key && typeof vaultMem.key.free === "function") { try { vaultMem.key.free(); } catch {} }
    localStorage.removeItem(VAULT_LS);
    vaultMem.key = null;
    vaultMem.entries = null;
    vaultMem.real = false;
    vaultBroadcast();
  };

  // ═════════════════════════════════════════════════════════════════════
  // COURIER preview engine — the payload seal flow with a REAL asymmetric
  // KEM+AEAD, but classical: ECDH P-256 + HKDF + AES-256-GCM (WebCrypto).
  // The real core (postern-courier) uses ML-KEM-768 + XChaCha20-Poly1305
  // (post-quantum) and rides an ephemeral Tor onion service (postern-tor).
  // Payload shape mirrors SealedPayload { kem_ct, nonce, ciphertext }.
  // ═════════════════════════════════════════════════════════════════════
  const ECDH = { name: "ECDH", namedCurve: "P-256" };

  preview.courier_generate_recipient = async () => {
    const kp = await crypto.subtle.generateKey(ECDH, true, ["deriveBits"]);
    return {
      public: UI.toB64(new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey))),
      secret: UI.toB64(new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey))),
    };
  };

  async function courierAesKey(privKey, pubKey) {
    const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: pubKey }, privKey, 256);
    const hk = await crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(16), info: UI.utf8("postern-courier-preview") },
      hk, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }

  preview.courier_seal = async ({ recipientPublic, bytesB64, name }) => {
    const rPub = await crypto.subtle.importKey("raw", UI.fromB64(recipientPublic), ECDH, false, []);
    const eph = await crypto.subtle.generateKey(ECDH, true, ["deriveBits"]);
    const key = await courierAesKey(eph.privateKey, rPub);
    const nonce = UI.randBytes(12);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, UI.fromB64(bytesB64)));
    return {
      v: "postern-courier-preview-1",
      name: name || "payload.bin",
      kem_ct: UI.toB64(new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey))),
      nonce: UI.toB64(nonce),
      ciphertext: UI.toB64(ct),
    };
  };

  preview.courier_open = async ({ recipientSecret, sealed }) => {
    const priv = await crypto.subtle.importKey("pkcs8", UI.fromB64(recipientSecret), ECDH, false, ["deriveBits"]);
    const ephPub = await crypto.subtle.importKey("raw", UI.fromB64(sealed.kem_ct), ECDH, false, []);
    const key = await courierAesKey(priv, ephPub);
    try {
      const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: UI.fromB64(sealed.nonce) }, key, UI.fromB64(sealed.ciphertext));
      return { name: sealed.name || "payload.bin", bytesB64: UI.toB64(new Uint8Array(pt)) };
    } catch {
      throw "open failed: wrong recipient key or corrupted payload (AEAD auth)";
    }
  };

  // ═════════════════════════════════════════════════════════════════════
  // MESSENGER / VESTNIK — deliberately NO preview engine. The old
  // Megolm-shaped AES-GCM demo engine was removed with the Vestnik shell:
  // the pane no longer simulates a messenger session, and neither the
  // vestnik_* custody commands nor the vestnik_* matrix-client commands
  // (vestnik_matrix_status/login/session_seal/restore/sync_once/rooms/
  // send/logout) may ever be faked — a pretend vault or a pretend matrix
  // client would be an overclaim. Without a backend the pane renders
  // preview-disabled and any vestnik invoke throws honestly; with a
  // backend built without `vestnik-matrix`, the backend itself returns the
  // clean "not built with matrix support" error and status.built === false.
  // ═════════════════════════════════════════════════════════════════════

  // ═════════════════════════════════════════════════════════════════════
  // KEYS preview engine — real WebAuthn-style ES256 (ECDSA P-256) via
  // WebCrypto. Real signatures; but in the real product the private key is
  // sealed in the TEE-wrapped Postern Vault, never kept in localStorage.
  // ═════════════════════════════════════════════════════════════════════
  const KEYS_LS = "postern.preview.keys";
  const ES256 = { name: "ECDSA", namedCurve: "P-256" };
  const keysLoad = () => JSON.parse(localStorage.getItem(KEYS_LS) || "[]");
  const keysSave = (l) => localStorage.setItem(KEYS_LS, JSON.stringify(l));

  preview.keys_list = async () => keysLoad().map(({ priv, ...pub }) => pub);

  preview.keys_create = async ({ rpId }) => {
    if (!rpId || !rpId.trim()) throw "relying party id required (e.g. github.com)";
    const kp = await crypto.subtle.generateKey(ES256, true, ["sign", "verify"]);
    const cred = {
      credentialId: UI.randHex(16),
      rpId: rpId.trim().toLowerCase(),
      created: Date.now(),
      signCount: 0,
      publicKey: UI.toB64(new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey))),
      priv: UI.toB64(new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey))),
    };
    const list = keysLoad();
    list.push(cred);
    keysSave(list);
    const { priv, ...pub } = cred;
    return pub;
  };

  preview.keys_sign = async ({ credentialId, challenge }) => {
    const cred = keysLoad().find((c) => c.credentialId === credentialId);
    if (!cred) throw "credential not found";
    const priv = await crypto.subtle.importKey("pkcs8", UI.fromB64(cred.priv), ES256, false, ["sign"]);
    const clientDataHash = await UI.sha256(UI.utf8(challenge));
    // authenticatorData: rpIdHash ‖ flags(0x01 user-present) ‖ signCount
    const rpIdHash = await UI.sha256(UI.utf8(cred.rpId));
    const authData = new Uint8Array(37);
    authData.set(rpIdHash, 0);
    authData[32] = 0x01;
    const count = cred.signCount + 1;
    new DataView(authData.buffer).setUint32(33, count);
    const signed = new Uint8Array([...authData, ...clientDataHash]);
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, priv, signed));
    // verify locally so the UI can show the roundtrip is sound
    const pub = await crypto.subtle.importKey("raw", UI.fromB64(cred.publicKey), ES256, false, ["verify"]);
    const valid = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pub, sig, signed);
    const list = keysLoad();
    list.find((c) => c.credentialId === credentialId).signCount = count;
    keysSave(list);
    return { signature: UI.toB64(sig), signCount: count, verifiedLocally: valid };
  };

  preview.keys_remove = async ({ credentialId }) => {
    keysSave(keysLoad().filter((c) => c.credentialId !== credentialId));
  };

  // ═════════════════════════════════════════════════════════════════════
  // HYGIENE preview engine — JPEG scrub is REAL (metadata segments actually
  // dropped, done locally); OOXML/ODF + PDF report what the Rust core
  // (postern-hygiene) would strip, without producing a cleaned file.
  // ═════════════════════════════════════════════════════════════════════
  preview.hygiene_scrub = async ({ name, bytesB64 }) => {
    const bytes = UI.fromB64(bytesB64);
    // JPEG: drop APP1 (EXIF/XMP), APP2 (ICC ext), APP13 (IPTC), COM segments
    if (bytes[0] === 0xff && bytes[1] === 0xd8) {
      const removed = [];
      const out = [0xff, 0xd8];
      let i = 2;
      while (i < bytes.length - 1) {
        if (bytes[i] !== 0xff) { out.push(...bytes.subarray(i)); break; } // entropy-coded data
        const marker = bytes[i + 1];
        if (marker === 0xda) { out.push(...bytes.subarray(i)); break; }  // SOS: rest is image
        const len = (bytes[i + 2] << 8) | bytes[i + 3];
        const seg = bytes.subarray(i, i + 2 + len);
        const names = { 0xe1: "APP1 (EXIF/XMP)", 0xe2: "APP2 (ICC ext)", 0xed: "APP13 (IPTC/Photoshop)", 0xfe: "COM (comment)" };
        if (names[marker]) removed.push(`${names[marker]} — ${len + 2} B`);
        else out.push(...seg);
        i += 2 + len;
      }
      return {
        kind: "jpeg", real: true, removed,
        cleanedB64: UI.toB64(new Uint8Array(out)),
        note: removed.length ? "metadata segments removed locally" : "no metadata segments found — already clean",
      };
    }
    // OOXML / ODF (ZIP)
    if (bytes[0] === 0x50 && bytes[1] === 0x4b) {
      return {
        kind: "ooxml", real: false,
        removed: [
          "docProps/core.xml → dc:creator (author)", "docProps/core.xml → cp:lastModifiedBy",
          "docProps/core.xml → revision, keywords, created/modified timestamps",
          "docProps/app.xml → Company, Manager", "docProps/custom.xml → all custom fields",
        ],
        note: "simulated report — the real scrub (postern-hygiene scrub_ooxml) needs the backend",
      };
    }
    if (UI.utf8dec(bytes.subarray(0, 5)) === "%PDF-") {
      return {
        kind: "pdf", real: false,
        removed: ["/Info dictionary → Author, Creator, Producer, Title, dates", "XMP metadata stream"],
        note: "simulated report — the real scrub (postern-hygiene scrub_pdf) needs the backend",
      };
    }
    throw `unsupported file type for '${name}' — hygiene handles OOXML/ODF, PDF and JPEG`;
  };

  // ═════════════════════════════════════════════════════════════════════
  // SEAL COMPANION preview engine — mirrors postern-seal-companion:
  // SelfAudit items + Verdict logic. The Falcon‖ML-DSA signature check and
  // the real posture probes need the backend, so the preview verdict is
  // honestly capped at UNVERIFIED.
  // ═════════════════════════════════════════════════════════════════════
  preview.seal_self_audit = async () => {
    await sleep(700);
    return {
      verdict: "unverified",
      items: [
        { name: "os_roothash", status: "unknown", detail: "dm-verity roothash needs the backend to read; compare against the published attested image" },
        { name: "tor_lockdown", status: "unknown", detail: "posture probe (all egress through Tor) requires the backend" },
        { name: "dns_leak", status: "unknown", detail: "leak probe requires the backend" },
        { name: "disk_encryption", status: "unknown", detail: "LUKS status requires the backend" },
        { name: "build_signature", status: "unknown", detail: "Falcon‖ML-DSA verification requires the backend (bloch_crypto)" },
      ],
    };
  };

  // ═════════════════════════════════════════════════════════════════════
  // PHONE-AS-SIGNER preview engine — mirrors the desktop requester backend
  // (src-tauri/src/pairing.rs). In-memory, honest, and clearly a preview:
  // there is no real phone, so the "peer" is a random stand-in key and the
  // SAS/transcript are computed with WebCrypto (SHA-256) to match the shapes
  // the Rust cores (courier fingerprint, seal-companion binding, consiglio
  // login transcript, postern-policy grants) produce. Desktop holds no key.
  // ═════════════════════════════════════════════════════════════════════
  const LOGIN_DOMAIN = "consiglio:wallet-login:v1";
  const pairMem = { pending: null, pairings: [], grants: [], requests: [], counter: 0, seq: 0 };
  const nextPairId = () => ++pairMem.seq;

  async function pvFingerprint(pubBytes) {
    // courier key_fingerprint: SHA-256(tag ‖ le64(len) ‖ pub)[..10] → 5 hex groups.
    const tag = UI.utf8("postern-courier/fingerprint/v2");
    const len = new Uint8Array(8);
    new DataView(len.buffer).setUint32(0, pubBytes.length, true);
    const d = await UI.sha256(new Uint8Array([...tag, ...len, ...pubBytes]));
    return [0, 2, 4, 6, 8].map((i) => UI.toHex(d.subarray(i, i + 2))).join("-");
  }
  async function pvSas(nonceBytes, a, b) {
    // seal-companion binding: report_data = SHA-256(nonce ‖ ordered(a)+ordered(b)).
    const cmp = (x, y) => { for (let i = 0; i < Math.min(x.length, y.length); i++) { if (x[i] !== y[i]) return x[i] - y[i]; } return x.length - y.length; };
    const [lo, hi] = cmp(a, b) <= 0 ? [a, b] : [b, a];
    const d = await UI.sha256(new Uint8Array([...nonceBytes, ...lo, ...hi]));
    const n = ((d[0] << 24) | (d[1] << 16) | (d[2] << 8) | d[3]) >>> 0;
    return String(n % 1000000).padStart(6, "0");
  }

  preview.pair_begin = async ({ lanHint, nickname }) => {
    // Preview stand-in: the real backend generates an ephemeral ML-KEM‖X25519
    // anchor inside postern-pairing and emits the crate's QR. Here we fake it.
    const pub = UI.randBytes(1600); // stand-in ephemeral channel pubkey
    const nonce = UI.randBytes(32);
    const hint = (lanHint && lanHint.trim()) || "mdns://_postern._tcp.local";
    const fingerprint = await pvFingerprint(pub);
    const noncePrefix = UI.toHex(nonce.subarray(0, 8));
    const qr = `PPQR|v1|${fingerprint}|${noncePrefix}|${hint}`;
    pairMem.pending = { pub, nonce, fingerprint, nickname: (nickname || "phone").trim() || "phone" };
    return { qr, fingerprint, channelBinding: fingerprint.slice(0, 16), lanHint: hint,
      note: "Ephemeral channel anchor only — no wallet key exists on this device. The phone scans this QR and returns its PairingInit; call pair_respond with it to derive the KEM-bound SAS (preview)." };
  };

  // The phone completed the hybrid KEM and returned its PairingInit; derive the
  // SAS from the (in preview, faked) shared secret. Real backend uses the crate.
  preview.pair_respond = async ({ pairingInitHex }) => {
    if (!pairMem.pending) throw "no pairing in progress — start with pair_begin";
    const peer = pairingInitHex ? UI.fromHex(pairingInitHex) : UI.randBytes(1600);
    const sas = await pvSas(pairMem.pending.nonce, pairMem.pending.pub, peer);
    pairMem.pending.peer = peer;
    pairMem.pending.sas = sas;
    return { sas, note: "Compare this SAS on BOTH screens — it is the KEM-bound MITM tripwire. Confirm only if the phone shows the SAME digits (preview)." };
  };

  // Fail-closed human gate: nothing is persisted unless userConfirmed === true.
  preview.pair_confirm = async ({ userConfirmed }) => {
    if (!pairMem.pending || pairMem.pending.sas == null) throw "no SAS to confirm yet — call pair_respond with the phone's PairingInit";
    if (!userConfirmed) { pairMem.pending = null; throw "SAS was NOT confirmed by the human — pairing aborted (fail-closed)"; }
    const { nickname, sas, peer, fingerprint } = pairMem.pending;
    const peerFp = await pvFingerprint(peer);
    const id = nextPairId();
    pairMem.pairings.push({ id, nickname, peerFingerprint: peerFp,
      channelBinding: fingerprint.slice(0, 16), sas, pairedAt: Math.floor(Date.now() / 1000), revoked: false });
    pairMem.pending = null;
    return { id, nickname, sas, peerFingerprint: peerFp, channelBinding: fingerprint.slice(0, 16),
      note: "Paired. The SAS was confirmed, so a TOFU record + a live forward-secret channel are pinned. Refusing the SAS persists nothing (preview)." };
  };

  preview.pair_cancel = async () => { pairMem.pending = null; return { ok: true }; };
  preview.pair_list = async () => ({ pairings: pairMem.pairings.map((p) => ({ ...p })) });
  preview.pair_unpair = async ({ id }) => {
    const p = pairMem.pairings.find((x) => x.id === id);
    if (!p) throw `no pairing #${id}`;
    p.revoked = true;
    pairMem.grants.filter((g) => g.subject === p.nickname).forEach((g) => (g.revoked = true));
    return { ok: true, revokedDevice: p.nickname };
  };

  preview.login_request = async ({ org, user, sessionId }) => {
    org = (org || "").trim(); user = (user || "").trim();
    if (!org || !user) throw "org and user are required for a wallet-login";
    if (!pairMem.pairings.some((p) => p.id === sessionId && !p.revoked)) throw "no live paired device for this session — pair a phone first";
    const nonce = UI.randBytes(32);
    const transcript = UI.toHex(await UI.sha256(UI.utf8(`${LOGIN_DOMAIN}|${org}|${user}|${UI.toHex(nonce)}`)));
    pairMem.counter += 1;
    const id = nextPairId();
    const req = { id, org, user, transcript, reqNonce: UI.randHex(32), counter: pairMem.counter, sessionId, status: "pending" };
    pairMem.requests.push(req);
    return { ...req, domain: LOGIN_DOMAIN,
      // The real backend composes via DesktopRequester + seals over the paired
      // channel; the phone opens THIS frame and signs the transcript.
      requestFrame: UI.randHex(96),
      summary: `Log in to “${org}” as “${user}” — this signature can only be a login, never a payment (domain-separated transcript).`,
      note: "Desktop holds NO key. It composed + sealed the request via the two shipped crates; the phone signs it after a user-presence check (preview)." };
  };

  preview.login_complete = async ({ id, approvalFrameHex, minutes }) => {
    minutes = Math.min(Math.max(Number(minutes) || 22, 1), 1440);
    const req = pairMem.requests.find((r) => r.id === id);
    if (!req) throw `no sign-request #${id}`;
    if (req.status === "approved") throw "this request is already completed";
    if (req.status === "rejected") throw "this request was rejected";
    // Real backend: open the sealed approval, match it, then VERIFY the phone's
    // hybrid Falcon‖ML-DSA signature over the transcript BEFORE minting (F-3).
    if (!approvalFrameHex) throw "no approval frame from the phone — nothing to verify (fail closed)";
    req.status = "approved";
    const dev = pairMem.pairings.find((p) => p.id === req.sessionId);
    const subject = dev ? dev.nickname : "phone";
    const expiry = new Date(Date.now() + minutes * 60000).toISOString();
    const gid = nextPairId();
    pairMem.grants.push({ id: gid, scope: `wallet-login:${req.org}`, subject, org: req.org,
      expiry, createdAt: Math.floor(Date.now() / 1000), revoked: false });
    return { grantId: gid, scope: `wallet-login:${req.org}`, subject, user: req.user, expiry,
      signatureVerified: true,
      note: "Phone signature VERIFIED over the login transcript (hybrid Falcon‖ML-DSA). Minted a time-boxed, revocable grant (preview)." };
  };

  preview.login_reject = async ({ id }) => {
    const req = pairMem.requests.find((r) => r.id === id);
    if (!req) throw `no sign-request #${id}`;
    req.status = "rejected";
    return { ok: true };
  };

  preview.grants_list = async () => {
    const now = Date.now();
    const grants = pairMem.grants.map((g) => {
      const remaining = Math.max(0, Math.floor((new Date(g.expiry).getTime() - now) / 1000));
      const expired = new Date(g.expiry).getTime() <= now;
      const allow = !g.revoked && !expired;
      return { id: g.id, scope: g.scope, subject: g.subject, org: g.org, expiry: g.expiry,
        createdAt: g.createdAt, remainingSecs: remaining, revoked: g.revoked, allow,
        reason: allow ? null : (g.revoked ? "grant revoked: treated as never given" : "grant expired: treated as never given") };
    });
    return { grants, enforcement: "integrity by construction: a userland, in-process check, not an OS sandbox or kernel boundary" };
  };

  preview.grant_revoke = async ({ id }) => {
    const g = pairMem.grants.find((x) => x.id === id);
    if (!g) throw `no grant #${id}`;
    g.revoked = true;
    return { ok: true };
  };

  preview.seal_issue_challenge = async () => UI.randHex(32);

  /** Peer-verify — JS mirror of verify_report(report, expected) → Verdict.
      Structural checks are real; the PQ signature check cannot run here. */
  preview.seal_verify_report = async ({ report, expected }) => {
    const checks = [];
    let verdict = "Genuine (structurally)";
    if (!report.os_roothash || !report.nonce || !report.signature) {
      return { verdict: "Malformed", checks: [{ name: "shape", ok: false, detail: "report must carry os_roothash, nonce, signature" }] };
    }
    const rootOk = report.os_roothash === expected.os_roothash;
    checks.push({ name: "os_roothash", ok: rootOk, detail: rootOk ? "matches expected attested image" : "MISMATCH — not the genuine build" });
    if (!rootOk) verdict = "RoothashMismatch";
    const nonceOk = report.nonce === expected.challenge;
    checks.push({ name: "nonce", ok: nonceOk, detail: nonceOk ? "fresh challenge echoed" : "STALE — possible replay" });
    if (rootOk && !nonceOk) verdict = "StaleNonce";
    checks.push({ name: "signature (Falcon‖ML-DSA)", ok: null, detail: "cannot verify in preview — requires the backend's PQ crypto" });
    return { verdict, checks, preview: true };
  };

})();
