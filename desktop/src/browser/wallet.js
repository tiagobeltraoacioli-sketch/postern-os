// browser/wallet.js — REAL wallet commands for the browser backend.
//
// Registers the wallet_* command set against the WASM build of the node's own
// bloch-crypto (browser/core.js), with the SAME argument/return shapes as the
// native Tauri commands (desktop/src-tauri/src/main.rs + walletjson.rs) — so
// the existing wallet pane works unchanged behind api.js's seam.
//
// Wired for REAL here:
//   wallet_generate         — bw_call new_mnemonic + wallet_from_mnemonic:
//                             real hybrid ML-DSA-65‖Falcon-1024 keygen.
//   wallet_from_mnemonic    — normalize_mnemonic + wallet_from_mnemonic.
//   wallet_import_keystore  — import_simple_wallet: real v2 EncryptedKeystore
//                             Argon2id/AES-256-GCM decrypt + address re-derive.
//   wallet_import_hd        — import_hd_wallet: real hd-wallet-v1 master-key path.
//   wallet_send             — rpc getutxos → build_and_sign_tx_from_mnemonic
//                             (signing is 100% LOCAL in wasm) → rpc
//                             sendrawtransaction. Only the address and the
//                             already-signed bytes ever cross /rpc.
//   wallet_keystore_send    — import_simple_wallet → rpc getutxos →
//                             build_and_sign_tx → rpc sendrawtransaction.
//   core_version            — honest "real hybrid-PQ core loaded" probe.
//
// Deliberately NOT registered:
//   wallet_address_at — the WASM core has NO index-derivation op
//     (keypair_from_mnemonic takes no index). The pane's preview engine stays
//     the labelled fallback; inventing a binding here would be a fabricated
//     non-derivation. Do not add one until a real core op exists.
//
// FAIL-LOUD gate: nothing is registered until (a) the wasm instantiates AND
// (b) the keygen GOLDEN VECTOR matches the hash the node pins
// (crates/bloch-crypto/src/crypto/mod.rs, same assertion as
// apps/mobile-wallet/test-wasm.mjs). If either fails, the registry stays
// empty for wallet_*, api.isReal() stays false, and the panes show their
// labelled preview badges — never a half-dead "live" one.
//
// The send paths reach the node ONLY through PosternBrowser.call("rpc", …):
// the /rpc proxy layer registers that command; this file never imports it.
// Classic script, no bundler. Load AFTER registry.js + core.js.
(function () {
  "use strict";
  if (window.PosternBrowserWallet) return; // idempotent across double-include

  const T = window.__TAURI__;
  const hasTauri = !!(T && T.core && typeof T.core.invoke === "function");
  const reg = window.PosternBrowser;
  const core = window.PosternBrowserCore;

  // Inside the native app the Tauri backend owns these commands — the browser
  // backend must not compete with (or shadow) the real native path.
  if (hasTauri || !reg || !core) {
    window.PosternBrowserWallet = { whenRegistered: Promise.resolve(false) };
    return;
  }

  // The node's pinned KAT: keygen(seed=0x11*32) → SHA3-256(ML-DSA-65 pk half).
  const GOLDEN_SEED_HEX = "11".repeat(32);
  const GOLDEN_MLDSA_PK_HASH =
    "bb34618ab597cc394fcfa9c9c5791d4767baacce3648285e8069742a55e2de37";

  // Fee tiers → sats, mirror of walletjson.rs fee_sats_for (bloch-cli defaults).
  const FEE_SATS = { slow: "50000", medium: "100000", next: "200000" };
  const feeSats = (tier) => FEE_SATS[tier] || FEE_SATS.medium;

  // JSON-RPC via the registry's `rpc` command (the /rpc same-origin proxy
  // layer registers it). Unwraps the JSON-RPC envelope; throws on rpc errors
  // and — loudly — when no rpc layer is registered at all.
  async function rpc(url, method, params, allowCustom) {
    const r = await reg.call("rpc", { url, method, params, allowCustom: !!allowCustom });
    if (r && r.error != null) throw new Error(`rpc ${method}: ${JSON.stringify(r.error)}`);
    return r ? r.result : undefined;
  }

  // getutxos result → the UtxoIn shape the wasm signer takes. Mirrors the
  // parsing in walletjson.rs (result.utxos, or a bare array).
  // STRICT numeric parsing for anything that goes into a signed transaction.
  // The previous `Number(u.index) | 0` collapsed an unparseable or >2^31 vout to
  // 0 — that does not mispay, it SIGNS THE WRONG OUTPOINT. And `Number(u.value)
  // || 0` both lost precision above 2^53 (9007199254740993 -> ...992, one sat,
  // silently) and turned garbage into a legitimate-looking 0-value UTXO. The
  // wasm signer takes these as decimal STRINGS, so there is no reason to round-
  // trip them through a float. Refuse instead of guessing.
  function strictU32(v, what) {
    const n = typeof v === "number" ? v : Number(String(v).trim());
    if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) {
      throw new Error(`${what}: expected a u32, got ${JSON.stringify(v)}`);
    }
    return n;
  }
  function strictSats(v, what) {
    const t = String(v).trim();
    if (!/^\d+$/.test(t)) throw new Error(`${what}: expected a decimal sat amount, got ${JSON.stringify(v)}`);
    const n = Number(t);
    // serde wants a real u64 here, and a JSON number above 2^53 cannot carry one
    // exactly (9007199254740993 arrives as ...992 — one sat, silently). REFUSE
    // rather than sign over a value we cannot represent. This is unreachable for
    // any realistic amount and is here so the failure is loud if it ever is not.
    if (!Number.isSafeInteger(n)) {
      throw new Error(`${what}: ${t} exceeds the exactly-representable range — refusing to sign over a rounded value`);
    }
    return n;
  }

  function parseUtxos(res, address) {
    const list = (res && res.utxos) || (Array.isArray(res) ? res : []);
    const utxos = list.map((u) => ({
      txid: String(u.txid || ""),
      index: strictU32(u.index, "utxo.index"),
      value: strictSats(u.value, "utxo.value"),
    }));
    if (!utxos.length) throw new Error(`no spendable UTXOs for ${address}`);
    return utxos;
  }

  async function broadcast(url, allowCustom, signed) {
    await rpc(url, "sendrawtransaction", [signed.raw_hex], allowCustom);
    return signed.txid_hex;
  }

  function registerAll() {
    // Shapes mirror desktop/src-tauri/src/main.rs wallet_generate.
    reg.register("wallet_generate", ({ testnet }) => {
      const { mnemonic } = core.call("new_mnemonic", { words: 24 });
      const w = core.call("wallet_from_mnemonic", { mnemonic, testnet: !!testnet });
      return { mnemonic, address: w.address, pubkey: w.public_key_hex };
    });

    reg.register("wallet_from_mnemonic", ({ phrase, testnet }) => {
      // normalize_mnemonic for input hygiene (whitespace/case), then derive.
      const { mnemonic } = core.call("normalize_mnemonic", { mnemonic: String(phrase || "") });
      const w = core.call("wallet_from_mnemonic", { mnemonic, testnet: !!testnet });
      return { address: w.address, pubkey: w.public_key_hex };
    });

    // Shapes mirror walletjson.rs. Like the native command, the private key is
    // NOT returned to the UI layer — spending re-decrypts via
    // wallet_keystore_send from the same ciphertext + password.
    reg.register("wallet_import_keystore", ({ json, password }) => {
      const r = core.call("import_simple_wallet", { json, password });
      const k = r.keys[0];
      return {
        kind: "simple",
        address: k.address,
        pubkey: k.public_key_hex,
        network: r.network,
        verified: true, // fact, not hope: the core re-derived address == stored address
      };
    });

    reg.register("wallet_import_hd", ({ json, mnemonic, passphrase, password }) => {
      const r = core.call("import_hd_wallet", {
        json, mnemonic, passphrase: passphrase || "", password,
      });
      return {
        kind: "hd",
        network: r.network,
        verified: true,
        addresses: r.keys.map((k) => ({ index: k.index, address: k.address, label: k.label })),
      };
    });

    // KEY BOUNDARY (same as the native command): the mnemonic/keystore is used
    // to SIGN locally inside the wasm; only getutxos(address) and the signed
    // sendrawtransaction bytes cross the rpc layer.
    // The two SEND paths are registered ONLY when the rpc layer is present.
    // Registering IS the claim of realness: api.isReal("wallet_send") drives the
    // pane's "live · signed on-device" badge, and without a registered `rpc`
    // command every send rejects at broadcast. A live badge over a Send button
    // that always throws is exactly the overclaim this backend exists to avoid.
    // Signing itself is local either way; it is the broadcast half that needs rpc.
    if (!reg.has("rpc")) {
      // No rpc layer: keygen/import stay real above, sends stay preview. Silent
      // by design — the pane reads isReal() and renders its labelled preview.
    } else {
    reg.register("wallet_send", async ({ rpcUrl, mnemonic, testnet, to, amount, fee, allowCustom }) => {
      const w = core.call("wallet_from_mnemonic", { mnemonic, testnet: !!testnet });
      const utxosRes = await rpc(rpcUrl, "getutxos", [w.address], allowCustom);
      const utxos = parseUtxos(utxosRes, w.address);
      const signed = core.call("build_and_sign_tx_from_mnemonic", {
        mnemonic, testnet: !!testnet, to,
        amount_sats: String(amount), fee_sats: feeSats(fee), utxos,
      });
      return broadcast(rpcUrl, allowCustom, signed);
    });

    reg.register("wallet_keystore_send", async ({ json, password, rpcUrl, to, amount, fee, allowCustom }) => {
      const imp = core.call("import_simple_wallet", { json, password });
      const k = imp.keys[0];
      const utxosRes = await rpc(rpcUrl, "getutxos", [k.address], allowCustom);
      const utxos = parseUtxos(utxosRes, k.address);
      const signed = core.call("build_and_sign_tx", {
        secret_hex: k.private_key_hex, public_hex: k.public_key_hex, address: k.address,
        to, amount_sats: String(amount), fee_sats: feeSats(fee), utxos,
      });
      return broadcast(rpcUrl, allowCustom, signed);
    });
    }

    // Honest capability probe: "real hybrid-PQ core loaded, version X".
    reg.register("core_version", () => core.call("core_version", {}));
  }

  const whenRegistered = core
    .loadCore()
    .then(() => {
      // Golden-vector gate: prove WASM keygen == node keygen BEFORE claiming
      // any wallet command is real. A mismatched core registers nothing.
      const { hash } = core.call("debug_seed_mldsa_pk_hash", { seed_hex: GOLDEN_SEED_HEX });
      if (hash !== GOLDEN_MLDSA_PK_HASH) {
        throw new Error(
          "wallet core FAILED the node-pinned keygen golden vector (got " + hash +
          ") — refusing to register wallet commands");
      }
      registerAll();
      return true;
    })
    .catch((e) => {
      // Fail loud, register nothing: isReal() stays false and every wallet
      // pane falls back to its labelled preview engine.
      console.warn("[postern-browser] wallet core NOT available — panes stay in labelled preview:", e);
      return false;
    });

  window.PosternBrowserWallet = { whenRegistered };
})();
