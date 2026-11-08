// Postern Wallet — mobile · REAL crypto-core (WASM) tests. Run: node test-wasm.mjs
//
// Loads bloch_wallet_wasm.wasm — the wasm32-wasip1 build of the node's own
// bloch-crypto (ML-DSA-65 ‖ Falcon-1024) — through the SAME minimal WASI shim +
// C-ABI (bw_alloc/bw_call/bw_free) that wallet-live.js uses in the browser, and
// exercises the trust-bearing seam:
//
//   • golden vector: keygen(seed=0x11*32) SHA3-256(ML-DSA pk half) == the hash
//     the NODE pins in crates/bloch-crypto/src/crypto/mod.rs — byte-proof that
//     WASM keygen == node keygen (address a wallet derives == what bloch-cli shows)
//   • deterministic address derivation from a mnemonic (bloch1q / bloch1t)
//   • app keystore seal→open round-trip (Argon2id + XChaCha20-Poly1305)
//   • real transaction build+sign: a hybrid Falcon‖ML-DSA signature is produced
//     and the raw tx / txid are non-empty (sig length in the PQ ballpark)
//   • import round-trip: a v2 simple keystore produced by the SAME on-disk
//     crypto decrypts and its embedded address re-derives byte-identically
//
// No DOM, no network. Argon2id at CLI strength (256 MiB) runs a couple seconds.
import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import assert from "node:assert/strict";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

// ── load the wasm through the browser-identical WASI shim + C-ABI ────────────
const wasmBytes = readFileSync(new URL("./bloch_wallet_wasm.wasm", import.meta.url));
let mem;
const view = () => new DataView(mem.buffer);
const shim = {
  wasi_snapshot_preview1: {
    random_get: (ptr, len) => { crypto.getRandomValues(new Uint8Array(mem.buffer, ptr, len)); return 0; },
    environ_sizes_get: (c, s) => { const v = view(); v.setUint32(c, 0, true); v.setUint32(s, 0, true); return 0; },
    environ_get: () => 0,
    fd_write: (fd, iovs, n, nw) => { const v = view(); let t = 0; for (let i = 0; i < n; i++) t += v.getUint32(iovs + i * 8 + 4, true); v.setUint32(nw, t, true); return 0; },
    proc_exit: (code) => { throw new Error("wallet core aborted (proc_exit " + code + ")"); },
  },
};
const { instance } = await WebAssembly.instantiate(wasmBytes, shim);
const ex = instance.exports;
mem = ex.memory;
const encoder = new TextEncoder();
const decoder = new TextDecoder();
function call(method, args) {
  const mb = encoder.encode(method);
  const ab = encoder.encode(JSON.stringify(args || {}));
  const mp = ex.bw_alloc(mb.length); new Uint8Array(mem.buffer, mp, mb.length).set(mb);
  const ap = ex.bw_alloc(ab.length); new Uint8Array(mem.buffer, ap, ab.length).set(ab);
  const rp = ex.bw_call(mp, mb.length, ap, ab.length);
  const dv = new DataView(mem.buffer);
  const ok = dv.getUint8(rp);
  const len = dv.getUint32(rp + 1, true);
  const payload = decoder.decode(new Uint8Array(mem.buffer, rp + 5, len));
  ex.bw_free(rp, 5 + len); ex.bw_free(mp, mb.length); ex.bw_free(ap, ab.length);
  if (!ok) throw new Error(payload);
  return JSON.parse(payload);
}

let passed = 0;
const t = (name, fn) => { fn(); passed++; console.log("  ok — " + name); };

// ── the module is the real bloch-crypto ──────────────────────────────────────
t("core_version reports the hybrid PQ scheme", () => {
  const v = call("core_version", {}).version;
  assert.match(v, /ML-DSA-65/);
  assert.match(v, /Falcon-1024/);
});

// ── GOLDEN VECTOR: WASM keygen == node keygen (byte-identical) ────────────────
// The node pins seed=0x11*32 → SHA3-256(ML-DSA-65 pk) =
// bb34618ab597cc394fcfa9c9c5791d4767baacce3648285e8069742a55e2de37
// (crates/bloch-crypto/src/crypto/mod.rs + tests/kat_mldsa65.rs).
t("keygen golden vector matches the node's pinned KAT (WASM crypto == node crypto)", () => {
  const seedHex = "11".repeat(32);
  const { hash } = call("debug_seed_mldsa_pk_hash", { seed_hex: seedHex });
  assert.equal(hash, "bb34618ab597cc394fcfa9c9c5791d4767baacce3648285e8069742a55e2de37");
});

// ── deterministic mnemonic → address (real derivation) ───────────────────────
const MNEMONIC = "legal winner thank year wave sausage worth useful legal winner thank yellow";
t("wallet_from_mnemonic derives a stable, network-prefixed address", () => {
  const a = call("wallet_from_mnemonic", { mnemonic: MNEMONIC, testnet: true });
  const b = call("wallet_from_mnemonic", { mnemonic: MNEMONIC, testnet: true });
  assert.equal(a.address, b.address, "derivation is deterministic");
  assert.ok(a.address.startsWith("bloch1t"), "testnet prefix bloch1t: " + a.address);
  assert.equal(a.network, "testnet");
  // mainnet flips only the human-readable prefix, not the key.
  const m = call("wallet_from_mnemonic", { mnemonic: MNEMONIC, testnet: false });
  assert.ok(m.address.startsWith("bloch1q"), "mainnet prefix bloch1q: " + m.address);
  assert.equal(a.public_key_hex, m.public_key_hex, "same pubkey, different network prefix");
  // address_from_pubkey reproduces the same string from the pubkey alone.
  const derived = call("address_from_pubkey", { pubkey_hex: a.public_key_hex, testnet: true });
  assert.equal(derived.address, a.address);
});

// ── app keystore: Argon2id + XChaCha20-Poly1305 seal → open round-trip ───────
// The wallet's OWN keystore is XChaCha20-Poly1305 (192-bit nonce, no GCM
// nonce-reuse footgun, constant-time in WASM). AES-256-GCM is reserved for the
// bloch-cli interop path only (asserted by the import tests below).
t("keystore_seal → keystore_open round-trips (XChaCha20-Poly1305), wrong passphrase fails closed", () => {
  const secret = JSON.stringify({ kind: "mnemonic", mnemonic: MNEMONIC });
  const blob = call("keystore_seal", { plaintext: secret, passphrase: "correct horse battery" });
  assert.equal(blob.kdf, "argon2id");
  assert.equal(blob.cipher, "xchacha20poly1305");
  // 24-byte XChaCha nonce (base64 of 24 bytes == 32 chars)
  assert.equal(Buffer.from(blob.nonce_b64, "base64").length, 24);
  const opened = call("keystore_open", { blob: JSON.stringify(blob), passphrase: "correct horse battery" });
  assert.equal(opened.plaintext, secret);
  assert.throws(() => call("keystore_open", { blob: JSON.stringify(blob), passphrase: "wrong" }),
    /decrypt failed/);
  // a fresh seal of the same secret must use a fresh salt AND fresh nonce
  const blob2 = call("keystore_seal", { plaintext: secret, passphrase: "correct horse battery" });
  assert.notEqual(blob2.salt_b64, blob.salt_b64, "fresh random salt per seal");
  assert.notEqual(blob2.nonce_b64, blob.nonce_b64, "fresh random nonce per seal");
  // an app-keystore open must refuse a non-XChaCha cipher tag (never silently try AES)
  const spoof = JSON.stringify(Object.assign({}, blob, { cipher: "aes-256-gcm" }));
  assert.throws(() => call("keystore_open", { blob: spoof, passphrase: "correct horse battery" }),
    /unsupported app-keystore cipher/);
});

// ── real transaction build + hybrid signature ────────────────────────────────
t("build_and_sign_tx_from_mnemonic produces a real signed tx (non-empty raw + PQ-sized sig)", () => {
  const w = call("wallet_from_mnemonic", { mnemonic: MNEMONIC, testnet: true });
  const utxos = [{ txid: "aa".repeat(32), index: 0, value: 500000000 }];
  const signed = call("build_and_sign_tx_from_mnemonic", {
    mnemonic: MNEMONIC, testnet: true,
    to: w.address, // send to self (same network) — we only assert the sig is real
    amount_sats: "100000000", fee_sats: "10000", utxos,
  });
  assert.ok(/^[0-9a-f]+$/.test(signed.raw_hex) && signed.raw_hex.length > 200, "raw tx hex present");
  assert.equal(signed.txid_hex.length, 64, "32-byte txid");
  assert.ok(signed.input_count >= 1);
  // A hybrid Falcon-1024 ‖ ML-DSA-65 script_sig is thousands of bytes; a stub
  // would be tiny. This asserts a real PQ signature was embedded.
  assert.ok(signed.sig_len > 1500, "script_sig too small to be a real hybrid PQ sig: " + signed.sig_len);
});

t("cross-network send is refused (fail-closed)", () => {
  const testnet = call("wallet_from_mnemonic", { mnemonic: MNEMONIC, testnet: true });
  const mainnet = call("wallet_from_mnemonic", { mnemonic: MNEMONIC, testnet: false });
  assert.throws(() => call("build_and_sign_tx_from_mnemonic", {
    mnemonic: MNEMONIC, testnet: true, to: mainnet.address,
    amount_sats: "1", fee_sats: "1", utxos: [{ txid: "aa".repeat(32), index: 0, value: 100 }],
  }), /cross-network/);
  assert.ok(testnet.address !== mainnet.address);
});

// ── IMPORT ROUND-TRIP against REAL bloch-cli-format files ────────────────────
// testdata/cli-simple.json and cli-hd.json were produced by bloch-crypto itself
// (Keypair::save_encrypted and HdWallet::save — the exact code bloch-cli uses).
// The WASM importer must decrypt them and re-derive the SAME address the crate
// recorded — proving byte-for-byte on-disk-format + address compatibility.
const FX = JSON.parse(readFileSync(new URL("./testdata/cli-fixtures.json", import.meta.url), "utf8"));
const simpleJson = readFileSync(new URL("./testdata/cli-simple.json", import.meta.url), "utf8");
const hdJson = readFileSync(new URL("./testdata/cli-hd.json", import.meta.url), "utf8");

t("import a real bloch-cli SIMPLE keystore — address matches what the crate recorded", () => {
  const r = call("import_simple_wallet", { json: simpleJson, password: FX.password });
  assert.equal(r.kind, "simple");
  assert.equal(r.keys[0].address, FX.simple.address);
  // the re-derived address must also match the pubkey the file carried
  const d = call("address_from_pubkey", { pubkey_hex: r.keys[0].public_key_hex, testnet: true });
  assert.equal(d.address, FX.simple.address);
});

t("import a real bloch-cli HD wallet — primary address + mnemonic match", () => {
  const r = call("import_hd_wallet", { json: hdJson, mnemonic: FX.hd.mnemonic, passphrase: "", password: FX.password });
  assert.equal(r.kind, "hd");
  assert.equal(r.network, FX.hd.network);
  assert.equal(r.mnemonic, FX.hd.mnemonic);
  assert.equal(r.keys[0].address, FX.hd.primary_address);
});

t("import fails closed on wrong password / wrong mnemonic", () => {
  assert.throws(() => call("import_simple_wallet", { json: simpleJson, password: "wrong" }), /decrypt failed/);
  const wrongMnem = "legal winner thank year wave sausage worth useful legal winner thank yellow";
  assert.throws(() => call("import_hd_wallet", { json: hdJson, mnemonic: wrongMnem, passphrase: "", password: FX.password }));
});

console.log("\n  " + passed + " passed.");
