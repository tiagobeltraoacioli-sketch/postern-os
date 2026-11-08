// desktop/src/modules/panes.test.mjs — run with: node --test desktop/src/modules/
//
// Proves the "consistent states + per-pane privacy caveat + accurate badges"
// change across EVERY registered pane:
//
//   (a) every module registered in P.modules renders HTML carrying the one
//       shared, honest privacy-caveat marker (UI.privacyCaveat) — live or
//       preview, the caveat is unconditional;
//   (b) every module's declared `live` flag equals api.isReal(<gating cmd>)
//       in BOTH phases (no backend / fake __TAURI__), the gating command of
//       every live-capable pane appears in the backend's registered command
//       list mirrored below, and the never-live set (messenger_*,
//       seal_self_audit, courier_host_onion) stays "preview";
//   (c) UI.loadingState / UI.emptyState / UI.errorState escape hostile input
//       (`<script>`) and emit the consistent state-* classes;
//   (d) no .js source (including the new helpers) references an http(s)
//       origin beyond the localhost RPC default.
//
// ui.js / api.js / modules/*.js are classic (non-module) browser scripts.
// Like the sibling suite.test.mjs / vault.test.mjs, this file stubs the
// minimum window surface they touch and loads them via indirect eval.
// Everything here is a mock-level test: no network, no Tauri, no real
// backend — compile + unit/mock-test green is the bar, not a live run.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { webcrypto } from "node:crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;
globalThis.window = globalThis;

// ---- minimal localStorage polyfill ----
{
  const mem = new Map();
  globalThis.localStorage = {
    getItem: (k) => (mem.has(k) ? mem.get(k) : null),
    setItem: (k, v) => { mem.set(k, String(v)); },
    removeItem: (k) => { mem.delete(k); },
    clear: () => mem.clear(),
  };
}

// ---- minimal DOM stub (panes render into innerHTML strings) ----
function stubEl() {
  return {
    innerHTML: "", value: "", textContent: "", title: "", disabled: false,
    checked: false, hidden: false, isConnected: false,
    style: {}, dataset: {}, files: [],
    classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
    addEventListener() {}, appendChild() {}, removeChild() {}, remove() {}, focus() {},
    querySelector: () => stubEl(),
    querySelectorAll: () => [],
  };
}
globalThis.document = {
  createElement: () => stubEl(),
  getElementById: () => stubEl(),
  querySelector: () => stubEl(),
  querySelectorAll: () => [],
  body: stubEl(),
  documentElement: stubEl(),
};

const here = path.dirname(fileURLToPath(import.meta.url));
const src = (rel) => readFileSync(path.join(here, rel), "utf8");
const load = (rel) => (0, eval)(src(rel));

// ── constants ──────────────────────────────────────────────────────────────
// Fixed marker text of UI.privacyCaveat — asserted verbatim; never weaken it.
const CAVEAT_MARKER =
  "UNAUDITED · hardened, not anonymous — metadata (who talks to whom, when) is not hidden; not a TEE until real hardware; zero-value pre-mainnet testnet.";
const ADVANCED_GROUP = "Advanced · testnet (zero value)";

// Mirror of the backend's registered command list — the generate_handler!
// block in desktop/src-tauri/src/main.rs. api.js's REAL set must be a
// subset of this: a command may only claim "live" if the backend really
// registers it.
const BACKEND_REGISTERED = new Set([
  // Advanced / testnet (zero value): node + wallet
  "node_start", "node_stop", "node_status", "rpc", "rpc_tor",
  "wallet_generate", "wallet_from_mnemonic", "wallet_address_at", "wallet_send",
  // Import a bloch-cli wallet.json (walletjson.rs)
  "wallet_import_keystore", "wallet_import_hd", "wallet_keystore_send",
  // Vault + Panic (vault.rs)
  "vault_status", "vault_create", "vault_unlock", "vault_lock",
  "vault_list", "vault_get", "vault_put", "vault_remove", "vault_discard",
  "vault_totp_code", "panic",
  // OS-keychain unlock (vault.rs) — registered unconditionally; without the
  // opt-in `vault-keychain` cargo feature they return a clean "not built
  // with keychain support" error (never a silent no-op).
  "vault_keychain_enable", "vault_unlock_keychain", "vault_keychain_forget",
  // Hygiene (hygiene.rs)
  "hygiene_scrub",
  // Quarantine (quarantine.rs) — the mirror of hygiene (receive side)
  "quarantine_rebuild",
  // Phone-as-signer, desktop requester side (pairing.rs)
  "pair_begin", "pair_respond", "pair_confirm", "pair_cancel", "pair_list", "pair_unpair",
  "login_request", "login_complete", "login_reject", "grants_list", "grant_revoke",
  // Terem QEMU/QMP POC (terem.rs)
  "terem_create", "terem_start", "terem_qmp", "terem_status", "terem_stop", "terem_destroy",
  // Courier (courier.rs)
  "courier_generate_recipient", "courier_seal", "courier_open",
  // Keys (keys.rs)
  "keys_create", "keys_list", "keys_sign", "keys_remove",
  // Vestnik custody (vestnik.rs) — vault-custodied recipient secret + opaque
  // sealed SavedSession blob.
  "vestnik_recipient_init", "vestnik_session_store", "vestnik_session_load", "vestnik_session_open",
  // Vestnik matrix client (vestnik_client.rs) — registered ALWAYS; a
  // backend built without the opt-in `vestnik-matrix` cargo feature returns
  // a clean "not built with matrix support" error and vestnik_matrix_status
  // reports built:false, which is what the messenger pane gates on.
  "vestnik_matrix_status", "vestnik_login", "vestnik_session_seal", "vestnik_restore",
  "vestnik_sync_once", "vestnik_rooms", "vestnik_send", "vestnik_logout",
  // Encrypted Backup — LOCAL seal → DATA0 anchor → DirBackend store (backup.rs),
  // wired to the real bloch-data scaffold. The Filecoin upload does NOT use
  // bloch-data::LiveBackend (hand-rolled HTTP, no in-crate TLS — still a todo!()
  // stub): backup_filecoin_upload POSTs the already-SEALED ciphertext to
  // Lighthouse over real HTTPS at the Tauri layer (ureq + rustls), and
  // backup_filecoin_retrieve fetches it back from the gateway for verify.
  "backup_default_dir", "backup_seal", "backup_store", "backup_restore",
  "backup_filecoin_upload", "backup_filecoin_retrieve",
]);

// Commands that must NEVER be claimed live — no backend command exists.
// (messenger_* lost their preview engine with the Vestnik shell rework;
// vestnik_login moved OUT of this list when the vestnik-matrix client
// landed: it is now a registered command whose no-feature build answers
// with the clean not-built error.)
const NEVER_LIVE = [
  "messenger_create_session", "messenger_encrypt", "messenger_decrypt",
  "seal_self_audit", "courier_host_onion",
];

// Panes whose gating command is honestly absent from the backend, so their
// badge must read "preview" even with a Tauri backend present.
// "vestnik" joined this set when vestnik.rs became the sealed-session CUSTODY
// layer: the in-process Megolm commands this pane gates on
// (vestnik_create_session/…) are no longer registered by generate_handler!, so
// the pane honestly falls back to its own labelled AES-GCM preview engine. The
// LIVE messenger surface is messenger.js, which capability-gates on the real
// vestnik_matrix_status.built answer (see CAPABILITY_GATED_MODULES below).
const PREVIEW_ONLY_MODULES = new Set(["seal", "vestnik"]);

// Panes whose gate command IS backend-registered but whose live claim is
// additionally CAPABILITY-gated on a backend status answer (the messenger
// pane gates on vestnik_matrix_status.built — the vault-keychain
// available:false pattern). With this file's fake backend answering
// built:false (what a no-feature build truly returns), their live() must
// stay false even though isReal(gate) is true. The built:true flip is
// covered by messenger.test.mjs.
const STATUS_GATED_MODULES = new Set(["messenger"]);

const MODULE_FILES = [
  "node.js", "wallet.js", "pair.js", "explorer.js", "terem.js", "vault.js",
  "panic.js", "backup.js", "keys.js", "courier.js", "messenger.js", "vestnik.js",
  "hygiene.js", "quarantine.js", "seal.js",
];

// ── loader: one boot per phase (modules capture P.api at load time) ────────
load("../ui.js");
const P = window.Postern;
const UI = P.ui;

function bootPhase() {
  P.modules.length = 0; // fresh registry
  load("../api.js");    // re-reads window.__TAURI__ at load
  for (const f of MODULE_FILES) load(f);
  return { api: P.api, byId: Object.fromEntries(P.modules.map((m) => [m.id, m])) };
}

// Gating command per module, extracted from source: the badge contract is
// that `live:` is exactly `() => api.isReal("<cmd>")` — nothing ad hoc.
// A pane may instead declare itself preview OUTRIGHT with `live: () => false`.
// That is not a loophole — it is the stricter option, and it exists for the case
// swap.js hits: a pane whose gating command IS backend-registered (swap_quote is
// real, exact-U256, tested) but whose PRODUCT is not usable, because no L2 runs,
// WBLCH was never deployed and nothing can be signed or broadcast. Gating on
// isReal there would badge it "live" on every desktop build. Such a pane returns
// null here and is required to be in PREVIEW_ONLY_MODULES, so the badge
// assertions below still cover it — it can never silently claim live.
function gateOf(file) {
  const text = src(file);
  const matches = [...text.matchAll(/live:\s*\(\)\s*=>\s*api\.isReal\("([a-z_]+)"\)/g)];
  if (matches.length === 0 && /live:\s*\(\)\s*=>\s*false/.test(text)) return null;
  assert.equal(
    matches.length, 1,
    `${file} must declare exactly one 'live: () => api.isReal("<cmd>")' (or 'live: () => false' for an unconditional-preview pane)`,
  );
  return matches[0][1];
}
const GATES = Object.fromEntries(MODULE_FILES.map((f) => {
  const id = path.basename(f, ".js");
  return [id, gateOf(f)];
}));
// An unconditional-preview pane must say so in BOTH places, or the badge
// assertions below would skip it.
for (const [id, gate] of Object.entries(GATES)) {
  if (gate === null) {
    assert.ok(
      PREVIEW_ONLY_MODULES.has(id),
      `${id}.js declares 'live: () => false' but is missing from PREVIEW_ONLY_MODULES`,
    );
  }
}

async function renderPane(mod) {
  const root = stubEl();
  await mod.render(root);
  // stop timers/subscriptions some panes start (explorer poll, pair grant tick)
  if (typeof mod.onHide === "function") { try { mod.onHide(); } catch { /* stub */ } }
  return root.innerHTML;
}

// ═════════ Phase A — NO backend (plain browser preview) ═════════
const phaseA = bootPhase();

test("no backend: every declared live flag equals api.isReal(gate) and is false", () => {
  assert.equal(phaseA.api.hasBackend, false);
  for (const [id, gate] of Object.entries(GATES)) {
    const mod = phaseA.byId[id];
    assert.ok(mod, `module '${id}' registered`);
    assert.equal(mod.live(), phaseA.api.isReal(gate), `${id}: live() must equal isReal("${gate}")`);
    assert.equal(mod.live(), false, `${id}: nothing may claim live without a backend`);
  }
  for (const cmd of NEVER_LIVE) {
    assert.equal(phaseA.api.isReal(cmd), false, `${cmd} must never be live`);
  }
});

test("no backend: every registered pane renders the shared privacy caveat", async () => {
  assert.equal(P.modules.length, MODULE_FILES.length, "all panes registered");
  for (const mod of [...P.modules]) {
    const html = await renderPane(mod);
    assert.ok(html.includes(CAVEAT_MARKER), `${mod.id} pane must carry the pane-caveat marker text`);
    assert.ok(html.includes('class="pane-caveat"'), `${mod.id} pane must use the shared pane-caveat block`);
  }
});

test("no backend: node/wallet keep the zero-value banners; main.js keeps the collapsed Advanced group", async () => {
  for (const id of ["node", "wallet"]) {
    assert.equal(phaseA.byId[id].group, ADVANCED_GROUP, `${id} stays in the Advanced group`);
    const html = await renderPane(phaseA.byId[id]);
    assert.ok(/unaudited/i.test(html), `${id} must say unaudited`);
    assert.ok(/no value/i.test(html), `${id} must say coins have no value`);
  }
  // The node pane runs the CANONICAL mainnet chain (honest "mainnet-beta"
  // wording); the wallet keeps the zero-value testnet banner.
  const nodeHtml = await renderPane(phaseA.byId["node"]);
  assert.ok(/mainnet-beta/i.test(nodeHtml), "node must say mainnet-beta");
  const walletHtml = await renderPane(phaseA.byId["wallet"]);
  assert.ok(walletHtml.includes("Zero-value testnet"), "wallet must say Zero-value testnet");
  const main = src("../main.js");
  assert.ok(main.includes(ADVANCED_GROUP), "main.js knows the Advanced group label");
  assert.ok(main.includes('document.createElement("details")'), "collapsible <details> nav group");
  assert.match(main, /no `open` attr|collapsed/i, "documented as collapsed by default");
});

// ═════════ Phase B — fake Tauri backend ═════════
const FAKE_RESPONSES = {
  vault_status: () => ({ exists: false, unlocked: false, count: 0 }),
  vault_list: () => [],
  terem_status: () => ({ defined: false, running: false, pid: null }),
  keys_list: () => [],
  pair_list: () => ({ pairings: [] }),
  grants_list: () => ({ grants: [], enforcement: "test stub" }),
  node_status: () => ({ running: false, pid: null }),
  rpc: () => ({ jsonrpc: "2.0", id: 1, result: {} }),
  // What a backend built WITHOUT the `vestnik-matrix` cargo feature truly
  // answers: the command is registered, the capability is not compiled in.
  // The messenger pane must read this as "not live" (STATUS_GATED above).
  vestnik_matrix_status: () => ({ built: false, logged_in: false, honesty: "test stub" }),
};
const invoked = [];
globalThis.__TAURI__ = {
  core: {
    invoke: async (cmd, args) => {
      invoked.push({ cmd, args });
      return cmd in FAKE_RESPONSES ? FAKE_RESPONSES[cmd]() : null;
    },
  },
};
const phaseB = bootPhase();

test("fake backend: live flags follow their gates; seal stays preview; messenger stays capability-gated", async () => {
  assert.equal(phaseB.api.hasBackend, true, "fake __TAURI__ detected");
  for (const [id, gate] of Object.entries(GATES)) {
    const mod = phaseB.byId[id];
    if (STATUS_GATED_MODULES.has(id)) {
      // The gate command is registered, but live is additionally gated on
      // the backend's REAL capability answer. This fake backend reports
      // built:false (a no-feature build's honest answer), so even after a
      // render the pane must NOT claim live — registration alone proves
      // nothing (the not-built stub is registered too).
      assert.ok(BACKEND_REGISTERED.has(gate), `${gate} must appear in the backend's registered list`);
      assert.equal(phaseB.api.isReal(gate), true, `${gate} is registered → isReal`);
      await renderPane(mod); // refreshes the pane's cached status (built:false here)
      assert.equal(mod.live(), false,
        `${id}: built:false must keep live() false even though isReal("${gate}") is true`);
    } else if (PREVIEW_ONLY_MODULES.has(id)) {
      assert.equal(mod.live(), phaseB.api.isReal(gate), `${id}: live() must equal isReal("${gate}")`);
      assert.equal(mod.live(), false, `${id} has no backend command — must keep showing 'preview'`);
      assert.equal(BACKEND_REGISTERED.has(gate), false, `${gate} must not be in the backend mirror`);
    } else {
      assert.equal(mod.live(), phaseB.api.isReal(gate), `${id}: live() must equal isReal("${gate}")`);
      assert.equal(mod.live(), true, `${id}: gate '${gate}' is backend-registered → live`);
      assert.ok(BACKEND_REGISTERED.has(gate), `${gate} must appear in the backend's registered list`);
    }
  }
  for (const cmd of NEVER_LIVE) {
    assert.equal(phaseB.api.isReal(cmd), false, `${cmd} must never be live`);
  }
});

test("fake backend: api.js's REAL set is a subset of the backend's registered commands", () => {
  const apiSrc = src("../api.js");
  const block = apiSrc.match(/const REAL = new Set\(\[([\s\S]*?)\]\);/);
  assert.ok(block, "api.js declares its REAL set");
  const cmds = [...block[1].matchAll(/"([a-z_]+)"/g)].map((m) => m[1]);
  assert.ok(cmds.length > 0, "REAL set is non-empty");
  for (const cmd of cmds) {
    assert.ok(BACKEND_REGISTERED.has(cmd),
      `REAL set claims '${cmd}' but the backend's generate_handler mirror does not register it`);
    assert.equal(phaseB.api.isReal(cmd), true, `isReal("${cmd}") with backend present`);
  }
  for (const cmd of NEVER_LIVE) {
    assert.ok(!cmds.includes(cmd), `REAL set must not contain '${cmd}'`);
  }
});

test("fake backend: every registered pane still renders the shared privacy caveat", async () => {
  for (const mod of [...P.modules]) {
    const html = await renderPane(mod);
    assert.ok(html.includes(CAVEAT_MARKER), `${mod.id} pane must carry the pane-caveat marker text`);
  }
});

// ═════════ Vault pane — OS-keychain wiring (opt-in `vault-keychain`) ═══════
// Mock-level UI tests: what they prove is the WIRING (controls render only
// from a backend-reported `keychain` object, and its honesty text renders
// verbatim wherever controls do) — NOT hardware protection. The Rust side
// (desktop/src-tauri/tests/vault_core.rs) proves the status JSON carries
// KEYCHAIN_HONESTY verbatim; here a distinctive injected string stands in.
const KC_CMDS = ["vault_keychain_enable", "vault_unlock_keychain", "vault_keychain_forget"];
const KC_HONESTY_INJECTED =
  "keychain unlock is a SOFTWARE convenience, not hardware protection [test-injected verbatim marker]";
const kcStatus = (unlocked, available, enrolled) => ({
  exists: true, unlocked, count: 0,
  keychain: { available, enrolled, honesty: KC_HONESTY_INJECTED },
});

test("keychain: the three commands are backend-registered, REAL with a backend, never live without one", () => {
  for (const cmd of KC_CMDS) {
    assert.ok(BACKEND_REGISTERED.has(cmd), `${cmd} must be in the backend's registered mirror`);
    assert.equal(phaseA.api.isReal(cmd), false, `${cmd} must not claim live without a backend`);
    assert.equal(phaseB.api.isReal(cmd), true, `${cmd} must be REAL with a backend`);
  }
});

test("keychain: deliberately NO preview engine — a faked OS keychain would be an overclaim", async () => {
  for (const cmd of KC_CMDS) {
    await assert.rejects(phaseA.api.invoke(cmd), /no handler/,
      `${cmd} must fail closed in the plain-browser preview, not fake a keychain`);
  }
});

test("keychain: locked pane offers 'Unlock with OS keychain' ONLY when available+enrolled, with the honesty text", async () => {
  const vault = phaseB.byId.vault;

  const enrolled = stubEl();
  await vault.renderBody(enrolled, kcStatus(false, true, true));
  assert.ok(enrolled.innerHTML.includes("vt-kc-unlock"), "enrolled → keychain-unlock button");
  assert.ok(enrolled.innerHTML.includes(KC_HONESTY_INJECTED),
    "the backend's keychain honesty text must render verbatim next to the offer");

  const notEnrolled = stubEl();
  await vault.renderBody(notEnrolled, kcStatus(false, true, false));
  assert.ok(!notEnrolled.innerHTML.includes("vt-kc-unlock"), "not enrolled → no keychain-unlock button");

  const unavailable = stubEl();
  await vault.renderBody(unavailable, kcStatus(false, false, false));
  assert.ok(!unavailable.innerHTML.includes("vt-kc-unlock"), "unavailable → no keychain-unlock button");
});

test("keychain: unlocked pane renders enable/forget by state, an honest 'Unavailable' note otherwise, honesty always", async () => {
  const vault = phaseB.byId.vault;

  const notEnrolled = stubEl();
  await vault.renderBody(notEnrolled, kcStatus(true, true, false));
  assert.ok(notEnrolled.innerHTML.includes("vt-kc-enable"), "available+not enrolled → Enable");
  assert.ok(!notEnrolled.innerHTML.includes("vt-kc-forget"), "…and no Forget");
  assert.ok(notEnrolled.innerHTML.includes(KC_HONESTY_INJECTED), "honesty rendered");

  const enrolled = stubEl();
  await vault.renderBody(enrolled, kcStatus(true, true, true));
  assert.ok(enrolled.innerHTML.includes("vt-kc-forget"), "enrolled → Forget");
  assert.ok(!enrolled.innerHTML.includes("vt-kc-enable"), "…and no Enable");
  assert.ok(enrolled.innerHTML.includes("vault key stored in the OS login keychain"),
    "enabled state says WHERE the key sits — no hardware claim");
  assert.ok(enrolled.innerHTML.includes(KC_HONESTY_INJECTED), "honesty rendered");

  const unavailable = stubEl();
  await vault.renderBody(unavailable, kcStatus(true, false, false));
  assert.ok(!unavailable.innerHTML.includes("vt-kc-enable"), "unavailable → no Enable");
  assert.ok(!unavailable.innerHTML.includes("vt-kc-forget"), "unavailable → no Forget");
  assert.ok(unavailable.innerHTML.includes("Unavailable here"), "honest unavailable note");
  assert.ok(unavailable.innerHTML.includes("vault-keychain"), "names the cargo feature");
  assert.ok(unavailable.innerHTML.includes(KC_HONESTY_INJECTED), "honesty still rendered");
});

test("keychain: no backend-reported keychain object (preview engine) → no keychain UI at all", async () => {
  const vault = phaseB.byId.vault;
  for (const st of [
    { exists: true, unlocked: false, count: 0 },
    { exists: true, unlocked: true, count: 0 },
  ]) {
    const body = stubEl();
    await vault.renderBody(body, st);
    assert.ok(!/keychain/i.test(body.innerHTML),
      "without a keychain object the pane must not mention a keychain (nothing to fake)");
  }
});

// ═════════ Shared state helpers ═════════
test("loadingState/emptyState/errorState escape <script> and emit consistent classes", () => {
  const hostile = "<script>alert(1)</script>";
  const loading = UI.loadingState(hostile);
  const empty = UI.emptyState(hostile, hostile);
  const error = UI.errorState(new Error(hostile));
  const errorStr = UI.errorState(hostile);
  for (const html of [loading, empty, error, errorStr]) {
    assert.ok(!html.includes("<script>"), "raw <script> must never survive");
    assert.ok(html.includes("&lt;script&gt;"), "hostile input must be escaped, not dropped");
  }
  assert.ok(loading.includes('class="state state-loading"'), "loading class");
  assert.ok(empty.includes('class="state state-empty"'), "empty class");
  assert.ok(empty.includes('class="state-hint"'), "empty hint escaped + rendered");
  assert.ok(error.includes('class="state state-error"'), "error class");
  // caveat marker itself is fixed and self-labeled
  assert.ok(UI.privacyCaveat().includes(CAVEAT_MARKER), "privacyCaveat carries the fixed marker");
  // and the state classes exist in the stylesheet for both themes (theme-var based)
  const css = src("../styles.css");
  for (const cls of [".state-loading", ".state-empty", ".state-error", ".pane-caveat"]) {
    assert.ok(css.includes(cls), `styles.css must style ${cls}`);
  }
});

// ═════════ Terem-specific assertions (QEMU/QMP POC pane) ═════════
// Mock-level only: no qemu binary is ever executed by these tests — the
// fake __TAURI__.core.invoke above is the deepest layer they touch.
const TEREM_CMDS = [
  "terem_create", "terem_start", "terem_qmp", "terem_status", "terem_stop", "terem_destroy",
];

test("terem: all six terem_* commands are backend-registered, REAL with a backend, never live without one", () => {
  for (const cmd of TEREM_CMDS) {
    assert.ok(BACKEND_REGISTERED.has(cmd), `${cmd} must be in the backend's registered mirror`);
    assert.equal(phaseA.api.isReal(cmd), false, `${cmd} must not claim live without a backend`);
    assert.equal(phaseB.api.isReal(cmd), true, `${cmd} must be REAL with a backend`);
  }
});

test("terem: pane carries the user-fetched-QEMU + unaudited + no-VM-boots honesty strings in BOTH phases", async () => {
  for (const [label, phase] of [["no backend", phaseA], ["fake backend", phaseB]]) {
    const html = await renderPane(phase.byId.terem);
    for (const s of [
      "UNAUDITED POC",
      "opt-in and user-fetched",
      "never downloads, ships, or links QEMU",
      "docs/os-portal-v2/LICENSE-DECISION.md",
      "No VM boots in CI or tests",
      "not attestation",
      "not Seal-covered",
      "unix-only",
      "Windows build honestly reports them unavailable",
    ]) {
      assert.ok(html.includes(s), `terem pane (${label}) must say: ${s}`);
    }
  }
});

test("terem: no-backend pane never renders a live badge — honest empty state, no fabricated guest", async () => {
  const html = await renderPane(phaseA.byId.terem);
  assert.ok(!html.includes("badge-live"), "no live badge without a backend");
  assert.ok(html.includes("badge-stub"), "stub badge shown instead");
  assert.ok(html.includes('class="state state-empty"'),
    "status card renders UI.emptyState, not a fabricated guest");
  assert.ok(html.includes("never fakes a VM"), "the no-preview-engine stance is stated");
  assert.ok(!/guest running/i.test(html), "no fabricated 'guest running' claim anywhere");
});

test("terem: QMP surface offers ONLY the allowlisted verbs (mirror of terem.rs's QMP_ALLOWED_COMMANDS)", async () => {
  const html = await renderPane(phaseB.byId.terem);
  for (const c of ["query-status", "query-name", "query-version", "qom-list", "system_powerdown"]) {
    assert.ok(html.includes(`<option value="${c}">`), `allowlisted verb ${c} offered`);
  }
  for (const bad of [
    "human-monitor-command", "drive_add", "blockdev-add",
    "device_add", "device_del", "netdev_add", "chardev-add", "migrate", "quit",
  ]) {
    assert.ok(!html.includes(`<option value="${bad}">`), `${bad} must never be offered as an option`);
  }
});

test("terem: isReal routes terem_status to T.core.invoke with the fake backend (no preview engine exists)", async () => {
  invoked.length = 0;
  const st = await phaseB.api.invoke("terem_status");
  assert.deepEqual(invoked.map((i) => i.cmd), ["terem_status"], "exactly one routed call");
  assert.deepEqual(st, { defined: false, running: false, pid: null });
  // and without a backend there is nothing to fall back to — honest throw:
  await assert.rejects(() => phaseA.api.invoke("terem_status"), /no handler for 'terem_status'/);
});

// ═════════ No-external-origin scan (includes the new helpers) ═════════
test("no .js source references an http(s) origin beyond the localhost RPC default", () => {
  const files = [
    ...readdirSync(here).filter((f) => f.endsWith(".js")).map((f) => path.join(here, f)),
    path.join(here, "../api.js"),
    path.join(here, "../main.js"),
    path.join(here, "../ui.js"),
  ];
  // Allowlist mirrors the backend RPC allowlist (main.rs validate_rpc_url): a
  // loopback http node, the official public HTTPS RPC (the new remote default),
  // and the RFC 2606 example placeholder shown in the custom-endpoint field.
  // Any OTHER hardcoded origin is still a failure.
  const allowed = [
    /^http:\/\/127\.0\.0\.1(?::|\/|$)/,
    /^http:\/\/localhost(?::|\/|$)/,
    /^https:\/\/posternlabs\.com(?::|\/|$)/,
    /^https?:\/\/my-node\.example\.org(?::|\/|$)/,
  ];
  for (const f of files) {
    const text = readFileSync(f, "utf8");
    for (const m of text.matchAll(/https?:\/\/[^\s"'`<>)\\]+/g)) {
      assert.ok(
        allowed.some((re) => re.test(m[0])),
        `${path.basename(f)} references a non-localhost origin: ${m[0]}`,
      );
    }
  }
});

// ── browser-backend wiring (the integration nobody did) ────────────────────
// The four browser/*.js files were landed by separate tracks and NOTHING loaded
// them: index.html listed 18 script tags and none was the backend, so the whole
// seam was dead code that read as done. These assertions make the wiring
// machine-checked instead of a comment.
test("browser backend: all four scripts are loaded, in an order that works", () => {
  const html = readFileSync(path.join(here, "..", "index.html"), "utf8");
  const order = [...html.matchAll(/<script src="([^"]+)"><\/script>/g)].map((m) => m[1]);
  for (const f of ["browser/registry.js", "browser/core.js", "browser/rpc.js", "browser/wallet.js"]) {
    assert.ok(order.includes(f), `index.html must load ${f} — without it the browser backend is dead code`);
  }
  const at = (f) => order.indexOf(f);
  // registry.js defines window.PosternBrowser; everything else registers into it.
  assert.ok(at("browser/registry.js") < at("browser/core.js"), "registry.js must precede core.js");
  assert.ok(at("browser/registry.js") < at("browser/rpc.js"), "registry.js must precede rpc.js");
  assert.ok(at("browser/registry.js") < at("browser/wallet.js"), "registry.js must precede wallet.js");
  // wallet.js gates its two SEND registrations on reg.has("rpc"): if rpc.js
  // loaded after it, the guard would always miss and sends would never be real.
  assert.ok(at("browser/rpc.js") < at("browser/wallet.js"), "rpc.js must precede wallet.js or the send guard never sees it");
  // api.js decides what isReal() may claim by reading the registry.
  assert.ok(at("browser/wallet.js") < at("api.js"), "the browser backend must be fully registered before api.js loads");
});

// The send paths sign locally but BROADCAST over rpc. Registering them without
// an rpc layer makes api.isReal("wallet_send") true while every send throws —
// a live badge over a dead button. Pin the guard.
test("browser backend: the send paths are gated on the rpc layer existing", () => {
  const src = readFileSync(path.join(here, "..", "browser", "wallet.js"), "utf8");
  assert.match(src, /reg\.has\("rpc"\)/, "wallet.js must gate its send registrations on reg.has('rpc')");
  const guardAt = src.indexOf('reg.has("rpc")');
  assert.ok(guardAt < src.indexOf('reg.register("wallet_send"'), "the guard must come before the wallet_send registration");
  assert.ok(guardAt < src.indexOf('reg.register("wallet_keystore_send"'), "…and before wallet_keystore_send");
});

// Anything that lands in a SIGNED transaction is parsed strictly. Number()
// coercion silently lost a sat above 2^53 and collapsed a bad vout to 0 —
// which signs the wrong outpoint rather than merely mispaying.
test("browser backend: utxo fields are parsed strictly, never Number()-coerced", () => {
  const raw = readFileSync(path.join(here, "..", "browser", "wallet.js"), "utf8");
  // Strip line comments first: the fix's own comment QUOTES the old
  // `Number(u.index)` to explain why it was wrong, and a naive grep over the
  // whole file would fail on the documentation rather than on the code.
  const src = raw.split("\n").map((l) => l.replace(/^\s*\/\/.*$/, "")).join("\n");
  assert.doesNotMatch(src, /Number\(u\.index\)/, "utxo.index must not be Number()-coerced");
  assert.doesNotMatch(src, /Number\(u\.value\)/, "utxo.value must not be Number()-coerced");
  assert.match(src, /strictU32\(u\.index/, "utxo.index goes through strictU32");
  assert.match(src, /strictSats\(u\.value/, "utxo.value goes through strictSats");
});

// address-at-index has NO core op in the browser. The pane must refuse, not fall
// through to the preview engine and present another wallet's address as yours.
test("wallet pane: rotation fails closed when wallet_address_at is not real", () => {
  const src = readFileSync(path.join(here, "wallet.js"), "utf8");
  const at = src.indexOf('rotIndex += 1');
  const guard = src.indexOf('!api.isReal("wallet_address_at")');
  assert.ok(guard !== -1, "the rotation handler must check api.isReal('wallet_address_at')");
  assert.ok(guard < at, "…and must refuse BEFORE incrementing the index / invoking");
});

// ── PWA service worker vs the real app shell ───────────────────────────────
// sw.js hand-lists every file it precaches. cache.addAll() rejects ATOMICALLY:
// one 404 and the worker never installs, so the whole offline story dies
// silently. It shipped listing modules/swap.js after that pane was withdrawn —
// exactly that failure. This test is the machine-checked agreement between the
// shell the app loads and the shell the worker caches.
test("pwa: sw.js precaches exactly the modules that exist and the scripts index.html loads", () => {
  const sw = readFileSync(path.join(here, "..", "..", "pwa", "sw.js"), "utf8");
  const html = readFileSync(path.join(here, "..", "index.html"), "utf8");
  const shell = [...sw.matchAll(/at\("([^"]*)"\)/g)].map((m) => m[1]);

  // (a) every module precached must exist on disk
  for (const p of shell.filter((u) => u.startsWith("modules/"))) {
    const f = path.join(here, path.basename(p));
    assert.ok(existsSync(f), `sw.js precaches ${p} but it does not exist — cache.addAll would reject and the SW would never install`);
  }
  // (b) every module on disk must be precached (a new pane must not be missed)
  for (const f of readdirSync(here).filter((f) => f.endsWith(".js"))) {
    assert.ok(shell.includes(`modules/${f}`), `modules/${f} exists but sw.js does not precache it — it would be missing offline`);
  }
  // (c) every <script> index.html loads must be precached
  const scripts = [...html.matchAll(/<script src="([^"]+)"><\/script>/g)].map((m) => m[1]);
  for (const s of scripts) {
    assert.ok(shell.includes(s), `index.html loads ${s} but sw.js does not precache it`);
  }
  // (d) the browser backend is never best-effort
  const optional = sw.slice(sw.indexOf("const SHELL_OPTIONAL"));
  assert.doesNotMatch(optional.slice(0, optional.indexOf("]")), /browser\//,
    "the browser backend must be in SHELL, not SHELL_OPTIONAL — a swallowed 404 there ships a dead wallet");
});
