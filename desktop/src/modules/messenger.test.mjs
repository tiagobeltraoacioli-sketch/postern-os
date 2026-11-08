// desktop/src/modules/messenger.test.mjs — run with: node messenger.test.mjs (Node >= 18)
//
// Proves the Vestnik pane keeps its wording machine-checked against the
// Rust crate and only ever claims what the backend really is:
//
//   1. BYTE-MATCH pin: the pane's tier badges and the three mandatory
//      bridged-disclosure strings are extracted from
//      crates/postern-messenger/src/lib.rs (SecurityTier::badge() arms;
//      disclosure::BRIDGE_TAB_BANNER / BRIDGED_CONVERSATION_HEADER /
//      BRIDGED_COMPOSE_NOTE) and asserted byte-identical in BOTH the pane's
//      rendered HTML and messenger.js's source — no UI layer can soften the
//      wording without failing here. Pins are asserted in every render
//      flavor (no backend / not-built / built / logged-in).
//   2. Capability-gating honesty: the vestnik_* matrix-client commands are
//      ALWAYS registered (the backend built without `vestnik-matrix` returns
//      a clean 'not built with matrix support' error), so the pane's live
//      claim is gated on the REAL vestnik_matrix_status.built answer — both
//      answers are mocked here: built:false keeps the honest disabled
//      preview; built:true enables the Account form and (once logged_in)
//      renders the REAL room list.
//   3. Tier wall: compose exists only on the internal tier — the bridged
//      section renders NO input/textarea/select in ANY flavor, real rooms
//      included; its compose line is the mandatory BRIDGED_COMPOSE_NOTE.
//   4. No preview engine exists for ANY vestnik_* command (custody or
//      client) — a faked vault or matrix client would be an overclaim: a
//      no-backend invoke throws honestly.
//   5. The honest-limits callout keeps every load-bearing claim (including
//      the new 'only in a vestnik-matrix build, only on user action' truth),
//      and no external http(s) origin appears in messenger.js.
//
// ui.js / api.js / modules/*.js are classic (non-module) browser scripts.
// Like the sibling suite.test.mjs, this file stubs the minimum window
// surface they touch and loads them via indirect eval. Everything here is a
// mock-level test: no network, no Tauri, no matrix client, no real backend —
// and no homeserver is ever contacted.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import assert from "node:assert/strict";
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

const here = path.dirname(fileURLToPath(import.meta.url));
const src = (rel) => readFileSync(path.join(here, rel), "utf8");
const load = (rel) => (0, eval)(src(rel));

let passed = 0;
const t = (name, fn) => Promise.resolve().then(fn).then(() => { passed++; console.log("  ok — " + name); });

// ═════════ the single source of truth: the Rust crate's constants ═════════
const RUST_LIB = src("../../../crates/postern-messenger/src/lib.rs");

/** Decode a Rust string literal body: \u{...}, \n, \t, \r, \0, \\, \", \'. */
const unRust = (s) =>
  s.replace(/\\(u\{([0-9a-fA-F]+)\}|.)/gs, (_, esc, hex) => {
    if (hex) return String.fromCodePoint(parseInt(hex, 16));
    switch (esc) {
      case "n": return "\n";
      case "t": return "\t";
      case "r": return "\r";
      case "0": return "\0";
      case "\\": return "\\";
      case '"': return '"';
      case "'": return "'";
      default: throw new Error(`unhandled Rust escape \\${esc} — extend unRust`);
    }
  });

function rustStr(re, what) {
  const m = RUST_LIB.match(re);
  assert.ok(m, `could not extract ${what} from crates/postern-messenger/src/lib.rs`);
  return unRust(m[1]);
}

const BADGE_INTERNAL = rustStr(
  /SecurityTier::InternalE2ee => "((?:[^"\\]|\\.)*)"/,
  "SecurityTier::InternalE2ee.badge()",
);
const BADGE_BRIDGED = rustStr(
  /SecurityTier::BridgedExternal => "((?:[^"\\]|\\.)*)"/,
  "SecurityTier::BridgedExternal.badge()",
);
const BRIDGE_TAB_BANNER = rustStr(
  /pub const BRIDGE_TAB_BANNER: &str = "((?:[^"\\]|\\.)*)";/,
  "disclosure::BRIDGE_TAB_BANNER",
);
const BRIDGED_CONVERSATION_HEADER = rustStr(
  /pub const BRIDGED_CONVERSATION_HEADER: &str = "((?:[^"\\]|\\.)*)";/,
  "disclosure::BRIDGED_CONVERSATION_HEADER",
);
const BRIDGED_COMPOSE_NOTE = rustStr(
  /pub const BRIDGED_COMPOSE_NOTE: &str = "((?:[^"\\]|\\.)*)";/,
  "disclosure::BRIDGED_COMPOSE_NOTE",
);

const ALL_PINS = [BADGE_INTERNAL, BADGE_BRIDGED, BRIDGE_TAB_BANNER, BRIDGED_CONVERSATION_HEADER, BRIDGED_COMPOSE_NOTE];

await t("extracted Rust constants are sane (distinct badges, warning glyphs, honest claims)", async () => {
  assert.equal(BADGE_INTERNAL, "E2EE (Postern)");
  assert.notEqual(BADGE_INTERNAL, BADGE_BRIDGED, "the two tiers must never share a badge");
  assert.ok(BADGE_BRIDGED.includes("not E2EE"), "bridged badge must warn");
  assert.ok(BADGE_BRIDGED.startsWith("⚠"), "bridged badge carries the warning glyph");
  assert.ok(BRIDGE_TAB_BANNER.includes("plaintext"), "banner: plaintext readable");
  assert.ok(BRIDGE_TAB_BANNER.includes("metadata"), "banner: metadata visible");
  assert.ok(BRIDGE_TAB_BANNER.includes("does not operate this bridge"), "banner: not Postern-operated");
  assert.ok(BRIDGED_CONVERSATION_HEADER.includes("not end-to-end encrypted"));
  assert.ok(BRIDGED_COMPOSE_NOTE.includes("Not E2EE"));
});

const PREVIEW_NOTE = "preview — not built with matrix support (rebuild with --features vestnik-matrix)";
const VESTNIK_CUSTODY = [
  "vestnik_recipient_init", "vestnik_session_store", "vestnik_session_load", "vestnik_session_open",
];
// The matrix-client commands: ALWAYS registered by the backend; a build
// without the `vestnik-matrix` cargo feature returns a clean not-built error
// and vestnik_matrix_status reports built:false. The pane gates on that.
const VESTNIK_CLIENT = [
  "vestnik_matrix_status", "vestnik_login", "vestnik_session_seal", "vestnik_restore",
  "vestnik_sync_once", "vestnik_rooms", "vestnik_send", "vestnik_logout",
];

// ---- stub-DOM render helper (same shape as suite.test.mjs) ----
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
async function renderPane(mod) {
  const root = stubEl();
  await mod.render(root);
  return root.innerHTML;
}

load("../ui.js");
const P = window.Postern;
assert.ok(P && P.ui, "ui.js loaded");

function bootPhase() {
  P.modules.length = 0; // fresh registry (and a fresh matrixStatus capture)
  load("../api.js");    // re-reads window.__TAURI__ at load
  load("messenger.js");
  const mod = P.modules.find((m) => m.id === "messenger");
  assert.ok(mod, "messenger module registered");
  return { api: P.api, mod };
}

function assertPins(html, label) {
  for (const s of ALL_PINS) {
    assert.ok(html.includes(s), `pane (${label}) must render byte-identical:\n${s}`);
  }
}

function assertNoBridgedCompose(html, label) {
  const start = html.indexOf('id="vk-bridged"');
  assert.ok(start >= 0, `bridged section rendered (${label})`);
  const bridged = html.slice(start, html.indexOf("</section>", start));
  assert.ok(!bridged.includes("<input"), `no compose input on the bridged tier (${label})`);
  assert.ok(!bridged.includes("<textarea"), `no compose textarea on the bridged tier (${label})`);
  assert.ok(!bridged.includes("<select"), `no room selector on the bridged tier (${label})`);
  assert.ok(bridged.includes(BRIDGED_COMPOSE_NOTE), `the mandatory compose note stands in its place (${label})`);
  assert.ok(bridged.includes(BRIDGED_CONVERSATION_HEADER), `bridged conversation header pinned (${label})`);
  assert.ok(bridged.includes(BRIDGE_TAB_BANNER), `bridge tab banner pinned (${label})`);
}

// ═════════ Phase A — NO backend (plain browser preview) ═════════
const phaseA = bootPhase();
const htmlA = await renderPane(phaseA.mod);

await t("byte-match: pane HTML renders every Rust badge/disclosure string verbatim (no backend)", async () => {
  assertPins(htmlA, "no backend");
});

await t("byte-match: messenger.js SOURCE carries the exact strings (pins live in the source, not by accident)", async () => {
  const js = src("messenger.js");
  for (const s of ALL_PINS) {
    assert.ok(js.includes(s), `messenger.js must contain the exact string:\n${s}`);
  }
});

await t("no backend: pane is preview — live() false, stub badge, disabled login/compose, no matrix live badge", async () => {
  assert.equal(phaseA.api.hasBackend, false);
  assert.equal(phaseA.mod.live(), false, "must never claim live without a backend");
  assert.ok(htmlA.includes(PREVIEW_NOTE), "the honest not-built preview note must render");
  assert.ok(htmlA.includes("badge-stub"), "stub badge shown");
  assert.ok(!htmlA.includes("badge-live"), "nothing may render live without a backend");
  for (const id of ["vk-hs", "vk-user", "vk-pass", "vk-storepass", "vk-loginbtn", "vk-compose", "vk-send"]) {
    const re = new RegExp(`<(?:input|button)[^>]*id="${id}"[^>]*\\bdisabled\\b`);
    assert.match(htmlA, re, `#${id} must be disabled (no matrix client in this build)`);
  }
});

await t("no backend: tier wall — compose exists ONLY on the internal tier", async () => {
  assertNoBridgedCompose(htmlA, "no backend");
  const iStart = htmlA.indexOf('id="vk-internal"');
  const internal = htmlA.slice(iStart, htmlA.indexOf("</section>", iStart));
  assert.ok(internal.includes('id="vk-compose"'), "internal tier carries the (disabled) compose box");
  assert.ok(internal.includes(BADGE_INTERNAL), "internal tier carries its badge");
});

await t("honest limits callout keeps every load-bearing claim (incl. the new build/user-action truth)", async () => {
  for (const claim of [
    "UNAUDITED",
    "not post-quantum",
    "social graph",
    "SavedSession blob only",
    "only in a vestnik-matrix build, only on user action",
    "not PQ-vault-wrapped",
  ]) {
    assert.ok(htmlA.includes(claim), `honest-limits must keep: ${claim}`);
  }
  assert.ok(
    !htmlA.includes("does not yet run the matrix client"),
    "the pre-vestnik-matrix wording must be gone — the client now exists behind the feature",
  );
  assert.ok(htmlA.includes('class="pane-caveat"'), "shared privacy caveat rendered");
});

await t("no backend: NO preview engine for ANY vestnik command (custody or client) — invoke throws honestly", async () => {
  for (const cmd of [...VESTNIK_CUSTODY, ...VESTNIK_CLIENT]) {
    assert.equal(phaseA.api.isReal(cmd), false, `${cmd} must not claim live without a backend`);
    await assert.rejects(
      () => phaseA.api.invoke(cmd),
      new RegExp(`no handler for '${cmd}'`),
      `a faked '${cmd}' would be an overclaim — must throw, not pretend`,
    );
  }
  // and api.js declares no vestnik preview engine at all:
  assert.ok(!/preview\.vestnik_/.test(src("../api.js")), "api.js must not define preview.vestnik_* engines");
});

// ═════════ Phase B — fake Tauri backend, built WITHOUT vestnik-matrix ═════════
// The backend answers vestnik_matrix_status with built:false (what the
// feature-off stub really returns) — the pane must keep the honest preview.
const invoked = [];
let fakeStatus = { built: false, logged_in: false, honesty: "test honesty" };
let fakeRooms = { rooms: [], honesty: "test honesty" };
globalThis.__TAURI__ = {
  core: {
    invoke: async (cmd, args) => {
      invoked.push({ cmd, args });
      if (cmd === "vestnik_matrix_status") return fakeStatus;
      if (cmd === "vestnik_rooms") return fakeRooms;
      return null;
    },
  },
};
const phaseB = bootPhase();
const htmlB = await renderPane(phaseB.mod);

await t("not-built backend: the pane STILL never claims a live messenger (status.built === false)", async () => {
  assert.equal(phaseB.api.hasBackend, true, "fake __TAURI__ detected");
  assert.equal(phaseB.api.isReal("vestnik_matrix_status"), true, "the status command IS registered");
  assert.equal(phaseB.mod.live(), false, "built:false must keep the badge preview — registration alone proves nothing");
  assert.ok(htmlB.includes(PREVIEW_NOTE), "login area keeps the honest not-built note");
  for (const id of ["vk-hs", "vk-user", "vk-pass", "vk-storepass", "vk-loginbtn", "vk-compose", "vk-send"]) {
    const re = new RegExp(`<(?:input|button)[^>]*id="${id}"[^>]*\\bdisabled\\b`);
    assert.match(htmlB, re, `#${id} must stay disabled (the build has no matrix client)`);
  }
  // …while the custody card honestly reports its live surface.
  assert.ok(htmlB.includes("badge-live"), "custody card may show live — the vestnik_* custody commands ARE real");
  assertPins(htmlB, "not-built backend");
  assertNoBridgedCompose(htmlB, "not-built backend");
});

await t("not-built backend: render probes ONLY the local status command — nothing network-shaped", async () => {
  const cmds = invoked.map((i) => i.cmd);
  assert.deepEqual([...new Set(cmds)], ["vestnik_matrix_status"],
    "render must invoke vestnik_matrix_status only (local state; login/sync/send stay user actions)");
});

// ═════════ Phase C — fake backend, vestnik-matrix build, NOT logged in ═════════
fakeStatus = { built: true, logged_in: false, honesty: "test honesty" };
const phaseC = bootPhase();
const htmlC = await renderPane(phaseC.mod);

await t("built backend: pane claims live ONLY now, and enables the Account login form", async () => {
  assert.equal(phaseC.mod.live(), true, "status.built === true is the ONLY thing that may flip live");
  assert.ok(!htmlC.includes(PREVIEW_NOTE), "the not-built note must be gone in a built backend");
  for (const id of ["vk-hs", "vk-user", "vk-pass", "vk-storepass"]) {
    const re = new RegExp(`<input[^>]*id="${id}"[^>]*\\bdisabled\\b`);
    assert.ok(!re.test(htmlC), `#${id} must be enabled in a built backend`);
  }
  const loginBtn = htmlC.match(/<button[^>]*id="vk-loginbtn"[^>]*>/)[0];
  assert.ok(!/\bdisabled\b/.test(loginBtn), "Log in button enabled (user action — that is when the homeserver is contacted)");
  // But compose stays gated until logged in + internal rooms exist:
  const re = new RegExp(`<(?:input|button)[^>]*id="vk-compose"[^>]*\\bdisabled\\b`);
  assert.match(htmlC, re, "compose stays disabled before login/sync");
  assertPins(htmlC, "built, not logged in");
  assertNoBridgedCompose(htmlC, "built, not logged in");
});

// ═════════ Phase D — built + logged in, REAL rooms from vestnik_rooms ═════════
fakeStatus = { built: true, logged_in: true, honesty: "test honesty" };
fakeRooms = {
  rooms: [
    { room_id: "!alpha:mock.invalid", name: "Postern core", tier: "internal", badge: BADGE_INTERNAL, is_direct: false },
    { room_id: "!beta:mock.invalid", name: "Telegram family (bridge)", tier: "bridged", badge: BADGE_BRIDGED, is_direct: false },
  ],
  honesty: "test honesty",
};
const phaseD = bootPhase();
const htmlD = await renderPane(phaseD.mod);

await t("logged in: the REAL room list renders with the byte-pinned tier badges", async () => {
  invoked.length = 0;
  const html = await renderPane(phaseD.mod);
  assert.ok(invoked.some((i) => i.cmd === "vestnik_rooms"), "render fetches the real room list (local sync state)");
  assert.ok(html.includes("Postern core"), "internal room rendered");
  assert.ok(html.includes("Telegram family (bridge)"), "bridged room rendered");
  const iStart = html.indexOf('id="vk-internal"');
  const internal = html.slice(iStart, html.indexOf("</section>", iStart));
  assert.ok(internal.includes("Postern core"), "internal room in the internal section");
  assert.ok(!internal.includes("Telegram family"), "bridged room NOT in the internal section");
  assert.ok(internal.includes(BADGE_INTERNAL), "internal badge pinned on the real list");
  const bStart = html.indexOf('id="vk-bridged"');
  const bridged = html.slice(bStart, html.indexOf("</section>", bStart));
  assert.ok(bridged.includes("Telegram family (bridge)"), "bridged room in the bridged section");
  assert.ok(bridged.includes(BADGE_BRIDGED), "bridged badge pinned on the real list");
  assert.ok(!html.includes("(sample)"), "sample rooms must NOT render when the real list exists");
});

await t("logged in: compose is enabled for internal rooms ONLY — the bridged section still has none", async () => {
  const re = new RegExp(`<input[^>]*id="vk-compose"[^>]*\\bdisabled\\b`);
  assert.ok(!re.test(htmlD), "compose enabled (built + logged in + internal room exists)");
  const roomSel = htmlD.match(/<select[^>]*id="vk-room"[^>]*>[\s\S]*?<\/select>/);
  assert.ok(roomSel, "room selector renders for internal rooms");
  assert.ok(roomSel[0].includes("!alpha:mock.invalid"), "internal room selectable");
  assert.ok(!roomSel[0].includes("!beta:mock.invalid"), "bridged room must NOT be selectable for compose");
  assertNoBridgedCompose(htmlD, "logged in");
  assertPins(htmlD, "logged in");
});

await t("api.js REAL-set parity: custody + all 8 client commands declared; no vestnik preview engines", async () => {
  const apiSrc = src("../api.js");
  const block = apiSrc.match(/const REAL = new Set\(\[([\s\S]*?)\]\);/);
  assert.ok(block, "api.js declares its REAL set");
  const cmds = [...block[1].matchAll(/"([a-z_]+)"/g)].map((m) => m[1]);
  for (const cmd of [...VESTNIK_CUSTODY, ...VESTNIK_CLIENT]) {
    assert.ok(cmds.includes(cmd), `REAL set must declare '${cmd}'`);
  }
  assert.ok(/not built with matrix support/.test(apiSrc),
    "api.js must carry the honesty comment about the not-built error contract");
  assert.ok(!/preview\.vestnik_/.test(apiSrc), "no preview engine may exist for any vestnik_* command");
});

await t("client commands route to T.core.invoke (registered always; not-built returns a clean error)", async () => {
  invoked.length = 0;
  await phaseD.api.invoke("vestnik_matrix_status");
  await phaseD.api.invoke("vestnik_rooms");
  assert.deepEqual(invoked.map((i) => i.cmd), ["vestnik_matrix_status", "vestnik_rooms"],
    "routed to the backend, not a preview");
});

await t("no external http(s) origin in messenger.js", async () => {
  const text = src("messenger.js");
  const allowed = [/^http:\/\/127\.0\.0\.1(?::|\/|$)/, /^http:\/\/localhost(?::|\/|$)/];
  for (const m of text.matchAll(/https?:\/\/[^\s"'`<>)\\]+/g)) {
    assert.ok(allowed.some((re) => re.test(m[0])), `messenger.js references a non-localhost origin: ${m[0]}`);
  }
});

console.log(`\nvestnik pane (byte-matched disclosure + capability-gated live claim): ${passed} checks passed`);
