// apps/izbushka/test-companion.mjs
// -----------------------------------------------------------------------------
// Sotto -> Izbushka consent/intent contract: proves the consent GATE
// (validateIntent) never opens the door without the exact ritual formula and
// a whitelisted verb, and that whatever it hands back is inert DATA — never
// an action. No DOM stubbing: izbushka-companion.js only touches `window`/
// `document` behind a `hasDOM` guard, and validateIntent (plus the six verbs
// / RITUAL_FORMULA) are plain CommonJS exports reachable from Node via
// createRequire, so these are pure-function assertions end to end.
//
// Run (full suite):
//   node --test apps/izbushka/test-companion.mjs
// Run (a subset, e.g. just the hash-fragment base64url codec):
//   node --test --test-name-pattern 'base64' apps/izbushka/test-companion.mjs
// Run (just the consent-gate contract):
//   node --test --test-name-pattern 'formula|action|normaliz' \
//     apps/izbushka/test-companion.mjs
// -----------------------------------------------------------------------------
"use strict";

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import path from "node:path";

// -----------------------------------------------------------------------------
// DOM-FREE HARNESS, ON PURPOSE, for the ackIntent() suite below.
//
// izbushka-companion.js gates its DOM-only side effects (the `storage` /
// `message` event listeners and the 800ms same-tab poll) behind:
//
//   const hasDOM = typeof document !== "undefined" && typeof window !== "undefined";
//
// We set globalThis.window to a minimal, Map-backed localStorage stub, but we
// deliberately do NOT set globalThis.document. That keeps hasDOM false, so
// none of the DOM wiring (setInterval poll, addEventListener) ever arms —
// nothing keeps the Node event loop alive. ackIntent()/readStored() reach
// `window.localStorage` directly (they are not gated by hasDOM), so they are
// fully exercisable headless. The suite's own clean exit (no hang, no
// dangling timers) is itself proof no DOM timer leaked.
//
// This file does NOT open a browser and does NOT exercise the storage
// event / postMessage / hash-fragment listeners that only exist when hasDOM
// is true — those need an actual DOM and are out of scope here.
// -----------------------------------------------------------------------------
const __intentStore = new Map();
globalThis.window = {
  localStorage: {
    getItem: (k) => (__intentStore.has(k) ? __intentStore.get(k) : null),
    setItem: (k, v) => { __intentStore.set(k, String(v)); },
    removeItem: (k) => { __intentStore.delete(k); },
  },
};
// NO globalThis.document — hasDOM must stay false.

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const companion = require(path.join(__dirname, "izbushka-companion.js"));

const { validateIntent, ackIntent, onIntent, RITUAL_FORMULA, ACTIONS, base64UrlToBase64 } = companion;
const INTENT_KEY = "izbushka.intent";

function seedIntent(id, overrides = {}) {
  const intent = {
    v: 1,
    id,
    action: "declare",
    formula: RITUAL_FORMULA,
    task: { name: "water the garden" },
    ts: "2026-01-01T00:00:00.000Z",
    ...overrides,
  };
  __intentStore.set(INTENT_KEY, JSON.stringify(intent));
  return intent;
}

const EXPECTED_KEYS = ["v", "id", "action", "formula", "task", "ts", "_preFillOnly"].sort();

// A minimal valid envelope to mutate per-case, so each test isolates the one
// thing it's checking (formula, then action, then shape).
function baseIntent(overrides = {}) {
  return {
    v: 1,
    id: "intent-1",
    action: "declare",
    formula: RITUAL_FORMULA,
    task: { name: "water the garden" },
    ts: "2026-01-01T00:00:00.000Z",
    ...overrides,
  };
}

/* ============================================================================
   THE GATE: no formula, no door.
   ========================================================================== */
describe("consent gate: formula", () => {
  test("absent formula returns null", () => {
    const raw = baseIntent();
    delete raw.formula;
    assert.equal(validateIntent(raw), null);
  });

  test("formula: undefined key explicitly (not just missing) returns null", () => {
    assert.equal(validateIntent(baseIntent({ formula: undefined })), null);
  });

  test("wrong formula (different phrase entirely) returns null", () => {
    assert.equal(validateIntent(baseIntent({ formula: "open-sesame" })), null);
  });

  test("wrong formula (uppercase variant) returns null — case is not folded", () => {
    assert.equal(
      validateIntent(baseIntent({ formula: RITUAL_FORMULA.toUpperCase() })),
      null
    );
  });

  test("wrong formula (mixed-case variant) returns null", () => {
    const mixed = RITUAL_FORMULA.replace(/^./, (c) => c.toUpperCase());
    assert.equal(validateIntent(baseIntent({ formula: mixed })), null);
  });

  test("wrong formula (leading/trailing whitespace) returns null — no trimming", () => {
    assert.equal(
      validateIntent(baseIntent({ formula: `  ${RITUAL_FORMULA}  ` })),
      null
    );
  });

  test("wrong formula (internal whitespace / newline) returns null", () => {
    assert.equal(
      validateIntent(baseIntent({ formula: RITUAL_FORMULA.replace(/-/g, " ") })),
      null
    );
    assert.equal(
      validateIntent(baseIntent({ formula: `${RITUAL_FORMULA}\n` })),
      null
    );
  });

  test("null/non-object raw input returns null (no crash)", () => {
    assert.equal(validateIntent(null), null);
    assert.equal(validateIntent(undefined), null);
    assert.equal(validateIntent("izbushka-turn-your-face-to-me"), null);
    assert.equal(validateIntent(42), null);
  });
});

/* ============================================================================
   THE GATE: only the six whitelisted verbs may pass, and only exactly.
   ========================================================================== */
describe("consent gate: action whitelist", () => {
  test("ACTIONS is exactly the six spec verbs", () => {
    assert.deepEqual(
      [...ACTIONS].sort(),
      ["declare", "grant", "pause", "revoke", "schedule", "list"].sort()
    );
  });

  test("non-whitelisted action 'execute' returns null", () => {
    assert.equal(validateIntent(baseIntent({ action: "execute" })), null);
  });

  test("non-whitelisted action 'grant ' (trailing whitespace) returns null — no fuzzy match", () => {
    assert.equal(validateIntent(baseIntent({ action: "grant " })), null);
  });

  test("non-whitelisted action ' grant' (leading whitespace) returns null", () => {
    assert.equal(validateIntent(baseIntent({ action: " grant" })), null);
  });

  test("non-whitelisted action 'Grant' (case variant) returns null", () => {
    assert.equal(validateIntent(baseIntent({ action: "Grant" })), null);
  });

  test("absent action returns null", () => {
    const raw = baseIntent();
    delete raw.action;
    assert.equal(validateIntent(raw), null);
  });

  test("empty-string action returns null", () => {
    assert.equal(validateIntent(baseIntent({ action: "" })), null);
  });

  for (const verb of ACTIONS) {
    test(`whitelisted action '${verb}' passes the gate and returns a normalized object`, () => {
      const result = validateIntent(baseIntent({ action: verb }));
      assert.notEqual(result, null);
      assert.equal(result.action, verb);
    });
  }
});

/* ============================================================================
   NORMALIZATION: whatever comes out is inert, canonical DATA — never an
   action. This is the proof that "an intent is DATA, never an action."
   ========================================================================== */
describe("canonical inert normalization", () => {
  test("_preFillOnly is true — the explicit never-auto-acts marker", () => {
    const result = validateIntent(baseIntent());
    assert.equal(result._preFillOnly, true);
  });

  test("formula on the returned object is pinned to RITUAL_FORMULA (not echoed from input)", () => {
    const result = validateIntent(baseIntent());
    assert.equal(result.formula, RITUAL_FORMULA);
    assert.equal(result.formula, companion.RITUAL_FORMULA);
  });

  test("string task + top-level description/schedule fold into a task object", () => {
    const raw = baseIntent({
      task: "buy-milk", // Sotto's kebab-slug shape
      description: "two litres, oat if they have it",
      schedule: "tomorrow 9am",
    });
    const result = validateIntent(raw);
    assert.deepEqual(result.task, {
      name: "buy-milk",
      description: "two litres, oat if they have it",
      schedule: "tomorrow 9am",
    });
  });

  test("object task passes through unchanged (canonical shape)", () => {
    const task = { name: "water the garden", schedule: "daily 7am" };
    const raw = baseIntent({ task });
    const result = validateIntent(raw);
    assert.deepEqual(result.task, task);
  });

  test("createdAt folds into ts when ts is absent", () => {
    const raw = baseIntent({ createdAt: "2025-06-15T12:00:00.000Z" });
    delete raw.ts;
    const result = validateIntent(raw);
    assert.equal(result.ts, "2025-06-15T12:00:00.000Z");
  });

  test("ts takes priority over createdAt when both are present", () => {
    const raw = baseIntent({
      ts: "2026-01-01T00:00:00.000Z",
      createdAt: "1999-01-01T00:00:00.000Z",
    });
    const result = validateIntent(raw);
    assert.equal(result.ts, "2026-01-01T00:00:00.000Z");
  });

  test("id defaults deterministically to String(ts) when raw.id is absent and ts is present", () => {
    const raw = baseIntent({ ts: "2026-01-01T00:00:00.000Z" });
    delete raw.id;
    const result = validateIntent(raw);
    assert.equal(result.id, "2026-01-01T00:00:00.000Z");
  });

  test("id defaults deterministically to String(createdAt) when raw.id and raw.ts are both absent", () => {
    const raw = baseIntent({ createdAt: "2025-06-15T12:00:00.000Z" });
    delete raw.id;
    delete raw.ts;
    const result = validateIntent(raw);
    assert.equal(result.id, "2025-06-15T12:00:00.000Z");
  });

  test("explicit string raw.id is preserved verbatim, not replaced by ts", () => {
    const raw = baseIntent({ id: "sotto-opaque-id-7", ts: "2026-01-01T00:00:00.000Z" });
    const result = validateIntent(raw);
    assert.equal(result.id, "sotto-opaque-id-7");
  });

  test("non-string raw.id is not trusted verbatim — falls back to the ts-derived default", () => {
    const raw = baseIntent({ id: 12345, ts: "2026-01-01T00:00:00.000Z" });
    const result = validateIntent(raw);
    assert.notEqual(result.id, 12345);
    assert.equal(result.id, "2026-01-01T00:00:00.000Z");
  });

  test("returned object's own keys are exactly {v,id,action,formula,task,ts,_preFillOnly} — nothing extra, nothing missing", () => {
    // Feed it an intent with extraneous fields to prove they are NOT carried
    // through onto the top level (e.g. no raw passthrough / no prototype
    // pollution surface).
    const raw = baseIntent({
      extraField: "should not survive",
      granted_by: "should not survive either",
    });
    const result = validateIntent(raw);
    assert.deepEqual(Object.keys(result).sort(), EXPECTED_KEYS);
  });

  test("this holds for every one of the six whitelisted verbs", () => {
    for (const verb of ACTIONS) {
      const result = validateIntent(baseIntent({ action: verb }));
      assert.deepEqual(Object.keys(result).sort(), EXPECTED_KEYS);
      assert.equal(result._preFillOnly, true);
      assert.equal(result.formula, RITUAL_FORMULA);
    }
  });

  test("no function-valued properties on the normalized object — it is DATA, never an action", () => {
    const result = validateIntent(baseIntent());
    for (const [key, value] of Object.entries(result)) {
      assert.notEqual(
        typeof value,
        "function",
        `key '${key}' must not be a function — an intent is DATA, never an action`
      );
    }
  });

  test("no function-valued properties for any of the six verbs, including task sub-object", () => {
    for (const verb of ACTIONS) {
      const result = validateIntent(baseIntent({ action: verb }));
      for (const [key, value] of Object.entries(result)) {
        assert.notEqual(typeof value, "function", `top-level key '${key}' (${verb})`);
      }
      if (result.task && typeof result.task === "object") {
        for (const [key, value] of Object.entries(result.task)) {
          assert.notEqual(typeof value, "function", `task key '${key}' (${verb})`);
        }
      }
    }
  });

  test("normalized object is a plain data object — JSON round-trips it losslessly", () => {
    const result = validateIntent(baseIntent());
    const roundTripped = JSON.parse(JSON.stringify(result));
    assert.deepEqual(roundTripped, result);
  });
});

/* ============================================================================
   ackIntent: exactly-once, id-scoped consumption of the stored intent.
   DOM-free harness (see the header comment at the top of this file) — window
   is a Map-backed localStorage stub, document is never set, hasDOM stays
   false, and no timer/listener is ever armed.
   ========================================================================== */
describe("ackIntent: id-scoped, exactly-once", () => {
  test.beforeEach(() => {
    __intentStore.clear();
  });

  test("ackIntent('wrong-id') leaves a non-matching stored intent in place", () => {
    seedIntent("abc");
    ackIntent("wrong-id");
    assert.ok(__intentStore.has(INTENT_KEY), "key must still be present — a wrong id must not ack it");
    const remaining = JSON.parse(__intentStore.get(INTENT_KEY));
    assert.equal(remaining.id, "abc");
  });

  test("ackIntent('abc') removes the stored intent whose id matches", () => {
    seedIntent("abc");
    ackIntent("abc");
    assert.equal(__intentStore.has(INTENT_KEY), false, "key must be removed once the matching id is acked");
  });

  test("a second ackIntent('abc') after the key is already gone is a harmless no-op", () => {
    seedIntent("abc");
    ackIntent("abc");
    assert.equal(__intentStore.has(INTENT_KEY), false);
    // second ack: nothing stored, nothing to match — must not throw, and
    // must leave the (already-empty) store alone.
    assert.doesNotThrow(() => ackIntent("abc"));
    assert.equal(__intentStore.has(INTENT_KEY), false);
  });

  test(
    "HONEST DOCUMENTATION: ackIntent(undefined) clears whatever is currently stored, " +
      "regardless of its id — the `id != null` guard at izbushka-companion.js:275 treats a " +
      "missing id as a wildcard, not a no-match",
    () => {
      // ackIntent(id) body (izbushka-companion.js:272-278):
      //   const cur = readStored();
      //   if (!cur || (id != null && cur.id !== id)) return;
      //   window.localStorage.removeItem(INTENT_KEY);
      //
      // When id is undefined, `id != null` is false, so the id-mismatch
      // branch of the guard can never trigger — the function falls through
      // and removes whatever intent is currently stored, no matter its id.
      // This is the ACTUAL, current behaviour of the shipped code, not a
      // hypothetical: calling ackIntent() with no argument (or an explicit
      // undefined) is a "clear whatever's pending" operation, not a
      // rejected/no-op ack of a specific intent. It is asserted here as a
      // characterization test — documenting the real code path — not as an
      // endorsement; a caller that wants strict id-scoped exactly-once
      // semantics must always pass the id it expects to consume.
      seedIntent("abc");
      ackIntent(undefined);
      assert.equal(
        __intentStore.has(INTENT_KEY),
        false,
        "ackIntent(undefined) clears the store — current, documented (not fixed) behaviour"
      );
    }
  );

  test("ackIntent(id) on an empty store is a harmless no-op (nothing to clear)", () => {
    assert.equal(__intentStore.has(INTENT_KEY), false);
    assert.doesNotThrow(() => ackIntent("abc"));
    assert.equal(__intentStore.has(INTENT_KEY), false);
  });

  test("ackIntent(id) ignores a stored value that fails validateIntent (e.g. wrong formula) — nothing to ack", () => {
    __intentStore.set(INTENT_KEY, JSON.stringify({ id: "abc", action: "declare", formula: "not-the-ritual" }));
    ackIntent("abc");
    assert.ok(__intentStore.has(INTENT_KEY), "an intent that never validated is not this function's to remove");
  });

  test("onIntent delivers a pending stored intent to a newly registered handler, without acking it", () => {
    seedIntent("abc");
    let delivered = null;
    onIntent((intent) => { delivered = intent; });
    assert.ok(delivered, "handler must receive the pending intent");
    assert.equal(delivered.id, "abc");
    assert.ok(__intentStore.has(INTENT_KEY), "onIntent must never ack/clear on its own — consent stays explicit");
  });
});

/* ============================================================================
   TRANSPORT C: hash-fragment base64url — the codec izbushka-companion.js uses
   to reverse Sotto's `btoa(unescape(encodeURIComponent(JSON.stringify(intent))))`
   encoder (see the header comment at izbushka-companion.js:47-60, encoder
   recipe at lines 51-56). base64UrlToBase64 is a pure string transform (no
   DOM), so it is exercised directly here alongside a full encode/decode
   round trip that mirrors Sotto's documented recipe exactly, including a
   non-ASCII task name to prove the unescape/decodeURIComponent UTF-8 dance
   survives the trip both ways.
   ========================================================================== */
describe("base64url: hash-fragment transport codec", () => {
  test("base64url: maps '-' to '+' and '_' to '/' with no padding added when length % 4 === 0", () => {
    // "-_-_" is length 4 -> pad === 0 -> returned as-is after char substitution.
    assert.equal(base64UrlToBase64("-_-_"), "+/+/");
  });

  test("base64url: re-pads with '==' when length % 4 === 2", () => {
    // "-_" is length 2 -> pad === 2 -> "==" appended.
    assert.equal(base64UrlToBase64("-_"), "+/==");
  });

  test("base64url: re-pads with '=' when length % 4 === 3", () => {
    // "-_-" is length 3 -> pad === 3 -> "=" appended.
    assert.equal(base64UrlToBase64("-_-"), "+/+=");
  });

  test("base64url: length % 4 === 1 throws Error('bad base64url length')", () => {
    // "-_-_-" is length 5 -> 5 % 4 === 1, the one remainder that can never be
    // a valid (unpadded) base64 length, per izbushka-companion.js:341.
    assert.throws(
      () => base64UrlToBase64("-_-_-"),
      { name: "Error", message: "bad base64url length" }
    );
    // also true for any other length%4===1 input, e.g. a single char.
    assert.throws(
      () => base64UrlToBase64("x"),
      { name: "Error", message: "bad base64url length" }
    );
  });

  test("base64url: full round-trip parity with Sotto's documented encoder (non-ASCII task name)", () => {
    // The intent to ship down the wire — deliberately includes a non-ASCII
    // task name ('café §') to prove the encodeURIComponent/unescape ⇄
    // escape/decodeURIComponent UTF-8 dance is exact in both directions.
    const intent = baseIntent({
      id: "sotto-frag-1",
      action: "declare",
      task: {
        name: "café §",
        description: "ritual déjà vu — naïve façade test",
        schedule: "daily 07:00",
      },
      ts: "2026-01-01T00:00:00.000Z",
    });

    // --- Sotto's encoder, verbatim per izbushka-companion.js:51-52/61-62/header:
    //     btoa(unescape(encodeURIComponent(JSON.stringify(intent))))
    //     then substitute '+'->'-', '/'->'_' and STRIP '=' padding.
    const json = JSON.stringify(intent);
    const std = btoa(unescape(encodeURIComponent(json)));
    const encoded = std.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

    // sanity: the wire payload is URL-safe-alphabet-only, no dangling padding.
    assert.ok(
      !/[+/=]/.test(encoded),
      "Sotto's encoded payload must be URL-safe with padding stripped"
    );

    // --- Izbushka's decoder, verbatim per izbushka-companion.js:336-343/362-364:
    //     base64UrlToBase64 (restore '-'/'_' -> '+'/'/', re-pad with '='),
    //     atob, then decodeURIComponent(escape(...)), JSON.parse,
    //     validateIntent — the SAME gate as transports A/B.
    const b64 = base64UrlToBase64(encoded);
    const decodedJson = decodeURIComponent(escape(atob(b64)));
    const parsed = JSON.parse(decodedJson);

    // the raw JSON round trip is exact, byte for byte, before the gate runs.
    assert.deepEqual(parsed, intent);

    const result = validateIntent(parsed);
    assert.notEqual(result, null, "the round-tripped fragment intent must validate through the SAME gate as A/B");
    assert.equal(result.id, intent.id);
    assert.equal(result.action, intent.action);
    assert.equal(result.formula, RITUAL_FORMULA);
    assert.deepEqual(result.task, intent.task);
    assert.equal(result.task.name, "café §", "non-ASCII task name must survive the round trip verbatim");
    assert.equal(result.ts, intent.ts);
  });
});
