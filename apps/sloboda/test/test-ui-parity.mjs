"use strict";
/* ============================================================================
   UI <-> CLI command-parity check for the Sloboda Waydroid gateway.

   Mirrors apps/sloboda-gate/test-ui-parity.mjs in spirit: instead of trusting a
   hand-copied stand-in, it runs the EXACT code that ships and asserts the two
   surfaces cannot silently drift. Where the gate test proves the browser's
   inline STORE LOGIC matches gate-store.mjs, this one proves the browser's
   COMMAND COMPOSER matches the bin/sloboda dispatcher: every command the UI can
   put on a "copy" button must name a subcommand the CLI actually accepts, and
   every documented subcommand must be present in the dispatcher.

   Mechanically:

     1. It extracts the <script> block straight out of ui/index.html and
        evaluates it in node under a tiny DOM shim (no real DOM, no network, no
        localStorage side effects) so the composed command strings come from the
        REAL shipping composer -- not a copy that could go stale.
     2. It drives that composer across several image-posture permutations
        (VANILLA/FOSS/GAPPS x microG on/off x store package) and harvests every
        `sloboda <subcommand>` string it emits onto the command cards.
     3. It parses the `case "$_paw_cmd" in ... esac` dispatch block out of
        bin/sloboda and collects every token (including aliases like show/launch)
        that routes to a real cmd_* handler.
     4. It asserts:
          A. every subcommand the UI composes is accepted by a dispatcher arm
             (UI -> CLI: catches a UI button pointing at a renamed/removed verb);
          B. every documented subcommand (the pinned product set) is represented
             in the dispatcher (CLI keeps its contract);
          C. every subcommand the UI composes is in the documented set (the UI
             never ships an undocumented verb).

   Any of those drifting -- the UI emitting `sloboda gui` after the CLI arm is
   renamed, a documented verb dropped from the dispatcher, a new undocumented UI
   button -- fails this file loudly (exit 1) instead of shipping a dead button.

   It BOOTS NOTHING: no Waydroid, no container, no Wayland, no network. It only
   reads two text files and runs the page's pure string-building code.
   Dependency-free: only node:assert, node:fs, node:path, node:url. No DOM libs.
   Run: node apps/sloboda/test/test-ui-parity.mjs
   ============================================================================ */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const uiPath = path.join(__dirname, "..", "ui", "index.html");
const binPath = path.join(__dirname, "..", "bin", "sloboda");

const html = readFileSync(uiPath, "utf8");
const bin = readFileSync(binPath, "utf8");

/* ---------------------------------------------------------------------------
   The pinned, documented subcommand set (from bin/sloboda usage() + the item
   spec). "show" is the canonical verb the UI uses for the full-UI entry; the
   CLI accepts it as an alias of `ui`. If the product adds/renames a documented
   verb, update this list AND the dispatcher together -- that is the drift this
   file is here to force into the open.
   --------------------------------------------------------------------------- */
const DOCUMENTED = [
  "init", "start", "status", "stop", "kill", "show",
  "app", "store", "launchers", "install-watch", "doctor", "config",
];

let pass = 0, fail = 0;
const ok = (name, cond) => {
  if (cond) { pass++; } else { fail++; console.error("FAIL:", name); }
};

/* ---- 1. extract the UI <script> block ------------------------------------ */

const scriptMatch = html.match(/<script>([\s\S]*?)<\/script>/);
assert.ok(scriptMatch, "could not find a <script>...</script> block in ui/index.html");
const scriptBody = scriptMatch[1];
assert.ok(scriptBody.includes("sloboda "),
  "extracted <script> does not look like the command composer (no 'sloboda ' literal)");

/* ---- 2. drive the real composer under a DOM shim ------------------------- */

// The captured innerHTML from the most recent build() of the command cards.
let capturedHtml = "";

function makeEl(props) {
  const el = {
    _listeners: Object.create(null),
    dataset: {},
    addEventListener(type, fn) {
      (this._listeners[type] || (this._listeners[type] = [])).push(fn);
    },
    setAttribute() {},
    removeAttribute() {},
    fire(type) {
      for (const fn of this._listeners[type] || []) fn.call(this, { target: this });
    },
  };
  return Object.assign(el, props);
}

// Mutable image-posture inputs the composer reads on every build().
const posture = { sys: "VANILLA", microg: false, storePkg: "com.aurora.store" };

const btnThemeEl = makeEl({ textContent: "" });
const optMicrogEl = makeEl({});
Object.defineProperty(optMicrogEl, "checked", { get: () => posture.microg });
const storePkgEl = makeEl({});
Object.defineProperty(storePkgEl, "value", { get: () => posture.storePkg });

const cmdsEl = makeEl({});
Object.defineProperty(cmdsEl, "innerHTML", {
  get: () => capturedHtml,
  set: (v) => { capturedHtml = v; },
});

const sysRadios = ["VANILLA", "FOSS", "GAPPS"].map((v) => makeEl({ value: v }));

const documentShim = {
  documentElement: makeEl({}),
  getElementById(id) {
    switch (id) {
      case "btnTheme": return btnThemeEl;
      case "optMicrog": return optMicrogEl;
      case "storePkg": return storePkgEl;
      case "cmds": return cmdsEl;
      default: throw new Error(`unexpected getElementById(${JSON.stringify(id)}) from ui/index.html`);
    }
  },
  querySelector(sel) {
    if (sel === 'input[name="sys"]:checked') return { value: posture.sys };
    throw new Error(`unexpected querySelector(${JSON.stringify(sel)}) from ui/index.html`);
  },
  querySelectorAll(sel) {
    if (sel === 'input[name="sys"]') return sysRadios;
    throw new Error(`unexpected querySelectorAll(${JSON.stringify(sel)}) from ui/index.html`);
  },
};

const localStorageShim = (() => {
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => { m.set(k, String(v)); },
    removeItem: (k) => { m.delete(k); },
  };
})();

// navigator/setTimeout are only touched inside the (never-fired) copy-click
// handler; provide inert stand-ins so the closure compiles cleanly.
const navigatorShim = {};
const setTimeoutShim = () => 0;

try {
  const run = new Function(
    "document", "localStorage", "navigator", "setTimeout",
    scriptBody,
  );
  run(documentShim, localStorageShim, navigatorShim, setTimeoutShim);
} catch (err) {
  console.error("FAIL: UI <script> failed to evaluate under the DOM shim:", err.message);
  process.exit(1);
}

// build() runs once on load. Re-drive it across posture permutations by mutating
// the inputs and firing the change/input listeners the page registered (exactly
// what a real user toggling the radios/box would trigger).
function rebuild() {
  // Any registered listener recomputes the whole card list; fire one on a radio.
  sysRadios[0].fire("change");
}

const HTML_SNAPSHOTS = [];
HTML_SNAPSHOTS.push(capturedHtml); // initial VANILLA / microG off / default pkg

const POSTURE_MATRIX = [
  { sys: "FOSS", microg: false, storePkg: "com.aurora.store" },
  { sys: "GAPPS", microg: true, storePkg: "org.fdroid.fdroid" },
  { sys: "VANILLA", microg: true, storePkg: "com.example.badpkg!" }, // invalid pkg -> composer sanitizes
];
for (const p of POSTURE_MATRIX) {
  Object.assign(posture, p);
  rebuild();
  HTML_SNAPSHOTS.push(capturedHtml);
}

ok("composer produced non-empty command HTML", HTML_SNAPSHOTS.every((h) => h && h.length > 0));

/* ---- 3. harvest the UI's composed subcommands ---------------------------- */

function htmlUnescape(s) {
  return s
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&amp;/g, "&");
}

// Every command card renders the literal command twice: inside <code>...</code>
// and in a data-copy="..." attribute. Harvest the data-copy strings (that is the
// exact text the copy button places on the clipboard) and pull the subcommand.
const uiSubs = new Set();
const uiRawCommands = new Set();
for (const snap of HTML_SNAPSHOTS) {
  const re = /data-copy="([^"]*)"/g;
  let m;
  while ((m = re.exec(snap)) !== null) {
    const cmd = htmlUnescape(m[1]);
    uiRawCommands.add(cmd);
    // Strip any leading `FOO=bar ` env-var assignments, then read the verb that
    // follows the `sloboda` binary name.
    const verbMatch = cmd.match(/(?:^|\s)sloboda\s+([A-Za-z0-9_-]+)/);
    ok(`UI command names a sloboda subcommand: ${cmd}`, !!verbMatch);
    if (verbMatch) uiSubs.add(verbMatch[1]);
  }
}
ok("UI emitted at least one command", uiSubs.size > 0);

/* ---- 4. parse the bin/sloboda dispatcher arms ---------------------------- */

const caseStart = bin.indexOf('case "$_paw_cmd" in');
assert.ok(caseStart !== -1, "could not find the dispatch `case \"$_paw_cmd\" in` block in bin/sloboda");
const caseEnd = bin.indexOf("\nesac", caseStart);
assert.ok(caseEnd > caseStart, "could not find the closing `esac` of the dispatch block in bin/sloboda");
const dispatchBlock = bin.slice(caseStart, caseEnd);

// Collect only arms that route to a real cmd_* handler. This deliberately
// excludes help/-h/--help (-> usage) and the *) wildcard (-> error), which are
// not subcommands the tool "accepts" as work.
const dispatcherSubs = new Set();
const armRe = /^[ \t]*([A-Za-z0-9_.|\-]+)\)\s*cmd_[A-Za-z_]+/gm;
let arm;
while ((arm = armRe.exec(dispatchBlock)) !== null) {
  for (const tok of arm[1].split("|")) {
    if (tok) dispatcherSubs.add(tok);
  }
}
ok("dispatcher exposed at least one cmd_* subcommand", dispatcherSubs.size > 0);

/* ---- 5. parity assertions ------------------------------------------------- */

// A. UI -> CLI: every subcommand the UI composes must be an accepted arm.
for (const sub of uiSubs) {
  ok(`A: UI subcommand '${sub}' is accepted by a bin/sloboda dispatcher arm`,
    dispatcherSubs.has(sub));
}

// B. every documented subcommand must be represented in the dispatcher.
for (const doc of DOCUMENTED) {
  ok(`B: documented subcommand '${doc}' is represented in the dispatcher`,
    dispatcherSubs.has(doc));
}

// C. UI -> docs: the UI never composes an undocumented verb.
for (const sub of uiSubs) {
  ok(`C: UI subcommand '${sub}' is in the documented set`,
    DOCUMENTED.includes(sub));
}

/* ---- report --------------------------------------------------------------- */

console.log("UI-composed subcommands:", [...uiSubs].sort().join(", "));
console.log("dispatcher subcommands :", [...dispatcherSubs].sort().join(", "));
console.log(`test-ui-parity: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
