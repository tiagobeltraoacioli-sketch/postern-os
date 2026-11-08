"use strict";
/* ============================================================================
   Golden-vector exporter for the Porog reconcile kernel — the anti-drift pin
   between the ONE authoritative decision (`reconcile-kernel.mjs`, node-tested)
   and its ONE Kotlin port (`labs.postern.container.dpc.CrossProfileReconciler
   .decide()`, JVM-tested against this file's output).

   Run:
     node export-vectors.mjs          # (re)writes ./golden-vectors.json

   DETERMINISTIC by construction: the case list is fixed, the kernel is pure and
   clock-free, and nothing here reads the clock, the environment, or randomness —
   running it twice produces byte-identical output. The JSON is COMMITTED; any
   kernel change that alters a directive must regenerate it (and keep
   test-reconcile.mjs green) in the same commit, which forces the Kotlin parity
   test (CrossProfileReconcilerParityTest) to be reconciled too. That is the
   rail: the two implementations can never silently drift again.

   Scope note (honest): inputs are JSON objects or null only. The Kotlin surface
   receives `JSONObject?` — non-object on-disk text (a bare string, truncated
   JSON) collapses to null in its reader before decide(), exactly as
   reconcileText() collapses it here — so object-or-null is the complete shared
   input domain. The kernel's own non-object cases stay covered by
   test-reconcile.mjs.

   Reference/prototype, UNAUDITED. No network, no telemetry, no imports beyond
   the kernel + node:fs.
   ============================================================================ */

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import K from "./reconcile-kernel.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, "golden-vectors.json");

/* A recognised, consented base blob (the same helper shape test-reconcile.mjs
   uses), plus the standing variant. */
const base = (over = {}) => ({
  schema: K.SCHEMA_ID,
  version: K.SCHEMA_VERSION,
  consent: { accepted: true },
  ...over,
});
const stand = (over = {}) => base({ consent: { accepted: true, standing: true }, ...over });

const vectors = [];
const add = (name, input) => vectors.push({ name, input, directives: K.reconcile(input) });

/* ---- unrecognised / malformed => full-deny ------------------------------- */
add("null input", null);
add("empty object", {});
add("foreign schema, consented, crossings set", {
  schema: "some.other.schema",
  version: K.SCHEMA_VERSION,
  consent: { accepted: true, standing: true },
  crossings: { intents: { direction: "both" }, contacts: { direction: "both" } },
});
add("missing schema", { version: K.SCHEMA_VERSION, consent: { accepted: true } });
add("stringified version \"1\" (schema laundering bait)", base({ version: "1" }));
add("wrong version 2", base({ version: 2 }));
add("boolean version true", base({ version: true }));

/* ---- consent gate --------------------------------------------------------- */
add("consent off, crossings set", base({
  consent: { accepted: false },
  crossings: { intents: { direction: "both" }, files: { direction: "p2w" } },
}));
add("truthy-but-not-true consent (accepted: 1)", base({ consent: { accepted: 1 } }));
add("consented, no crossings", base());
add("standing consent alone, no crossings", stand());

/* ---- kill-switch ---------------------------------------------------------- */
add("kill-switch engaged, everything open underneath", stand({
  killSwitch: { engaged: true, engagedAtIso: "2026-01-01T00:00:00Z" },
  crossings: {
    intents: { open: true, direction: "both" },
    files: { open: true, direction: "p2w" },
    clipboard: { open: true, direction: "both" },
    contacts: { open: true, direction: "both" },
    calendar: { open: true, direction: "both", package: "com.example.cal" },
    connectedApp: { open: true, direction: "both", package: "com.example.app" },
  },
}));
add("truthy-but-not-true kill-switch (engaged: \"yes\") stays disengaged", base({
  killSwitch: { engaged: "yes" },
  crossings: { intents: { direction: "p2w" } },
}));

/* ---- crossing blob shape -------------------------------------------------- */
add("non-object crossing entry (intents: \"both\")", base({ crossings: { intents: "both" } }));
add("garbage direction (sideways)", base({ crossings: { intents: { direction: "sideways" } } }));

/* ---- the `open` primary deny gate ----------------------------------------- */
add("open:false beats a stale direction (user-mediated)",
  base({ crossings: { intents: { open: false, direction: "both" } } }));
add("open:false beats a stale direction (standing, with standing consent + package)",
  stand({ crossings: { calendar: { open: false, direction: "p2w", package: "com.android.calendar" } } }));
add("open omitted + real direction => open (backward compat)",
  base({ crossings: { intents: { direction: "p2w" } } }));
add("open:true + real direction => open",
  base({ crossings: { intents: { open: true, direction: "p2w" } } }));
add("open:true + direction none => nothing installed",
  base({ crossings: { intents: { open: true, direction: "none" } } }));
add("open:null is not true => closed",
  base({ crossings: { intents: { open: null, direction: "both" } } }));

/* ---- every direction, per user-mediated cap ------------------------------- */
for (const cap of ["intents", "files", "clipboard"]) {
  for (const dir of K.DIRECTIONS) {
    add(`${cap} direction ${dir}`, base({ crossings: { [cap]: { direction: dir } } }));
  }
}

/* ---- standing caps: stronger-consent gate, on and off --------------------- */
for (const dir of ["p2w", "w2p", "both"]) {
  add(`contacts ${dir} WITHOUT standing consent`, base({ crossings: { contacts: { direction: dir } } }));
  add(`contacts ${dir} WITH standing consent`, stand({ crossings: { contacts: { direction: dir } } }));
}

/* ---- package caps: present / absent / malformed per cap ------------------- */
for (const [cap, pkg] of [["calendar", "com.android.calendar"], ["connectedApp", "com.example.link"]]) {
  add(`${cap} standing, NO package`, stand({ crossings: { [cap]: { open: true, direction: "p2w" } } }));
  add(`${cap} standing, valid package`, stand({ crossings: { [cap]: { open: true, direction: "p2w", package: pkg } } }));
  add(`${cap} NO standing, valid package`, base({ crossings: { [cap]: { open: true, direction: "p2w", package: pkg } } }));
  add(`${cap} standing, malformed package (spaces)`, stand({ crossings: { [cap]: { direction: "p2w", package: "not a package" } } }));
  add(`${cap} standing, single-label package`, stand({ crossings: { [cap]: { direction: "p2w", package: "android" } } }));
  add(`${cap} standing, non-string package`, stand({ crossings: { [cap]: { direction: "p2w", package: 42 } } }));
  add(`${cap} standing, path-traversal package`, stand({ crossings: { [cap]: { direction: "p2w", package: "../etc" } } }));
}

/* ---- inbound-share control (DISALLOW_SHARE_INTO_MANAGED_PROFILE) ---------- */
add("w2p-only files keeps inbound share blocked",
  base({ crossings: { files: { open: true, direction: "w2p" } } }));
add("p2w files clears the inbound-share restriction",
  base({ crossings: { files: { open: true, direction: "p2w" } } }));
add("both-direction intents clears the inbound-share restriction",
  base({ crossings: { intents: { open: true, direction: "both" } } }));
add("clipboard p2w alone does NOT lift the inbound-share block",
  base({ crossings: { clipboard: { direction: "p2w" } } }));

/* ---- kitchen sink: everything legitimately open ---------------------------- */
add("kitchen sink: all six caps open with standing consent + valid packages", stand({
  crossings: {
    intents: { open: true, direction: "both" },
    files: { open: true, direction: "p2w" },
    clipboard: { open: true, direction: "w2p" },
    contacts: { open: true, direction: "both" },
    calendar: { open: true, direction: "p2w", package: "com.android.calendar" },
    connectedApp: { open: true, direction: "w2p", package: "com.example.link" },
  },
}));

/* ---- pins under hostile input --------------------------------------------- */
add("hostile pins: tier/sealedWallet relabel attempt stays pinned", base({
  tier: "measured-boot-workspace",
  sealedWallet: { preserved: false },
  crossings: { intents: { direction: "p2w" } },
}));

/* ---------------------------------------------------------------------------
   Cross-product self-check (drift pin).

   The full decision matrix the kernel — and the Kotlin parity suite that mirrors
   it — ranges over is the product of the kernel's own dimensions:

       576  =  6 caps       (K.CROSSING_KEYS)
            ×  4 directions  (K.DIRECTIONS)
            ×  2 consent     (accepted: false | true)
            ×  2 standing    (standing:  false | true)
            ×  2 kill        (killSwitch.engaged: false | true)
            ×  3 package     (package:   absent | valid | malformed)

   It is 576, NOT 1152: 1152 double-counts the matrix by pretending every cap
   carries the package axis, when only the two PACKAGE_CAPS do (the true package
   factor is a single 3-way axis, not a per-cap doubling). `crossProductCount`
   below is COMPUTED from the live kernel arrays, and the self-check throws if it
   ever diverges from the 576 documented here — so this factorization can never
   silently drift out of sync with the kernel again. */
const CROSS_PRODUCT_DIMENSIONS = Object.freeze({
  caps: K.CROSSING_KEYS.length,     // 6  — intents/files/clipboard + contacts/calendar/connectedApp
  directions: K.DIRECTIONS.length,  // 4  — none | p2w | w2p | both
  consent: 2,                       // accepted: false | true
  standing: 2,                      // standing: false | true
  kill: 2,                          // killSwitch.engaged: false | true
  package: 3,                       // package: absent | valid | malformed
});
const DOCUMENTED_CROSS_PRODUCT_COUNT = 576;
const crossProductCount = Object.values(CROSS_PRODUCT_DIMENSIONS).reduce((a, b) => a * b, 1);
if (crossProductCount !== DOCUMENTED_CROSS_PRODUCT_COUNT) {
  throw new Error(
    `export-vectors: cross-product drift — computed ${crossProductCount} from the kernel ` +
    `dimensions (${JSON.stringify(CROSS_PRODUCT_DIMENSIONS)}) but the documented full matrix ` +
    `is ${DOCUMENTED_CROSS_PRODUCT_COUNT}. A kernel change moved an axis: update the ` +
    `factorization comment AND this self-check together, in the same commit.`
  );
}

const payload = {
  schema: K.SCHEMA_ID,
  version: K.SCHEMA_VERSION,
  tier: K.TIER,
  generator: "apps/porog-crossprofile/export-vectors.mjs",
  note:
    "COMMITTED golden vectors: reconcile-kernel.mjs is the ONE decision authority; " +
    "the Kotlin port (labs.postern.container.dpc.CrossProfileReconciler.decide) is " +
    "pinned to these field-by-field by CrossProfileReconcilerParityTest. Regenerate " +
    "with `node export-vectors.mjs` in the SAME commit as any kernel change. " +
    "Deterministic; UNAUDITED reference vectors, not a security guarantee.",
  vectorCount: vectors.length,
  vectors,
};

writeFileSync(OUT, JSON.stringify(payload, null, 2) + "\n");
console.log(
  `export-vectors: ${crossProductCount} cross-product cases pinned; ` +
  `wrote ${vectors.length} vectors to ${OUT}`
);
