// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
"use strict";
/* ============================================================================
   izbushka-companion.js  ·  Postern Labs · Yagabona/Izbushka
   ----------------------------------------------------------------------------
   Two jobs, no dependencies, no network:
     1. celebrate() — the cursor-companion mascot (the hut with Yagabona
        waving from the window). A DELIGHT CUE and a CONSENT RECEIPT: the hut
        only dances when a task was properly scheduled — i.e. the ritual was
        spoken. Never call it on any other event.
     2. The Sotto voice-INTENT bridge — read a same-origin intent that Sotto
        wrote, hand it to the portal to PRE-FILL a form. An intent NEVER
        auto-grants; consent stays explicit.

   Loaded as a CLASSIC script (not an ES module) and exposes window.Izbushka.
   Why classic, not `export`? The spec's reference uses `export function
   celebrate` — that is the shape of the intent. We attach to window instead so
   the page needs no module MIME type and still works from file:// (ES modules
   are blocked over file:// by CORS). Under the page CSP this file is served
   same-origin and allowed by `script-src 'self'`; it opens NO connections.

   ==========================================================================
   MASCOT TIMINGS (spec §3, exact) — 4.0 s total
   --------------------------------------------------------------------------
     0.0–0.3 s  pop-in       scale 0 → 1, ease-out-back
     0.3–3.3 s  follow       tracks the pointer; full 360° spin every 1.2 s
                             (2.5 turns) + a gentle ±6° leg wobble
     3.3–4.0 s  fade-out     opacity → 0, drift up 14 px
     offset     28 px right / 12 px below the pointer (never occludes the click)
     asset      izbushka-mascot.svg (same-origin; img-src 'self')
     a11y       prefers-reduced-motion: reduce → NO motion; a static 2 s toast
   The Rust / Postern OS compositor port follows the same timings.

   ==========================================================================
   SOTTO ↔ IZBUSHKA INTENT CONTRACT  (the handoff, defined here)
   --------------------------------------------------------------------------
   Sotto (the voice front-end) hands Izbushka an INTENT. Three same-origin
   transports, all accepted; whichever Sotto has is fine:

     A) localStorage  — Sotto writes the key `izbushka.intent` (string JSON).
                        Izbushka notices it via the cross-tab `storage` event
                        and via a short same-tab poll, then CLEARS the key
                        (ackIntent) so it is handled exactly once.
     B) postMessage   — Sotto posts to the same window/opener:
                        { source: "sotto-intent", intent: <Intent> }
                        Only messages whose event.origin === location.origin
                        are accepted. Cross-origin messages are dropped.
     C) hash fragment — Sotto's deep link `../izbushka/#izbushka-intent=<b64>`
                        carries the intent as base64url(JSON) in the URL hash
                        (no network, no server ever sees it — the fragment
                        never leaves the browser). Sotto encodes it with
                        `btoa(unescape(encodeURIComponent(JSON.stringify(intent))))`
                        then substitutes `+`→`-`, `/`→`_` and strips `=`
                        padding. On load, this file reverses that exactly —
                        restore `-`/`_`→`+`/`/`, re-pad with `=`, `atob`,
                        then `decodeURIComponent(escape(...))` — parses the
                        JSON, and runs it through the SAME validateIntent()
                        as A/B. The fragment is stripped via
                        history.replaceState right after it is read (valid
                        or not) so it is consumed exactly once: it neither
                        re-fires on reload nor lingers in the URL bar.

   Intent shape (v1):
     {
       "v": 1,
       "id": "<opaque unique id, for ack>",
       "action": "declare" | "grant" | "schedule" | "pause" | "revoke" | "list",
       "formula": "izbushka-turn-your-face-to-me",   // REQUIRED, exact
       "task": {                                      // optional; pre-fill data
         "name": "...", "description": "...",
         "schedule": "...", "expires": "...",
         "read_paths": ["..."], "write_paths": ["..."],
         "network": "none" | "api.anthropic.com",
         "granted_by": "...", "target": "<task id for grant/pause/revoke>"
       },
       "ts": "<ISO-8601>"
     }

   RULES enforced here before an intent is ever surfaced:
     · formula MUST equal the literal "izbushka-turn-your-face-to-me".
       No formula, no door — the intent is ignored (logged to console).
     · action MUST be one of the six verbs above.
     · An intent is DATA, never an action. It is handed to the registered
       handler to PRE-FILL the declare/grant form. It NEVER grants, schedules,
       pauses or revokes on its own. The human confirms in the UI. Consent
       stays explicit; the ritual is spoken by the user, not by Sotto.

   API (window.Izbushka):
     celebrate(svgUrl = "izbushka-mascot.svg")  → play the mascot / toast
     onIntent(handler)  → handler(intent) for any pending + future intent
     ackIntent(id)      → remove the consumed intent from the store
     RITUAL_FORMULA     → the literal formula string
     version
   ========================================================================== */

(function () {
  const RITUAL_FORMULA = "izbushka-turn-your-face-to-me";
  const ACTIONS = ["declare", "grant", "schedule", "pause", "revoke", "list"];
  const INTENT_KEY = "izbushka.intent";
  const STYLE_ID = "izb-companion-css";
  const MASCOT = "izbushka-mascot.svg";

  /* ---- guard: this file needs a DOM. If required, it degrades quietly. ---- */
  const hasDOM = typeof document !== "undefined" && typeof window !== "undefined";

  const reducedMotion = () =>
    hasDOM && typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* -------------------------------------------------------------------------
     One-time CSS injection. Kept inside the companion so it is self-contained
     when dropped into any page. Governed by the page's `style-src 'unsafe-inline'`.
     The spin lives on the WRAPPER (`rotate`); the ±6° wobble lives on the inner
     IMG (`rotate`) — two elements so the two rotations never fight. pop (scale),
     fade (opacity + translate) also sit on the wrapper as independent transform
     properties, exactly as the spec's reference keyframes do.
     ------------------------------------------------------------------------- */
  function ensureCss() {
    if (!hasDOM || document.getElementById(STYLE_ID)) return;
    const css = `
.izb-companion {
  position: fixed; left: 0; top: 0; z-index: 2147483000;
  width: 64px; height: auto; pointer-events: none;
  transform-origin: 50% 60%;
  will-change: left, top, transform, opacity;
  animation:
    izb-pop  .3s cubic-bezier(.34,1.56,.64,1) both,
    izb-spin 1.2s linear .3s 2.5,
    izb-fade .7s ease-in 3.3s forwards;
}
.izb-companion img {
  display: block; width: 100%; height: auto;
  transform-origin: 50% 78%;               /* pivot near the chicken legs */
  animation: izb-wobble .6s ease-in-out .3s 5;
}
@keyframes izb-pop    { from { scale: 0 } to { scale: 1 } }
@keyframes izb-spin   { to { rotate: 360deg } }
@keyframes izb-fade   { to { opacity: 0; translate: 0 -14px } }
@keyframes izb-wobble { 0%,100% { rotate: -6deg } 50% { rotate: 6deg } }

/* Reduced-motion path: a still toast, no cursor chase, no spin. */
.izb-toast {
  position: fixed; left: 50%; bottom: 26px; transform: translateX(-50%);
  z-index: 2147483000; pointer-events: none;
  display: flex; align-items: center; gap: 12px;
  padding: 12px 18px 12px 12px; border-radius: 14px;
  background: rgba(24,18,12,.94); color: #f6e9d2;
  border: 1px solid rgba(242,193,78,.55);
  box-shadow: 0 14px 40px rgba(0,0,0,.4);
  font: 500 14px/1.35 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  max-width: min(92vw, 420px);
}
.izb-toast img { width: 40px; height: auto; display: block; flex: none; }
.izb-toast b { color: #f2c14e; font-weight: 700; }
@media (prefers-color-scheme: light) {
  .izb-toast { background: #fff7ea; color: #4f2d18; border-color: rgba(154,98,16,.5); }
  .izb-toast b { color: #9a6210; }
}
`;
    const style = document.createElement("style");
    style.id = STYLE_ID;
    style.textContent = css;
    (document.head || document.documentElement).appendChild(style);
  }

  /* ---- the reduced-motion consent receipt: a static 2 s toast ---- */
  function toast(svgUrl) {
    ensureCss();
    const wrap = document.createElement("div");
    wrap.className = "izb-toast";
    wrap.setAttribute("role", "status");
    const img = document.createElement("img");
    img.src = svgUrl || MASCOT;
    img.alt = "Izbushka";
    const msg = document.createElement("span");
    // built via DOM, not innerHTML — nothing user-controlled reaches markup
    const b = document.createElement("b");
    b.textContent = "Task scheduled.";
    msg.append(b, document.createTextNode(" Izbushka turned her face to you."));
    wrap.append(img, msg);
    document.body.appendChild(wrap);
    setTimeout(() => wrap.remove(), 2000);
  }

  /* ---- celebrate(): the mascot. Consent receipt for a spoken ritual. ---- */
  function celebrate(svgUrl) {
    if (!hasDOM || !document.body) return;
    if (reducedMotion()) return toast(svgUrl);
    ensureCss();

    const wrap = document.createElement("div");
    wrap.className = "izb-companion";
    wrap.setAttribute("aria-hidden", "true");
    const img = document.createElement("img");
    img.src = svgUrl || MASCOT;
    img.alt = "";
    wrap.appendChild(img);

    // 28 px right / 12 px below the pointer so it never covers the click target
    const move = (e) => {
      wrap.style.left = (e.clientX + 28) + "px";
      wrap.style.top = (e.clientY + 12) + "px";
    };
    // seed a sensible start position (centre-ish) until the first mouse move
    wrap.style.left = (window.innerWidth / 2 + 28) + "px";
    wrap.style.top = (window.innerHeight / 2 + 12) + "px";

    window.addEventListener("mousemove", move);
    document.body.appendChild(wrap);
    setTimeout(() => {
      wrap.remove();
      window.removeEventListener("mousemove", move);
    }, 4000); // 0.3 pop + 3.0 follow + 0.7 fade
  }

  /* =========================== INTENT BRIDGE =============================== */
  const handlers = [];

  function validateIntent(raw) {
    if (!raw || typeof raw !== "object") return null;
    if (raw.formula !== RITUAL_FORMULA) {
      // No formula, no door. Never guess the ritual; ignore and say so.
      if (typeof console !== "undefined")
        console.warn("[Izbushka] intent ignored: missing/incorrect ritual formula.");
      return null;
    }
    if (!ACTIONS.includes(raw.action)) {
      if (typeof console !== "undefined")
        console.warn("[Izbushka] intent ignored: unknown action", raw.action);
      return null;
    }
    // Normalise into an inert, pre-fill-only shape. Never carries execution.
    // Tolerant of Sotto's emitted shape: `task` may be a kebab slug string with
    // `description`/`schedule` carried at the top level, and the timestamp may
    // arrive as `createdAt` rather than `ts`. Fold both into the canonical
    // task object so the pre-fill never silently loses the spoken task.
    const task = (raw.task && typeof raw.task === "object")
      ? raw.task
      : {
          name: typeof raw.task === "string" ? raw.task : undefined,
          description: raw.description,
          schedule: raw.schedule,
        };
    const ts = raw.ts || raw.createdAt || null;
    return {
      v: 1,
      id: typeof raw.id === "string" ? raw.id : String(ts || Date.now()),
      action: raw.action,
      formula: RITUAL_FORMULA,
      task,
      ts,
      _preFillOnly: true, // marker: an intent NEVER acts on its own
    };
  }

  function readStored() {
    try {
      const s = window.localStorage.getItem(INTENT_KEY);
      if (!s) return null;
      return validateIntent(JSON.parse(s));
    } catch { return null; }
  }

  function deliver(intent) {
    if (!intent) return;
    for (const h of handlers) {
      try { h(intent); } catch (e) {
        if (typeof console !== "undefined") console.error("[Izbushka] intent handler threw", e);
      }
    }
  }

  function ackIntent(id) {
    try {
      const cur = readStored();
      if (!cur || (id != null && cur.id !== id)) return;
      window.localStorage.removeItem(INTENT_KEY);
    } catch { /* storage unavailable — nothing to clear */ }
  }

  function onIntent(handler) {
    if (typeof handler !== "function") return;
    handlers.push(handler);
    // deliver any intent already waiting when the portal registered
    const pending = readStored();
    if (pending) deliver(pending);
    // C) hash-fragment intent — delivered exactly once, then cleared
    if (pendingFragmentIntent) {
      const fi = pendingFragmentIntent;
      pendingFragmentIntent = null;
      deliver(fi);
    }
  }

  if (hasDOM) {
    // A) cross-tab storage event (fires in OTHER tabs when Sotto writes)
    window.addEventListener("storage", (e) => {
      if (e.key !== INTENT_KEY || !e.newValue) return;
      deliver(validateIntent(safeParse(e.newValue)));
    });

    // A') same-tab poll — the storage event does NOT fire in the writing tab,
    //     so Sotto-in-this-tab handoffs are caught by a light poll.
    let lastSeen = null;
    setInterval(() => {
      let s = null;
      try { s = window.localStorage.getItem(INTENT_KEY); } catch { return; }
      if (s && s !== lastSeen) {
        lastSeen = s;
        deliver(validateIntent(safeParse(s)));
      } else if (!s) {
        lastSeen = null;
      }
    }, 800);

    // B) postMessage — same-origin only
    window.addEventListener("message", (e) => {
      if (e.origin !== location.origin) return;         // drop cross-origin
      const d = e.data;
      if (!d || d.source !== "sotto-intent") return;
      deliver(validateIntent(d.intent));
    });
  }

  function safeParse(s) { try { return JSON.parse(s); } catch { return null; } }

  /* ---------------------------------------------------------------------
     C) hash-fragment transport — reverses Sotto's
     btoa(unescape(encodeURIComponent(JSON))) encoder, then substitutes
     '-'→'+', '_'→'/' and re-pads with '=' before atob(). Read once at
     load; the fragment is stripped immediately (valid or not) so it is
     consumed exactly once and never lingers in the URL bar or re-fires
     on reload.
     ------------------------------------------------------------------- */
  const FRAGMENT_KEY = "izbushka-intent=";

  function base64UrlToBase64(b64url) {
    let b64 = String(b64url).replace(/-/g, "+").replace(/_/g, "/");
    const pad = b64.length % 4;
    if (pad === 2) b64 += "==";
    else if (pad === 3) b64 += "=";
    else if (pad !== 0) throw new Error("bad base64url length");
    return b64;
  }

  function readFragmentIntent() {
    if (!hasDOM) return null;
    const hash = window.location.hash || "";
    const idx = hash.indexOf(FRAGMENT_KEY);
    if (idx === -1) return null;
    const encoded = hash.slice(idx + FRAGMENT_KEY.length);

    // Strip the fragment right away — before we even know whether the
    // payload validates — so it never lingers in the URL bar and never
    // re-fires on a later reload of the same tab.
    try {
      const url = new URL(window.location.href);
      url.hash = "";
      window.history.replaceState(window.history.state, document.title, url.toString());
    } catch { /* replaceState/URL unavailable — nothing else we can do here */ }

    try {
      const b64 = base64UrlToBase64(decodeURIComponent(encoded));
      const json = decodeURIComponent(escape(atob(b64)));
      return validateIntent(JSON.parse(json));
    } catch (e) {
      if (typeof console !== "undefined")
        console.warn("[Izbushka] fragment intent ignored: malformed payload", e);
      return null;
    }
  }

  // Read (and strip) the fragment intent once, synchronously, at load —
  // before any handler has necessarily registered yet.
  let pendingFragmentIntent = hasDOM ? readFragmentIntent() : null;

  /* ------------------------------- export -------------------------------- */
  const api = { celebrate, onIntent, ackIntent, RITUAL_FORMULA, version: "0.1.0-draft" };
  if (hasDOM) window.Izbushka = api;
  // classic-script friendly; also visible to a CommonJS `require` in tests
  // (pure helpers exported for tests)
  if (typeof module !== "undefined" && module.exports)
    module.exports = { ...api, validateIntent, base64UrlToBase64, ACTIONS };
})();
