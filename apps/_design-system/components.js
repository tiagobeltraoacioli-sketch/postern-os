/* ============================================================================
   Postern Design System — COMPONENT JS  (PosternDS)
   ----------------------------------------------------------------------------
   Dependency-free, framework-free, CSP-safe (no eval, no network). UMD-ish:
   attaches `window.PosternDS` in a browser and exports the same object under
   Node/CommonJS/ESM bundlers so `node --check` and tooling stay happy.

   STATUS: UNAUDITED reference work. The trust helper enforces a *labeling*
   discipline (green cannot be faked from a caption), not cryptography — the
   caller must pass a real verification result.
   ============================================================================ */
(function (root, factory) {
  var api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.PosternDS = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  var hasDOM = typeof document !== "undefined";
  var hasWin = typeof window !== "undefined";

  /* -- small helpers ------------------------------------------------------ */
  function prefersReducedMotion() {
    return hasWin && typeof window.matchMedia === "function"
      ? window.matchMedia("(prefers-reduced-motion: reduce)").matches
      : false;
  }
  var store = {
    get: function (k, d) { try { var v = localStorage.getItem(k); return v === null ? d : v; } catch (e) { return d; } },
    set: function (k, v) { try { localStorage.setItem(k, v); } catch (e) {} }
  };

  /* ======================================================================
     THEME — cycles auto -> light -> dark, persists, tracks OS in "auto".
     Uses the same `data-theme` attribute the apps already read, so the whole
     page (app styles + ps-* tokens) flips together.
     ====================================================================== */
  var THEME_KEY = "ps.theme";
  var THEME_ORDER = { auto: "light", light: "dark", dark: "auto" };
  var THEME_GLYPH = { auto: "◐" /* ◐ */, light: "○" /* ○ */, dark: "●" /* ● */ };

  var theme = {
    current: function () { return store.get(THEME_KEY, "auto"); },
    apply: function () {
      if (!hasDOM) return;
      var t = this.current();
      if (t === "auto") document.documentElement.removeAttribute("data-theme");
      else document.documentElement.setAttribute("data-theme", t);
      this._syncButtons(t);
    },
    set: function (t) { if (THEME_ORDER[t]) { store.set(THEME_KEY, t); this.apply(); } },
    cycle: function () { this.set(THEME_ORDER[this.current()] || "auto"); },
    _syncButtons: function (t) {
      if (!hasDOM) return;
      var btns = document.querySelectorAll("[data-ps-theme-toggle]");
      for (var i = 0; i < btns.length; i++) {
        var b = btns[i];
        if (b.dataset.psGlyph !== "off") b.textContent = THEME_GLYPH[t] || "◐";
        b.setAttribute("aria-label", "Color theme: " + t + " (activate to change)");
        b.setAttribute("title", "Theme: " + t);
      }
    },
    /* Wire every [data-ps-theme-toggle] button and apply the saved theme. */
    init: function () {
      if (!hasDOM) return;
      var self = this;
      var btns = document.querySelectorAll("[data-ps-theme-toggle]");
      for (var i = 0; i < btns.length; i++) {
        btns[i].addEventListener("click", function () { self.cycle(); });
      }
      this.apply();
    }
  };

  /* ======================================================================
     TRUST STATE — the honest core.
     States: checking | unsigned | unverifiable | verified | tampered.
     "verified" (green) may only be reached by passing the sentinel
     PosternDS.VERIFIED_OK as the 3rd arg — a caption string can never turn a
     surface green by accident. This mirrors the check-trust-labels guardrail
     in code: the earned state is gated, everything else is honest-by-default.
     ====================================================================== */
  var VERIFIED_OK = { __psVerified: true }; // opaque sentinel; hard to forge by typo

  var TRUST_LABELS = {
    checking:     "CHECKING",
    unsigned:     "UNSIGNED",
    unverifiable: "UNVERIFIABLE",
    verified:     "VERIFIED",
    tampered:     "TAMPERED"
  };
  var TRUST_DEFAULT_WHY = {
    checking:     "Verifying signature…",
    unsigned:     "No signature was provided. Treat as untrusted.",
    unverifiable: "A signature exists but could not be checked here.",
    verified:     "A detached signature verified against a known key.",
    tampered:     "Signature check FAILED — do not trust this artifact."
  };

  /* Build the inner markup (key + dot + value + why) once. */
  function ensureTrustParts(el) {
    if (el.querySelector(".ps-trust__val")) return;
    el.classList.add("ps-trust");
    var dot = document.createElement("span"); dot.className = "ps-trust__dot"; dot.setAttribute("aria-hidden", "true");
    var key = document.createElement("span"); key.className = "ps-trust__key"; key.textContent = "TRUST";
    var val = document.createElement("span"); val.className = "ps-trust__val";
    var why = document.createElement("span"); why.className = "ps-trust__why";
    el.appendChild(dot); el.appendChild(key); el.appendChild(val); el.appendChild(why);
  }

  var trust = function (el, state, why, proof) {
    if (!el) return;
    if (!TRUST_LABELS[state]) state = "unverifiable";
    // Gate the earned green state.
    if (state === "verified" && proof !== VERIFIED_OK) {
      state = "unverifiable";
      if (!why) why = "Verification not proven to the UI; showing UNVERIFIABLE by policy.";
    }
    ensureTrustParts(el);
    el.setAttribute("data-trust", state);
    el.setAttribute("role", "status");
    el.setAttribute("aria-live", state === "checking" ? "polite" : "assertive");
    el.querySelector(".ps-trust__val").textContent = TRUST_LABELS[state];
    el.querySelector(".ps-trust__why").textContent = why || TRUST_DEFAULT_WHY[state];
    // Screen-reader summary so state isn't color-only.
    el.setAttribute("aria-label", "Trust state: " + TRUST_LABELS[state] + ". " + (why || TRUST_DEFAULT_WHY[state]));
    return state;
  };
  trust.VERIFIED_OK = VERIFIED_OK;

  /* ======================================================================
     HONESTY STRIP — keep a caveat impossible to lose.
     mount() guarantees a role="note" strip exists at the top of a container;
     setCaveat() toggles the amber "active caveat" styling + text.
     ====================================================================== */
  var honesty = {
    mount: function (container, text) {
      if (!hasDOM || !container) return null;
      var strip = container.querySelector(".ps-honesty");
      if (!strip) {
        strip = document.createElement("div");
        strip.className = "ps-honesty";
        strip.setAttribute("role", "note");
        container.insertBefore(strip, container.firstChild);
      }
      if (text != null) strip.innerHTML = text;
      return strip;
    },
    setCaveat: function (strip, on, text) {
      if (!strip) return;
      strip.setAttribute("data-caveat", on ? "1" : "0");
      if (text != null) strip.innerHTML = text;
    }
  };

  /* ======================================================================
     DIALOG — thin ergonomics over native <dialog> (focus trap is native).
     ====================================================================== */
  var dialog = {
    open: function (el) {
      if (!el) return;
      if (typeof el.showModal === "function") el.showModal();
      else el.setAttribute("open", "");
      var first = el.querySelector("[autofocus], input, button, select, textarea, [tabindex]");
      if (first && typeof first.focus === "function") first.focus();
    },
    close: function (el) {
      if (!el) return;
      if (typeof el.close === "function") el.close();
      else el.removeAttribute("open");
    },
    /* Auto-wire: [data-ps-open="#id"], [data-ps-close], backdrop click, Esc. */
    init: function (scope) {
      if (!hasDOM) return;
      var self = this;
      var s = scope || document;
      var openers = s.querySelectorAll("[data-ps-open]");
      for (var i = 0; i < openers.length; i++) {
        (function (btn) {
          btn.addEventListener("click", function () {
            var target = document.querySelector(btn.getAttribute("data-ps-open"));
            self.open(target);
          });
        })(openers[i]);
      }
      var closers = s.querySelectorAll("[data-ps-close]");
      for (var j = 0; j < closers.length; j++) {
        (function (btn) {
          btn.addEventListener("click", function () {
            var d = btn.closest("dialog"); if (d) self.close(d);
          });
        })(closers[j]);
      }
      // Click on backdrop closes.
      var dialogs = s.querySelectorAll("dialog.ps-dialog");
      for (var k = 0; k < dialogs.length; k++) {
        dialogs[k].addEventListener("click", function (e) {
          if (e.target === this) self.close(this);
        });
      }
    }
  };

  /* ======================================================================
     Convenience: init everything the DOM opts into.
     ====================================================================== */
  function init(scope) {
    theme.init();
    dialog.init(scope);
  }

  if (hasDOM) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", function () { /* opt-in only */ });
    }
  }

  return {
    version: "0.1.0-unaudited",
    theme: theme,
    trust: trust,
    VERIFIED_OK: VERIFIED_OK,
    honesty: honesty,
    dialog: dialog,
    prefersReducedMotion: prefersReducedMotion,
    init: init
  };
});
