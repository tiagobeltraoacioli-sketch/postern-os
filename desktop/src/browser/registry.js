// browser/registry.js — Postern PWA browser-backend command registry.
//
// The THIRD backend behind api.js's single seam. In the native app,
// window.__TAURI__ answers real commands; in a plain browser this registry
// does — but ONLY for commands something real has actually registered
// (the WASM wallet core in browser/wallet.js, the /rpc proxy layer, …).
// api.js asks `PosternBrowser.has(cmd)` from isReal(), so an EMPTY registry
// means every pane honestly falls back to its labelled preview engine.
//
// Contract (deliberately tiny — this object is the ONLY coupling between
// browser-backend providers):
//   register(cmd, fn)  — fn(args) -> value | Promise. Registering is a claim
//                        that the command is REAL here; never register a stub.
//   has(cmd)           — true iff a handler is registered.
//   call(cmd, args)    — always returns a Promise; rejects with a clear error
//                        when nothing is registered (fail loud, never fake).
//   list()             — registered command names (debug/badge use).
//
// Classic script, no bundler, no framework. MUST load BEFORE api.js.
(function () {
  "use strict";
  if (window.PosternBrowser) return; // idempotent across accidental double-include

  const commands = Object.create(null);

  window.PosternBrowser = {
    register(cmd, fn) {
      if (typeof cmd !== "string" || !cmd) throw new Error("register: command name required");
      if (typeof fn !== "function") throw new Error(`register('${cmd}'): handler must be a function`);
      commands[cmd] = fn;
    },
    has(cmd) {
      return typeof commands[cmd] === "function";
    },
    call(cmd, args) {
      const fn = commands[cmd];
      if (!fn) {
        return Promise.reject(new Error(
          `no browser-backend handler for '${cmd}' — the command is not real in this browser build`));
      }
      try {
        return Promise.resolve(fn(args || {}));
      } catch (e) {
        return Promise.reject(e);
      }
    },
    list() {
      return Object.keys(commands).sort();
    },
  };
})();
