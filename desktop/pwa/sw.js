/* ============================================================================
   Postern PWA · service worker (offline app shell)
   ============================================================================
   Precaches the EXISTING desktop frontend (the classic-script app shell) plus
   the real hybrid-PQ WASM wallet core so the app installs and cold-boots
   offline. Same-origin, self-contained: there is nothing external to cache
   (no CDNs, fonts, trackers), the worker makes no network call of its own and
   adds no telemetry.

   Honest scope — what offline MEANS here:
   - The WALLET keeps working offline (mnemonic generation, address derivation,
     local signing) because bloch_wallet_wasm.wasm is precached — that wasm is
     the whole point of the offline story.
   - CHAIN STATE does not: /rpc is NETWORK-ONLY and NEVER cached. When the
     network is down, /rpc calls get an explicit JSON-RPC error (below), so the
     explorer/height panes show an honest offline state — never a stale block
     height or balance presented as current.
   - No node runs in the browser and no mining happens, online or offline.

   Same-origin only: fetch handling ignores cross-origin requests and anything
   outside this app's scope (except the explicit /rpc no-cache rule), so the
   worker can never become a caching proxy for anything but its own files.
   ============================================================================ */
"use strict";

// Bumped 2026-07-19. The first publish shipped an index.html with NO script
// tags (the assemble lane was missing on main), so a broken shell got cached
// under v1 and skipWaiting could not replace it — the cache name never changed.
// Any string change here forces activate() to delete the old cache and claim
// the page. Bump this whenever the shell changes; a stale SW serving a
// scriptless index is invisible until someone opens the app and nothing loads.
const VERSION = "postern-pwa-v3-mobile-nav";
// sw.js is served from the scope root (/apps/postern/sw.js), so the scope is
// simply this worker's own directory — no hardcoded path to drift.
const SCOPE = new URL("./", self.location).pathname;
const at = (p) => SCOPE + p;

// App shell — every classic script index.html loads, in-repo order. Install
// FAILS if any of these is missing (a partial shell must not claim offline).
const SHELL = [
  at(""), // scope root → index.html
  at("index.html"),
  at("manifest.webmanifest"),
  at("styles.css"),
  at("ui.js"),
  at("vendor/qrcode.js"),
  // The browser backend is REQUIRED, not best-effort: index.html <script>-tags
  // all four, and a worker installed without them would serve an offline shell
  // whose wallet is dead. They were in SHELL_OPTIONAL, where a fetch failure is
  // swallowed — that is precisely how you ship a PWA that renders and does nothing.
  at("browser/registry.js"),
  at("browser/core.js"),
  at("browser/rpc.js"),
  at("browser/wallet.js"),
  at("api.js"),
  at("main.js"),
  at("modules/node.js"),
  at("modules/wallet.js"),
  at("modules/pair.js"),
  at("modules/explorer.js"),
  at("modules/terem.js"),
  at("modules/vault.js"),
  at("modules/panic.js"),
  at("modules/backup.js"),
  at("modules/keys.js"),
  at("modules/courier.js"),
  at("modules/messenger.js"),
  at("modules/vestnik.js"),
  at("modules/hygiene.js"),
  at("modules/quarantine.js"),
  at("modules/seal.js"),
  // The real hybrid-PQ core (540KB). Cache-first for this file IS the offline
  // wallet story: with it precached the wallet pane can still generate an
  // address / sign locally with no network at all.
  at("bloch_wallet_wasm.wasm"),
  at("icons/icon-192.png"),
  at("icons/icon-512.png"),
  at("icons/icon-512-maskable.png"),
  at("icons/apple-touch-icon.png"),
];

// Browser-backend layer (registry/core/wallet/rpc seam behind api.js). Cached
// best-effort so the worker still installs on a build published before that
// layer landed; once the files are served they are precached like the shell.
// Nothing is best-effort today: the browser backend moved into SHELL above.
// Keep this list EMPTY rather than deleting it — an entry here means "the app
// still works if this 404s", and that judgement belongs at the call site.
const SHELL_OPTIONAL = [];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(VERSION)
      .then((cache) =>
        cache.addAll(SHELL).then(() =>
          Promise.all(SHELL_OPTIONAL.map((u) => cache.add(u).catch(() => null)))
        )
      )
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== VERSION).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return; // never touch cross-origin

  // ── /rpc: NETWORK-ONLY, NEVER cached (any method — reads are POSTed too). ──
  // On network failure return an explicit JSON-RPC error instead of anything
  // stale, so chain panes render an honest offline state, not old numbers.
  if (url.pathname === "/rpc" || url.pathname.startsWith("/rpc/")) {
    event.respondWith(
      fetch(event.request).catch(() =>
        new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id: null,
            error: {
              code: -32001,
              message: "offline — node unreachable; chain state is unavailable (never served from cache)",
            },
          }),
          { status: 503, headers: { "Content-Type": "application/json" } }
        )
      )
    );
    return;
  }

  // ── App shell: cache-first within this app's scope, GET only. ─────────────
  if (event.request.method !== "GET") return;
  if (!url.pathname.startsWith(SCOPE)) return;
  event.respondWith(
    caches.match(event.request).then(
      (hit) =>
        hit ||
        fetch(event.request)
          .then((res) => {
            // Runtime-fill the same VERSION cache (e.g. browser/*.js published
            // after install) so the next offline boot has them too.
            if (res && res.ok) {
              const copy = res.clone();
              caches.open(VERSION).then((c) => c.put(event.request, copy)).catch(() => {});
            }
            return res;
          })
          .catch(() => {
            // Fully offline and not precached: navigations fall back to the
            // cached shell; anything else fails honestly.
            if (event.request.mode === "navigate") return caches.match(at("index.html"));
            return Response.error();
          })
    )
  );
});
