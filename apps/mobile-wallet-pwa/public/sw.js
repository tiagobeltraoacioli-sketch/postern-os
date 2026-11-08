/* ============================================================================
   Postern Wallet — mobile PWA · service worker (offline app shell)
   ============================================================================
   Precaches THIS app's OWN, same-origin, self-contained shell so it opens
   offline once installed. It caches nothing external (there is nothing
   external — no CDNs, fonts, trackers, or remote images), makes no network
   call of its own, and adds no telemetry.

   Honest scope: this is installability + an offline shell — software keystore /
   offline shell only, not a security upgrade. The keystore is still a browser
   SOFTWARE keystore (not the phone's StrongBox / Secure Enclave), and the wallet
   still moves NO real funds until the real send path is wired. The shipped
   wallet-live.js signs for real via the WASM core when a wallet is unlocked;
   caching the shell changes none of that.

   Same-origin only: fetch handling ignores any cross-origin request and any
   request outside this app's scope, so the worker can never become a caching
   proxy for anything but its own files. It also never caches the /rpc proxy.
   ============================================================================ */
const VERSION = 'postern-wallet-pwa-v1';
const SCOPE = '/apps/mobile-wallet-pwa/';
const SHELL = [
  '/apps/mobile-wallet-pwa/',
  '/apps/mobile-wallet-pwa/index.html',
  '/apps/mobile-wallet-pwa/manifest.webmanifest',
  '/apps/mobile-wallet-pwa/icon-192.png',
  '/apps/mobile-wallet-pwa/icon-512.png',
  '/apps/mobile-wallet-pwa/icon-512-maskable.png',
  '/apps/mobile-wallet-pwa/apple-touch-icon.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(VERSION).then((cache) => cache.addAll(SHELL)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== VERSION).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return; // /rpc reads/broadcasts are POST — never cached.
  const url = new URL(req.url);
  // Same-origin AND within this app's scope only — never proxy anything else.
  if (url.origin !== self.location.origin) return;
  if (!url.pathname.startsWith(SCOPE)) return;
  // Never cache the RPC proxy (it is outside SCOPE anyway; belt and braces).
  if (url.pathname === '/rpc' || url.pathname.startsWith('/rpc/')) return;
  // Cache-first for the self-contained shell; fall back to network (same-origin),
  // then to the cached shell root when fully offline.
  event.respondWith(
    caches.match(req).then((hit) => hit || fetch(req).catch(() => caches.match('/apps/mobile-wallet-pwa/')))
  );
});
