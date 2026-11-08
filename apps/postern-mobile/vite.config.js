import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// ---------------------------------------------------------------------------
// Postern Mobile — Vite build config
// ---------------------------------------------------------------------------
// The SHIPPED app must be SELF-CONTAINED + SAME-ORIGIN + CSP-strict:
//   • base '/apps/postern-mobile/' — the app is served at this path on
//     posternlabs.com, alongside apps/mobile-wallet. Absolute same-origin
//     asset URLs, correct service-worker scope + manifest paths.
//   • modulePreload.polyfill = false — Vite otherwise injects a small INLINE
//     <script> polyfill into index.html. Turning it off keeps index.html free
//     of any inline code block, so a strict `script-src 'self'` (no unsafe
//     hashes) covers the whole app path.
//   • assetsInlineLimit = 0 — never fold assets into data: URIs; every asset
//     stays an external, hashed, same-origin file under assets/.
//   • rollupOptions.output — force all JS/CSS to hashed assets/ filenames and
//     keep the entry as an external module script (no inlined module code).
//   • target es2020 — modern baseline, no legacy inline system-loader shims.
// The only network the app itself makes is to the SAME-ORIGIN '/rpc' proxy
// (reads + sendrawtransaction) and its own assets — connect-src 'self'.
// ---------------------------------------------------------------------------
export default defineConfig({
  base: '/apps/postern-mobile/',
  plugins: [svelte()],
  build: {
    target: 'es2020',
    assetsInlineLimit: 0,
    cssCodeSplit: false,
    modulePreload: {
      polyfill: false,
    },
    rollupOptions: {
      output: {
        // No inlined dynamic imports; every chunk is an external same-origin file.
        inlineDynamicImports: false,
        entryFileNames: 'assets/[name]-[hash].js',
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
      },
    },
  },
});
