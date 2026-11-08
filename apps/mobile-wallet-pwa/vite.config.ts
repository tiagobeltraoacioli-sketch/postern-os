import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// SHIPPED SAME-ORIGIN: base is the app's own subpath; every asset (framework
// JS/CSS, the reused WASM core, wallet-live.js, sw.js, manifest, icons) is
// served from this origin. No CDN, no third-party font/script/analytics.
// charset:'utf8' keeps honest copy (incl. the em dash in the /rpc line) as
// literal UTF-8 bytes in the bundle so the machine-checkable honesty test and
// the reader see the same string.
export default defineConfig({
  base: "/apps/mobile-wallet-pwa/",
  plugins: [react()],
  esbuild: { charset: "utf8" },
  build: {
    outDir: "dist",
    target: "es2020",
    assetsInlineLimit: 0,
  },
});
