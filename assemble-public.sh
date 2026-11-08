#!/usr/bin/env bash
# assemble-public.sh — build the Postern Labs static bundle for deploy.
# Produces ./public/ containing the site at the root and every self-contained
# app under /apps/<name>/. Called by both the GitLab Pages job and the primary
# Cloudflare Pages job so the two always publish identical trees.
#
# NOT included: the tolmach-subscription PROXY (server/proxy.mjs) — it is a
# server, not a static page, and is deployed separately (Workers / a host),
# never to Pages. Only its static client ships here.
set -euo pipefail
cd "$(dirname "$0")"

# 1) Site pages (self-contained HTML; build.js writes into site/).
node site/build.js
rm -rf public && mkdir -p public
cp site/*.html public/

# 1a) The two roadmaps (linked from products + downloads) → published as
#     markdown at the root, next to the static PDFs. Source of truth stays in
#     docs/ so the site can never drift from the repo. The pair REPLACES the
#     old single Postern-Future-Roadmap.pdf that mixed the ownerless protocol
#     with the owned products.
cp docs/BLOCH-ROADMAP.md   public/Bloch-Roadmap.md
cp docs/POSTERN-ROADMAP.md public/Postern-Roadmap.md
cp docs/BLOCH-UPGRADE-REACHABILITY.md public/Bloch-Upgrade-Reachability.md

# 1b) Mining/pool page also at /pool/ so posternlabs.com/pool works.
#     Root-anchor its internal links so nav/footer resolve from /pool/ too.
mkdir -p public/pool
sed -E 's|href="([a-z-]+\.html)"|href="/\1"|g' site/pool.html > public/pool/index.html

# 2) Self-contained apps → /apps/<name>/ (strip the "postern-" prefix for the URL).
for dir in sotto vedetta postern-store postern-login postern-onboard postern-enterprise tolmach ezekiel1 noporis-switcher noporis-gate gramota gramota-kyc sloboda-gate mobile-wallet; do
  name="${dir#postern-}"
  if [ -f "apps/$dir/index.html" ]; then
    mkdir -p "public/apps/$name"
    cp "apps/$dir/index.html" "public/apps/$name/index.html"
  fi
done

# 2b) Postern Wallet — mobile is an installable PWA: besides index.html (copied
#     above) it needs its manifest, service worker, and icons served from the
#     SAME same-origin path (/apps/mobile-wallet/) so the SW scope and manifest
#     resolve. All are self-contained, same-origin, no external assets.
if [ -d apps/mobile-wallet ]; then
  mkdir -p public/apps/mobile-wallet
  for f in manifest.webmanifest sw.js icon-192.png icon-512.png icon-512-maskable.png apple-touch-icon.png \
           wallet-live.js bloch_wallet_wasm.wasm; do
    [ -f "apps/mobile-wallet/$f" ] && cp "apps/mobile-wallet/$f" "public/apps/mobile-wallet/$f"
  done
fi

# 2c) apps/mobile-wallet-pwa — NOT PUBLISHED (2026-07-18).
#     The React/TS rewrite of the wallet screens never wired the crypto core. It
#     ships the 540KB bloch_wallet_wasm.wasm but NO screen imports it:
#     KeysScreen.tsx has zero handlers (no create-wallet, no keystore import),
#     SendScreen.tsx has handlers but zero core calls, and BalanceScreen.tsx:74
#     says outright that the address shape is "illustrative". Its honesty copy is
#     accurate about being a prototype — but a screen that RENDERS is not a screen
#     that WORKS, and publishing it beside the real wallet put two wallets on the
#     site, one of which does nothing.
#
#     The REAL wallet is apps/mobile-wallet/ (block 2b above): a 979-line
#     wallet-live.js that actually WebAssembly.instantiate()s the PQ core, with 9
#     passing tests covering bloch-cli SIMPLE + HD keystore import, wrong-password
#     fail-closed, and cross-network send refusal. /apps/mobile-wallet-pwa/ now
#     301s there (site/static/_redirects), so links already in the wild land on
#     the app that works instead of 404ing.
#
#     Re-publishing is a deliberate act: wire the panes to wallet-live.js first,
#     then restore this block. Do not restore it just to make the route resolve.
# 2d) Postern PWA → /apps/postern/ — the EXISTING desktop frontend
#     (desktop/src/: dependency-free classic browser JS, no build step)
#     published as an installable, offline-capable PWA. The wallet is a pane
#     inside it, not a separate app. What ships:
#       - desktop/src/  → the app shell verbatim (index.html, styles, ui/api/
#         main, modules/, vendor/, and the browser/ backend layer when present);
#         test files (*.test.mjs) are never shipped.
#       - desktop/pwa/  → manifest.webmanifest + sw.js + icons/ served from the
#         SAME same-origin path so SW scope and manifest resolve (exactly like
#         the mobile-wallet lane above).
#       - bloch_wallet_wasm.wasm → the real hybrid-PQ core, reused from the
#         mobile wallet PWA. HARD-REQUIRED: the wallet pane's browser backend
#         and its offline story are dead without it.
#     Honesty: node access is READ-ONLY via the same-origin /rpc proxy; no node
#     runs in the browser and no mining is possible; native-only surfaces stay
#     labelled preview in-app.
if [ -f desktop/src/index.html ]; then
  mkdir -p public/apps/postern/modules public/apps/postern/vendor public/apps/postern/icons
  cp desktop/src/index.html desktop/src/styles.css desktop/src/ui.js \
     desktop/src/api.js desktop/src/main.js public/apps/postern/
  cp desktop/src/modules/*.js public/apps/postern/modules/     # *.js only — *.test.mjs never ships
  cp desktop/src/vendor/*.js  public/apps/postern/vendor/
  # HARD-REQUIRED, not "when present": index.html carries <script> tags for all
  # four browser/*.js files. Shipping the shell without them publishes a PWA whose
  # scripts 404 — an app that renders and does nothing, which is the exact failure
  # this whole lane exists to avoid repeating.
  for f in registry.js core.js rpc.js wallet.js; do
    if [ ! -f "desktop/src/browser/$f" ]; then
      echo "FATAL: desktop/src/browser/$f missing — index.html <script>-tags it; publishing without it ships a dead PWA" >&2
      exit 1
    fi
  done
  mkdir -p public/apps/postern/browser
  cp desktop/src/browser/*.js public/apps/postern/browser/
  rm -f public/apps/postern/browser/*.test.mjs
  cp desktop/pwa/manifest.webmanifest desktop/pwa/sw.js public/apps/postern/
  cp desktop/pwa/icons/*.png public/apps/postern/icons/
  # The core comes from apps/mobile-wallet/ — the PUBLISHED wallet. T3 sourced it
  # from apps/mobile-wallet-pwa/public/, the tree of an app deliberately withdrawn
  # (block 2c): building one shipped product out of an unshipped one means a future
  # cleanup of that directory silently breaks this lane.
  if [ ! -f apps/mobile-wallet/bloch_wallet_wasm.wasm ]; then
    echo "FATAL: bloch_wallet_wasm.wasm missing — the Postern PWA wallet pane cannot ship without the real PQ core" >&2
    exit 1
  fi
  cp apps/mobile-wallet/bloch_wallet_wasm.wasm public/apps/postern/
  # Ship-time self-contained backstop (same FATAL grep as mobile-wallet-pwa):
  # the shell must not pull any remote script/stylesheet — same-origin only.
  if grep -Eiq '<(script|link)[^>]*(src|href)[[:space:]]*=[[:space:]]*"https?://' "public/apps/postern/index.html"; then
    echo "FATAL: postern/index.html loads a remote resource — not a self-contained same-origin bundle" >&2
    exit 1
  fi
fi

# 2a) Self-contained + reachability GATE for the four ready on-device tier apps.
#     assemble-public.sh's contract is that each app ships as ONE self-contained
#     index.html (no build step, no external script/style/asset). This block
#     hard-fails the build if a tier app went missing from the loop above, or if
#     its shipped single file grew an external <script src>, an external
#     stylesheet <link>, or any http(s):// asset reference — i.e. it stops a
#     stale/leaky single-file bundle from ever being published. The BEHAVIOURAL
#     inlined-vs-source parity + CSP hash pinning are gated separately in CI
#     (apps/gramota*/inline-parity-check.mjs + test-csp.mjs, gate test-store.mjs);
#     this is the ship-time backstop that the file that lands in public/ is the
#     honest, self-contained one.
tier_apps="noporis-gate sloboda-gate gramota gramota-kyc"
for name in $tier_apps; do
  f="public/apps/$name/index.html"
  if [ ! -f "$f" ]; then
    echo "FATAL: ready tier app '$name' is not reachable in the public build ($f missing)" >&2
    exit 1
  fi
  if grep -Eiq '<script[^>]*[[:space:]]src[[:space:]]*=' "$f"; then
    echo "FATAL: $f references an external <script src> — not a self-contained bundle" >&2
    exit 1
  fi
  if grep -Eiq '<link[^>]*rel[[:space:]]*=[[:space:]]*"?stylesheet' "$f"; then
    echo "FATAL: $f links an external stylesheet — not a self-contained bundle" >&2
    exit 1
  fi
  if grep -Eiq '(src|href)[[:space:]]*=[[:space:]]*"https?://' "$f"; then
    echo "FATAL: $f loads a remote resource (http(s):// src/href) — not self-contained" >&2
    exit 1
  fi
done
echo "self-contained tier apps OK: $tier_apps"

# 2c) HONESTY GATE for the Postern Wallet PWA (the framework app that wraps the
#     WASM PQ core + wallet-live.js + same-origin /rpc). Mirrors the tier-app
#     self-contained backstop above, but for per-screen HONESTY copy: once the
#     wallet-app is built (its dist/ exists), EVERY shipped screen must carry its
#     mandatory disclosures in its own built output — reference prototype;
#     UNAUDITED; software keystore (not hardware / StrongBox / Secure Enclave);
#     coin BLOCH no value + not a security; moves no real funds unless labelled.
#     honesty-check.mjs is fail-closed (a dropped phrase, a missing screen file,
#     or an empty/absent manifest all exit non-zero), so `set -e` hard-fails the
#     deploy and a screen can never ship having quietly dropped its honesty
#     surface. Gated on dist/ presence so the build stays green before the app
#     lands; once its build emits dist/, the gate is enforced on every assemble.
if [ -d apps/mobile-wallet-app/dist ]; then
  node apps/mobile-wallet-app/honesty-check.mjs --dist apps/mobile-wallet-app/dist
  echo "wallet-app honesty gate OK"
fi

# 3) Tolmach subscription — NOT deployed for now. Tolmach is bring-your-own-key
#    only today; the hosted subscription (operator-proxy) tier is a planned future
#    evolution. The client code stays in the repo (apps/tolmach-subscription/) but
#    is not published until that tier ships. Re-enable this block then.
# if [ -f apps/tolmach-subscription/client/index.html ]; then
#   mkdir -p public/apps/tolmach-subscription
#   cp apps/tolmach-subscription/client/index.html public/apps/tolmach-subscription/index.html
# fi

# 3b) Izbushka task portal → /apps/izbushka/ — multi-file (page + companion JS
#     + mascot SVG), so it needs its own block rather than the index-only loop.
if [ -f apps/izbushka/index.html ]; then
  mkdir -p public/apps/izbushka
  cp apps/izbushka/index.html apps/izbushka/izbushka-companion.js apps/izbushka/izbushka-mascot.svg public/apps/izbushka/
fi

# 4) Blochscan explorer → /explorer/ (self-contained; JS inlined by its build.js;
#    defaults to the blochv-node.fly.dev demo node, connect-src https: so users
#    can repoint it at any node they trust). Runs after the site build because
#    explorer/build.js reads ../site/index.html for the shared shell.
if [ -f explorer/build.js ]; then
  node explorer/build.js
  mkdir -p public/explorer
  cp explorer/index.html explorer/network.html explorer/hashrate.html public/explorer/
fi

# 5) Demo videos (honest UI design previews) → /media/
if [ -d site/media ]; then
  mkdir -p public/media
  cp site/media/*.mp4 public/media/ 2>/dev/null || true
  cp site/media/*.vtt public/media/ 2>/dev/null || true   # caption tracks (WebVTT)
  cp site/media/*.png public/media/ 2>/dev/null || true   # video poster frames
fi

# 6) Security static assets → public root. These MUST be re-emitted every build
#    because step 1 does `rm -rf public`. Source of truth is site/static/
#    (tracked); dropping them straight into public/ (gitignored) would be wiped
#    here and never committed. Covers Cloudflare _headers/_redirects and the
#    RFC 9116 /.well-known/security.txt.
if [ -d site/static ]; then
  cp -R site/static/. public/
fi
# The security.txt Policy field points at /SECURITY.md — publish the repo-root
# disclosure policy at that exact URL.
[ -f SECURITY.md ] && cp SECURITY.md public/SECURITY.md

echo "assembled public/: $(find public -name '*.html' | wc -l | tr -d ' ') pages"
echo "security assets: $(ls public/_headers public/_redirects public/.well-known/security.txt public/SECURITY.md 2>/dev/null | wc -l | tr -d ' ')/4 present"
find public -name index.html | sort | sed 's#^public/#  /#'
