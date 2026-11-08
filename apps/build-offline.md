# Offline / network-free build of the Postern web apps

Purpose: the app suite is packaged as an Alpine apk (`pmos-overlay/postern-apps/`),
and `abuild` runs **without network** (Alpine discourages `options="net"`), so
nothing in the packaging path may run `npm install`, hit a CDN, or fetch anything.

**Finding (inspected 2026-07): every app is already network-free.** There is no
`package.json`, no lockfile, no `vite`/`webpack`/`tsconfig` anywhere under
`apps/` — each app is a single self-contained `index.html` with all CSS/JS
inlined and **zero external `src=`/`href=` references** (no CDN scripts, no web
fonts). `assemble-public.sh` already treats them this way: it just `cp`s the
HTML files into `public/`. The apk build is therefore a pure copy step.

## Manifest

| App | Source file (the artifact itself) | Build step | In `postern-apps` apk |
|---|---|---|---|
| sotto | `apps/sotto/index.html` | none | yes |
| vedetta | `apps/vedetta/index.html` | none | yes |
| tolmach | `apps/tolmach/index.html` | none | yes |
| postern-store | `apps/postern-store/index.html` | none | yes |
| postern-login | `apps/postern-login/index.html` | none | yes |
| postern-onboard | `apps/postern-onboard/index.html` | none | yes |
| postern-enterprise | `apps/postern-enterprise/index.html` | none | yes |
| tolmach-subscription (client) | `apps/tolmach-subscription/client/index.html` | none | optional — see below |
| tolmach-subscription (proxy) | `apps/tolmach-subscription/server/proxy.mjs` | none (single-file Node, zero deps) | **no** — operator-side server, never ships on-device (see `assemble-public.sh` header) |

- **Pure-static (no build): 8 of 8 web artifacts.** Build-required: **0**.
- `apps/postern-login/test-core.mjs` and `apps/postern-onboard/test-core.mjs`
  are standalone Node test scripts (candidates for the APKBUILD `check()`),
  not build steps.
- The only `node` invocations in the repo's assembly (`site/build.js`,
  `explorer/build.js`) belong to the **website/explorer**, not to `apps/*`,
  and are not part of the apk.
- The tolmach-subscription *client* is static and shippable, but it is only
  useful pointed at a deployed metering proxy; on-device the Sovereign
  (BYO-key) `apps/tolmach/index.html` is the right default. Recommendation:
  leave it out of the apk until an operator proxy exists.

## Packaging path (what the apk copies)

For each app in the manifest, the apk installs exactly one file:

```
apps/<app>/index.html  →  /usr/share/postern/apps/<app>/index.html
```

No `dist/` directory exists or is needed — the committed `index.html` **is**
the dist artifact. `pmos-overlay/postern-apps/APKBUILD` implements this: an
empty (no-op) `build()` and a `package()` that loops over the app list and
`install -Dm644`s each `index.html`, plus one `.desktop` entry per app.

## Offline recipe — what must be committed for `abuild` to work offline

1. **The HTML files themselves** — already committed. They are the release
   artifacts; keep them self-contained (any future edit that adds a CDN
   `<script src>` or webfont breaks both offline packaging and the privacy
   story — `check()` in the APKBUILD greps for this).
2. **A real `source=` tarball** — `abuild` fetches sources *before* the
   offline build phase, from a tagged repo archive
   (e.g. `.../bloch-protocol/archive/refs/tags/v$pkgver.tar.gz`). A plain
   `git archive` of the repo suffices because the artifacts are committed;
   nothing must be injected into the tarball. Then run
   `abuild checksum` / `pmbootstrap checksum postern-apps` to fill `sha512sums=`.
3. **`.desktop` entries** — `pmos-overlay/desktop/<app>.desktop` are referenced
   by `package()` but do not exist yet; they must be written and committed.
4. **No npm anywhere**: `makedepends` must NOT list `npm` (the scaffold's
   `makedepends="npm"` was a placeholder from before inspection; corrected).
   `depends` stays per the launch strategy chosen in the APKBUILD (system
   browser vs webview shell).

## If a future app ever grows a real build (vite/webpack/npm)

Rules for keeping the apk offline, in order of preference:

- **(a) Commit the prebuilt `dist/`** (this is what the current apps do
  implicitly — the committed HTML is the dist). CI runs `npm ci && npm run
  build` *at release-tag time*, commits/attaches `apps/<app>/dist/`, and the
  APKBUILD copies `dist/` instead of `index.html`. `build()` stays a no-op.
- **(b) Vendor the npm cache** only if committing dist is unacceptable:
  commit `package-lock.json` plus a populated cache directory
  (`npm ci --cache .npm-cache` on a networked host, commit `.npm-cache/`),
  then in `build()`: `npm ci --offline --cache ./.npm-cache && npm run build`
  and add `makedepends="npm"` back. This bloats the repo and drags nodejs
  into the build chroot — prefer (a).

Either way `options="net"` must never appear in the APKBUILD.
