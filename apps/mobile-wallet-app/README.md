# Postern Wallet PWA — honesty ship-gate

`honesty-check.mjs` is a **ship-time gate**: it refuses to let the wallet PWA
deploy unless **every screen** carries its mandatory honesty copy in its own
built output. It is wired into `assemble-public.sh` and mirrors the existing
self-contained tier-app backstop — a dropped phrase hard-fails the build.

## Mandatory copy (the gate owns these — a screen cannot weaken them)

Every screen's built file(s) must contain all of:

- **reference prototype**
- **UNAUDITED**
- **software keystore** — explicitly **not hardware / StrongBox / Secure Enclave**
- the coin **BLOCH** has **no value** by design and is **not a security**
- **moves no real funds unless labelled**

There is one canonical banner exported from `honesty-check.mjs` that satisfies
all of the above — import it so there is a single source of truth:

```js
import { HONESTY_COPY } from '../honesty-check.mjs';
```

## Contract with the app build

The app's build must emit `dist/honesty-manifest.json` declaring every shipped
screen and which built file(s) render it. The gate owns the required phrases;
the manifest only says which files are screens.

```json
{
  "screens": [
    { "id": "send",     "file":  "assets/send-8f3a.js" },
    { "id": "receive",  "files": ["assets/receive.js"] },
    { "id": "settings", "glob":  "assets/settings-*.js" }
  ]
}
```

Each entry accepts `file` (one path), `files` (array), or `glob` (a `*`/`**`
pattern), all relative to `dist/`. A screen's copy is checked against the
**concatenation** of its resolved files, so a code-split screen still passes as
long as the copy ships in one of its chunks.

## Run it

```bash
# against a real build
node apps/mobile-wallet-app/honesty-check.mjs --dist apps/mobile-wallet-app/dist

# against the shipped contract example (green demo of the manifest shape)
node apps/mobile-wallet-app/honesty-check.mjs --dist apps/mobile-wallet-app/example-dist

# tests (headless, node:test, no deps)
node --test apps/mobile-wallet-app/test-honesty-check.mjs
```

## Fail-closed guarantee

The gate exits non-zero — never vacuously passes — when there is nothing to
certify: no `dist/`, no `honesty-manifest.json`, an empty screen list, a
manifest screen whose file is absent, invalid JSON, or any screen missing a
mandatory phrase. `example-dist/` is a live, always-green demonstration of the
manifest shape and is **not** part of the deployed bundle (`assemble-public.sh`
only ever checks `dist/`).
