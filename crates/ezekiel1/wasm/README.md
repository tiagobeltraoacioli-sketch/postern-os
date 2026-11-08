<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Ezekiel 1 — WebAssembly build + WASM↔native parity

The shipping browser console (`apps/ezekiel1/index.html`) no longer re-implements
its access decisions in JavaScript. It loads **this crate**, compiled to
WebAssembly, and drives its Bell–LaPadula floor and Brewer–Nash wall verdicts
from the real evaluator. The console's verdicts **are** the crate's verdicts.

Everything crosses the wasm-bindgen boundary through **one** module,
[`crate::api`], which is the same code `cargo test` and the native
`ezekiel1-parity` binary run. The browser and the test suite therefore cannot
diverge — and the parity harness here proves it on a fixture set.

## Layout

| Path | What |
|---|---|
| `fixtures.json` | Shared fixtures: policies + evaluate/BLP/wall cases + expectations. |
| `build.sh` | Builds the `.wasm` + wasm-bindgen glue. **Refuses to fake** an artifact if the toolchain is missing. |
| `parity.mjs` | Proof: runs every fixture through the **WASM** module and the **native** binary and asserts byte-identical output. |
| `serve-check.mjs` | Proof of the exact **browser load path**: the `no-modules` glue + init from the raw `.wasm`, then crate-correct decisions. |
| `pkg-web/`, `pkg-node/`, `pkg-inline/`, `ezekiel1.wasm` | Generated (git-ignored). |

## Build

```sh
bash crates/ezekiel1/wasm/build.sh
```

Needs `rustup target add wasm32-unknown-unknown` and a `wasm-bindgen` CLI whose
version matches the `wasm-bindgen` dep in `Cargo.toml` (0.2.126). Emits:

* `pkg-web/`     — ES-module glue (`--target web`).
* `pkg-node/`    — CommonJS glue (`--target nodejs`), used by `parity.mjs`.
* `pkg-inline/`  — `no-modules` glue (`ezekiel1.js`) + `ezekiel1_bg.wasm`; this is
  what the browser console loads.
* `ezekiel1.wasm` — a copy of the optimized module.

## Prove parity (HOST-provable-now)

```sh
cargo test -p ezekiel1                       # 32 tests (crate + api), all green
bash  crates/ezekiel1/wasm/build.sh          # build the module
node  crates/ezekiel1/wasm/parity.mjs        # WASM decision == native decision, every fixture
node  crates/ezekiel1/wasm/serve-check.mjs   # the browser's glue+init path, crate-correct
```

`parity.mjs` prints `parity: PASS — N cases, WASM decision == native decision for
every one.`

## Run the wired console locally (offline)

The page expects two files **beside `index.html`**:

* `ezekiel1-engine.js` — the wasm-bindgen `no-modules` glue (`pkg-inline/ezekiel1.js`).
* `ezekiel1.wasm`      — the module (`pkg-inline/ezekiel1_bg.wasm`).

```sh
cp crates/ezekiel1/wasm/pkg-inline/ezekiel1.js       apps/ezekiel1/ezekiel1-engine.js
cp crates/ezekiel1/wasm/pkg-inline/ezekiel1_bg.wasm  apps/ezekiel1/ezekiel1.wasm
( cd apps/ezekiel1 && python3 -m http.server 8000 )   # then open http://localhost:8000
```

Serve over http(s), not `file://` — a bare file URL cannot fetch the module. The
B·5 badge shows **Rust / WASM vX.Y.Z** when the engine is live; each engine-decided
check is tagged `· engine`. If the module is absent the console falls back to the
in-page JS mirror of the same rules and the badge says so.

### CSP note

Loading the engine required exactly two same-origin additions to the page's
Content-Security-Policy (see the comment at the top of `index.html`):

* `script-src` gains `'self'` (admit `ezekiel1-engine.js`) and `'wasm-unsafe-eval'`
  (compile the module — WebAssembly compilation, not JS `eval`).
* `connect-src` moves `'none' → 'self'` for the one same-origin GET of
  `ezekiel1.wasm`. No cross-origin request, no telemetry, no user data leaves.

## Assemble seam (for the site integrator — do NOT edit `assemble-public.sh` here)

`bp-wt-site/assemble-public.sh` today copies each app's `index.html` only. Ezekiel 1
additionally needs its engine copied next to the assembled `index.html`. Add, in the
per-app loop for `ezekiel1` (source = this repo), the equivalent of:

```sh
# after copying apps/ezekiel1/index.html into the output dir <out>/ezekiel1/:
cp crates/ezekiel1/wasm/pkg-inline/ezekiel1.js       "<out>/ezekiel1/ezekiel1-engine.js"
cp crates/ezekiel1/wasm/pkg-inline/ezekiel1_bg.wasm  "<out>/ezekiel1/ezekiel1.wasm"
```

(Build them first with `crates/ezekiel1/wasm/build.sh`.) The `.wasm` is served with
`Content-Type: application/wasm`; Cloudflare Pages does this by extension. No other
assemble change is needed.

## Honesty

**UNAUDITED draft.** The engine enforces its lattice/walls/firmament **by
construction inside one process** (here, one WASM instance) — it is not an OS,
kernel, or hardware boundary. WASM parity guarantees the browser computes the
*same decision* as the crate; it does not turn a userland check into a sandbox.
