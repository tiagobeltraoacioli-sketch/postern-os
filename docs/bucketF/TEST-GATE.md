<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Bucket F — TEST GATE (the full HOST battery, integration is gated on this)

Run from repo root (`/Users/tiagoacioli/dev/bloch-protocol`, or the equivalent
integration worktree once merged) unless a `cd` is shown. All commands are
**offline** — no network, no VM, no device, no live secrets. Every command
below must exit 0 / print no `FAIL` before Bucket F integrates.

## Pre-existing regression floor (must stay green — proves F didn't break what fleet2 already closed)

```
cd apps/noporis-bridge-glue && cargo test
cargo test -p postern-courier
cargo test -p postern-courier --features onion-transport   # (excludes --ignored live-network test)
cargo test -p postern-sdk
cargo build -p postern-sdk --target wasm32-unknown-unknown --no-default-features --features wasm --lib
node apps/postern-login/test-core.mjs
node apps/postern-onboard/test-core.mjs
node apps/gramota-kyc/test-core.mjs
node apps/gramota-kyc/review-seam.test.mjs
node apps/gramota-kyc/issuance.test.mjs
node apps/gramota-kyc/inline-parity-check.mjs
node apps/noporis-gate/test-store.mjs
```

## F1 — NoporIS daemon core

```
cd apps/noporis-bridge-glue && cargo test daemon
cd apps/noporis-bridge-glue && cargo test --test daemon_loop
cd apps/noporis-bridge-glue && cargo run --bin noporis-orchestrator -- --once --state-dir "$(mktemp -d)"
```
**Expected:** all green; the `--once` smoke run exits 0 and prints a
`DaemonReport` summary (no panic, no unwrap-on-None).

## F2 — NoporIS persistence + full-loop E2E

```
cd apps/noporis-bridge-glue && cargo test --test orchestrator_e2e_hoststub
cd apps/noporis-bridge-glue && cargo test --test persistence_recovery
```
**Expected:** the E2E test explicitly asserts, in order: persona created →
`Direction`-pinned `ConsentRecord` minted → one capability crosses via
`receive_crossing_audited` → kill-switch engaged → re-check denies everything
→ `sealedWallet.preserved == true` holds throughout. The persistence test
asserts no torn write is ever observed on reload after simulated interruption.

## F3 — SDK real-core wiring + parity (all 9 apps)

```
node apps/postern-login/test-core.mjs
node apps/postern-onboard/test-core.mjs
node apps/postern-store/test-core.mjs
node apps/sotto/test-core.mjs
node apps/tolmach/test-core.mjs
node apps/vedetta/test-core.mjs
node apps/postern-enterprise/test-core.mjs
node apps/tolmach-subscription/client/test-core.mjs
node desktop/src/modules/vault.test.mjs
```
**Expected:** every file asserts THREE states per app — (a) `PosternSDK` absent
→ honest PBKDF2-stand-in label + working seal/open, (b) a stub `PosternSDK`
installed → real-core dispatch, tagged `KDF_REAL = "Argon2id-postern-sdk"`,
(c) a real-core-tagged blob never silently opens under the stand-in path
(fail closed, not a downgrade).

## F4 — Intel TCB-info / QE-identity collateral verification

```
cargo test -p postern-seal-companion --features tdx-verify
```
**Expected:** existing 26 lib + 12 vector tests stay green, PLUS new vectors:
a genuine TCB-info/QE-identity signature verifies under the pinned root; a
tampered signature is rejected; a `tcbStatus != UpToDate` is enforced (not
silently accepted); a missing/malformed collateral document fails closed.

## F5 — wasm artifact emission, Gramota OCR seam, comms deploy authoring

```
bash crates/postern-sdk/wasm/build-wasm.sh
node apps/gramota-kyc/ocr-engine.test.mjs
node apps/gramota-kyc/test-core.mjs
node apps/gramota-kyc/review-seam.test.mjs
docker build -f enterprise/comms/app/deploy/Dockerfile -t postern-comms-app:host-check .
```
**Expected:** `build-wasm.sh`'s compile gate (`cargo build --target
wasm32-unknown-unknown`) passes unconditionally; the glue-emission step either
succeeds (if `wasm-bindgen-cli` is present, version-matched to `Cargo.lock`) or
prints its documented "SKIPPED — not installed" message and exits 0 (never
fakes the artifact). The OCR test file's existing honesty-invariant tests
(no-engine → MANUAL, adapter throw → fail-closed, verbatim passthrough) stay
green AND new tests prove the real adapter recognizes text on a checked-in
fixture image. `docker build` succeeds locally with no secrets and no network
call beyond package installation inside the build (mirror the console
Dockerfile's precedent).

## Full-battery one-liner (CI-style, run everything above in sequence)

```
set -e
cd apps/noporis-bridge-glue && cargo test && cargo test --test daemon_loop \
  && cargo test --test orchestrator_e2e_hoststub && cargo test --test persistence_recovery \
  && cd -
cargo test -p postern-courier
cargo test -p postern-sdk
cargo test -p postern-seal-companion --features tdx-verify
for f in apps/postern-login/test-core.mjs apps/postern-onboard/test-core.mjs \
         apps/postern-store/test-core.mjs apps/sotto/test-core.mjs \
         apps/tolmach/test-core.mjs apps/vedetta/test-core.mjs \
         apps/postern-enterprise/test-core.mjs \
         apps/tolmach-subscription/client/test-core.mjs \
         desktop/src/modules/vault.test.mjs \
         apps/gramota-kyc/test-core.mjs apps/gramota-kyc/ocr-engine.test.mjs \
         apps/gramota-kyc/review-seam.test.mjs; do
  node "$f" || { echo "FAIL: $f"; exit 1; }
done
bash crates/postern-sdk/wasm/build-wasm.sh
docker build -f enterprise/comms/app/deploy/Dockerfile -t postern-comms-app:host-check .
echo "BUCKET F — ALL GREEN"
```

## Gate rule

Integration proceeds **per-dev**, not all-or-nothing: a dev whose own section
above is fully green AND whose Advisor findings are `critical: 0` integrates
independently of the others. The "regression floor" and "full-battery"
sections must stay green after EVERY individual dev's integration (re-run
after each merge, not just once at the end).
