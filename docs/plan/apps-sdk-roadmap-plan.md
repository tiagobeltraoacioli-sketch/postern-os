<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- APPS/SDK/COMMS track — roadmap-completion partition (track-lead fable5) -->

# APPS / SDK / COMMS — 5-dev roadmap-completion partition

**Track-lead:** fable5 · **Date:** 2026-07-13
**Source gap docs:** `docs/gap/apps-sdk-comms-gaps.md` (A4), `docs/gap/POSTERN-GAP-BACKLOG.md`
**Repo:** `/Users/tiagoacioli/dev/bloch-protocol`

> This is a **planning artifact only** — no code was modified and nothing was
> committed to produce it. Ownership below is **strict non-overlapping**: every
> file/dir is written by exactly one dev. Cross-dev seams are read-only for the
> consumer and listed under "shared-file coordination."

## Proof-tier legend (inherited from A4)
- **HOST-now** — provable on the dev host with no device/network (cargo test, a
  headless-browser drive, a Node `.mjs` run, a local sign/verify).
- **VM-gated** — needs a QEMU/Tor/arti bring-up or an `#[ignore]`d live test.
- **hardware-gated** — needs a real phone keystore / TEE / R2 host.
- **written-only** — code/prose lands but the claim is NOT exercised end-to-end
  in this task (labeled honestly, never dressed as verified).

---

## The headline this partition attacks

Per A4: the crypto **cores are real and honestly labeled; the product seams
around them are the gap.** The three load-bearing shortfalls map onto Dev1+Dev2
(SDK not adopted by apps), Dev4 (transports default-off), and Dev3
(phone-as-signer not unified). Dev5 closes the store-catalog honesty gap. No
task invents a "verified" state it cannot back — the seam's honest fallback is
preserved everywhere.

---

## Dev 1 — SDK wasm bundle → main tree + real-crypto adoption in the read-only apps

- **devLabel:** `apps-sdk/dev1-sdk-seam`
- **scope:** Build the `postern-sdk` browser seam (wasm Argon2id + XChaCha20)
  into the **main tree** (today it exists only in a gitignored worktree), ship
  the reference loader, and make the four **read-only / BYOK** single-file apps
  actually consume the real `globalThis.PosternSDK` primitive instead of only
  probing for it. Own and freeze the `globalThis.PosternSDK` contract shape that
  Dev2 (Chiave) and Dev5 (Store) consume.
- **files/dirs OWNED:**
  - `crates/postern-sdk/src/wasm.rs` (the `#[wasm_bindgen]` export surface)
  - `crates/postern-sdk/wasm/` (all: `build-wasm.sh`, `postern-sdk.js` loader,
    `README.md`, and the built `pkg/` output committed into the tree)
  - `apps/sotto/index.html`
  - `apps/vedetta/index.html`
  - `apps/tolmach/index.html`
  - `apps/postern-onboard/index.html` (Sarto)
- **proof + tier:**
  - `cargo build -p postern-sdk --target wasm32-unknown-unknown
    --no-default-features --features wasm --lib` compiles — **HOST-now (T1)**,
    already the CI gate.
  - Producing the browser-ready `postern_sdk_bg.wasm` + JS glue needs
    `wasm-bindgen-cli`/`wasm-pack`; if present, a headless-browser drive shows
    the apps flip to the real Argon2id label and seal/open round-trips through
    the core — **HOST-now** when the toolchain is installed, else the bundle
    step is **written-only** (script checks for the tool and says so — do not
    fake the artifact).
  - The four apps are BYOK/read-only, so "adoption" here = the at-rest/seal path
    routing through the seam; label flips are **HOST-now** in a browser.
- **deps:** none upstream. Dev2 and Dev5 depend on this dev freezing the
  `PosternSDK` global contract early.
- **shared-file coordination:** `crates/postern-sdk/wasm/postern-sdk.js` is the
  **single source of the `globalThis.PosternSDK` API shape**. Dev1 authors it;
  Dev2/Dev5 are read-only consumers. Publish the frozen interface (method names:
  `kdf.deriveKey`, `aeadSeal`/`aeadOpen`, `kdfLabel`, `__postern` marker) in the
  README before Dev2/Dev5 wire against it.
- **HONEST label:** HOST-provable that the *crate* compiles to wasm and that the
  apps consume the seam **when a shell injects it**; the built-bundle-in-a-plain-
  tab claim is only HOST-provable if `wasm-bindgen-cli` is on the host, else
  written-only.

---

## Dev 2 — Chiave: retire the PBKDF2-310k stand-in for real SDK Argon2id

- **devLabel:** `apps-sdk/dev2-chiave-kdf`
- **scope:** Flip Chiave (`postern-login`) off the WebCrypto **PBKDF2-SHA-256
  (310,000 it.)** at-rest stand-in and onto the real SDK **Argon2id (64 MiB,
  t=3)** via the Dev1 seam, preserving the existing KDF-downgrade clamp and the
  honest fallback when no host shell is present. Explicitly **label the
  hardware-keystore goal** (today: software keystore) in the UI/trust panel.
  Keep the ceremony logic (nonce single-use, expiry, origin-bind) intact.
- **files/dirs OWNED:**
  - `apps/postern-login/index.html`
  - `apps/postern-login/test-core.mjs`
- **proof + tier:**
  - `node apps/postern-login/test-core.mjs` — the ceremony props (nonce
    single-use, expiry, origin-bind, **KDF-downgrade clamp**) run on host —
    **HOST-now (T1)**.
  - Real Argon2id seal/open only when `globalThis.PosternSDK` is injected;
    label-flip to "Argon2id — REAL, via postern-sdk" is **HOST-now** in a shell,
    the plain-tab path stays the labeled PBKDF2 stand-in (honest fallback).
  - Hardware-keystore is **hardware-gated** and stays **written-only** (labeled
    as the stated goal, not shipped).
- **deps:** **Dev1** — needs the frozen `PosternSDK` contract and (for a live
  real-crypto demo) the built wasm bundle.
- **shared-file coordination:** read-only consumer of
  `crates/postern-sdk/wasm/postern-sdk.js` (owned by Dev1). No shared writes.

---

## Dev 3 — Phone-as-signer: unify desktop+phone on one wire + re-pin the golden

- **devLabel:** `apps-sdk/dev3-signer-unify`
- **scope:** Unify the desktop and phone signer ends onto **one wire message
  shape** (today they are two references not on one wire; a v2 shape is
  forward-declared-not-built), and **re-pin the byte-identity golden** for the
  mobile signer (same seed → same address; wire bytes stable). Keep the
  structural key-denylist (secret types un-`Serialize`-able) and its
  build-failing golden census intact. The default `ScaffoldSigner` stays a
  labeled non-crypto stand-in in the protocol crate; the **real**
  `WalletCoreSigner` (Falcon‖ML-DSA) remains the phone's signer.
- **files/dirs OWNED:**
  - `integration/signer-protocol/` (all `src/*`, `tests/flow.rs`,
    `tests/golden_denylist.rs`, `Cargo.toml`)
  - `mobile/signer/` (all `src/*`: `signer.rs`, `facade.rs`, `bridge.rs`,
    `ffi.rs`, `txwysiwys.rs`, `lib.rs`)
  - `mobile/signer-app/` (desktop end: `bridge/`, `signer-cli/`, `web/`)
  - `integration/e2e-demo/`
  - `integration/interop-test/`
- **proof + tier:**
  - `cargo test -p postern-signer-protocol` (flow + golden_denylist) and the
    mobile-signer tests — **HOST-now (T1)**.
  - Real desktop↔phone interop over the unified wire, demonstrable via
    `integration/e2e-demo` / `interop-test` — **HOST-now (T3 reference)** for
    the loopback/LAN wire; a real phone run is **hardware-gated**.
  - Byte-identity **golden re-pin** — **HOST-now (T1)**, a committed fixture.
- **deps:** none on other track devs. Uses `integration/pairing` (DONE,
  read-only).
- **shared-file coordination:** none — the signer wire message type is internal
  to this dev's owned crates. `integration/pairing` is a read-only upstream dep
  (not owned, not modified).
- **HONEST label:** wire-unify + golden re-pin are HOST-provable; hardware
  keystore and a real-phone end-to-end run stay hardware-gated / written-only.

---

## Dev 4 — Comms transports: promote (or honestly document) Tor + close courier sender-auth/anti-replay

- **devLabel:** `apps-sdk/dev4-comms-transports`
- **scope:** Two honest moves. (1) **Messenger Tor** (`tor` feature) and
  **courier onion** (`onion-transport` feature) are OFF by default; either
  promote them toward a real default path **or** make the default's honest
  posture unmistakable in the module docs/labels (no "delivered over an ephemeral
  Tor onion" phrasing that a seal-only default build can't back). (2) **Close the
  courier sender-auth + anti-replay gap** — add a PQ sender-signature story over
  the seal (authenticity, currently "anyone with the recipient's public key can
  seal") and anti-replay hardening beyond the 64 MiB size cap. Keep the classical
  leg of the hybrid seal (RustCrypto `ml-kem` is pre-1.0).
- **files/dirs OWNED:**
  - `crates/postern-messenger/` (all `src/*`: `channel.rs`, `transport.rs`,
    `tor.rs`, `matrix.rs`, `megolm_reference.rs`, `store.rs`, `lib.rs`,
    `Cargo.toml` features)
  - `crates/postern-courier/` (`src/lib.rs`, `Cargo.toml` features)
- **proof + tier:**
  - Default-build unit tests (wire codec, seal/open, replay-reject, at-rest
    seal, the new sender-auth signature verify, anti-replay window) —
    **HOST-now (T1)**.
  - Actually routing Megolm frames over a live Tor circuit / publishing a real
    ephemeral onion service — **VM-gated** (arti bring-up; today an `#[ignore]`d
    live test, T3).
  - Matrix federation persistence/cross-signing is Phase-2 — **written-only**
    (out of this task's provable scope; label honestly).
- **deps:** none on other track devs. `postern-tor` (DONE, read-only dep).
- **shared-file coordination:** none — no other dev writes these crates.
- **HONEST label:** the sender-auth + anti-replay + default-posture docs are
  HOST-provable in the default build; the real Tor/onion live path is VM-gated
  and stays an ignored live test unless a VM is stood up.

---

## Dev 5 — Postern Store: build+sign one real apk, fill catalog checksums/signatures, sign the index

- **devLabel:** `apps-sdk/dev5-store-publish`
- **scope:** Move the store catalog off "everything unpublished." Build **at
  least one real signed apk** through the pmOS overlay pipeline, fill that
  entry's `checksum` + `signing` (currently all `null`, `state:"unpublished"`),
  and produce the detached **Ed25519 `catalog.json.sig`** + pin the curator
  pubkey (`CATALOG_PUBKEY_B64`) so the Store's in-page verifier renders a real
  trust state instead of UNSIGNED. Respect the structural invariant
  (`hosted_by_us` can never be true for `proprietary`; `attestable` reserved for
  `attestable-nix`).
- **files/dirs OWNED:**
  - `apps/postern-store/` (all: `catalog.json`, `index.html`, `SIGNING.md`,
    `CURATION.md`)
  - `pmos-overlay/` (main-tree copy: `HONESTY.md`, `publish-to-r2.sh`, APKBUILD
    additions for the one built app)
- **proof + tier:**
  - Building an apk from an APKBUILD + minisign-signing it, and Ed25519-signing
    `catalog.json` + in-page verify passing — **HOST-now (T1/T2)** (local build
    + sign + the Store's own `crypto.subtle.verify` over the exact bytes).
  - **Publishing** to the `postern-downloads` R2 bucket (public download) is
    **hardware-gated / infra-gated** (R2 S3 token + `aws s3 cp`, per the R2
    publish runbook) — the artifact and its `.minisig` are producible on host;
    the *live-hosted* claim is only true post-publish.
  - Any entry left unbuilt keeps `state:"unpublished"` + null signature —
    **honest scaffold**, never faked.
- **deps:** Dev1 (read-only) for the `PosternSDK` contract used by the Store's
  BYOK NL-search — non-blocking (search is optional; the sign/catalog work is
  independent).
- **shared-file coordination:** read-only consumer of `postern-sdk.js` (Dev1).
  No shared writes. `pmos-overlay/` in the **main tree** is owned here; the
  `.claude/worktrees/*/pmos-overlay` copies are other agents' worktrees — out of
  scope, do not touch.

---

## Ownership matrix (no file written by two devs)

| Dev | Crates owned | Apps/dirs owned |
|---|---|---|
| Dev1 | `postern-sdk/src/wasm.rs`, `postern-sdk/wasm/` | `sotto`, `vedetta`, `tolmach`, `postern-onboard` |
| Dev2 | — | `postern-login` (Chiave) |
| Dev3 | `signer-protocol`, `mobile/signer`, `mobile/signer-app` | `integration/e2e-demo`, `integration/interop-test` |
| Dev4 | `postern-messenger`, `postern-courier` | — |
| Dev5 | — | `postern-store`, `pmos-overlay/` (main tree) |

**Shared read-only seam (one writer, N readers):**
`crates/postern-sdk/wasm/postern-sdk.js` — written by **Dev1**; read by Dev2
(Chiave) and Dev5 (Store). Freeze the `globalThis.PosternSDK` interface first.

**Not owned by anyone here (read-only upstream deps):** `integration/pairing`
(DONE), `crates/postern-tor` (DONE), `crates/postern-core` (cores), `bloch-crypto`.

## Provable-first ranking (do these first)

1. **Dev3 golden re-pin** + **Dev4 courier sender-auth/anti-replay** — pure
   HOST-now cargo tests, no toolchain risk.
2. **Dev2 Chiave** ceremony `test-core.mjs` + label work — HOST-now Node run.
3. **Dev5** local apk build + Ed25519 catalog sign + in-page verify — HOST-now.
4. **Dev1** wasm compile gate (HOST-now); built-bundle-in-tab only if
   `wasm-bindgen-cli` present, else honestly written-only.
5. **VM/hardware-gated tails** (real Tor/onion live path, real-phone signer,
   R2 publish, hardware keystore) — attempted only where the VM/host exists;
   otherwise land labeled, not faked.
