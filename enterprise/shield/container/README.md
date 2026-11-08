<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
-->

# Postern SHIELD — work-container + access broker (Business/Enterprise edition)

**STATUS: design / reference prototype — UNAUDITED, pre-production. Not secure, not deployed, not an offering.**

A model of a **shielded corporate work-container** on an employee's *personal* phone, plus an **access broker** to the corporate Linux system. Corporate data lives **only** inside the container, sealed at rest, strictly segregated from the personal OS; access requires a live enterprise sub-token; and **de-provisioning == leaving**: revoke or expire the grant and the container refuses access and self-wipes its own corporate data.

This is the **container + access model and its gating**. It contains **no cryptography of its own** and **does not** implement the DLP/traceability layer (that is `enterprise/shield/dlp/`, a separate module). It plugs into the real Postern building blocks through injected interfaces.

## What it is / is not

- **Enterprise-only.** Nothing here gates or touches the free personal apps. The community edition is never "Postern OS".
- **Containment by construction, not a kernel boundary.** All gating is a userland, in-process check — the exact honest wording pinned by `crates/postern-policy` `EnforcementMode::ByConstruction`. **A rooted / jailbroken phone defeats it.** It is not unbreakable.
- **Corporate-scope only.** There is deliberately **no code path** that can read, list, name, or surveil the personal side of the device. Item names are forced into the `corp/` namespace; path-escapes are refused.
- **Not "fully secure" or "100% private".** It is an employer-provisioned tool on a personal device. Unaudited. The Bloch-SIS-PoW coin is not a security and buys no software.

## Modules (`src/`)

| File | Role | Plugs into (injected, not reimplemented) |
|------|------|------------------------------------------|
| `grant-binding.mjs` | Consent gate (fail-closed `Decision` / required future `Expiry` / monotonic revoke) **and** binds the container's at-rest key to the **live** grant. | Mirrors `crates/postern-policy` semantics + wording (source of truth). |
| `shield-container.mjs` | The sealed work-container: seal/open at rest, corporate-namespace isolation, `selfWipe()`, `enforceOrWipe()`. | Injected **seal engine** (`seal`/`open`/`deriveKey`) = the canonical Postern seal (XChaCha20-Poly1305 + Argon2id), via `real-seal-engine.mjs`. A **labelled, non-cryptographic demo engine** runs if none is wired — it never claims to protect anything. |
| `real-seal-engine.mjs` | The REAL seal engine. Auto-selects an **in-process WASM** backend (key never leaves the process) and falls back to a **CLI subprocess** backend. Fails closed if neither is built. | `seal-wasm/` (cdylib → `wasm32-unknown-unknown`, loaded by Node's built-in `WebAssembly`) **preferred**; `seal/` (Rust CLI over `postern-core`) **fallback**. Both delegate to `crates/postern-core` — no crypto is defined in either. |
| `consiglio-bridge.mjs` | Challenge/response bridge for the enterprise **sub-token** login. | Injected verifier = `crates/postern-consiglio-auth` (hybrid Falcon-1024 ‖ ML-DSA-65 wallet-as-login). No verifier wired ⇒ honest "not authenticated". |
| `access-broker.mjs` | Four fail-closed gates in series (license → live grant → sub-token → container), then authorizes a remote session. | Injected license gate (`enterprise/features/license-hook.mjs`), grant, Consiglio bridge, wallet signer, and **transport**. |
| `transparency-hook.mjs` | Employee-facing transparency panel. States the container facts; **injects** the DLP/compliance disclosure text. | Disclosure text **owned by `enterprise/shield/dlp/`** (the DLP dev), injected via `disclosure()`. Absent ⇒ disclosed as absent, never faked. |

## The key-binding invariant (revoke ⇒ data unreadable)

The at-rest wrapping key is **derived from material released only while the grant is live**:

```
wrappingKey = deriveKey( grant.releaseKeyMaterial(), salt )   // Argon2id, via postern-vault
```

`releaseKeyMaterial()` throws once the grant is revoked or expired, so the wrapping key **cannot be re-derived** and the sealed blob is unreadable — *before* the bytes are even wiped. `enforceOrWipe()`, called at every access boundary, then self-wipes the corporate data.

### The `grantSecret` is **never persisted** (SEAL-1 — the invariant the whole guarantee rests on)

The `grantSecret` that the wrapping key is derived from is **memory-only**. It is **released by the broker per session** (unwrapped from the live grant) and lives **only in process RAM** — it is **never written to disk, a keychain, a log, a cache, or any durable store**, and it is **never embedded in a persisted container blob**.

This is not a nicety; **the `revoke ⇒ inert` guarantee depends on it.** If the secret were persisted, a de-provisioned employee (or a rooted OS) could re-derive the wrapping key and re-open sealed corporate data *after* revocation, and `revoke()` would stop meaning anything. Enforced / documented here as:

- `revoke()` and `zeroize()` **wipe the in-memory secret immediately** (SEAL-2) — once revoked the grant is inert forever, so the bytes are dropped, not just flagged.
- The grant object **refuses serialization**: `toJSON()` returns a **redacted** view, so an accidental `JSON.stringify(grant)` to a file or log **cannot leak the secret**.
- There is deliberately **no "load secret from a path" API** in `grant-binding.mjs`; callers must inject the secret as in-memory bytes from the broker.

A caller that chooses to persist the secret elsewhere breaks the contract — this userland module cannot physically prevent that, but it **never does so itself** and states the invariant loudly here and in the module docs.

## The real seal: in-process (WASM) vs subprocess (CLI) — closing SEAL-3

The container's real seal delegates to the ONE canonical Postern seal in `crates/postern-core` (XChaCha20-Poly1305 v2 — versioned, key-committing, context-bound — with the 32-byte key from Argon2id at the at-rest tier). Neither backend re-implements any crypto. They differ **only** in *where the key lives while the op runs*:

| Backend | Where | Key handling | Status |
|---------|-------|--------------|--------|
| **WASM (preferred)** | `seal-wasm/` → `wasm32-unknown-unknown`, loaded by Node's built-in `WebAssembly` | The 32-byte key is written into **this process's** wasm linear memory. **No subprocess, no pipe, no argv.** | Closes the SEAL-3 prototype gap. |
| **CLI (fallback)** | `seal/` Rust binary, spawned once per op | The key + plaintext transit a **process boundary** over stdin/stdout (hex). | **Prototype-only key handling.** Documented, kept working for checkouts without the wasm module. |

`createRealSealEngine()` picks WASM when the module is built, else the CLI, else it **fails closed** (never a silent downgrade to the non-crypto demo engine). Both backends produce byte-compatible blobs and identical derived keys (same context string `postern-shield/container/v1`, same Argon2id parameters), verified by `self-check.mjs` and a cross-backend round-trip.

**Honest labels.** The seal is real but this is still a **reference prototype — UNAUDITED**. "In-process" means the Node process's own address space (wasm linear memory) — strictly better than a spawned CLI, but **NOT** a TEE / enclave / secure element: a rooted phone, a debugger on this process, or a RAM capture still defeats it. The wasm module is a **build artifact** — it must be compiled once (`./build-wasm.sh`); nothing here ships a prebuilt binary or fakes real crypto.

### Building the in-process seal

```sh
./build-wasm.sh                 # PREFERRED: compiles seal-wasm/ → .wasm (in-process, key never leaves the process)
                                # (equivalently: cd seal-wasm && cargo build --release --target wasm32-unknown-unknown)
(cd seal && cargo build --release)   # optional CLI fallback binary
```

The wasm build needs only `cargo` + the `wasm32-unknown-unknown` target (the script adds it if missing) and Node ≥ 16 — **no** wasm-bindgen, wasm-pack, or npm build deps. Randomness for the AEAD nonce is supplied in-process by the host from `node:crypto` (the OS CSPRNG) through a single imported `sh_host_random` function; wasm has no ambient RNG of its own.

## The access transport, honestly

The broker does **not** open sockets or run a server. It **authorizes** a session and hands an opaque ticket (`kind: "ssh-remote-session"`) to an injected transport — an SSH / remote-desktop session over the already-paired, authenticated channel. **The corporate host (sshd, the Linux box, its own authN/authZ) is operator-run by the customer and is neither implemented nor shipped here.** The broker decides whether to *start* a session and can tear one down at the next re-check.

## Honest limits on de-provisioning

- **Offline revocation is best-effort and clock-based.** A phone with no signal only learns of a revocation when it can re-check, or when the grant's **required expiry** passes on the *local* clock. A back-dated device clock can delay the expiry check — which is why grants carry a short, required expiry.
- **A personal device cannot be guaranteed remote-wiped.** `selfWipe()` overwrites and drops the blob **this** container holds on **this** process/store. If the phone is offline, powered off, or was already rooted and copied the blob first, those bytes may persist outside our reach. This is not a remote "kill" guarantee.
- **A live session ends at the next boundary re-check** (`revalidate()`), not necessarily instantly.

## Verify

The JS model needs no build step or framework; the real seal needs one Rust build:

```sh
node --check src/*.mjs self-check.mjs      # syntax
./build-wasm.sh                            # build the in-process seal (optional but PREFERRED)
node self-check.mjs                        # 49-check smoke test / demo
```

Reported honest result: `node --check` passes on all files. With the wasm module built, `node self-check.mjs` prints **49/49 checks passing**, `backend = wasm (IN-PROCESS…)`, and a rendered transparency panel. **Without** any real backend built it still passes 40/40 on the labelled non-crypto demo engine and skips section 8 with a clear "no real seal backend built" notice — never a silent pass, never a faked claim of real crypto. This is a standalone ES-module prototype — it imports only `enterprise/features/license-hook.mjs` (a sibling enterprise interface) and its own `src/`; the seal backends compile from `seal-wasm/` (wasm) and `seal/` (CLI) against `crates/postern-core`.

## License

Dual-licensed **MIT OR Apache-2.0** — see `LICENSE-MIT` and `LICENSE-APACHE`.
