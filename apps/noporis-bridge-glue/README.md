<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs -->

# noporis-bridge-glue — the NoporIS guarded-crossing DATA glue

**Status: SCAFFOLD / reference-prototype. UNAUDITED — certifies nothing.**

> **Porog is the guarded *door*; NoporIS is the guarded *bridge*.** This crate is
> the narrow, net-new glue that carries an **approved crossing's payload** between
> NoporIS's two personas — the clean/hardened world and the Google-Play world, on
> **one** stock-Android handset — over the already-tested pairing channel's
> consent model. Nothing crosses without a live grant.

It invents no crypto, no pairing, no signing, and no gate. It **composes** the
pieces the other devs shipped, through their **public APIs only**.

## What it does

A "crossing" is one of five capability payloads (`clipboard, files, mic, camera,
location`) handed from one persona to the other. Every crossing is **explicit,
per-capability, revocable, and fail-closed**:

```
 Persona A (sends)                                  Persona B (receives)
 ─────────────────                                  ────────────────────
 open_lane(cap, …)  ── a live CapabilityGrant ─┐
 send_crossing(cap, payload) ──────────────────┤ fresh nonce + monotonic counter
   SEALED into the pairing Channel (AEAD,        │ + session binding
   per-direction counter, session AAD)  ─────────┼─▶ receive_crossing()
                                                 │    open_frame  (channel replay guard)
                                                 │    CrossingGuard (nonce/counter/session)
                                                 │    GateConsent.decide(cap)  ← deny-by-default
                                                 │    Allow ⇒ deliver (zeroizing)
                                                 └──  Deny  ⇒ fail closed, nothing crosses
```

Two independent consent checks compose (defense in depth): the near side won't
**send** without a live [`CapabilityGrant`](src/grant.rs), and the far side won't
**deliver** without a live [`GateConsent`](src/consent.rs) `Allow`.

## What it consumes (owned by others — never edited here)

| Consumed | From | Used for |
|---|---|---|
| `Channel` (`seal_frame`/`open_frame`), `Transport`, `PairingRecord` | `integration/pairing` | the PQ-hybrid (ML-KEM-1024‖X25519), SAS-anchored, mutually-authenticated, replay-guarded pipe + peer pin |
| `SessionId`, `fresh_nonce()`, `RequestCounter`, `ConsequenceTier` | `integration/signer-protocol` | the consent-model freshness primitives + the crossing's consequence tier |
| the N-gate consent decision | Dev N-gate's `apps/noporis-gate/` | the deny-by-default per-capability authority — consumed via the `GateConsent` seam; **this crate never owns or edits that gate** |

`ReferenceGate` in [`src/consent.rs`](src/consent.rs) is a clearly-labelled
**test/reference stand-in** for the real N-gate so the crate builds and runs
standalone; on device the decision is Dev N-gate's.

## Build / test / run

```sh
cargo test                 # 16 tests: happy path + every fail-closed branch
cargo run --example crossing   # a printed, end-to-end guarded crossing
```

Standalone crate (owns its own empty `[workspace]`); no network needed once the
RustCrypto deps are cached. `#![forbid(unsafe_code)]`.

## Binding rails (carry on every surface — do not round off)

- **Reference-prototype, UNAUDITED.** Nothing here is built on hardware,
  attested, or deployed. Internal review is not an audit.
- **Nothing crosses without a live grant** AND a live gate `Allow`. Both are
  time-boxed, revocable, per-capability, per-peer, fail-closed. No blanket "open
  all"; no lane is ever silent.
- **The Google-Play persona is the LESS-PRIVATE side by construction** — GMS
  phones home. The world label is *derived from the pairing*, never from a field
  the requester controls.
- **The per-crossing gate is a userland, in-process check — NOT an OS/kernel
  boundary** (`EnforcementMode::ByConstruction`). Only the managed-profile
  storage/process boundary is `KernelBoundary`, and that is not this crate. A
  **rooted/kernel-compromised host defeats every boundary here.**
- **App on stock Android — NEVER "Postern OS."** The guardian is **Yagabona**,
  never "Baba Yaga". The coin (BLCH) is not a security and buys no software.

Licensed `MIT OR Apache-2.0`.
