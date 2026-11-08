<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Porog container — workspace-app surface via the `postern-sdk` facade

**Status: DESIGN / reference-prototype. UNAUDITED. No security claim.**
Nothing here has been built into a shipped container. This is the A5 contract:
*how the in-container workspace apps load real audited-path cores through the
**one** FFI facade — with no classical WebCrypto stand-in.*

> **Naming.** **Porog** (Slavic: *threshold / soleira* — the door between two
> worlds, per the Izbushka tale) is the **PROPOSED** name for the stock-Android
> managed-profile container, **pending formal trademark clearance**. "Postern" is
> the suite brand; "Porog" is this app. This is a **different product** from the
> non-attestable Waydroid **community edition** (`apps/sloboda`), and is
> **never** "Postern OS". Porog is **key-attested device, not measured-boot
> workspace**; hardened, not anonymous.

## The one facade rule

Every Rust core reaches the container's Compose UI through **exactly one** FFI
surface: `crates/postern-sdk` (`cdylib` `libpostern_sdk.so`), which carries the
single `uniffi::setup_scaffolding!()` in the tree (guarded by
`mobile/ci/check-one-setup-scaffolding.sh`). The apps below **do not** each open
their own bridge, and **do not** stand in a browser `WebCrypto`/`PBKDF2` shim for
the real post-quantum cores (that stand-in is Chiave / `apps/postern-login`, and
it is explicitly **out** of the container).

- **Ownership seam:** the facade internals + generated bindings are **Dev-B**'s.
  This document is only the *consumer contract* — it names which core each app
  calls; it does not implement the FFI.
- **Not owned here:** the Kotlin/DPC app, `postern-sdk` internals, and the
  attestation verifier are other devs' paths. This file lives with the
  container's egress glue (`porog-tor-glue`) as the container-integration
  reference.

## App → core map (all through `uniffi.postern_sdk.*`)

| Workspace app | Audited-path core (via facade module) | Assurance today |
|---|---|---|
| **Postern Wallet** (anchor) | `wallet` (folded `mobile/core` WalletCore, hybrid Falcon‖ML-DSA) | Rust-tested + golden byte-compat; **not** ndk-built here |
| **Sotto** (messenger) | `messenger` (Megolm/vodozemac) | **UNAUDITED**; Megolm classical; Tor/persistence = remaining work |
| **Vedetta** (metadata scrub) | `hygiene` (+ `quarantine` rebuild-from-pixels) | fail-closed; non-JPEG/PNG passed through unscrubbed |
| **Postern Login** (passkeys) | `keys` (WebAuthn ES256; Keystore/StrongBox-backed) | classical signatures; software authenticator < hardware key |
| **Vault** (secrets) | `vault` (`VaultKey::from_bytes` ← StrongBox-unwrapped 32 bytes) | Argon2id + XChaCha20-Poly1305 at rest; TEE wrap = app-layer, not shipped |
| *(shared)* | `courier`, `panic`, `seal`, `deniable` | see `crates/*` honesty labels; several **UNAUDITED** |

Secrets cross the FFI only as **opaque `Arc<Object>` handles**, never as UniFFI
`Record`s — the facade's strict secret-handling policy. Keys live in RAM in the
Rust core (`Zeroizing`), transiently, during use.

## How egress composes with the apps (this crate's part)

All of the above talk to the network **only** through the container's Tor egress,
which is **fail-closed and Tor-only**:

- `porog-tor-glue` bootstraps a **client-only** `postern_tor::PosternTor`, derives
  a **circuit-isolated** identity for the container (`for_identity()`), and gates
  every connection behind the `postern-policy` `Decision` in
  [`egress_decision`](./src/lib.rs). No live Tor circuit ⇒ **no egress**.
- The single boolean *"is a container Tor circuit up?"* is written by the wrapper
  into the consent gate as `egress.torBootstrapped`
  (`apps/sloboda-gate`); the gate's `egressAllowed()` and this crate's
  `egress_decision()` are the **same fail-closed rule** on the two sides of the
  seam.
- **SECURITY, stated not solved:** distinct identities (wallet vs. messenger
  account vs. the container itself) **must** each use their own `for_identity()`
  handle, or a shared exit + timing lets an observer link them. The egress gate
  is `EnforcementMode::ByConstruction` — a userland, in-process check, **not** a
  kernel network boundary; a rooted host defeats it.

## What stays DESIGN until proven

- Any app running "on real cores inside the profile" until `postern-sdk` is
  actually `cargo ndk`-built into `libpostern_sdk.so` and the Kotlin bindings are
  generated (Dev-B; today `jniLibs/` holds placeholders).
- No "attestable workspace" phrasing — Porog is a key-attested device, not a measured-boot workspace.
  That phrasing stays forbidden until a live StrongBox key-attestation chain is verified on
  hardware (Dev-C / A3); even then it attests the **phone**, not the workspace.
- Removal of the Chiave WebCrypto stand-in is an **F5/E2** input; this contract
  is what the container consumes once that lands.
