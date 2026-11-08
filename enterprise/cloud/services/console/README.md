<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Consiglio admin console — wallet-as-login backend

**STATUS: design / reference prototype. UNAUDITED. Pre-production. No security claims.**

This directory is the deployed console's server-side of **wallet-as-login**: org
authentication where control of a Postern **hybrid post-quantum wallet key**
(Falcon-1024 ‖ ML-DSA-65 — *not* Ed25519, *not* a password) *is* the login. It
is the Node mirror of the authoritative Rust crate
`crates/postern-consiglio-auth`, and it delegates the one thing JS cannot do —
verify a hybrid-PQ signature — to that crate's real verifier.

## Files

| File | What it is |
|---|---|
| `consiglio-verifier.mjs` | The **bridge to the real Rust verifier**. Spawns the `consiglio-verify` binary (crate feature `verifier-bin`), which reconstructs the domain-separated login transcript and verifies the signature with `bloch_crypto::crypto::verify`. **Replaces the reference `"SIG(...)"` string stub with genuine cryptography.** Fail-closed: if the binary is not built, `verify()` THROWS — it never accepts a login without the real check. |
| `console-auth.mjs` | The console orchestration: challenge issuance, **session id + TTL**, nonce replay guard, **durable snapshot/restore**, **offboard-invalidates-everything**, and **ENFORCED dual-control + Brewer–Nash SoD** on enroll/offboard. The signature check is delegated to the verifier bridge — there is no signature stub here. |
| `self-check.mjs` | `node self-check.mjs` — exercises the orchestration with an injected stub verifier, then runs a **real hybrid-PQ login end-to-end** through the Rust bridge when the binary is built (signing with `consiglio-sign`). |

## What the reference prototype was missing, and what landed here

| Gap (design doc §1) | Landed |
|---|---|
| No session after login | Random 128-bit session id + TTL, validated + swept, revocable by id or by user. (Rust `server.rs` + JS `console-auth.mjs`.) |
| No revocation / offboarding durability | Enrollment/nonce/session/pending state is snapshot/restore-able for a durable store (Postgres/Redis); nonce TTL sweep; **offboard revokes live sessions AND purges pending challenges**. |
| Info-wall / SoD declared, not enforced | **Enforced** at runtime: every enroll/offboard is a two-person rule — one IT-admin **and** one compliance-officer (the Brewer–Nash separated pair) must both sign off; self-approval and same-side approval are refused. |
| Console bridge is a `"SIG(...)"` stub | The bridge spawns the **real** hybrid-PQ verifier; fail-closed, no stub fallback. |

## Building the verifier

```sh
cargo build --release --features verifier-bin --bins -p postern-consiglio-auth
node enterprise/cloud/services/console/self-check.mjs
```

### Pinning the verifier binary (origin/key hardening)

The verifier binary is the cryptographic trust anchor of wallet-as-login, so on
a shared build host its **provenance** matters. By default the bridge
auto-discovers it under the workspace `target/` (release, then debug). Set
**`CONSIGLIO_VERIFIER_BIN`** to an **absolute** path to pin the exact trusted
binary — the pin is **fail-closed**: when set, the bridge runs *only* that path
and **refuses to fall back** to a `target/` scan (a missing or relative pin
throws at construction rather than silently spawning a discovered binary).

```sh
CONSIGLIO_VERIFIER_BIN=/opt/postern/bin/consiglio-verify node …
```

## Rails (non-negotiable)

- **UNAUDITED / reference prototype.** `self-checked ≠ audited`. No third-party audit exists.
- **No security claims.** A signature proves origin + integrity, nothing about what it signs.
- **Wallet-as-login is novel and unaudited.** This is a hardening of the reference scaffold, not a certified IAM.
- Enterprise features are **additive**; a personal-free app is never gated.
- Billing is **fiat only**; the coin is never billed and is not a security. (No billing lives here.)
