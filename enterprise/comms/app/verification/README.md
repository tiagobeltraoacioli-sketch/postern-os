<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
-->

# Bloch — device verification (fail-closed)

**Additive** hardening submodule for the Bloch org messenger. Enterprise-only,
**UNAUDITED reference prototype**, pre-production. It does **not** touch the
existing app modules or the `compliance/` layer.

## The gap it closes

`crates/postern-messenger` and the app's `src/transparency.mjs` both state the
honest gap: **no device verification (SAS) yet**. A Megolm session is only as
trustworthy as your confidence that the key you're talking to is really your
coworker's device — without verification, a malicious/compromised homeserver
could inject a device unnoticed. This submodule closes that gap at the app layer:
an **interface + flow** to verify a peer device's E2EE **identity key**.

## Fail-closed, always

- Every device starts **Unverified** — a **flag**, never silent trust.
- `isTrusted()` / `is_trusted()` is true **only** for an explicitly verified device.
- A fingerprint / SAS **mismatch** → **Blocked** (a possible MITM), never a shrug.
- An identity-key **change** on a verified device → re-flagged **Unverified**
  (TOFU break), never auto-re-trusted.
- `guardSend()` / `guard_send()` **refuses** toward any non-verified device, so a
  caller cannot "accidentally" send to an unverified peer. Verification applies
  to the **internal E2EE** tier only (bridged is disclosed, never "verified").

## What it is / is not

Models the verification **state machine** and a **reference** short-authentication
-string (SAS) derivation: a transcript hash over both identity-key fingerprints,
mapped to the standard Matrix emoji/decimal tables — enough to drive an honest UX
and self-check. It is **not** the audited Matrix `m.key.verification.*` protocol,
does **not** run an ECDH, and does **not** implement cross-signing. A real
deployment binds vodozemac/matrix-sdk verification and passes the decision in.

## Files

```
verification/
  device-verification.mjs   JS primary: trust state machine + out-of-band + SAS
  verify-rs/                Rust reference: same fail-closed rail, bound to SecurityTier
    Cargo.toml
    src/lib.rs
```

## Verify

```sh
node --check verification/device-verification.mjs
cd verification/verify-rs && cargo check && cargo test
# The app self-check (enterprise/comms/app/self-check.mjs) also exercises it.
```
