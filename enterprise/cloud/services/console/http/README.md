<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs -->

# Consiglio console — HTTP service

**Reference prototype. UNAUDITED. Pre-production. NO SECURITY CLAIMS.**
This service DEMONSTRATES controls that ENABLE compliance/governance — it is
**NOT compliance and NOT legal advice.** Audit is **tamper-EVIDENT, not
tamper-proof.** Billing is **fiat only; the coin is never billed and is not a
security.** Privacy is **LGPD/GDPR-minimal by construction** (sessions,
enrollments, and snapshots hold **public keys + metadata only**, no secret
material). SPDX: **MIT OR Apache-2.0**.

The HTTP surface that turns the Consiglio wallet-login **console** (the Node
mirror of the authoritative Rust crate `postern-consiglio-auth`) into a real,
**durable** admin service for *liberação de acessos* — releasing accesses into
the Ezekiel1 access-governance chain. It adds **only** an HTTP layer + a durable
backend + the seat/device host wiring; it **rolls no cryptography**. The wallet
login signature check is the **REAL hybrid post-quantum verifier** (Falcon-1024 ‖
ML-DSA-65) run by the native `consiglio-verify` binary — never a stub.

## Files

| File | Role |
|---|---|
| `service.mjs` | The service factory: routes, the session gate, and the two first-class verbs `grantAccess` / `revokeAccess`. Wires console-auth + sub-access + audit + store. |
| `server.mjs` | Entrypoint. `node server.mjs`. Reads `PORT`, `CONSOLE_DATA_DIR`, `SESSION_TTL_SECS`, `MASTER_BUNDLE`. |
| `store.mjs` | Durable, **atomic** file-backed store (temp + rename) over the existing seams: console-auth `snapshot()`/`{state}`, sub-access `onChange`, and the audit chain. |
| `audit.mjs` | Tamper-EVIDENT **SHAKE-256** hash-chained trail; one entry per grant/revoke/commit; `verify()` re-walks the chain. |
| `sub-access-host.mjs` | Hosts `enterprise/features/sub-access.mjs` as the seat/device registry: mint a sub (a seat) → count against the unlimited master → revoke → CRL serial (`jti`) → **deprovision** signal. |
| `licensing-signer.mjs` | Injects the **real** licensing signer (`@postern/licensing`, canonical Ed25519 vendor→master→sub) when built; otherwise the console runs with sub-access's honest **unsigned demo** stand-in and reports `signerWired:false`. |
| `self-check.mjs` | End-to-end HTTP self-check (below). |

Additive, in the Rust crate: `crates/postern-consiglio-auth/src/store.rs` — a
`SnapshotStore` trait + a real **atomic** `FileSnapshotStore` + a
`PersistentAuthServer` that persists over the existing `snapshot()`/`restore()`
seam after every mutating verb. No crypto is touched.

## Endpoints

Every verb except health/posture, login, and **first-admin-pair bootstrap**
requires a live, in-TTL session as `Authorization: Bearer <sessionId>`. All are
**fail-closed**.

```
GET  /healthz                       liveness + verifier availability + rails
GET  /v1/posture                    the rails/privacy posture

POST /v1/login/challenge            { orgId, userId } -> { challenge }
POST /v1/login/verify               { response:{orgId,userId,nonceHex,publicKeyB64,signatureB64}, challenge } -> { session }
                                    (REAL hybrid-PQ verify; nonce burned only on a valid sig)

POST /v1/bootstrap-enroll           seed the first it-admin AND compliance-officer; refused once both exist

GET  /v1/session                    the current session (gated)
POST /v1/session/logout             revoke the current session
POST /v1/session/sweep              drop expired nonces/sessions

GET  /v1/status                     seat meter, live sessions, pending changes, CRL feed, audit integrity
GET  /v1/audit                      the tamper-evident trail + integrity check

POST /v1/changes                    { kind:"enroll"|"offboard", payload }  propose (proposer = session)
GET  /v1/changes                    pending changes
POST /v1/changes/:id/approve        commit under two-person rule (approver = session; SoD enforced)
POST /v1/changes/:id/reject         drop a pending change

POST /v1/grant                      grantAccess (routed):
                                      { kind:"enroll-person", payload:{orgId,userId,role,clearance,publicKeyB64} }
                                          -> dual-control PENDING (approve via /v1/changes/:id/approve)
                                      { kind:"device", label, expires? } -> mint a sub (a seat)
POST /v1/revoke                     revokeAccess (routed):
                                      { kind:"offboard-person", payload:{orgId,userId} } -> dual-control PENDING
                                      { kind:"device", id } -> revoke sub -> { crlSerial } -> deprovision signal
                                      { kind:"org-kill" } -> emit masterPub for CRL revoked_master_pub (control-plane deprovisions)
```

**Dual-control + SoD.** `grant enroll-person` and `revoke offboard-person` stage
a `PendingChange`; committing it needs a **second, distinct** admin whose role is
the Brewer–Nash separated counterpart of the proposer's — one **it-admin** AND
one **compliance-officer**. Self-approval and same-side approval are refused; the
change stays pending and state is untouched (fail-closed). This is enforced in
`console-auth.mjs`, mirroring the crate's `control.rs`.

## Durability

State is injected into a real backend over the seams the reference already
exposed — no schema was invented:

- **console-auth** → `store.saveAuth(auth.snapshot())` after every mutating verb;
  restored on boot via `createConsoleAuth({ state })`.
- **sub-access** → `onChange(records)` → `store.saveSubs(records)`; restored via
  `{ records }`.
- **audit** → `onChange(entries)` → `store.saveAudit(entries)`; restored on boot.

Writes are atomic (temp file + `rename`), so a crash never leaves a torn file.
The self-check restarts the service against the same directory and proves
enrollments, the sub registry, the CRL feed, and the audit chain all survive.

## Run it

```sh
# 1. Build the REAL hybrid-PQ verifier (login fails closed without it — never a stub):
cargo build --release --features verifier-bin --bins   # in crates/postern-consiglio-auth

# 2. Start the service (auth-only; add MASTER_BUNDLE to enable seat/device verbs):
PORT=8803 CONSOLE_DATA_DIR=./console-data \
  node enterprise/cloud/services/console/http/server.mjs

# 3. End-to-end self-check (boots the service on an ephemeral port, drives every verb,
#    proves durability across a restart, and runs the REAL PQ login if the bin is built):
node enterprise/cloud/services/console/http/self-check.mjs
```

`MASTER_BUNDLE` is a JSON file `{ token, masterKey, expires, seats,
masterPublicKey?, vendorPublicKey?, masterTokenObj? }` — the verified master from
Gramota onboarding. The master **private key** is read into memory only and is
never written to disk by this code.

## Honest gaps (carried from the integration doc §10)

- **`org-kill`** emits the `masterPub` signal; the actual CRL build (`crl.ts`
  `buildCrl`) and the `license-binding.reverify()` **deprovision loop** live in
  the control plane, not here.
- **Sub signing** uses the real licensing signer only when `@postern/licensing`
  is built and master public/vendor keys are supplied; otherwise subs are the
  **honest unsigned demo** stand-in (`signerWired:false`), never claimed as
  verified.
- Compartment (Chinese-wall) binds are **declared in Ezekiel1**, not here; the
  grant verb points the caller there.
- This is a **reference orchestration, not a hardened IAM.** UNAUDITED.
