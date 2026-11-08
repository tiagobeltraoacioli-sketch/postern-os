# Enterprise Systems — Gap Analysis (Architect A2 / fable5)

Scope: license spine (`enterprise/licensing`, `functions/license/*`), Consiglio
(`crates/postern-consiglio-auth`), Ezekiel1 (`crates/ezekiel1` + `apps/ezekiel1`),
Gramota (`apps/gramota`, `apps/gramota-kyc`, `functions/license/review.js`),
enterprise comms compliance runtime (`enterprise/comms`). Compared against
posternlabs.com claims in `bp-wt-site/site/build.js` (enterprise section + the
Consiglio / Ezekiel 1 / Gramota cards). Read-only pass; no code modified.

**Proof tiers:** DONE (implemented + tested/enforced) · SCAFFOLD (real logic, not
wired to a shipping/deployed surface or backed by durable state) · MISSING (claim
has no implementation) · OVERCLAIMED (site says more than the code does).
A fourth axis, **UNDERCLAIMED**, is flagged where the site is *stale* and the code
is further along than the page admits.

Headline: the **crates are further along than the site claims** (Consiglio SoD /
dual-control / Chinese-Wall and Ezekiel1 BLP/walls are runtime-enforced and tested,
though the site still says "declared but not yet runtime-enforced"). The real gaps
are **wiring and deployment**, not core logic: nothing durable, wallet-login not in
any shipping console, CRL/KYC endpoints effectively inert in production.

---

## 1. License spine

### 1.1 Master-license generator — `functions/license/master.js`
- **Status: DONE (live).** Ed25519 vendor-signed, offline-verifiable master token;
  per-org master keypair minted client-returns private key; DUNS format gate;
  role + attestation; jti/kid/iss serials; canonical-JSON stable signing. Deployed
  copy present in `bp-wt-site/functions/license/master.js`, `LICENSES` KV bound,
  `VENDOR_PRIV_PKCS8_B64` is a documented Pages secret. Matches the site's "generator
  is live" claim. Proof tier: DONE.
- **Missing to be "real":** nothing for the generator itself. (KYC/D&B and CRL
  binding gaps are separate items below.) Priority: —. Effort: —.

### 1.2 D&B Direct+ KYC gate — `master.js` / `renew.js` / `review.js verifyDunsWithDnB`
- **Status: SCAFFOLD (code real, runtime not wired). Site UNDERCLAIMS.** Full OAuth2
  client-credentials + `/v1/data/duns` Direct+ integration exists in all three
  functions, fail-open on outage (format-only fallback), fail-closed on a
  `not-found` (refuses issuance / revokes at renewal). Bound into the token's `dnb`
  field so it cannot be silently over-claimed. Site says "D&B KYC remains a
  documented TODO — DUNS is format-checked only" — the *code* is done; only the
  *credentials* are absent.
- **Missing:** `DNB_CLIENT_ID`/`DNB_CLIENT_SECRET` (or `DNB_BEARER`) provisioned on
  the Pages deployment; a D&B Direct+ contract/account; live-response mapping
  verification against real payloads (field paths assumed from docs). Until then
  every issuance is `source: "format-only"`.
- **Proof tier:** SCAFFOLD. **Priority: P1.** **Effort:** ~0.5 day wiring +
  procurement/contract lead time for the D&B account (external, weeks).

### 1.3 CRL / revocation — `functions/license/status.js` + `enterprise/licensing/src/crl.ts`
- **Status: SCAFFOLD (endpoint present, enforcement not wired). Site accurate
  ("merged but not deployed").** `status.js` GETs a freshly vendor-signed, versioned
  CRL and POST-admits admin revocations; `renew.js` auto-revokes an org master_pub on
  non-renewal / failed KYC. The `crl.ts` library is a complete offline enforcement
  kit — `verifyCrl`, `crlFreshness` (soft-offline grace), `pickNewerCrl`
  (anti-rollback), `checkRevocation` over master_pub + master jti + sub jti.
- **Missing (the real gap):** (a) **no shipping install fetches or enforces the CRL**
  — `checkRevocation` is exported but unreferenced by any deployed verifier; the
  browser console (`console.html`) verifies the license chain but never calls the
  CRL. (b) `LICENSE_ADMIN_TOKEN` is unset on the deploy, so admin revocation writes
  return 501 (only renewal-driven revocation can populate `crl:state`). (c) In-memory
  KV state keyed by token-signature hash, not server-signed durable store — the site
  flags exactly this ("in-memory reference store … not server-signed").
- **Proof tier:** SCAFFOLD. **Priority: P1.** **Effort:** ~2-3 days — wire
  `checkRevocation` into the desktop/app verify path + a cached-CRL fetch/refresh
  loop; set `LICENSE_ADMIN_TOKEN`; durable signed CRL store.

### 1.4 Renewal + fiat-billing hook — `functions/license/renew.js`
- **Status: DONE (logic) / MISSING (billing).** Offline master re-verify, KYC re-run,
  re-mint with same `master_pub` + fresh exp/jti, CRL revoke on decline. Deployed.
  Billing is **INTENT ONLY** — records a `billing:<duns>` KV row, charges nothing,
  pricing "TBD". Honest and matches the site.
- **Missing:** an actual billing implementation (fiat processor, invoicing). Design
  decision pending revenue-model structuring. **Proof tier:** MISSING (billing) /
  DONE (renewal). **Priority: P3** (deliberately deferred). **Effort:** multi-week
  once pricing is decided.

### 1.5 Licensing library — `enterprise/licensing/src/*.ts`
- **Status: DONE (as a library) / SCAFFOLD (as a product).** token issue/mintSub/
  verifyChain, CRL, status, encoding, keys — self-contained + unit-tested
  (`self-check.mjs`, `site-functions.test.mjs`). Header self-labels "SCAFFOLD /
  pre-production / UNAUDITED". It is a library, not a running service.
- **Missing:** nothing internal; its consumers (console, installs) are the gap.
  **Proof tier:** DONE. **Priority: —.**

---

## 2. Consiglio — `crates/postern-consiglio-auth`

### 2.1 Wallet-as-login hybrid-PQ verify
- **Status: DONE (crate) / SCAFFOLD (product wiring).** `server.rs::verify_response`
  delegates to `bloch_crypto::crypto::verify` (real hybrid Falcon-1024 ‖ ML-DSA-65,
  same verifier the node runs). Domain-separated transcript, single-use nonce replay
  guard, enrolled-key identity binding, sessions with 128-bit id + TTL + revoke,
  offboard-invalidates-live-state. 12 passing tests. Site "the hybrid-PQ verify is
  real" — accurate. Proof tier: DONE (crypto).
- **Missing (the gap):** **no shipping/deployed surface runs it.** The real verifier
  reaches JS only via `enterprise/cloud/services/console/consiglio-verifier.mjs`, a
  Node bridge that spawns the `consiglio-verify` binary — and that cloud services
  layer is itself "reference prototype, not deployed". The **browser console
  (`apps/postern-enterprise/console.html`) does license-chain Ed25519 verify, NOT
  wallet-login PQ verify** (a browser cannot run the PQ verifier; the reference
  console historically used a `"SIG(...)"` string stub). So wallet-as-login is real
  as a crate + CLI + Node bridge but wired into **nothing that ships**.
- **Proof tier:** SCAFFOLD (wiring). **Priority: P1.** **Effort:** ~3-5 days — stand
  up the Node console-service (pin `CONSIGLIO_VERIFIER_BIN`), build+ship the verifier
  binary in the deploy, connect a real login UI to it.

### 2.2 Dual-control / SoD / Brewer-Nash (control action)
- **Status: DONE. Site UNDERCLAIMS (stale).** `control.rs` enforces a two-person rule:
  admin-only propose, distinct-approver (no self-approval), and Brewer-Nash
  *separated* pair (one IT-admin + one compliance-officer) via `sod_separated_from`;
  fail-closed, offboard-on-commit revokes sessions. Tested. The site card and the
  presentation caption still say "declared but not yet runtime-enforced" /
  "declared-not-yet-runtime-wired" — **that is now false**; the crate docstring itself
  says "were merely declared are now runtime-enforced and tested."
- **Missing:** update the site copy (this is a docs/marketing gap, not a code gap);
  and note it still guards an **in-memory** store (see 2.3). **Proof tier:** DONE.
  **Priority: P2** (correct the site claim). **Effort:** trivial (site copy).

### 2.3 Durability / state backend
- **Status: SCAFFOLD.** All Consiglio state (enrollments, nonces, sessions, pending
  changes) lives in in-memory `HashMap`s. `persist.rs` provides a snapshot/restore
  seam (round-trip tested) and `store.rs` a `FileSnapshotStore`, but **no
  Postgres/KV/Redis backend is wired**; a real multi-instance deployment has no shared
  durable store. Honestly self-labelled in `lib.rs`.
- **Proof tier:** SCAFFOLD. **Priority: P1** (blocks any real deployment).
  **Effort:** ~3-5 days — implement `SnapshotStore` over a real DB + wire at the
  service layer; concurrency/locking for the pending-change queue.

---

## 3. Ezekiel1 — `crates/ezekiel1` + `apps/ezekiel1`

### 3.1 Bell-LaPadula levels + no-widening lattice
- **Status: DONE.** `lattice.rs` — acyclic forest build, `validate_no_widening`
  (child may not exceed parent), `may_read` (no-read-up) / `may_write`
  (no-write-down). Tested. Matches the site's "Bell-LaPadula levels, nested
  no-widening layers." Proof tier: DONE.

### 3.2 Brewer-Nash Chinese walls
- **Status: DONE.** `walls.rs` — history-based COI denial, no-bypass enforced at
  validation, `may_access` pure decision, deliberate `lower_wall` only. Tested.
  Proof tier: DONE.

### 3.3 SHAKE-256 hash-chained audit trail
- **Status: DONE.** `trail.rs` is a thin adapter over shared `postern_trail`:
  canonical-JSON preimage, SHAKE-256 `prev ‖ preimage` chain, `verify_chain` +
  `verify_chain_to_head` (pinned-head truncation detection). Honestly "tamper-evident,
  not tamper-proof." Tested. Matches the site. Proof tier: DONE.

### 3.4 Tenant firmament isolation
- **Status: SCAFFOLD (by design, honestly labelled).** `firmament.rs` enforces
  isolation **by construction inside one process** — explicitly "not an OS, kernel, or
  hardware boundary." Site says the same ("enforced in userland by construction, not
  an OS/kernel boundary"). Accurate; not an overclaim, but not a hard boundary.
  **Priority: P3** (it is a documented ceiling, not a bug). **Effort:** large (would
  need OS/sandbox work — out of scope for the crate).

### 3.5 Ezekiel1 product surface — `apps/ezekiel1/index.html`
- **Status: SCAFFOLD.** The shipping app is a single offline HTML console
  (`connect-src 'none'`). The Rust engine is the real evaluator; the browser app is a
  separate demonstration surface — the two are **not wired together** (no WASM build of
  the crate is loaded by the HTML). Personal (parental) vs Business editions gated by
  `edition.rs` in the crate. **Priority: P2.** **Effort:** ~2-4 days to compile the
  crate to WASM and drive the console from it (if a unified surface is wanted).

---

## 4. Gramota — `apps/gramota`, `apps/gramota-kyc`, `functions/license/review.js`

### 4.1 DUNS owner/manager onboarding — `apps/gramota`
- **Status: SCAFFOLD.** Onboarding UI (`index.html` + `core.js` + `app.js`,
  `test-core.mjs`) for owner/manager attestation and master→sub flow. Real client
  logic, offline. Reference prototype; not a deployed service. Proof tier: SCAFFOLD.

### 4.2 Person→entity KYC binder / LoA gate — `functions/license/review.js` + `apps/gramota-kyc`
- **Status: SCAFFOLD, and NOT DEPLOYED.** `review.js` is a well-built KYC seam:
  fail-closed LoA 0-3 computation, D&B re-check, PII/image tripwire (`scanForPII`),
  authoritative verdict stored under `kyc:<ref>` and bound by reference into the token
  (client cannot inflate its own LoA), `KYC_MODE=enforce` cap. `kyc-loa.mjs` mirrors
  the ladder on-device.
- **Missing (critical):** **`review.js` is NOT present in the deploy repo**
  (`bp-wt-site/functions/license/` has master/renew/status only). So there is **no
  server endpoint to compute the person→entity verdict in production**; `KYC_MODE` is
  unset → everything is self-declared LoA-0 parity. The master.js `resolveKyc`
  binding also depends on this endpoint's KV writes, which never happen.
- **Proof tier:** SCAFFOLD (undeployed). **Priority: P1.** **Effort:** ~0.5 day to
  deploy `review.js` + set `KYC_MODE`; depends on 1.2 (D&B creds) to be meaningful
  above LoA-0.

### 4.3 On-device OCR — `apps/gramota-kyc/index.html`
- **Status: SCAFFOLD / mild OVERCLAIM.** The privacy rail is real (images + OCR text
  never leave the device; only booleans + field *names* + LoA cross the wire; server
  tripwire refuses PII). But the **OCR engine is not bundled**: `runOcr` uses
  `window.Tesseract` *if a self-hosted build is present*, else **falls back to manual
  on-device entry**. Ships with no Tesseract → default is type-it-in. Site says
  "on-device OCR KYC" — the pipeline is OCR-capable and on-device, but out of the box
  it is manual entry, not automated OCR.
- **Proof tier:** SCAFFOLD. **Priority: P2.** **Effort:** ~1-2 days to self-host a
  Tesseract-WASM build next to the app and expose `window.Tesseract`; liveness/IDV
  (LoA-3) needs an external provider (larger).

---

## 5. Enterprise comms compliance runtime — `enterprise/comms`

### 5.1 Compliance runtime (retention / DSAR / breach / audit)
- **Status: SCAFFOLD (real logic mounted, in-memory, not deployed).**
  `compliance-runtime.mjs` mounts previously-unwired pure engines against a store:
  legal-hold-aware deletion executor, DSAR intake with identity-verification gate +
  deadline clock + real fetch/rectify/erase hooks, breach assessment (72h clock,
  ciphertext-mitigation) with case persistence, append-only admin-audit on every act.
  Engines (`retention.mjs`, `rights-engine.mjs`, `breach.mjs`, `audit-trail.mjs`) are
  real and self-checked.
- **Missing:** store is **in-memory** (`createMetadataStore`) — production must inject
  a real store; the transport/E2EE is a **reference** (`reference-e2ee.mjs`), bodies
  never actually sealed by a shipped transport; not deployed anywhere. Auto-notify is
  deliberately absent (breach output is a DRAFT). Site labels the whole business/
  enterprise edition "designs and reference prototypes … only master-license generator
  + SDK clients live." Accurate.
- **Proof tier:** SCAFFOLD. **Priority: P2.** **Effort:** ~1-2 weeks to back with a
  durable store + wire to a real messenger transport; legal review is a hard gate
  before any compliance claim ships.

---

## Structured summary

| # | Capability | Status | Proof tier | Priority | Effort |
|---|------------|--------|-----------|----------|--------|
| 1.1 | Master-license generator | DONE (live) | DONE | — | — |
| 1.2 | D&B Direct+ KYC gate | code real, no creds/mapping-verify | SCAFFOLD | P1 | 0.5d + D&B contract |
| 1.3 | CRL / revocation enforcement | endpoint present, no install enforces, admin writes off | SCAFFOLD | P1 | 2-3d |
| 1.4 | Renewal logic / fiat billing | renewal DONE, billing MISSING | MISSING (billing) | P3 | weeks |
| 1.5 | Licensing TS library | DONE as lib | DONE | — | — |
| 2.1 | Wallet-login PQ verify | crypto DONE, wired into nothing shipping | SCAFFOLD | P1 | 3-5d |
| 2.2 | Dual-control / SoD / Brewer-Nash | enforced+tested; **site says otherwise** | DONE (UNDERCLAIMED) | P2 (fix site) | trivial |
| 2.3 | Consiglio durable state | in-memory only, persist seam unwired | SCAFFOLD | P1 | 3-5d |
| 3.1 | Bell-LaPadula lattice | enforced+tested | DONE | — | — |
| 3.2 | Brewer-Nash walls | enforced+tested | DONE | — | — |
| 3.3 | SHAKE-256 audit trail | enforced+tested | DONE | — | — |
| 3.4 | Tenant firmament isolation | in-process only (honestly) | SCAFFOLD | P3 | large |
| 3.5 | Ezekiel1 app↔crate wiring | HTML app not driven by the crate | SCAFFOLD | P2 | 2-4d |
| 4.1 | Gramota DUNS onboarding | reference prototype | SCAFFOLD | P2 | — |
| 4.2 | Person→entity KYC / LoA gate | built but **review.js not deployed** | SCAFFOLD | P1 | 0.5d (+1.2) |
| 4.3 | On-device OCR | privacy rail real; OCR engine unbundled → manual default | SCAFFOLD (mild OVERCLAIM) | P2 | 1-2d |
| 5.1 | Comms compliance runtime | engines mounted, in-memory, undeployed, ref-E2EE | SCAFFOLD | P2 | 1-2wk + legal gate |

### Cross-cutting themes
1. **Logic is ahead of wiring.** The hard parts (PQ verify, BLP, Brewer-Nash, SoD,
   hash-chained audit, CRL crypto, KYC LoA + PII tripwire) are DONE and tested. The
   deficit is everywhere the same: no durable backend, no deployed endpoint, no
   shipping surface calling the real engine.
2. **Two site UNDERCLAIMS to correct:** Consiglio SoD/dual-control/Chinese-Wall is now
   runtime-enforced (site still says "declared, not enforced"); D&B integration code
   exists (site says "documented TODO"). The site is conservative/stale, not
   overclaiming — good posture, but the copy should be refreshed.
3. **One mild OVERCLAIM:** "on-device OCR KYC" ships without a bundled OCR engine
   (manual entry by default).
4. **Deployment gaps that make live claims inert:** `review.js` absent from the deploy
   repo; `DNB_*`, `LICENSE_ADMIN_TOKEN`, `KYC_MODE` unset; no client enforces the CRL.
5. **Honesty of the site is otherwise high** — nearly every card is correctly labelled
   pre-production / unaudited / reference prototype, and the "only the master-license
   generator + SDK clients are live today" statement holds up against the code.

_UNAUDITED across the board — no third-party review of any enterprise component.
Not legal advice; a legal + data-protection review is the stated hard gate before any
compliance-adjacent piece ships._
