<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- ENTERPRISE track-lead (fable5) · roadmap-completion partition -->

# Enterprise roadmap — 5-dev partition (strict non-overlapping ownership)

**Track:** ENTERPRISE · **Lead:** fable5 · **Date:** 2026-07-13
**Inputs:** `docs/gap/enterprise-gaps.md` (A2), `docs/gap/POSTERN-GAP-BACKLOG.md`.
**Repos:** dev/source = `bloch-protocol` (this repo, main = make-it-work + Wave-0);
deploy = `bp-wt-site` (Cloudflare Pages project `posternlabs`; license Functions
deploy natively from `bp-wt-site/functions/`; static site + apps assemble via
`bp-wt-site/assemble-public.sh` → `node site/build.js` + per-app `index.html`).

**Guiding cut:** logic is ahead of wiring everywhere (PQ verify, SoD/dual-control,
BLP/walls, CRL crypto, KYC LoA are DONE + tested). So every task is *wire + deploy +
prove*, partitioned so no two devs edit the same file. Priority order favors work
that is **HOST-provable now** and **makes a live site claim real**.

**Proof tiers used below:**
- **HOST-provable-now** — provable on the macOS host today (cargo test, node
  self-check, local signed-CRL harness). This is the bar for "done."
- **VM/host-service-gated** — code is real + host-tested, but the *shipping* form
  is a running server (Fly/Workers), not a static asset; deploy needs an operator.
- **needs-external-cred** — code is real but the live behavior needs a third-party
  credential/contract (D&B Direct+). Written, not provable, until provisioned.

---

## Shared-file coordination (READ FIRST — the only cross-dev contention)

1. **`bp-wt-site/site/build.js`** — four devs each correct ONE disjoint copy block
   (Consiglio card, CRL dd, Gramota/D&B line, Ezekiel1 figcaption). Same file →
   **must be sequenced**. **DEV-2 is the site-copy integrator:** DEV-3/4/5 hand
   DEV-2 their one-block diff (exact old→new string); DEV-2 applies all four in a
   single pass last. No one else edits `build.js` directly. (If `bloch-protocol`
   keeps a mirror `site/build.js`, the deploy-repo copy is source of truth.)
2. **`crl:state` KV key** (`LICENSES` KV, key `"crl:state"`, shape
   `{version:int, revoked_jti:[], revoked_master_pub:[]}`, monotonic `version`) —
   **written by two functions in two owners:** `status.js` admin POST (DEV-3) and
   `renew.js` auto-revoke-on-decline (DEV-4). This is a **shared data contract, not
   a shared file.** DEV-3 owns the schema; DEV-4 conforms to it (same key, same
   shape, always bump `version` on a set change). Lock the shape before either ships.
3. **`bp-wt-site/assemble-public.sh`** — only DEV-5 needs a change (a copy step for
   the Ezekiel1 `.wasm` asset; today the loop copies each app's `index.html` only).
   DEV-5 owns that one edit; flag to lead before landing.
4. **`consiglio-verify` binary** — produced by DEV-1 (owns `src/bin/`), consumed by
   DEV-2 (pins `CONSIGLIO_VERIFIER_BIN`). Seam, not a shared file.

---

## DEV-1 — Consiglio Rust crate: governance + PQ verify + durable snapshot (authoritative core)

- **Scope.** The dual-control / Brewer–Nash SoD, hybrid-PQ wallet-login verify,
  sessions (TTL/revoke/offboard), and snapshot/restore durability already live and
  pass `cargo test` (12/12) here — this is the single source of truth the console
  binary and the JS mirror track. Harden and *productionize the durable seam*: build
  the `consiglio-verify`/`consiglio-sign` bins, add a production-shaped `SnapshotStore`
  backend beside `FileSnapshotStore` (a SQLite- or KV-blob-backed store implementing
  the same trait), and add a restart-survival integration test. Do **not** change the
  crypto — only add durability + keep cargo green.
- **Files/dirs OWNED (exclusive):** `crates/postern-consiglio-auth/**` — incl.
  `src/control.rs`, `src/server.rs`, `src/store.rs`, `src/persist.rs`, `src/org.rs`,
  `src/enroll.rs`, `src/challenge.rs`, `src/client.rs`, `src/error.rs`, `src/lib.rs`,
  `src/bin/consiglio-verify.rs`, `src/bin/consiglio-sign.rs` (create if absent),
  `Cargo.toml`.
- **Proof that closes it + tier:** `cargo test -p postern-consiglio-auth` (SoD +
  dual-control + self-approval refusal + separated-approver commit + snapshot
  round-trip + new backend restart test) **and**
  `cargo build --release --features verifier-bin --bins` emits `consiglio-verify`.
  **Tier: HOST-provable-now.**
- **Dependencies:** none (upstream of DEV-2).
- **Shared-file coordination:** none. Emits the `consiglio-verify` binary as the
  seam DEV-2 pins.

## DEV-2 — Consiglio deployable console SERVICE: run the verifier + durable store end-to-end; fix the SoD claim

- **Scope.** Turn the Node console (the JS mirror of DEV-1's crate) into the shipping
  *runtime* of wallet-login + dual-control. Pin `CONSIGLIO_VERIFIER_BIN` to DEV-1's
  binary (fail-closed — never the `"SIG(...)"` stub), wire the durable file/KV store
  so enrollments, live sessions, the sub registry, and the SHAKE-256 audit chain
  survive a restart, and drive a full self-check: real PQ login → dual-controlled
  enroll that self-approval and a same-side (SoD) approver both reject and a
  *separated* admin commits → offboard revokes the live session. Then correct the
  stale site copy that says SoD/dual-control/Chinese-Wall is "declared but not yet
  runtime-enforced / not yet wired into the shipping console."
- **Files/dirs OWNED (exclusive):** `enterprise/cloud/services/console/**` —
  `console-auth.mjs`, `consiglio-verifier.mjs`, `self-check.mjs`, `README.md`,
  `http/service.mjs`, `http/server.mjs`, `http/store.mjs`, `http/audit.mjs`,
  `http/sub-access-host.mjs`, `http/licensing-signer.mjs`, `http/self-check.mjs`,
  `http/README.md`. **Also: the `build.js` site-copy integrator role** (applies all
  four disjoint copy diffs — see Shared #1); its own block = the Consiglio
  card/caption (`bp-wt-site/site/build.js` ~lines 858, 883, 911).
- **Proof that closes it + tier:**
  `node enterprise/cloud/services/console/http/self-check.mjs` — real hybrid-PQ
  verify via the spawned binary + the dual-control/SoD sequence + a kill-and-restart
  showing restored state. **Tier: HOST-provable-now** for the runtime + enforcement.
  **The live deploy is VM/host-service-gated:** the console is a *server*, not a
  Pages static asset — actually hosting it (Fly/Workers) needs an operator. Label the
  shipped-service claim WRITTEN-and-host-tested, not deployed, until then.
- **Dependencies:** DEV-1 (needs the built `consiglio-verify` binary to pin).
- **Shared-file coordination:** `bp-wt-site/site/build.js` (integrator; receives
  DEV-3/4/5 blocks). Does **not** touch `apps/postern-enterprise/**` (that is DEV-3).

## DEV-3 — CRL: deploy the signed endpoint + enforce it in the shipping browser console

- **Scope.** The CRL crypto (`buildCrl`/`verifyCrl`/`checkRevocation`/`crlFreshness`/
  `pickNewerCrl` anti-rollback) and the `status.js` endpoint exist, but **no shipping
  install enforces the CRL** and admin writes return 501. (a) Deploy `status.js` into
  the Pages functions dir and document/provision `LICENSE_ADMIN_TOKEN`. (b) Wire the
  **shipping** offline license-verifying browser console (`apps/postern-enterprise/`,
  which already does the vendor→master→sub Ed25519 `verifyChain`) to fetch
  `GET /license/status`, verify the CRL against the vendor pubkey it already trusts,
  prefer the higher `version` (anti-rollback), honor soft-offline freshness, and
  **refuse** a revoked `master_pub`/`jti` — offline verification preserved (CRL only
  revokes, never grants; personal-free base never gated). (c) Correct the CRL site
  copy (from "in-memory, not server-signed, merged-not-deployed" to the deployed,
  vendor-signed, versioned reality).
- **Files/dirs OWNED (exclusive):** `enterprise/licensing/src/crl.ts`,
  `enterprise/licensing/src/index.ts` (CRL export surface),
  `functions/license/status.js` (staged), `bp-wt-site/functions/license/status.js`
  (deploy copy), `apps/postern-enterprise/index.html` **and**
  `apps/postern-enterprise/console.html` (the browser console — add CRL fetch/cache/
  enforce atop the existing chain verify).
- **Proof that closes it + tier:** a Node harness that runs
  `buildCrl → verifyCrl → checkRevocation` against a locally vendor-signed CRL
  (revoke a `master_pub`, assert the console's enforce path denies; assert an older
  `version` is rejected in favor of the cached newer one). **Tier: HOST-provable-now**
  for crypto + client enforcement. **The live endpoint is host-deploy-gated:**
  `GET/POST /license/status` on Pages + `LICENSE_ADMIN_TOKEN` secret — written and
  deployable; prove-live only after the Pages deploy.
- **Dependencies:** none hard (reuses the existing vendor keypair / `VENDOR_PUB_RAW_B64`).
- **Shared-file coordination:** hands its CRL copy block to DEV-2 for `build.js`;
  **`crl:state` KV schema** — DEV-3 owns the shape, DEV-4's `renew.js` must conform
  (Shared #2). `enterprise/licensing/src/index.ts` is DEV-3's; DEV-4 only reads it.

## DEV-4 — KYC person→entity gate: deploy review.js, wire KYC_MODE / LoA binding (D&B cred-gapped)

- **Scope.** `review.js` is a complete person→entity KYC seam (fail-closed LoA 0–3,
  D&B re-check, PII/image tripwire `scanForPII`, authoritative verdict stored under
  `kyc:<ref>` and bound into the token **by reference** so a client can't inflate its
  own LoA) — but it is **absent from the deploy repo**, so production KYC is
  self-declared LoA-0. Deploy `review.js` to the Pages functions dir, set the
  `KYC_MODE` plumbing (`enforce` caps LoA-0 → provisional; unset = today's parity, no
  regression), confirm `master.js`/`renew.js` `resolveKyc` bind the stored verdict,
  and keep the on-device Gramota-KYC LoA ladder (`kyc-loa.mjs`) in parity. **D&B
  credentials are external:** do all plumbing; issuance stays `source:"format-only"`
  until `DNB_CLIENT_ID`/`DNB_CLIENT_SECRET` (or `DNB_BEARER`) are provisioned —
  label the cred-gap plainly.
- **Files/dirs OWNED (exclusive):** `functions/license/review.js` (staged),
  `functions/license/master.js`, `functions/license/renew.js` (the `resolveKyc` +
  auto-revoke bindings), and their deploy copies
  `bp-wt-site/functions/license/{review.js,master.js,renew.js}`;
  `apps/gramota-kyc/**` (`index.html`, `kyc-loa.mjs`, `postern-license.mjs`,
  `self-check.mjs`, `review-seam.test.mjs`, `issuance.test.mjs`,
  `inline-parity-check.mjs`, `test-core.mjs`, `README.md`); `apps/gramota/**`.
- **Proof that closes it + tier:** `node apps/gramota-kyc/self-check.mjs` +
  `review-seam.test.mjs` + `issuance.test.mjs` (LoA ladder, PII tripwire refuses any
  document/PII, verdict-bound-by-reference so a client can't inflate LoA).
  **Tier: HOST-provable-now** for the seam + parity + tripwire. **needs-external-cred:**
  real LoA > 0 needs a D&B Direct+ contract — WRITTEN, cred-gated. **host-deploy-gated:**
  live `/license/review` + `KYC_MODE` secret on Pages.
- **Dependencies:** soft on DEV-3 for the `crl:state` schema (renew.js writes it).
- **Shared-file coordination:** hands its Gramota/D&B copy block to DEV-2 for
  `build.js`; conforms to DEV-3's `crl:state` shape (Shared #2). Owns
  `master.js`/`renew.js`; DEV-3 owns `status.js` — same dir, disjoint files.

## DEV-5 — Ezekiel1: drive the shipping app from the tested crate (WASM or a real seam)

- **Scope.** The Rust engine (Bell-LaPadula no-widening lattice, Brewer–Nash walls,
  SHAKE-256 hash-chained trail, fail-closed `eval`, edition gate) is DONE + tested,
  but the shipping HTML console (`apps/ezekiel1/index.html`, `connect-src 'none'`)
  re-implements access decisions in JS and is **not wired to the crate**. Compile the
  crate to WASM (`wasm-pack` / `wasm32-unknown-unknown` + a thin wasm-bindgen surface)
  and drive the console's access decisions from the real evaluator so the app's
  verdicts *are* the crate's verdicts, fully offline. If a full WASM build proves
  out of reach on host, ship the compiled `.wasm` as a self-hosted asset behind a
  thin JS seam and label exactly what is proven vs deferred.
- **Files/dirs OWNED (exclusive):** `crates/ezekiel1/**` (`src/lattice.rs`,
  `src/walls.rs`, `src/trail.rs`, `src/firmament.rs`, `src/eval.rs`, `src/policy.rs`,
  `src/edition.rs`, `src/jobs.rs`, `src/lib.rs`, `Cargo.toml`, plus a new
  wasm-bindgen glue module/crate); `apps/ezekiel1/index.html`;
  `bp-wt-site/assemble-public.sh` (the one added `.wasm` copy step — flag to lead).
- **Proof that closes it + tier:** `cargo test -p ezekiel1` (already green) +
  `wasm-pack build` / `cargo build --target wasm32-unknown-unknown` producing a
  loadable module + a headless parity check that the WASM decision equals the crate
  decision for a policy fixture (grant/deny, no-widening, wall COI). **Tier:
  HOST-provable-now** (build + parity). The in-browser wired console is
  HOST-provable once the `.wasm` loads offline in a local serve.
- **Dependencies:** none (own crate; `postern-trail`/`postern-policy` are read-only
  deps — do not edit).
- **Shared-file coordination:** hands its Ezekiel1 figcaption block to DEV-2 for
  `build.js`; owns the `assemble-public.sh` `.wasm` copy step (Shared #3). DEV-1 owns
  a *different* crate (`postern-consiglio-auth`) — no crate overlap.

---

## Ownership matrix (no file appears twice)

| Area | DEV-1 | DEV-2 | DEV-3 | DEV-4 | DEV-5 |
|---|---|---|---|---|---|
| `crates/postern-consiglio-auth/**` | ✅ | | | | |
| `enterprise/cloud/services/console/**` | | ✅ | | | |
| `enterprise/licensing/src/crl.ts` + `index.ts` | | | ✅ | | |
| `functions/license/status.js` (+deploy) | | | ✅ | | |
| `apps/postern-enterprise/{index,console}.html` | | | ✅ | | |
| `functions/license/{review,master,renew}.js` (+deploy) | | | | ✅ | |
| `apps/gramota-kyc/**`, `apps/gramota/**` | | | | ✅ | |
| `crates/ezekiel1/**`, `apps/ezekiel1/index.html` | | | | | ✅ |
| `bp-wt-site/site/build.js` (copy) | | ✅ integ | block→DEV-2 | block→DEV-2 | block→DEV-2 |
| `bp-wt-site/assemble-public.sh` | | | | | ✅ |
| `crl:state` KV schema | | | ✅ owner | conforms | |
| `consiglio-verify` binary | ✅ emits | pins | | | |

## Honest proof-tier summary (what gets PROVEN vs only WRITTEN)

- **DEV-1** — fully **HOST-provable-now** (cargo).
- **DEV-2** — runtime + SoD enforcement **HOST-provable-now** (node self-check);
  the *shipped hosted service* is **VM/host-service-gated** (needs an operator to run
  the server — a browser can't run the PQ verifier).
- **DEV-3** — CRL crypto + client enforcement **HOST-provable-now**; the *live
  endpoint* is **host-deploy-gated** (Pages deploy + `LICENSE_ADMIN_TOKEN`). This is
  the strongest "make a shipping claim real" item — enforcement lands in the app that
  actually ships.
- **DEV-4** — seam + LoA ladder + PII tripwire + verdict-by-reference
  **HOST-provable-now**; live endpoint **host-deploy-gated** (`KYC_MODE`); LoA > 0 is
  **needs-external-cred** (D&B Direct+ contract). Label the cred-gap on the site.
- **DEV-5** — crate + WASM build + parity **HOST-provable-now**; the wired offline
  console is HOST-provable via a local serve.

_All five carry the standing gate: UNAUDITED, no third-party review. Nothing here is
legal advice; the legal + data-protection review is the hard gate before any
compliance-adjacent piece ships. Do not modify product code from this plan; devs are
launched against the owned paths above._
