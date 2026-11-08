<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- PMO gap-analysis · consolidated prioritized backlog -->

# POSTERN-GAP-BACKLOG — the single prioritized "what's missing" list

**Owner:** PMO (fable5) · **Date:** 2026-07-13
**Framework:** `docs/gap/00-postern-systems-inventory.md` (systems map + rubric)

> ## Consolidation status — READ FIRST
> This is a **preliminary backlog built from the PMO inventory alone**. The four
> architect gap docs were **NOT yet present** when this was written and will
> deepen every band:
>
> | Architect doc | Scope | Status |
> |---|---|---|
> | `os-platform-gaps.md` (A1) | OS mobile/desktop/enterprise, Seal/attestation | ⏳ **PENDING** |
> | `enterprise-gaps.md` (A2) | license-spine, Consiglio, Ezekiel 1, Gramota | ⏳ **PENDING** |
> | `cloud-chiostro-gaps.md` (A3) | Cloud, Chiostro CVM, managed-node | ⏳ **PENDING** |
> | `apps-sdk-comms-gaps.md` (A4) | apps, SDK, comms, Porog/NoporIS/Sloboda | ⏳ **PENDING** |
>
> **Zero of four consolidated.** Re-run consolidation when they land; the
> `[A#-TBD]` markers show where their findings slot in.

**Scoring:** each item is `CVR × HX / E` per the rubric (§7 of the inventory).
Priority is led by **honesty risk (CVR × HX)** — *the site is the spec; a P0 is
where the site says something today's repo can't back.*

**What the PMO verified live (2026-07-13):** both endpoints the site calls
"live" **resolve HTTP 200** — `posternlabs.com/license/master` and
`postern-cloud-demo.fly.dev/v1/posture`. So neither is a false-liveness P0
**today**. The site's per-item status badges otherwise hold up on inspection:
**Postern's honesty discipline is real, and there are few genuine over-claims.**
That is the headline finding — the backlog below is mostly "prove it / finish
it / keep the words true," not "the site is lying."

---

## P0 — honesty risk: fix the words or ship the thing NOW

> P0 = site presents as done/live/enforced but reality diverges, OR an internal
> contradiction on a security-adjacent claim. All are cheap-to-fix (copy/deploy),
> which is exactly why they go first.

### P0-1 · Consiglio SoD claim — site and repo directly contradict each other
- **System:** Enterprise / Consiglio admin console
- **Gap:** `products.html` (via `build.js`) says dual-control / separation-of-
  duties / Chinese-Wall are **"declared but not yet runtime-enforced."** The
  backend `enterprise/cloud/services/console/README.md` + `console-auth.mjs` say
  they are **"ENFORCED at runtime"** (two-person rule, self-approval refused,
  with a `self-check.mjs` exercising it). One of them is stale.
- **Why it matters:** a security-governance claim that **contradicts itself
  across the company's own artifacts** is the single worst honesty look — a
  skeptic quotes both lines side by side. (Direction is "safe": the site
  *under*-claims, so no user is misled into trusting an absent control — but it
  undersells real work and is provably inconsistent.)
- **Tier to prove:** HOST (run `self-check.mjs`; confirm the deployed console
  actually spawns the built verifier binary and enforces the pair-signoff).
- **Effort:** small — reconcile once verified, then a copy edit on `build.js`.
  → **A2 must confirm which statement is true and align both.**

### P0-2 · "Live/hosted" claims have no standing liveness guard
- **System:** Cross-cutting (Cloud posture demo on Fly; R2 download host; license
  generator)
- **Gap:** the site asserts specific external URLs are **live** (`B_LIVE`) and
  hosts signed downloads on R2. These resolve **today** (PMO checked). But they
  are external Fly/R2/Pages deps that can 404 silently — at which point an honest
  claim becomes a false one **with zero code change**, undetected.
- **Why it matters:** honesty that depends on an unmonitored third-party host is
  one outage away from being a lie on the homepage.
- **Tier to prove:** HOST (a scheduled probe of `/license/master`,
  `/v1/posture`, and each R2 artifact URL + its `.minisig`; alert on non-200 or
  digest drift).
- **Effort:** small — a cron/monitor; no product change.

### P0-3 · The standing disclosed gate: external audit (meta-P0)
- **System:** ALL (every system carries `B_UNAUD`)
- **Gap:** nothing is third-party audited; the audit is **contracted, not done**
  (`PROJECT-STATUS.md`).
- **Why it matters:** it is the one gap gating every "secure/private" claim. It
  is **honestly disclosed everywhere**, so it is *not* a hidden over-claim — but
  it is the #1 thing missing in plain terms, so it leads the list by stakes even
  though the words are true.
- **Tier to prove:** external auditors (out of PMO scope).
- **Effort:** large — the standing company gate.

> **PMO note:** after live-probing, **no *hidden* false-liveness P0 remains
> today.** P0-1 (contradiction) is the only concrete "words wrong now" fix; P0-2
> keeps the true claims true; P0-3 is the disclosed umbrella. Architects: if you
> find a badge that over-claims (says built/enforced where a test fails), it is a
> new P0 — raise it here.

---

## P1 — a "live/built" thing a visitor will actually test that only partly delivers

### P1-1 · Mobile image: signed, click-to-download — and **never booted on any platform**
- **System:** OS / Postern OS — Mobile (`os/mobile.nix`, `.#mobile-image`)
- **Gap:** the sharpest-labelled download on the site. A **signed download button**
  is the strongest "it works" signal a site can send; this artifact has **not
  booted on QEMU-aarch64 or hardware**. Labelled honestly ("built ≠ booted"),
  but the affordance still invites a flash-and-fail.
- **Why it matters:** highest honesty-exposure surface — a user who flashes it
  and gets nothing tests the whole "we don't over-claim" promise.
- **Tier to prove:** VM first (QEMU-aarch64 boot), then hardware (PinePhone).
- **Effort:** medium.

### P1-2 · First **hardware** boot of the x86_64 node + desktop ISOs
- **System:** OS / Postern OS — Node + Desktop (`.#iso`, `.#desktop-iso`)
- **Gap:** QEMU-boot-validated, **hardware boot pending** (stated). The headline
  proof-point of the whole "reproducible, bootable OS" story.
- **Why it matters:** not an over-claim (site says pending), but it is the
  credibility milestone a serious evaluator waits for.
- **Tier to prove:** hardware (a PC).
- **Effort:** medium.

### P1-3 · Postern Seal: `verify()` tested on host, **no real TEE host wired**
- **System:** OS / Postern Seal (`os/attested.nix`, `crates/postern-seal-companion`)
- **Gap:** the attestation core + `os_roothash` flow are implemented and tested,
  but a **real SEV-SNP/TDX quote has never been fetched on real hardware**. The
  differentiator ("reproducible + remotely attestable") is unproven end-to-end.
- **Why it matters:** attestation is *the* Postern differentiator; the site is
  careful ("hosting a signed image is not attestation"), so this is a prove-it,
  not a lie.
- **Tier to prove:** hardware (a real SEV-SNP host).
- **Effort:** large. `[A1-TBD]`

### P1-4 · Chiostro CVM profile: code exists, **unbuilt and unbooted**
- **System:** Cloud / Chiostro (`os/cloud.nix`, `enterprise/cloud/image/`)
- **Gap:** SEV-SNP report-fetch + AMD-root verify + TDX parser have code; the
  profile has **never been built or booted**.
- **Why it matters:** the "a TEE you can verify" claim needs one real build+boot
  to move from `B_NOTSHIP` to demonstrable.
- **Tier to prove:** VM/hardware (confidential VM).
- **Effort:** medium–large. `[A3-TBD]`

### P1-5 · Phone-as-signer: two ends **not unified on one wire**; golden re-pin pending
- **System:** Apps / mobile↔desktop signer (`mobile/signer`, `integration/signer-protocol`)
- **Gap:** v1 reference interop works, but "the desktop and phone ends are not yet
  unified on one wire," a v2 shape is forward-declared-not-built, and the mobile
  signer's **byte-identity golden re-pin is still pending** (a correctness prop).
- **Why it matters:** presented as "real interop" a visitor may try; the unify +
  golden re-pin are what make it a shipped feature vs a shape.
- **Tier to prove:** HOST/VM (run both ends; re-pin the golden).
- **Effort:** medium. `[A4-TBD]`

### P1-6 · CRL / revocation endpoint: **merged, not deployed**; not server-signed
- **System:** Enterprise / license spine (`enterprise/licensing/`, `functions/license`)
- **Gap:** revocation exists as an **in-memory, unsigned reference store**,
  "merged but not yet deployed" — not a live endpoint.
- **Why it matters:** revocation is the missing half of a license system; a
  durable **signed** store + deploy is the design vs today's state.
- **Tier to prove:** HOST (deploy; sign the store).
- **Effort:** medium. `[A2-TBD]`

---

## P2 — honest prototype gaps a visitor can poke (next builds)

- **P2-1 · SDK real-KDF adoption in HTML apps** — `postern-sdk` exposes the real
  Argon2id KDF, but Chiave (and other HTML demos) still use a **PBKDF2 stand-in**.
  Wire the demos to the SDK. (Apps/SDK) `[A4-TBD]`
- **P2-2 · postmarketOS apks never device-booted** — 3 signed apks on a live
  repo; `postern` meta only resolves on a booted pmOS. First real pmOS boot.
  (OS) `[A1-TBD]`
- **P2-3 · Porog: StrongBox skeleton only; DPC isolation + Tor-only egress
  unstarted in code** — the defining container feature is still spec. (Bridge)
  `[A4-TBD]`
- **P2-4 · Enterprise features layer** (SSO, audit export, fleet defaults) —
  design/prototype; only generator + SDK clients ship. (Enterprise) `[A2-TBD]`
- **P2-5 · Managed-node control plane** — orchestration logic + interfaces only;
  **no real infra provisioned by the code**; needs an operator driver to be real.
  (Cloud) `[A3-TBD]`
- **P2-6 · Bloch Shield DLP + container** — enterprise-only design/prototype;
  corporate-scope rail defined, not shipping. (Enterprise) `[A2-TBD]`

---

## P3 — correctly-labelled design/spec; pure feature backlog

- **P3-1 · NoporIS** dual-persona bridge — concept scaffold, not shipping. (Bridge)
- **P3-2 · Sloboda** Android userland escape hatch — architecture + scaffolds
  only; never Seal-covered by design. (Bridge)
- **P3-3 · Matrix federation + Bridges tab** — design (`POSTERN-MESSAGING-INTEROP.md`);
  substantial Phase-1+ work. (Comms) `[A4-TBD]`
- **P3-4 · Tolmach subscription (hosted, less-private) tier** — planned, not
  enabled; correctly future-tense. (Apps)
- **P3-5 · D&B KYC verification** — DUNS format-checked only; real D&B check is a
  documented TODO. (Enterprise) `[A2-TBD]`
- **P3-6 · Org internal messenger, compliance engines** — enterprise-only
  prototypes mounted; design. (Enterprise) `[A2-TBD]`
- **P3-7 · Concept-video ⟷ shipped-UI drift** — the two Postern OS videos are
  labelled "design preview" (desktop UI is hardened GNOME, not the concept). Keep
  labels; eventually re-shoot from the real image. (OS)

---

## Consolidation checklist (for when A1–A4 land)

1. Merge each architect's findings into the matching band; replace `[A#-TBD]`.
2. Re-score any item an architect proves is an **over-claim** (badge says
   built/enforced/live but a test fails) → promote to **P0**.
3. Re-probe every `B_LIVE` URL + R2 digest at consolidation time (P0-2).
4. Confirm P0-1 (Consiglio) resolution direction with A2 and align site copy.
5. Collapse duplicates where two architects flag the same shared crate/seam.
