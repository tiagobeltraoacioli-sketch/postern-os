<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- MASTER / INTEGRATION PMO (fable5) — cross-track coordination for the 20-dev roadmap fleet -->

# ROADMAP FLEET — MASTER / INTEGRATION PLAN

**Owner:** MASTER/INTEGRATION PMO (fable5) · **Date:** 2026-07-13 · **Repo:** `bloch-protocol`
**Base (authoritative):** `origin/main` @ `7108d77` (make-it-work + Wave-0 + `roadmap/wave0-bridges` merge).
**Inputs consolidated:** the 4 architect gap docs (`docs/gap/{os-platform,enterprise,cloud-chiostro,apps-sdk-comms}-gaps.md`) + `POSTERN-GAP-BACKLOG.md`; the 3 bridge Wave-1 partition docs (`docs/plan/{noporis,porog,sloboda}-wave1-plan.md`).

> ## Consolidation status — READ FIRST
> | Track (expected partition doc) | Status |
> |---|---|
> | `os-roadmap-plan.md` (OS/images) | ⏳ **PENDING** — gap doc present; no formal partition doc. Bridge OS slice covered by `sloboda-wave1-plan.md`. |
> | `enterprise-roadmap-plan.md` (Enterprise) | ⏳ **PENDING** — gap doc present; no partition doc. |
> | `cloud-seal-roadmap-plan.md` (Cloud/Seal) | ⏳ **PENDING** — gap doc present; no partition doc. |
> | `apps-sdk-roadmap-plan.md` (Apps/SDK/comms) | ⏳ **PENDING** as one doc — but the **bridge slice** is fully partitioned in `noporis`/`porog`/`sloboda` Wave-1 plans (15 devs). |
>
> **Consolidated: 3 bridge sub-partitions (file ownership folded into the map below).
> Pending: all 4 formal per-track partition docs.** The cross-cutting design below is
> built from the 4 gap docs + the 3 bridge plans, per mandate. A concurrent bridge
> Wave-1 fleet is already live (branches `roadmap/wave1-{noporis,porog,sloboda,integrate}`
> + `worktree-agent-*`) — its shared surfaces are the highest-collision zone and are mapped in §1.

---

## 0. The two overlapping fleets (why this needs one integrator)

1. **The 4-track / 20-dev roadmap-completion fleet** (this plan's mandate) — tasks derived
   from the 4 gap docs, bucketed 5 devs/track (§3).
2. **The bridge Wave-1 fleet** (already spun up) — 3 products × 5 devs = 15 devs over
   Porog/NoporIS/Sloboda, branches live. It is a **sub-effort inside the Apps/SDK + OS tracks**,
   and its three plans **collide with each other** on `apps/consent-contract`, `android-common`,
   `scripts/vm/`, and `flake.nix`. Resolving those (§1, §4) is the single most load-bearing thing
   this document does — it is exactly the class of collision that bit the last fleet.

---

## 1. Cross-track shared-file ownership map (ONE file → ONE owner)

**Rule:** every file below has exactly one owner across all tracks/fleets. Everyone else
reaches it through a seam or hands the owner a hunk. A collision resolved here is a bug
that did **not** happen at integration.

### 1.1 Repo-wide shared surfaces

| File / dir | Tracks that WANT it | **Sole owner** | Rule for everyone else |
|---|---|---|---|
| `flake.nix` | OS (iso/desktop/mobile/attested outputs), Cloud/Seal (`cloud-image`, `.#seal-gate`), Sloboda (`sloboda-vm` entry) | **OS/images lead** | Cloud/Seal + Sloboda hand the OS owner a single additive hunk (`nixosConfigurations.*` / `packages.*` attr). No one else edits. |
| `Cargo.lock` | any dep-adding task | **Integration PMO** | **No dev commits it.** Regenerated ONCE at integration (`cargo generate-lockfile`), after all `Cargo.toml` edits land. (Note the seal-companion dual-git-rev dedupe caveat — regen resolves it.) |
| `Cargo.toml` (workspace root) | any new crate/member | **Integration PMO** | Devs request a member/dep line; PMO applies. |
| `deny.toml` | any new dep licence/advisory | **Integration PMO** | Same. |
| `.gitlab-ci.yml` | OS (nix build jobs), Cloud/Seal (hardware runbook = out-of-CI), Porog/Sloboda/NoporIS (`t1:*` VM jobs) | **CI owner (Integration PMO)** | Each track hands a tier-prefixed job stanza; PMO merges. Tier prefix mandatory (`t0:`/`t1:`) — a `t0` pass never implies `t1`. |
| `scripts/check-trust-labels.sh` | all | **Honesty-gate (PMO) — FROZEN** | No edits this fleet. It is the CRITICAL blocking gate. |
| `scripts/ci-honesty-products.sh` | Sloboda (tier-name strings) | **Honesty-gate (PMO)** | Sloboda Dev D coordinates any tier-name string change; may be intentional. |

### 1.2 Seal / attestation crate — `crates/postern-seal-companion/**` (file-level split)

The crate is claimed by **Cloud/Seal** (A3: SEV-SNP/TDX) AND touched by the **bridge/Apps**
attestation dev (Porog Dev 4 edits `mobile.rs`; A4 references `mobile-attest`). Split by file:

| File | **Owner** |
|---|---|
| `src/snp.rs`, `src/tdx.rs`, `src/gate.rs`, `src/binding.rs`, `tests/snp_*.rs`, `tests/tdx_*.rs` | **Cloud/Seal** |
| `src/mobile.rs` (StrongBox verifier — Porog's A↔C wire) | **Bridge/Apps attestation dev (Porog Dev 4)** |
| `Cargo.toml` (features `sev-snp`/`tdx`/`mobile-attest`) | **Cloud/Seal owner** applies feature/dep edits on both sides' behalf |

### 1.3 OS ↔ Cloud/Seal Nix seam

| File | **Owner** | Rule |
|---|---|---|
| `os/attested.nix` (measured-boot base, `os_roothash` producer) | **OS/images** | Cloud consumes read-only. **Cloud's `cloud.nix` build DEPENDS on this — sequence OS first.** |
| `os/cloud.nix` (Chiostro CVM profile) | **Cloud/Seal** | — |
| `os/seal-gate.nix` (gate packaging; 5 `lib.fakeHash` sentinels to fill on a Nix host) | **Cloud/Seal** | OS adds the `.#seal-gate` output attr in `flake.nix`; Cloud fills the sentinels (VM task). |
| `os/sloboda-compat.nix` (binder kernel, Waydroid; excluded from attested closure) | **Sloboda Dev C** | OS must not touch; kept OUT of the attested list. |
| `os/configuration.nix`, `os/desktop.nix`, `os/browser.nix`, `os/mobile.nix`, `os/telephony.nix` | **OS/images** | — |

### 1.4 Bridge shared surfaces (the 3-way collision zone — resolved)

| File / dir | Claimed by | **Sole owner** | Resolution |
|---|---|---|---|
| `apps/consent-contract/**` (shared consent spine + schema) | **Porog Dev 3 AND Sloboda Dev D both claim ownership**; NoporIS marks frozen | **Consent-Spine steward = Porog Dev 3** | **FROZEN for Sloboda + NoporIS.** Schema changes go only through the steward with cross-product ack. This is the top collision — two plans both wrote "owner." |
| `android-common/**` (shared DPC core) | Porog Dev 1 (edits), NoporIS Dev A (consumes) | **Porog Dev 1** | NoporIS/Sloboda read-only; additive generic changes only, with N-lead ack. Do **not** fork. |
| `scripts/vm/**` | **NoporIS Dev E claims `scripts/vm/**`; Sloboda Dev E claims `scripts/vm/waydroid-boot-smoke.sh`** | **namespaced** | Split: `scripts/vm/{noporis,porog,sloboda}/**`. No bare files at `scripts/vm/` root. Collision resolved by directory. |
| `mobile/android/.../wallet/StrongBoxKey.kt`, `PlayIntegrity.kt`, `AttestationTier.kt` | Porog Dev 4; A1 #9 + A4 also reference | **Porog Dev 4** | OS/Apps reference the verdict, don't edit. |
| `android-container/profile/**` Gradle + `gradle/libs.versions.toml` | Porog Dev 5 | **Porog Dev 5** | All Porog dep additions route here. |
| `android-bridge/persona/**` Gradle | NoporIS Dev A/B | **NoporIS Dev B** (owns `lib.rs`/`Cargo.toml`/Kotlin `bridge/` pkg integration point) | NoporIS internal file split per its §5. |
| `apps/noporis-bridge-glue/src/lib.rs` + `Cargo.toml` | NoporIS A/B/E | **NoporIS Dev B** | Sole applier of A's/E's re-export/dep one-liners. |

### 1.5 Cross-repo (site) — out of this repo's merge, flagged for the honesty pass

| Surface | Owner | Note |
|---|---|---|
| `bp-wt-site/site/build.js` (Consiglio SoD copy; D&B "TODO" copy) | Enterprise lead + site owner | P0-1 + 2 UNDERCLAIMS live here, not in `bloch-protocol`. Cross-repo edit. |
| `bp-wt-site/functions/license/review.js` (deploy target) | Enterprise lead | Gramota KYC endpoint absent from deploy repo (A2 §4.2). |

---

## 2. HOST-provable vs VM-gated vs hardware-gated vs needs-external-cred

Consolidated across all four gap docs. **Blunt headline:** of ~37 tracked closure items,
only **~11 genuinely CLOSE now** on the current macOS host. The rest get **WRITTEN** this
fleet but cannot close here — **the two flagship differentiators (a booted OS, a real
attestation quote) are entirely outside the HOST tier.** Do not let a green `t0` imply a
`t1`/hardware truth.

| Tier | Count | What it means | Headline items |
|---|---|---|---|
| **HOST (closes now)** | **~11** | `cargo`/`node`/`shellcheck` on macOS; claim==reality achievable this fleet | CRL enforcement wiring + host tests (A2 1.3); Consiglio durable `SnapshotStore`-over-DB (A2 2.3); Ezekiel1 crate→WASM app wiring (A2 3.5); OCR Tesseract-WASM self-host (A2 4.3); SDK wasm adoption into HTML apps / retire Chiave PBKDF2 (A4 P1); phone-as-signer unify-one-wire reference (A4 P1, hw keystore excepted); AMD-KDS CRL fetch code (A3 A2); TDX pin Intel root DER + collateral (A3 B2/B3, once DER sourced); NoporIS/Porog/Sloboda Rust+node+shell control-flow. **Plus already-DONE cores** (Consiglio SoD/BLP/walls, messenger Megolm, courier PQ seal, seal core verifier) that only need proof+copy. |
| **VM-gated (written, needs Linux+Nix+QEMU)** | **~12** | Blocked ONLY on "no Nix here" — the biggest OS/Cloud bucket | `flake.lock` + `nix flake check`; `nix build .#iso/.#desktop-iso/.#mobile-image/.#attested-image/.#cloud-image`; `.#seal-gate` output + fill 5 fakeHash; QEMU x86 boot harness (MISSING — the one true overclaim, A1 #17) + aarch64 QEMU mobile boot; two-builder bit-for-bit reproduction; Porog Gradle `assembleDebug` + work-profile emulator; NoporIS Gradle + emulator + binder-VM broker; Sloboda binder-VM Waydroid → `Session: RUNNING`; in-guest LUKS/persist + WG keygen (D3/D4). |
| **Hardware-gated (written, needs real TEE/phone/PC)** | **~7** | Physical: cannot be faked in a VM | SEV-SNP live report fetch + gate/verify handshake + negative controls (A3 A3/A5/C2/C3 — GCP N2D Milan); TDX real instance (A3 B2); TPM2 PCR measurement + TPM2-seal on CVM (A1 #4, A3 D3); x86_64 ISO + desktop **hardware** boot + Secure-Boot signing (A1 #17/#18); PinePhone + pmOS device boot (A1 #3/#13); StrongBox attest + Play-Integrity STRONG-fails on real Android (Porog device tier); Sloboda GPU path Lima/Panfrost (item 11, device-only). |
| **Needs external cred / account / deploy (written, blocked on non-code)** | **~7** | No amount of Nix/hardware supplies these | D&B Direct+ account + `DNB_CLIENT_ID/SECRET` (A2 1.2 — procurement, weeks); deploy `review.js` + set `KYC_MODE`/`LICENSE_ADMIN_TOKEN`/`DNB_*` Pages secrets (A2 4.2/1.3); store catalog/apk publish to R2 (A4 P2 — R2 creds); Fly/R2 liveness monitor deploy (P0-2); managed-node real operator `driver` + cloud infra (A3 E3); Azure vTPM/paravisor adapter + Azure account (A3 D5); **external third-party audit (P0-3) — standing company gate.** |

**One-line truth for the fleet:** enterprise-wiring, app-adoption and site-copy CLOSE now;
everything that makes Postern *Postern* (bootable reproducible OS, real remote attestation)
only gets WRITTEN — it is gated on the Linux+Nix+QEMU box, real SEV-SNP/TDX/phone hardware,
or external creds. Label each accordingly; never green-fake a tier.

---

## 3. The 20-dev launch table (4 tracks × 5)

Derived from the 4 gap docs. Base for **every** dev = `origin/main` @ `7108d77` (§4).
Tier = the highest tier the dev's work can be PROVEN at this fleet.

### Track OS/images (owns `flake.nix`, `os/*` except `cloud.nix`/`sloboda-compat.nix`)
| Dev | Scope | Owned files | Proof tier |
|---|---|---|---|
| OS-1 | `flake.lock` + `nix flake check` + two-builder reproduction | `flake.nix` (sole owner), `flake.lock` (new) | VM |
| OS-2 | Node + Desktop ISO build + **x86 QEMU boot harness** (fix the one overclaim, A1 #17) | `os/configuration.nix`, `os/desktop.nix`, `os/browser.nix`, new `os/boot-harness/x86/**` | VM (HW pending) |
| OS-3 | Mobile image + aarch64 QEMU boot (harness exists, never run, A1 #3/#16) | `os/mobile.nix`, `os/telephony.nix`, `os/boot-harness/*aarch64*` | VM (HW: PinePhone) |
| OS-4 | Attested/measured-boot image + real `os_roothash` producer (A1 #4) | `os/attested.nix` (Cloud consumes RO) | VM build / HW (TPM2) |
| OS-5 | pmOS community edition first boot (A1 #13) + Secure-Boot signing plan (A1 #18) | `pmos-overlay/**` | VM build / HW device |

### Track Enterprise (owns `enterprise/*`, `functions/license/*`)
| Dev | Scope | Owned files | Proof tier |
|---|---|---|---|
| ENT-1 | CRL enforcement: wire `checkRevocation` into verify path + cached fetch; set `LICENSE_ADMIN_TOKEN`; durable signed store (A2 1.3) | `enterprise/licensing/src/crl.ts`, `functions/license/status.js` | HOST (deploy: cred) |
| ENT-2 | D&B Direct+ live mapping verify (A2 1.2) — code done, gated on account | `functions/license/{master,renew,review}.js` (D&B paths) | HOST code / external cred |
| ENT-3 | Consiglio wallet-login PQ verify: stand up Node console-service + ship verifier bin (A2 2.1) + durable state backend (A2 2.3) | `crates/postern-consiglio-auth/**`, `enterprise/cloud/services/console/**` | HOST (deploy: infra) |
| ENT-4 | Gramota: deploy `review.js` + `KYC_MODE` (A2 4.2); OCR Tesseract-WASM self-host (A2 4.3); Ezekiel1 crate→WASM (A2 3.5) | `apps/gramota-kyc/**`, `apps/ezekiel1/**` | HOST (deploy: cred) |
| ENT-5 | **P0-1 reconcile** — align Consiglio SoD copy (site UNDERCLAIMS; crate is enforced+tested); comms compliance durable store (A2 5.1) | cross-repo `build.js` + `enterprise/comms/**` | HOST / cross-repo copy |

### Track Cloud/Seal (owns `os/cloud.nix`, seal-companion snp/tdx/gate)
| Dev | Scope | Owned files | Proof tier |
|---|---|---|---|
| CS-1 | Chiostro CVM build+boot (D1) — depends on OS-4's `attested.nix` | `os/cloud.nix`, `enterprise/cloud/image/**` | VM build / HW (SNP/TDX) |
| CS-2 | SEV-SNP live report fetch + gate/verify handshake + negative controls (A3/A5/C2/C3) | `crates/postern-seal-companion/src/{snp.rs,gate.rs,binding.rs}` | HOST (fixture) → HW |
| CS-3 | AMD-KDS CRL fetcher (A2) + release-manifest `sev-snp-measure` pipeline (A6) | seal-companion snp CRL path, new manifest tool | HOST code / HW verify |
| CS-4 | TDX: paste Intel root DER (B2) + collateral sig verify (B3) | `crates/postern-seal-companion/src/tdx.rs` | HOST (once DER) → HW |
| CS-5 | `seal-gate.nix` fill 5 fakeHash + `.#seal-gate` output; managed-node real `driver` (E3); in-guest LUKS/WG (D3/D4) | `os/seal-gate.nix`, `enterprise/cloud/control-plane/**` | VM / external infra |

### Track Apps/SDK/comms (owns `apps/*`, `crates/postern-{sdk,messenger,courier,tor,...}`, bridges)
The **bridge slice (Porog/NoporIS/Sloboda)** is already partitioned in the 3 Wave-1 plans;
those 15 devs are the concrete Apps/OS-bridge headcount. Representative track roles:
| Dev | Scope | Owned files | Proof tier |
|---|---|---|---|
| APP-1 | Wire wasm SDK into HTML apps; retire Chiave PBKDF2 stand-in (A4 P1) | `crates/postern-sdk/wasm.rs`, `apps/postern-login/**`, `apps/{sotto,vedetta,tolmach}/**` | HOST |
| APP-2 | Phone-as-signer unify desktop↔phone on one wire (A4 P1) | `integration/signer-protocol/**`, `mobile/signer/**` | HOST/interop (HW keystore) |
| APP-3 | Promote transports: courier onion + messenger Tor/Matrix out of feature-gated ref (A4 P2) | `crates/postern-{courier,messenger,tor}/**` | HOST (codec) / VM |
| APP-4 | Store catalog signing pipeline + publish (A4 P2) | `apps/postern-store/**` | HOST build / R2 cred |
| APP-5 | **Bridge integration lead** — reconciles Porog/NoporIS/Sloboda shared surfaces per §1.4; owns `roadmap/wave1-integrate` | consent-spine steward coordination, `scripts/vm/` namespacing | HOST / VM |

> The 15 named bridge devs (Porog 1-5, NoporIS A-E, Sloboda A-E) sit under APP-5's
> integration and follow their own Wave-1 plans, with §1.4 overriding any ownership
> conflict between those plans.

---

## 4. Base + integration strategy

### 4.1 Base verification (the last-fleet bug: worktrees silently on an old commit)
- **Authoritative base = `origin/main` @ `7108d77`** (make-it-work + Wave-0 + wave0-bridges merge).
- The current checkout `roadmap/wave1-base` @ `78e9799` is **exactly one commit behind** it
  (`git merge-base --is-ancestor HEAD origin/main` = true; only the wave0-bridges merge is ahead).
- **Every dev worktree MUST, before starting:**
  ```
  git fetch origin
  git merge-base --is-ancestor origin/main HEAD && echo OK || echo DIVERGED
  # if DIVERGED or behind:  git reset --hard origin/main
  ```
- Branches already exist (`roadmap/wave1-{noporis,porog,sloboda,integrate}`, `worktree-agent-*`).
  **Each must be re-verified against `origin/main`** — do not assume; last fleet, worktrees
  branched from an older commit and rebuilt Wave-0 files divergently.

### 4.2 Contract freeze (day 0, PMO) — before any dev writes
Freeze these signatures; changes route through PMO: consent-spine schema
(`apps/consent-contract/consent-spine.schema.json`), `Substrate` trait + `GateState`
(NoporIS), the seal-gate wire codec (`gate.rs`), `mobile.rs` A↔C wire (Porog), and the
seal-companion feature set.

### 4.3 Integration runbook
1. **Land disjoint dirs per track.** Each track merges to its track branch; dirs are
   partitioned so track branches don't overlap (OS `os/*`+`flake.nix`, ENT `enterprise/*`,
   CS `os/cloud.nix`+seal snp/tdx, APP `apps/*`+`crates/*`).
2. **Reconcile shared files per §1** in owner order: `flake.nix` (OS applies Cloud/Sloboda
   hunks) → `android-common` (Porog Dev 1) → `apps/consent-contract` (steward) →
   seal-companion `Cargo.toml` (Cloud) → `.gitlab-ci.yml` (CI owner) → `scripts/vm/` namespaced.
3. **Sequence dependency:** OS-4 `attested.nix` builds **before** CS-1 `cloud.nix` (D1←D2).
4. **Regenerate `Cargo.lock` ONCE** (`cargo generate-lockfile`) after all `Cargo.toml` edits —
   no dev commits it; resolves the seal-companion dual-git-rev dedupe caveat.
5. **HOST gate (must be green):** `cargo test` across touched crates; `node` unit tests;
   `shellcheck`; `node --check` on HTML.
6. **Honesty gate (BLOCKING):** `bash scripts/check-trust-labels.sh` +
   `bash scripts/ci-honesty-products.sh` — no attestation-word bleed, never "Postern OS".
7. **VM gate (Linux+Nix+QEMU box):** tier-prefixed `t1:*` jobs — `nix flake check`, image
   builds, QEMU/emulator/binder boots. A `t1` absence surfaces as `UNTESTED-until-VM`, never green.
8. **Hardware runbook (out-of-CI):** SNP/TDX/TPM2/PinePhone/StrongBox — signed manual log,
   `untested-inventory.yml`, never a pipeline exit code.
9. **MR** per track to `main` once HOST + honesty green; VM/HW status carried as honest labels.

---

## 5. Cross-track de-dup / sequencing findings

| # | Overlap | Resolution |
|---|---|---|
| DD-1 | **`apps/consent-contract/` claimed by BOTH Porog Dev 3 and Sloboda Dev D** (NoporIS froze it) | Single Consent-Spine steward = **Porog Dev 3**; FROZEN for Sloboda+NoporIS; schema changes need cross-product ack. **Highest-risk collision.** |
| DD-2 | `android-common/` co-edited (Porog Dev 1) + consumed (NoporIS Dev A) | **Porog Dev 1** sole owner; others read-only, additive-only, N-lead ack. |
| DD-3 | **`scripts/vm/` claimed by both NoporIS Dev E and Sloboda Dev E** | Namespace `scripts/vm/{noporis,porog,sloboda}/**`; no bare root files. |
| DD-4 | `seal-companion` split — Cloud/Seal (snp/tdx) vs Porog Dev 4 (`mobile.rs`) | File-level split per §1.2; crate `Cargo.toml` → Cloud owner. |
| DD-5 | `seal-gate.nix` (Cloud content) vs `flake.nix` `.#seal-gate` output (OS) | Cloud owns `.nix` + fills fakeHash; OS adds the flake output attr. |
| DD-6 | `attested.nix` needed by OS (#4) AND Cloud (D2) — same measured-boot base | **OS owns**; Cloud consumes RO; **sequence OS before Cloud**. |
| DD-7 | SEV-SNP verify appears in A3 (Cloud) AND A4 (Apps cross-ref) | Not a real dup — one owner (Cloud/Seal); A4 references only. |
| DD-8 | Sloboda edits `flake.nix` (`sloboda-vm` entry) vs OS owns `flake.nix` | Sloboda Dev C hands the hunk to OS flake owner; keep OUT of attested list. |
| DD-9 | Mobile StrongBox attest in A1 #9, A4, and Porog Dev 4 — same `mobile.rs`/`StrongBoxKey.kt` | Merge under **Porog Dev 4**; OS/Apps reference the verdict. |
| DD-10 | x86 QEMU boot harness (A1 #17) = the one true site overclaim | **Sequence first in OS track** — build harness+evidence OR soften site "boots on QEMU x86_64" copy. Honesty-critical. |

---

*PMO coordination artifact — no product code modified, nothing committed. Plans/design only;
nothing here is built, booted, attested, or audited. UNAUDITED across the board.*
