<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- PMO gap-analysis · systems inventory + prioritization framework -->

# 00 — Postern Systems Inventory + Prioritization Framework

**Owner:** PMO (fable5) · **Date:** 2026-07-13 · **Repo:** `bloch-protocol`
**Companion site:** `bp-wt-site/site` (built by `site/build.js`, deployed as the
`posternlabs` Cloudflare Pages project).

This is the single source of truth for **what Postern systems exist, where they
live, and exactly what posternlabs.com claims for each**. It exists so the four
architect gap docs and the consolidated backlog (`POSTERN-GAP-BACKLOG.md`) score
against one shared map. Sibling architect docs (pending):
`os-platform-gaps.md` (A1), `enterprise-gaps.md` (A2),
`cloud-chiostro-gaps.md` (A3), `apps-sdk-comms-gaps.md` (A4).

---

## 0. The two-layer frame (why honesty is the axis)

Postern deliberately separates **the ownerless protocol** (Bloch-SIS-PoW, RPC/API
only, no owner, `docs/POSTERN-LABS.md`) from **the owned products** (Postern
Labs). This inventory covers the **products** — the systems A1–A4 are gapping.
The site's whole credibility rests on one promise it repeats on every page:

> *"If a claim isn't true yet, we phrase it as the plan — and a plan is all it
> is."* (`build.js` §status)

So the gap that matters most is not "feature missing" — it is **"the site states
something as done/live/hosted that the repo does not actually deliver."** That is
the P0 axis. The site is already unusually disciplined (per-item status badges:
`built` / `proto` / `design` / `unaud` / `live` / `merged`), which means most
gaps are honestly labelled — the P0 hunt is for the few places where the label
over-claims reality.

**Site status badge vocabulary** (`build.js` lines ~478–489):

| Badge | Site wording | Honest meaning |
|---|---|---|
| `B_LIVE` | "live" | reachable/working endpoint today |
| `B_ISO_QEMU`/`B_ISO_GDM` | "built · hosted + signed · boots on QEMU x86_64 · hardware pending" | ISO exists, QEMU-booted, **not** hardware-booted |
| `B_IMG_MOBILE` | "built · hosted + signed · not yet boot-tested" | image exists, **never booted** (QEMU or hw) |
| `B_APK_REPO` | "3 signed apks · repo live · non-attestable · never device-booted" | apks published, never run on a device |
| `B_MERGED` | "merged · not yet deployed" | code merged, **not a live endpoint** |
| `B_PROTO` | "reference prototype" | front-end/logic works, demonstrates design |
| `B_DESIGN`/`B_NOTSHIP` | "designed · reference prototype · not shipping" | documented plan, not running software |
| `B_POROG` | "StrongBox key-attest skeleton · DPC isolation design-only" | one narrow piece coded, defining feature is spec |
| `B_PROPOSED` | "name proposed · pending trademark clearance" | provisional name |
| `B_UNAUD` | "unaudited" | **everything** carries this |

---

## 1. OS / platform (A1)

| System | Repo location | Site claim (posternlabs.com) | Reality delta |
|---|---|---|---|
| **Postern OS — Node ISO** (x86_64) | `flake.nix` `.#iso`, `os/configuration.nix`, `os/bloch-node.nix` | ISO built, hosted, release-signed (R2), QEMU-boots to the Postern OS shell; **hardware boot pending** | Matches. No hardware boot. |
| **Postern OS — Desktop ISO** (x86_64) | `os/desktop.nix`, `os/browser.nix`, `.#desktop-iso` | ISO built, hosted, signed; QEMU-boots to GNOME/GDM; **hardware boot pending**; UI is hardened GNOME, **not** the concept-video shell | Matches. Video is labelled "design preview." |
| **Postern OS — Mobile image** (aarch64/PinePhone, Mobile NixOS) | `os/mobile.nix`, `.#mobile-image`, `os/telephony.nix`, `crates/postern-telephony` | image built, hosted, signed — **not yet boot-tested on any platform (QEMU or hw)**; "least-proven download" | Matches, but this is the **thinnest ice**: hosted+signed download of a never-booted image. Honestly labelled; verify labels persist everywhere it appears. |
| **postmarketOS community edition** (3 apks) | `pmos-overlay/`, `pmos-overlay/publish-apk-repo.sh`, `functions/dl` | `postern-wallet` + `postern-apps` + `postern` meta, signed, on a live aarch64 apk repo; **never device-booted** | Matches. `postern` meta only resolves on a booted pmOS. |
| **Postern Seal** (attestation / TEE) | `os/attested.nix`, `os/ATTESTATION.md`, `os/seal-gate.nix`, `crates/postern-seal-companion` | dm-verity+UKI+measured boot → `os_roothash` into `getattestation`/`verify()`; SEV-SNP/TDX/TPM providers; **"hosting a signed image is not attestation"** stated | Core `verify()` tested on host; **no real TEE host wired** (SEV-SNP quote never fetched on real hw). Site does not over-claim. |
| **Postern Browser** | `os/browser.nix` | hardened Firefox (resistFingerprinting, HTTPS-only, uBlock) inside desktop profile | Nix module; not independently proven. |

## 2. Enterprise (A2) — license spine, Consiglio, Ezekiel 1, Gramota

| System | Repo location | Site claim | Reality delta |
|---|---|---|---|
| **License spine / master-license generator** | `enterprise/licensing/` (TS lib, `dist/`, `keys/`), `functions/license/master.js` | **generator is LIVE** at `/license/master` — unlimited users, offline-verified, no telemetry | The one enterprise thing labelled `B_LIVE`. Verify the endpoint actually serves. |
| **Revocation (CRL) endpoint** | `enterprise/licensing/` (crl.js), `functions/license/` | `B_MERGED` — "merged but not yet deployed", in-memory reference store, keyed by token-signature hash, **not server-signed** | Honestly under-claimed. Not a live endpoint. |
| **DUNS / D&B KYC** | `enterprise/licensing/`, `apps/gramota-kyc/`, `functions/gramota/kyc.js` | **documented TODO** — DUNS is **format-checked only** (9 digits), not verified against D&B | Correctly labelled as not-done. |
| **Consiglio** (enterprise admin console, wallet-as-login) | `enterprise/cloud/services/console/` (Node), `crates/postern-consiglio-auth` (Rust verifier), `apps/postern-enterprise/` | `B_PROTO` — "real hybrid-PQ (Falcon‖ML-DSA) verifier"; dual-control/SoD/Chinese-Wall **"declared but not yet runtime-enforced"** on products page | **NOTE:** `enterprise/cloud/services/console/README.md` says dual-control + Brewer–Nash SoD are now **ENFORCED** in `console-auth.mjs`. Site (products.html card) says "not yet runtime-enforced." **Potential stale claim in EITHER direction — A2 must reconcile.** |
| **Ezekiel 1 — Personal** (parental controls) | `apps/ezekiel1/`, `crates/ezekiel1`, `crates/postern-policy` | `B_PROTO` offline console; free for personal use | Matches. |
| **Ezekiel 1 — Business** (governance engine: Bell-LaPadula, Brewer-Nash, tenants) | `apps/ezekiel1/`, `crates/ezekiel1`, `crates/postern-trail` (audit) | `B_PROTO` fail-closed userland; "not legal advice" | Matches. Userland-not-kernel caveat stated. |
| **Gramota** (enterprise onboarding + OCR KYC) | `apps/gramota/`, `apps/gramota-kyc/`, `functions/gramota/` | `B_PROTO` — DUNS attestation + on-device OCR KYC to lift 3-device→unlimited master | Matches. LGPD/GDPR-aware, unaudited. |
| **Enterprise features layer** (SSO, audit export, fleet defaults) | `enterprise/features/` | `B_DESIGN`/`B_PROTO` — "with two exceptions … designs and reference prototypes, not shipping" | Matches. Only generator + SDK clients live. |
| **Bloch Shield** (BYOD DLP + container) | `enterprise/shield/dlp/`, `enterprise/shield/container/`, `.../seal-wasm/` | referenced in enterprise editions block, `B_DESIGN` | Matches. Enterprise-only, corporate-scope-only rail. |
| **Org internal messenger** ("Bloch" comms) | `enterprise/comms/app/`, `enterprise/comms/compliance/` | referenced under enterprise editions; rides Postern Messenger E2EE | `B_PROTO`/`B_DESIGN`. Refuses to run without license. |

## 3. Cloud / Chiostro (A3)

| System | Repo location | Site claim | Reality delta |
|---|---|---|---|
| **Chiostro** (confidential-VM profile) | `os/cloud.nix`, `enterprise/cloud/image/` | attestation path "now has code" — feature-gated SEV-SNP report-fetch + AMD-root verify + fail-closed TDX parser — **"all still unbuilt and unbooted"** | Code exists, never built/booted. Honestly labelled `B_NOTSHIP`. |
| **Managed-node service / control plane** | `enterprise/cloud/control-plane/`, `enterprise/cloud/services/` | "promises, does no cryptography"; **"a promise, not a proof"**; hosting less private than self-host; DPA required | Orchestration logic + interfaces only; **no real infra provisioned by the code** (README confirms). |
| **Cloud posture demo endpoint** | `enterprise/cloud/services/console/http/`, deployed on Fly | **hosted reference-prototype LIVE** at `postern-cloud-demo.fly.dev/v1/posture` — "hosts no private key", staging, unaudited | Live endpoint claim → **A3 must confirm it still resolves** (external Fly dep). |

## 4. Apps / SDK / comms (A4)

| System | Repo location | Site claim | Reality delta |
|---|---|---|---|
| **Postern SDK** | `crates/postern-sdk` (+ `src`, `wasm`) | single UniFFI `setup_scaffolding!` surface, exactly-one-scaffolding CI-checked; exposes **real Argon2id KDF Rust-side**; app shells import `postern_sdk` | Built + test-verified. **But HTML app demos (e.g. Chiave) still use a PBKDF2 stand-in** — stated. |
| **Shared crates** (Core, Quarantine, Tor, Telephony, Trail, Policy) | `crates/postern-core`, `-quarantine`, `-tor`, `-telephony`, `-trail`, `-policy` | all "built + test-verified; all unaudited"; one canonical XChaCha20-Poly1305 + Argon2id seal | Matches — these are the verified foundation. |
| **Vault / wallet crates** | `crates/postern-vault`, `crates/postern-keys`, `crates/postern-messenger`, `crates/postern-courier`, `crates/postern-panic`, `crates/postern-hygiene`, `yagabona` | seal, keys, messenger (Matrix+vodozemac/Megolm), etc. | Built cores; unaudited. |
| **Phone-as-signer** (mobile↔desktop) | `mobile/signer`, `mobile/signer-app`, `integration/signer-protocol`, `integration/pairing`, `crates/postern-consiglio-auth` | **v1 reference impl (real interop)** — QR+spoken-code pairing over PQ-hybrid channel, replay-proof, monotonic revoke; **v2 shape forward-declared, not built; ends not unified on one wire** | Matches. "Reference of the shape, not a shipped feature." Byte-identity golden re-pin pending. |
| **HTML reference apps** (Sotto, Vedetta, Tolmach, Chiave, Sarto, Postern Store, Izbushka, Ezekiel 1, Yagabona explainer) | `apps/sotto`, `apps/vedetta`, `apps/tolmach`, `apps/postern-login` (Chiave), `apps/postern-onboard` (Sarto), `apps/postern-store`, `apps/izbushka`, `apps/ezekiel1` | all `B_PROTO`+`B_UNAUD`, self-contained HTML, BYO-Claude-key, honest privacy panels; "none claims 100% private" | Matches. BYOK + browser-speech-to-Google exception + Vedetta market-data leaks all disclosed. |
| **Tolmach subscription tier** | `apps/tolmach-subscription/` | **planned, not enabled today**; would proxy prompts (less-private), clearly labelled when it ships | Correctly future-tense. |
| **Comms / messenger** | `crates/postern-messenger`, `crates/postern-courier`, `crates/postern-telephony`, `enterprise/comms/` | Matrix client on matrix-rust-sdk + vodozemac/Megolm; classical-E2EE, metadata limits stated | Core referenced; full federation/Bridges tab is design (`POSTERN-MESSAGING-INTEROP.md`). |

## 5. Bridge apps (the folklore tier — dual-persona / Android reach)

| System | Repo location | Site claim | Reality delta |
|---|---|---|---|
| **Porog** (Android managed-profile container, "the door") | `apps/porog-crossprofile/`, `apps/porog-tor-glue/`, `android-bridge/`, `android-common/`, `android-container/` | `B_POROG` — **real StrongBox key-attestation skeleton** in the app shell; **self-enrolled-DPC / managed-profile isolation + Tor-only egress remain design/spec (unstarted in code)**; key-attested device ≠ measured-boot workspace; not shipping; proposed name | Matches. One narrow piece coded, defining feature is spec. |
| **NoporIS** (dual-persona bridge, "the crossing") | `apps/noporis-gate/`, `apps/noporis-switcher/`, `apps/noporis-bridge-glue/`, `apps/noporis-signer-glue/`, `apps/noporis-tor-glue/` | `B_DESIGN` — concept scaffold, not shipping; sells "separation, not privacy" on the Google side; no GMS redistribution, no Play-Integrity circumvention; proposed name | Matches. Reuses Porog plumbing. |
| **Sloboda** (Android userland escape hatch, "the outsiders' quarter") | `apps/sloboda/`, `apps/sloboda-gate/`, `os/sloboda-compat.nix` | `B_DESIGN` — **"in development — architecture + scaffolds only, not shipping"**; Waydroid-based LXC; **never Postern-Seal-covered; Play-Integrity STRONG fails by design; keep real secrets out**; proposed name | Matches. Honestly the tier where data leaves the sealed base. |

## 6. Cross-cutting / support

| System | Repo location | Notes |
|---|---|---|
| Site + downloads | `bp-wt-site/site/build.js`, `public/`, `functions/dl` | Cloudflare Pages `posternlabs`; R2 download host `pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev` |
| Explorer / Blochscan | `explorer/`, `bp-wt-site/explorer/` | protocol-layer product; deployed |
| Onboarding (Sarto) web app | `apps/postern-onboard/index.html` | openable today; demo video is a real walkthrough |
| Consent contract | `apps/consent-contract/CONTRACT.md` | policy artifact |

---

## 7. Prioritization rubric

Each gap is scored on three axes, 1–3, and the **product** drives the priority
band. The framework is tuned to Postern's actual risk surface: the company's
single greatest asset is that **its honesty is verifiable**, so honesty-exposure
dominates.

### Axes

**A. User-visible claim risk (CVR)** — does the public site (posternlabs.com,
downloads, videos) lead a visitor to believe this works?
- 3 = site presents it as **live / hosted / built / done** (a badge like
  `B_LIVE`, `B_ISO_*`, `B_IMG_MOBILE`, `B_APK_REPO`, `B_MERGED`), or a download
  button / reachable URL exists.
- 2 = site presents it as **reference prototype** the visitor can open/try.
- 1 = site presents it as **design/spec/roadmap** (clearly future).

**H. Honesty exposure (HX)** — if a skeptic tested this today, how badly would
reality diverge from the words? This is the reputational blast radius.
- 3 = **claim materially overstates reality** (says done/enforced/live but isn't;
  or a security-adjacent word — "attested", "verified", "enforced" — that a test
  would falsify). A P0 trigger on its own.
- 2 = claim is technically hedged but a casual reader would over-infer; label
  drift between repo README and site.
- 1 = claim and reality already match; nothing to fix but the feature itself.

**E. Effort to close (inverse weight)** — how much work to make claim==reality
(either build the thing, or correct the words).
- 3 = small (edit copy, wire an existing verifier, deploy a merged endpoint).
- 2 = medium (finish a coded-but-unbuilt path, first hardware boot).
- 1 = large (new subsystem, external audit, real TEE host, federation).

### Scoring → band

Priority is **led by CVR × HX** (the honesty risk), with E as the tie-breaker
that says *how cheaply* to close it:

| Band | Trigger | Meaning |
|---|---|---|
| **P0** | HX = 3 **AND** CVR ≥ 2 | Site claims it works / is live / is enforced and it isn't. **Honesty risk — fix the words or ship the thing NOW.** Cheap-to-fix P0s (E=3, i.e. correct copy) go first. |
| **P1** | (HX = 3 AND CVR = 1) **OR** (HX = 2 AND CVR = 3) | Either a real over-claim buried in future-framing, or a "live/built" thing a visitor will actually test that only partly delivers. First-hardware-boot class lives here. |
| **P2** | HX = 2 AND CVR = 2, or HX = 1 AND CVR = 3 | Prototype-labelled gaps a visitor can poke; honest today but the obvious next build. |
| **P3** | HX = 1, CVR ≤ 2 | Nice-to-have. Correctly labelled design/spec; pure feature backlog. |

**Rule of thumb:** *the site is the spec.* A P0 is never "we lack feature X" — it
is "we **say** X in a way today's repo can't back." The fastest P0 fix is often a
copy edit, not a build. Every gap also inherits the blanket `unaud` truth: **no
gap is "closed" in a security sense until the external audit lands** — that audit
is itself the standing P0 the whole site already discloses.

### Worked examples (from this inventory)

- **Consiglio SoD "declared but not yet runtime-enforced" (site) vs "ENFORCED"
  (console README):** CVR 2, HX 3 (label contradiction touching a governance
  claim), E 3 (reconcile + edit) → **P0 (copy/reconcile).**
- **Mobile image "built + signed" download of a never-booted image:** CVR 3, HX 2
  (hedged but a download button invites "does it boot?"), E 2 → **P1.**
- **Cloud posture demo `postern-cloud-demo.fly.dev/v1/posture` (live URL):** CVR
  3, HX 3 **if the endpoint is down**, else HX 1. E 3 → **P0 iff unreachable**,
  else P3. (A3 must probe.)
- **Porog DPC isolation (design-only, clearly labelled):** CVR 1, HX 1, E 1 →
  **P3.**
- **First hardware boot of the x86_64 ISOs:** CVR 3 (download + "boots on QEMU"),
  HX 1 (site explicitly says hardware pending), E 2 → **P1** (it's the headline
  proof-point, but not an over-claim).
