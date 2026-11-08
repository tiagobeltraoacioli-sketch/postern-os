<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# NoporIS — Google / Android License & Policy Compliance

**Status: DESIGN CONCEPT. NOT YET STAFFED. UNAUDITED / reference-prototype.**
Nothing described here has been built, provisioned, or run on a device. This
document is the *compliance surface* for a **future** NoporIS bridge app: an
auditable statement of how NoporIS intends to respect Google's and the AOSP
project's licenses, policies, and trademarks.

> **⚠ THIS IS NOT LEGAL ADVICE.** Every determination below is provisional and
> must be reviewed and signed off by **qualified counsel** (IP / trademark +
> platform-policy + a DPO/Encarregado for data-protection points) **before any
> release**. Where a point is a legal judgement, it is tagged `LEGAL:`. Counsel
> review is a **hard release gate**, not a formality — see the CHECKLIST in §11.

> **Prime honesty label (kept verbatim from the Master Plan, binds this doc):**
> NoporIS is a **separation-and-convenience** bridge on the **stock Android you
> already own** — two personas, one handset, no second phone. **The Google-Play
> persona is the LESS-private side, by construction: it phones home to Google.**
> NoporIS gives you *separation and convenience, not privacy on that side.* A
> **rooted host defeats the separation entirely.** This is an app on stock
> Android — it is **NEVER "Postern OS."** *(Design only; unaudited; no security
> claim until an audit gate. The coin is worthless by design and is not a
> security.)*

---

## 0. Scope and what NoporIS actually is (the fact that drives every answer)

NoporIS is an **unprivileged application that runs on stock, unmodified,
user-supplied Android.** It configures Android's *own* dual-persona mechanism
(a `DevicePolicyManager` managed profile, and/or Android 15+ Private Space — the
mechanism is still open, see the Master Plan §2) to let a clean persona and a
Google-Play-enabled persona coexist on one handset.

The two facts that decide every compliance answer:

1. **NoporIS does not build, fork, patch, redistribute, or ship an operating
   system.** It does not ship AOSP, does not ship a ROM, does not ship Google
   Mobile Services (GMS), does not ship the Play Store. **The user brings their
   own device, their own OS, and their own Google account.**
2. **NoporIS is a self-enrolled Device Policy Controller (DPC) / persona
   orchestrator.** Its compiled artifacts are Kotlin/Android app code plus a few
   permissively-licensed AndroidX/Kotlin libraries. It compiles *against* the
   Android SDK; it does not incorporate AOSP source into its binary.

Because NoporIS ships **no OS image and no Google binaries**, the bulk of the
classic "Android compliance" surface (CDD/CTS conformance for a device build,
the GMS distribution agreement, "Android Compatible" branding rights) **does not
apply to NoporIS** — those obligations live with whoever built the user's device
and OS. NoporIS's compliance surface is the narrower set covered here:
attribution for the permissive components it *does* use, honest platform-policy
posture, and correct **nominative** use of Google's trademarks.

---

## 1. AOSP — Apache License 2.0

**What NoporIS uses:** the Android SDK / platform APIs (`DevicePolicyManager`,
`DeviceAdminReceiver`, managed-profile provisioning intents, Private Space
surfaces where applicable). These are the AOSP framework interfaces NoporIS
compiles against. AOSP is licensed under **Apache License, Version 2.0** (a
handful of AOSP components carry other permissive licenses; NoporIS's use is
confined to the Apache-2.0 framework API surface).

**How NoporIS respects Apache-2.0:**

- **Attribution + license text.** A copy of the Apache-2.0 license ships at
  [`licenses/Apache-2.0.txt`](./licenses/Apache-2.0.txt). The
  [`NOTICE`](./NOTICE) file attributes AOSP and the AndroidX/Kotlin libraries
  and travels with any distribution (§4 of the Apache license — the NOTICE
  obligation). Attribution appears in-app under an **"Open-source licenses"**
  screen in any shipped build.
- **No misnaming / no false origin (Apache-2.0 §6, trademarks; §4(b) "You must
  cause any modified files to carry prominent notices").** NoporIS does **not**
  call itself "Android", does not imply it *is* Android or an Android
  distribution, and does not present itself as endorsed by Google or the AOSP
  project. It is "an app **on** Android", never "Android" and never "**Postern
  OS**".
- **No patent/attribution stripping.** NoporIS does not remove or alter
  copyright, patent, trademark, or attribution notices from any Apache-2.0
  material it references or vendors (§4(c),(d)).
- **We do not modify AOSP.** NoporIS consumes AOSP as a compile-time SDK; it
  ships no modified AOSP source. If that ever changes (e.g. vendoring a patched
  AOSP helper), the modified files must carry prominent change notices per §4(b)
  and this document + `NOTICE` must be updated **before** that build ships.

`LEGAL:` confirm the exact license inventory of any AOSP-derived source that
ends up vendored (some AOSP subtrees are BSD/MIT/others) before release.

---

## 2. Google Play Developer Program Policies

Two distinct things must not be conflated:

- **The Play persona** — a persona in which the *user's own* Play Store and
  *user's own* GMS run. Apps installed there are governed by Google's agreements
  with **the user and those apps' developers**. NoporIS is not a party to that.
- **The NoporIS bridge app itself** — if it were ever listed on Google Play, it
  is subject to the **Google Play Developer Program Policies** and the
  **Developer Distribution Agreement**.

**Honest reality (drives distribution, see §8):** NoporIS is a **self-enrolled
DPC** that provisions a persona *for the device owner themselves*. Google Play
policy permits device-management provisioning primarily in an **EMM
(enterprise-managed) context** — an organization managing devices — and
**restricts or disallows apps that self-enroll a user's own device as its own
device/profile owner** outside that EMM model. **NoporIS therefore does not plan
to rely on Google Play as its primary distribution channel for the bridge app**
(this mirrors Porog, which ships F-Droid + signed direct APK). See §8.

**How NoporIS respects Play policy regardless of channel:**

- **No deceptive behaviour, no hidden functionality, honest store listing.** The
  "separation ≠ privacy / the Play persona is the less-private side" label is
  front-and-centre, not buried — the same honesty the store's Deceptive Behaviour
  and User Data policies demand.
- **Device & Network Abuse policy — no integrity circumvention.** NoporIS does
  **not** interfere with, evade, or spoof SafetyNet / Play Integrity, does not
  hide root, does not tamper with GMS. See §5.
- **User Data / permissions.** The personal edition ships **no server, no
  account, no telemetry, no analytics** (Master Plan / Trust-Boundary §5). Any
  runtime permission NoporIS requests (device-admin, provisioning) is disclosed
  with its purpose; there is no undisclosed data collection to declare.
- **Subscriptions / payments.** Personal use is **free**. There is no in-app
  purchase, no coin sale, no payment flow in the bridge app. (The coin is
  worthless by design and is **not a security**; it buys no software.)

`LEGAL:` a platform-policy review of the *then-current* Play policies is required
before any Play listing attempt — Google's policies change frequently and
override anything written here.

---

## 3. GMS is NOT redistributed — the user brings their own

**Google Mobile Services (Play Services, Play Store, and the Google apps) are
proprietary and are only distributable under Google's Mobile Application
Distribution Agreement (MADA) to licensed OEMs.** NoporIS is not an OEM and holds
no such agreement, and it does not need one, because:

- **NoporIS ships zero Google binaries.** No GMS APKs, no Play Store, no Google
  blobs are bundled, downloaded by, or embedded in NoporIS.
- **GMS is already on the user's device** (on a stock Google-certified phone,
  Play Services runs in the primary user regardless of NoporIS — Trust-Boundary
  §0/§1c). The Play persona simply *reuses the GMS the user already has and is
  already licensed to use* by their device manufacturer and their acceptance of
  Google's terms.
- **The user contracts with Google directly.** Using the Play persona is the
  user sending their data to Google under Google's terms (Trust-Boundary §5).
  NoporIS neither instructs, sees, nor stores that data.

**Google-free path is the default.** The clean persona's Google posture is a
**user-visible config input defaulting to Google-free** (`VANILLA` / no Google),
with **microG** and **full GApps** offered as *options with honest trade-offs,
never silently GApps* (Trust-Boundary §4). NoporIS never plants Google binaries a
user did not ask for. If a user chooses full GApps, **the user obtains GMS
themselves** (their device / their flashing / their choice) — NoporIS documents
the trade-off; it does not distribute the blobs.

---

## 4. Android & Google Play trademarks — nominative use only

"Android", the Android robot, "Google Play", the Google Play triangle, and
"Google" are **trademarks of Google LLC**. NoporIS uses these marks **only
nominatively** — to truthfully identify Google's products that NoporIS
interoperates with — under Google's brand and Android brand guidelines.

**Rules NoporIS follows:**

- **Reference, never brand.** NoporIS may say *"works with the Google Play
  persona"*, *"the Android work-profile mechanism"*, *"reach Google Play apps"*.
  NoporIS **never** names itself, a persona, or a feature *"Android …"*,
  *"Google …"*, or *"Play …"* as if it were a Google product or sub-brand.
- **No logos as our own.** NoporIS does not use the Android robot, the Google
  Play icon, or Google wordmark logos in its own logo, icon, or branding, and
  does not restyle/recolour them. Where a Google mark must appear (e.g. to label
  the Play persona in-UI), it is used per Google's guidelines, unaltered, and
  clearly referring to Google's product — not to NoporIS.
- **No implied endorsement.** No "endorsed by / certified by / partnered with
  Google" wording. NoporIS is independent and says so.
- **"Android" is an adjective, not our noun.** Follow Google's rule: *"Android"*
  qualifies a real Google offering ("an Android app", "stock Android"); it is
  never used as the name of the NoporIS product or a NoporIS component.
- **NoporIS's own mark still needs clearance.** Independently of Google's marks,
  the **"NoporIS / Nopor Internet Systems"** mark shares the *Nopor* root with an
  existing bare "NOPOR" filing and needs **formal trademark clearance
  (USPTO/EUIPO/INPI + counsel) before the mark is committed** (Master Plan R4).
  `LEGAL:` this is a high-priority clearance item, tracked in the CHECKLIST.

`LEGAL:` review any in-UI use of a Google mark against the *current* Android
Brand Guidelines and Google Play badge/branding guidelines before release.

---

## 5. NO SafetyNet / Play Integrity circumvention — honest attestation labeling

This is a bright line. **NoporIS does not, and must never, circumvent, evade,
spoof, or defeat SafetyNet Attestation or the Play Integrity API.** Doing so
would (a) violate Google Play's Device & Network Abuse policy, and (b) be
dishonest — the entire NoporIS thesis is honest labeling, not integrity theatre.

**What NoporIS does instead — honest attestation labeling:**

- **It states the truth: nothing here is attestable.** Play Integrity / hardware
  key attestation measure the **whole device** (bootloader lock, verified boot,
  TEE), **not a persona** (Trust-Boundary §1c/§2b). NoporIS labels the Play
  persona **less-private / non-attestable** and says so *on the persona itself*.
- **It never claims to pass, and never tries to fake, a STRONG verdict.** If an
  app inside the Play persona checks Play Integrity, that check reads the real
  device state and returns whatever the real device honestly is. NoporIS does not
  intervene. Banking / Wallet / DRM apps that gate on STRONG **will refuse** on a
  non-standard device, and NoporIS documents that they *should* — it does not
  help them be deceived.
- **No root hiding, no Magisk/Zygisk-style masking, no property spoofing** is
  part of NoporIS. A rooted / unlocked / kernel-compromised host **defeats the
  separation**, and NoporIS says that plainly rather than papering over it.
- **Attestation seams stay `NoOp`.** The trusted-persona attestation plumbing
  reuses Porog's `AttestationGateway` seam and remains a no-op stub until a live
  StrongBox chain is verified on real hardware (Master Plan §3.1, §7.2). No
  "attestable / hardened" headline ships on the Play persona.

CI enforcement already exists in the suite: `scripts/check-trust-labels.sh`
forbids attestation-implying words on the non-attestable tier. NoporIS's surfaces
must pass that same check.

---

## 6. EMM / device-admin policy for the self-enrolled DPC

NoporIS acts as a **profile owner (DPC)** via Android's `DevicePolicyManager`,
using the **self-enrolled managed-profile** pattern (Shelter/Island-style) — the
user provisions a profile on *their own* device, with no enterprise EMM server
and no remote admin. Honest posture:

- **Self-enrollment, not enterprise MDM.** There is no NoporIS EMM console, no
  remote wipe by a third party, no organization silently administering a
  stranger's phone. The device owner is the admin. The personal edition **never
  surveils the personal side** (Trust-Boundary §5).
- **Device-admin permissions are least-privilege and disclosed.** NoporIS
  requests only the device-admin / provisioning capabilities needed to create and
  lifecycle the persona (provision, name, enable, persona-scoped wipe). It does
  **not** request full device-owner control of the user's whole phone for the
  personal use case.
- **Business/BYOD use → the employer is the controller of corporate data.** If an
  organization deploys NoporIS to run a managed business persona, the company is
  the data controller for that persona's corporate data; the employee's personal
  persona **stays out of the org's reach** (posture, not content). This is
  **adherence by design, not certification** — `LEGAL:` DPO/counsel gate
  (Trust-Boundary §5).
- **The AOSP device-admin deprecation reality.** Google has progressively
  deprecated legacy `DeviceAdmin` policies in favour of the managed-profile /
  work-profile DPC model. NoporIS targets the *supported* managed-profile DPC
  APIs, gates provisioning at runtime via `isProvisioningAllowed(...)`, and never
  assumes the platform supports a managed profile. `LEGAL:` track ongoing Android
  DPC-API and Play EMM-policy changes each release — this surface moves.

---

## 7. Obligation-to-section map (auditor quick-reference)

| Obligation / surface | Governing party | How NoporIS meets it | Section |
|---|---|---|---|
| Apache-2.0 attribution + NOTICE | AOSP / AndroidX / Kotlin | `NOTICE` + `licenses/` travel with the build; in-app licenses screen | §1, [`NOTICE`](./NOTICE) |
| No AOSP misnaming / false origin | Apache-2.0 §6, §4(b) | "app on Android", never "Android" / "Postern OS" | §1, §4 |
| GMS not redistributed | Google MADA | Ships zero Google binaries; user brings own GMS | §3 |
| Google/Play trademarks | Google LLC | Nominative use only; no logo appropriation | §4 |
| No integrity circumvention | Play Device & Network Abuse | Honest non-attestable labeling; seams stay `NoOp` | §5 |
| DPC / device-admin posture | Android DPC APIs + Play EMM policy | Self-enrolled, least-privilege, disclosed | §6 |
| Distribution channel | Google Play policy | F-Droid + signed direct APK (off-Play) | §8 |
| Data protection | GDPR / LGPD | Design-level map; DPO/counsel is the authority | §9 |
| NoporIS's own mark | trademark law | Formal clearance before commit | §4, §11.B |

## 8. Distribution reality — F-Droid / direct APK (Play blocks non-EMM self-enrollment)

State this plainly, because it is a compliance *consequence*, not a marketing
choice:

- **Google Play is a poor / disallowed fit for a self-enrolling DPC.** Play
  policy tolerates device-management provisioning chiefly under the **EMM
  (enterprise-managed)** model; an app that enrolls a user's *own* device as its
  own profile/device owner outside that model is restricted. Porog already goes
  **F-Droid + signed direct APK** for exactly this reason (Master Plan §1, R7).
- **NoporIS's bridge app plans the same:** primary distribution via **F-Droid**
  and a **signed direct APK**, not the Play Store. This is honest and
  policy-respecting: NoporIS does not smuggle a self-enrollment DPC past Play
  review by hiding what it is.
- **Do not conflate the two Plays.** The *Play persona* uses Google Play
  **natively and legitimately** (the user's own Play Store, into their own
  profile). The *NoporIS bridge app* is distributed off-Play. Both statements are
  true simultaneously; keep them separate in all copy.
- **F-Droid inclusion requires FOSS-clean builds.** NoporIS ships MIT OR
  Apache-2.0 and depends only on permissive libraries (§4 of NOTICE), which keeps
  the F-Droid path open. `LEGAL:`/build: verify no proprietary or GPL/AGPL
  dependency creeps in before an F-Droid submission.

---

## 9. GDPR / LGPD posture (design-level, not a determination)

Summarised from Trust-Boundary §5 — every point is a `LEGAL: DPO/Encarregado +
counsel` flag, not a conclusion:

- **Play persona → Google is an independent controller.** The user contracts
  with Google directly; NoporIS is **not a processor** for Google's collection.
- **NoporIS personal app → not a controller/processor of user content** (no
  server, no account, no telemetry). It configures Android's own mechanism
  locally.
- **Business persona → the employer is the controller** of corporate data;
  personal side stays out of reach. Adherence by design, **legal review is a hard
  gate**.
- **If Postern ever hosts anything → Postern becomes a processor and a DPA is
  required.** Default is to host nothing.
- **What we won't claim:** that installing NoporIS makes anyone compliant; that
  the Google persona's data flows are Postern's to control; that separation
  equals data protection.

---

## 10. What NoporIS will NOT claim (compliance edition)

- That NoporIS is "Android", an Android distribution, or **"Postern OS"**.
- That it is endorsed by, certified by, or partnered with Google or the AOSP
  project.
- That the Play persona is private, attestable, or passes Play Integrity STRONG.
- That NoporIS distributes, sublicenses, or is licensed to distribute GMS.
- That anything here is audited, certified, or legally cleared — until the
  CHECKLIST gates in §11 are signed off by counsel.

---

## 11. COMPLIANCE CHECKLIST — a human/legal reviewer runs this before ANY release

Any **NO / UNRESOLVED** is a **release blocker**. This checklist must be
completed and signed by a named reviewer (and, where marked `LEGAL:`, by
counsel) before a NoporIS build is tagged, published, or submitted anywhere.

### A. Attribution & licenses (Apache-2.0)
- [ ] `NOTICE` present in the distribution and current; lists AOSP + every
      third-party component actually shipped, with correct license IDs.
- [ ] `licenses/` contains the full text of every license referenced by `NOTICE`
      (Apache-2.0 at minimum).
- [ ] An in-app **"Open-source licenses"** screen renders the same attributions
      in any build with a UI.
- [ ] No copyright/attribution/patent/trademark notice stripped from any
      third-party material. `LEGAL:` license inventory of any vendored source
      confirmed (watch for non-Apache AOSP subtrees).
- [ ] Every new source file carries SPDX `MIT OR Apache-2.0`.

### B. Trademarks
- [ ] No component, persona, or feature is named "Android…", "Google…", or
      "Play…" as if it were a Google sub-brand. `grep` clean.
- [ ] No Android robot / Google Play / Google logo used as NoporIS branding or
      restyled. `LEGAL:` any in-UI Google mark checked against current Google /
      Android brand guidelines.
- [ ] No "endorsed/certified/partnered with Google" wording anywhere.
- [ ] **NoporIS / Nopor** mark: formal trademark clearance obtained
      (USPTO/EUIPO/INPI + counsel) **before the mark is committed**. `LEGAL:`

### C. GMS
- [ ] Build ships **zero** Google binaries (no GMS/Play APKs, no Google blobs).
      Verified against the built artifact, not just the source.
- [ ] Clean-persona Google posture defaults to **Google-free**; microG / GApps
      are explicit user-visible options, never silent GApps.
- [ ] No code path where NoporIS itself downloads or installs GMS.

### D. Integrity / attestation honesty
- [ ] No SafetyNet / Play Integrity circumvention, root hiding, or property
      spoofing anywhere in the codebase. `grep`/review clean.
- [ ] Play persona labeled **less-private / non-attestable** *on the persona
      itself*; no "attestable/hardened/private" headline on it.
- [ ] Attestation seams remain `NoOp` (no live STRONG claim without an
      on-hardware chain). Passes `scripts/check-trust-labels.sh`.
- [ ] "A rooted / compromised host defeats the separation" stated on every
      surface that makes a separation claim.

### E. Platform policy & distribution
- [ ] Bridge app distribution plan is **F-Droid + signed direct APK**, not a
      Play self-enrollment DPC listing. If a Play listing is attempted anyway,
      `LEGAL:` current Play Developer Program Policy review completed.
- [ ] Store/listing/README copy is non-deceptive; the "separation ≠ privacy"
      label is prominent, not buried.
- [ ] No undisclosed data collection; personal edition has no server/account/
      telemetry. Any runtime permission disclosed with purpose.
- [ ] No in-app purchase / coin sale / payment flow; personal use is free.
- [ ] F-Droid path: no proprietary or GPL/AGPL dependency present.

### F. EMM / device-admin
- [ ] DPC requests least-privilege device-admin/provisioning capabilities, each
      disclosed.
- [ ] No third-party remote administration of a personal user's device; the user
      is the admin. Personal side never surveilled.
- [ ] Provisioning gated at runtime via `isProvisioningAllowed(...)`; no assumed
      platform support. Current Android DPC-API / Play EMM-policy deltas reviewed.

### G. Data protection & standing rails
- [ ] GDPR/LGPD points reviewed by DPO/Encarregado + counsel; no "makes you
      compliant" claim. `LEGAL:`
- [ ] Standing rails hold: **UNAUDITED / reference-prototype**; **coin worthless
      / not a security**; **ownerless base ⟂ owned products**; **personal-free**;
      **never "Postern OS"**; **not legal advice / counsel is the authority**.
- [ ] This document + `NOTICE` re-reviewed against the *then-current* Google
      policies and the actual shipped dependency set (see `licenses/README.md`).

---

*Grounding: `Postern-NoporIS-Trust-Boundary.md`, `Postern-NoporIS-Master-Plan.md`,
`android-container/profile/app/build.gradle.kts` (actual AndroidX/Kotlin deps),
repo-root `LICENSE-MIT` / `LICENSE-APACHE`. There is no repo-level
`ACKNOWLEDGMENTS.md` today — NoporIS's third-party attribution lives in
[`NOTICE`](./NOTICE) and [`licenses/`](./licenses/). DESIGN concept — not yet
staffed. Not legal advice.*
