<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Google / AOSP / Play — License & Policy Compliance Architecture

**Scope:** the legal/compliance surface that keeps three Postern products shippable
against Google, AOSP, and Play terms: **Porog** (self-enrolled managed-profile
workspace on stock Android), **NoporIS** (dual-persona bridge to a Google-Play
persona), and **Waydroid** (full AOSP userland in an LXC container).

**Status:** UNAUDITED reference-prototype design. This is engineering compliance
architecture, **not legal advice**; a lawyer must clear anything before ship,
especially any Play Store listing and any trademark-bearing marketing copy.

This document is the companion and extension of the license-respect section in
[`ACKNOWLEDGMENTS.md`](../../ACKNOWLEDGMENTS.md). Where the two overlap,
ACKNOWLEDGMENTS is the public homage; this is the operational rulebook.

---

## 0. The four honesty rails (apply to all three products, no exceptions)

1. **No GMS redistribution.** Postern never ships, mirrors, bundles, or hosts
   Google Mobile Services, Google Play Services, GApps packages, or any Google
   proprietary binary. The user brings their own Google install; Waydroid pulls
   images at init from upstream, never from us.
2. **No Play Integrity / SafetyNet circumvention.** We integrate the Integrity
   API **honestly**: we request verdicts, present them truthfully, and disclose
   a weak/failed verdict. We never spoof, patch, hook, replay, or hide a verdict,
   and we never help a user do so.
3. **Nominative trademark use only.** "Works with Google Play", "runs on stock
   Android" — factual interoperability statements. Never Google/Android logos,
   never "endorsed by / partnered with / certified by Google", never a product
   name that reads as a Google or Android sub-brand. Never "Postern OS."
4. **microG-vs-GApps is a user config input, default VANILLA.** The Google-free
   vanilla AOSP base is the shipped default. microG (Apache-2.0, a separate
   community project) and GApps (user-supplied, not ours) are opt-in config the
   user selects and installs themselves. Nothing is hardcoded to Google.

---

## 1. Per-product compliance boundary table

| Concern | **Porog** (managed profile on stock Android) | **NoporIS** (dual-persona bridge) | **Waydroid** (AOSP-in-LXC) |
|---|---|---|---|
| **Where AOSP comes from** | Not shipped — runs *as an app* on the user's stock Android. No AOSP redistribution. | Same — app on stock Android. | **Redistribution surface**: Waydroid runs an AOSP system image. Postern does **not** host it; the image is pulled at `waydroid init` from the upstream (Waydroid/LineageOS) repos. If Postern ever mirrors an image, Apache-2.0 + NOTICE obligations attach (see §3). |
| **Where GMS/GApps comes from** | The user's own phone already has Google Play. Porog's managed profile may or may not have Play provisioned by the user's org/self — **we install nothing Google**. | The user brings their own Google account + Play install into the Google-Play persona. Postern provisions the *profile plumbing*, not the Google binaries. | **VANILLA by default (no Google at all).** If the user opts into GApps, *they* supply and flash the package; if microG, it is installed from microG's own repo. Postern ships neither. |
| **Play Integrity / attestation available?** | **Yes, honestly, bounded.** Hardware Key Attestation (StrongBox/TEE, Google-CA-rooted) is the primary signal; Play Integrity is an *optional* secondary. Strong verdict often unavailable to the security-conscious users who most want this (unlocked bootloader / custom ROM → MEETS_BASIC or fail). We report the tier actually obtained. | **Yes, on the Google side only.** The Google-Play persona can obtain Integrity verdicts because it *is* a real Google-provisioned persona. The personal side gets none and says so. | **Structurally weak / usually fails.** A vanilla or microG Waydroid container is not a Google-certified device; Play Integrity will return a failing / basic verdict. This is **disclosed as expected behavior, never spoofed.** |
| **Ships on Play Store?** | **Maybe** (the only candidate). If it does, the self-enrolled-DPC policy surface in §4 governs it. | Unlikely on Play; if ever, same DPC surface applies. More likely sideloaded / F-Droid-style. | **No.** Distributed as an OS-level component, not a Play app. |
| **Trademark exposure** | "Porog" is a *proposed name pending trademark clearance*. Uses "Android"/"Google Play" nominatively only. | "NoporIS" *proposed name pending clearance*. Same nominative rule. | "Waydroid" is an **upstream project's** name — nominative reference only ("built on Waydroid"), never rebranded as a Postern mark, never "Postern OS". |
| **Root / integrity honesty** | A rooted host defeats it — disclosed. | A rooted host defeats the separation — disclosed. | LXC container; not a security boundary against a compromised host — disclosed. |

---

## 2. The hard GMS/GApps line — stated per product

The single most important compliance boundary. **Postern is never in the
Google-binary distribution path.**

- **Porog:** the device is *already the user's Google phone*. Porog adds a managed
  profile via a self-enrolled DPC (the Shelter/Island pattern). It installs Postern
  apps into that profile. It does **not** download, bundle, or provision Google
  Play Services. If Play is present in the profile, it arrived through the user's
  own/org provisioning, not through us.
- **NoporIS:** NoporIS builds the *bridge* (deny-by-default, per-capability
  crossing) between the personal side and a Google-Play-enabled persona. The
  Google persona is created and signed into **by the user with the user's own
  Google account**. NoporIS ships the plumbing; the user brings Google.
- **Waydroid:** the default base is **vanilla AOSP — zero Google**. `waydroid init`
  fetches the system image from **upstream** infrastructure (not Postern). GApps
  is a **user-supplied flash** the user performs; microG is installed from the
  **microG community repo**. Postern's role is to expose a *config choice*
  (`vanilla | microg | gapps`) that **defaults to `vanilla`** and to document each
  path — never to host or auto-pull a Google binary.

**Do / Don't (GMS):**

- DO: link to upstream/official sources and let the user's tooling fetch.
- DO: keep `vanilla` the default and make the Google paths explicit opt-in.
- DON'T: mirror, cache, bundle, or CDN-host any Google/GApps package.
- DON'T: script an automatic Google-binary download as part of Postern install.
- DON'T: imply the Google-enabled path is more private — it is **less** private.

---

## 3. AOSP / microG attribution & NOTICE mechanics

**When it attaches:** Apache-2.0 §4 attribution + NOTICE obligations trigger on
**redistribution of, or derivative works from,** covered code. Porog and NoporIS
run *on* AOSP without redistributing it, so they carry the nominative statement
but not a per-image NOTICE. **Waydroid** is the redistribution-adjacent case: if
Postern ever hosts or repackages an AOSP-derived image or modifies AOSP sources,
full mechanics apply.

**Mechanics to implement:**

1. **`NOTICE` preservation.** Any AOSP-derived artifact Postern distributes must
   carry the upstream `NOTICE` file **unmodified**, plus a Postern NOTICE stanza
   for our additions. Never strip upstream copyright headers.
2. **`LICENSE` inclusion.** Ship the Apache-2.0 text with any derivative.
3. **Modification statements.** Apache-2.0 §4(b): mark files we change with a
   "modified by Postern" notice; do not remove existing notices.
4. **microG (Apache-2.0).** Same rules if we ever redistribute microG (we default
   to *not* — user installs from microG's repo). Even when only *referencing*
   microG, frame it as a **separate community project under its own license and
   its own trust chain** — a step the user takes into a third-party ecosystem, not
   a Postern feature. Do not imply microG is Google-sanctioned (it is a
   re-implementation; that is the point).
5. **No trademark grant assumed.** Apache-2.0 §6 grants **no** trademark rights.
   The "Android", "Google Play", "Waydroid", "microG" names are used under
   nominative fair use, not under the license.
6. **Attribution registry.** Maintain a machine-readable third-party manifest
   (`ACKNOWLEDGMENTS.md` + a per-product dependency list) enumerating each
   component, its license, and its source URL. Waydroid images, if hosted, get an
   entry with the upstream NOTICE checked in alongside.

---

## 4. Play Store Developer Program Policy surface (only if Porog/NoporIS ship on Play)

Relevant only for a Play-distributed build. A self-enrolled DPC app on Play is a
narrow, scrutinized category.

**What a self-enrolled DPC may do (current policy posture):**

- Create and own a **managed profile** it provisions on the user's device
  (`DevicePolicyManager` profile-owner path) — the documented BYOD flow.
- Apply policy **only to the profile it owns**, with the user's on-device consent.
- Isolate storage/apps within that profile.

**What it may NOT do (and what Play scrutinizes):**

- **Play requires prominent disclosure + consent** for the device-admin /
  profile-owner privilege. The provisioning consent screen must be truthful and
  not bury the privilege.
- **No device-owner** takeover (Porog's design already REJECTS device owner — good).
- **Permissions policy:** any high-risk permission must map to the disclosed
  core function; no undisclosed background data collection. A privacy-labelled
  Data Safety form is mandatory and must match actual behavior.
- **Managed-configuration / EMM impersonation:** don't present as a certified
  Android Enterprise EMM unless enrolled in that program. Porog is a *consumer
  self-enrolled* DPC, not an Android Management API partner — say so.
- **No circumvention signals:** an app that advertises defeating Play Integrity or
  hiding root would be removed. Porog's honest-attestation stance is the compliant
  posture; keep marketing free of "bypass"/"spoof" language.
- **Metadata/impersonation:** the listing must not use Google/Android branding in
  a way that implies official status (ties to §5).

**Practical stance:** treat Play distribution as *optional and lawyer-gated*. The
non-Play path (sideload / F-Droid-style, like Shelter/Island) is the safer default
and carries none of the Data-Safety/DPC-listing risk. Ship there first.

---

## 5. Honest Play-Integrity / attestation presentation rules (UI-binding)

These are **requirements on the UI**, not suggestions. The verdict must be shown as
it is, never dressed up.

1. **Show the tier actually obtained.** If the device yields `MEETS_BASIC` or a
   failing verdict, show exactly that. Never upgrade the displayed tier.
2. **Name the two distinct signals separately.** Hardware **Key Attestation**
   (StrongBox/TEE, Google-CA-rooted, measures key + boot state + app identity) and
   **Play Integrity** (Google-server verdict) are different claims. Don't collapse
   them into one "verified" badge.
3. **State the bound.** Key Attestation proves *the key is hardware-backed on a
   device whose verified-boot/patch state is as reported* — **not** that the
   workspace is measured-boot. The UI must not imply "measured boot of the
   workspace" (it isn't) or "anonymous" (it isn't).
4. **Disclose failure as expected, not as a defect to route around.** For Waydroid,
   a failing Integrity verdict is the *correct, honest* result of a non-certified
   container. Copy: "This is not a Google-certified device; Play Integrity reports
   a basic/failing verdict. That is expected and we do not hide it."
5. **No spoof affordance anywhere.** No setting, toggle, hidden flag, or
   documentation that changes what a verdict *reports* versus what is *true*. The
   only honest lever is improving the actual device state (locked bootloader,
   current patch), never faking the signal.
6. **Trust-chain disclosure.** State plainly that attestation trusts Google's CA
   and Play Integrity trusts Google's server — a real dependency, disclosed, not
   hidden, and a reason a privacy-maximal user may *choose* the vanilla no-Google
   path and accept no attestation.
7. **Per-persona truth (NoporIS).** The Google persona can attest; the personal
   side cannot. Label each side's real capability; never let the Google side's
   verdict imply anything about the private side.

---

## 6. Trademark / nominative-use guidelines (feeds the site copy)

Nominative fair use test we hold to: (a) use only as much of the mark as needed to
identify the thing, (b) don't imply sponsorship/endorsement, (c) use the word, not
the logo/trade dress.

**Allowed (nominative):**

- "Runs on stock **Android**." / "Bridges to a **Google Play**-enabled persona."
- "Built on **Waydroid**." / "Optionally uses **microG** (a separate community
  project)."
- "Works with Google Play" as a factual interoperability statement.

**Not allowed:**

- Google, Android, Play, Waydroid, or microG **logos** or trade dress.
- "Endorsed by / partnered with / certified by / official … Google/Android."
- A product name that reads as a Google/Android sub-brand, or **"Postern OS"**
  (already prohibited repo-wide) or "Postern Android".
- Implying the Google-enabled path is private (it is the **less-private** side).
- Claiming any Integrity/attestation status the device did not actually return.

**Postern's own names:** "Porog" and "NoporIS" are **proposed names pending
trademark clearance** — the site already labels them so; keep that label until
clearance. "Waydroid" and "microG" are **other projects' names** — reference only.

Site alignment (`/Users/tiagoacioli/dev/bp-wt-site/site/build.js`): the current
Porog/NoporIS cards and the acknowledgments block already follow these rules
(no-GMS-redistribution, no-circumvention, nominative-only, pending-clearance).
Any new Waydroid copy must add: vanilla-default, no-GApps-hosting, user-brings-
Google, and "built on Waydroid / optional microG" nominative framing.

---

## 7. Pre-ship compliance checklist (devs must satisfy every applicable line)

**Universal (all three):**

- [ ] No Google/GApps/GMS binary is bundled, mirrored, cached, or auto-pulled by Postern.
- [ ] No code path spoofs, hooks, replays, or hides a Play Integrity / SafetyNet verdict.
- [ ] All Google/Android/Waydroid/microG references are nominative (word, not logo; no endorsement implied).
- [ ] `ACKNOWLEDGMENTS.md` + per-product third-party manifest list every component, license, and source URL.
- [ ] UNAUDITED / reference-prototype disclaimer present.
- [ ] "Postern OS" naming does not appear for any of these products.

**Porog / NoporIS (managed-profile):**

- [ ] DPC uses profile-owner (BYOD) path only; **never** device-owner.
- [ ] Provisioning consent screen truthfully discloses the device-admin/profile-owner privilege.
- [ ] Attestation UI shows the *actual* tier; Key Attestation and Play Integrity shown as distinct signals with their stated bounds.
- [ ] "Hardened not anonymous", "key-attested not measured-boot", "rooted host defeats it" disclosures present.
- [ ] NoporIS: Google side labelled the *less-private* side; per-persona attestation truth shown.
- [ ] Google binaries come from the user's own device/account, not from Postern.

**If shipping on Play Store (Porog/NoporIS):**

- [ ] Legal review of the listing completed.
- [ ] Data Safety form filled and matches actual behavior; high-risk permissions map to disclosed core function.
- [ ] No "bypass/spoof/hide" language in listing or app.
- [ ] Not presented as a certified Android Enterprise EMM (it is a consumer self-enrolled DPC).

**Waydroid:**

- [ ] Default base is **vanilla** (zero Google); `microg`/`gapps` are explicit opt-in config.
- [ ] AOSP system image is pulled at `waydroid init` from **upstream**, not hosted by Postern.
- [ ] If any AOSP/microG-derived artifact is ever hosted by Postern: upstream `NOTICE` + `LICENSE` preserved, modification statements added, dependency-manifest entry created.
- [ ] GApps path documents that the **user** supplies/flashes the package; microG path points to the **microG community repo**.
- [ ] Failing Play Integrity verdict disclosed as expected behavior for a non-certified container.
- [ ] LXC "not a boundary against a compromised host" disclosure present.

---

## 8. Top legal risks (ranked)

1. **Accidental GMS redistribution** — a convenience "download GApps for you"
   feature or a cached Waydroid+GApps image would cross Google's redistribution
   line. *Mitigation:* keep Postern out of the Google-binary path entirely;
   vanilla default; upstream/user-sourced only.
2. **Play Integrity misrepresentation** — any UI that overstates a verdict, or any
   "improve your score" feature that actually spoofs, is both a policy violation
   and a dishonesty-rail breach. *Mitigation:* §5 UI rules, no spoof affordance.
3. **Play Store DPC-listing rejection/removal** — self-enrolled DPCs are heavily
   scrutinized; a weak consent screen or mismatched Data Safety form gets pulled.
   *Mitigation:* lawyer-gate Play; prefer sideload/F-Droid first.
4. **Trademark overreach in marketing** — a Google/Android logo, an "official/
   certified" claim, or a sub-brand-looking name invites a trademark complaint.
   *Mitigation:* §6 nominative rules; keep "pending clearance" labels.
5. **Attribution/NOTICE lapse on a hosted Waydroid image** — stripping an upstream
   NOTICE or failing modification statements breaches Apache-2.0. *Mitigation:*
   §3 mechanics; don't host images unless necessary, and if hosted, preserve
   NOTICE/LICENSE verbatim.
6. **microG framed as a Google/Postern feature** — implying microG is
   Google-sanctioned or a native Postern capability. *Mitigation:* frame as a
   separate community project under its own license and trust chain, user opt-in.
