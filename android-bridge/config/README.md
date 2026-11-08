<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# `android-bridge/config/` — NoporIS disclosure + posture config

**DESIGN ONLY, not yet staffed. Reference-prototype, UNAUDITED. Certifies
nothing. Not legal advice.**

NoporIS is the guarded **bridge** between two personas — a clean side and a
second (business or Google-Play) side — on **one stock-Android handset**, so the
user doesn't carry a second phone. This directory holds only the **honest
disclosure copy** and the **posture config** for that bridge. It mirrors the
suite's existing less-private disclosures: `site/products.html` (BYOK / Chiostro
"sells convenience, not privacy"), `apps/sloboda` (VANILLA/GApps "less
private", default-safe bridges), and the consent gate's fixed
`TIER = "non-attestable"`.

## The fixed posture (never softened)

- **The Google-Play persona is the LESS-PRIVATE side, by construction.** NoporIS
  sells **separation + convenience, not privacy** on that side. A persona
  running GMS phones home to Google; NoporIS cannot change that.
- **NoporIS is an app on stock Android — never "Postern OS", never Porog, never
  a "Seal".** Its isolation is Android's own work-profile mechanism, configured
  by an unprivileged app, only as strong as the shared kernel.
- **Root / an unlocked or compromised host defeats it.** Device identity is
  shared across personas. GMS phones home. Play Integrity STRONG fails by design.
- microG / GApps / vanilla are **user-selectable options with honest trade-offs
  (compatibility vs contained), defaulting to Google-free** — not promises.
- Attestation badges are shown **only where true** (never, on stock Android); the
  Google persona is badged **"less private"**, never a padlock it hasn't earned.

## Files

| File | What it is |
|---|---|
| `noporis.conf.sample` | Posture config (POSIX-sh `KEY=VALUE`, `NIS_` prefix). Tier fixed non-attestable; mechanism; the microG/GApps/vanilla clean-persona choice (default VANILLA); Google persona off by default; deny-by-default cross-persona bridges; strict badge mode. |
| `disclosure.md` | Canonical disclosure copy: honesty header, top-of-page strip, Google-side panel + honest ledger + ceiling, clean-persona limits, "what we won't claim", default-off bridges, microG/de-Googled options. |
| `badges.json` | Machine-readable badge rules: attestation only where proven true; Google persona always "less private"; forbidden badges; fail-closed on unknown. |

## Scope / ownership

Owned here: **`android-bridge/config/` only** — disclosure + posture config.

Not touched by this component:

- `android-bridge/persona/` (N-persona / N-play) — the persona runtime.
- `COMPLIANCE.md` (N-compliance) — the GDPR/LGPD controller/processor map. The
  design-level posture is summarized inside `disclosure.md` only as disclosure,
  and every such point is a `LEGAL: DPO/counsel` flag, not a determination.

## Rails (must hold on any NoporIS surface built from this config)

- Never over-claims privacy on the Google side — "**separation + convenience,
  not privacy**" is the fixed headline.
- Labels the Google persona **less-private / non-attestable**; states the ceiling
  (device-wide identity, device-global attestation, shared kernel/baseband).
- States that **root / an unlocked or compromised host defeats it**.
- Never called **"Postern OS"**; NoporIS is an app on stock Android.
- Google-vs-Google-free is a **config input defaulting to Google-free**;
  microG/de-Googled are **options with honest trade-offs, not promises**.
- Cross-persona bridges **default OFF**; NoporIS never opens one itself.
- Carries the standing disclaimers: **UNAUDITED / reference-prototype**, **coin
  worthless / not a security**, **ownerless base ⟂ owned products**,
  **personal-free**, **not legal advice**, **DPO/counsel is the authority**.
- **Respects Google/Android licenses**: Google, Android, Google Play, and Play
  Integrity are trademarks of Google LLC, used **nominatively** to describe
  interoperation; NoporIS **neither circumvents nor modifies** Google's services.
- **Trademark:** NoporIS/Nopor needs formal clearance before the mark is
  committed (shares the existing "NOPOR" filing root) — sanity note, not
  clearance.

*Design/reference-prototype only. UNAUDITED. No security claim. SPDX:
MIT OR Apache-2.0.*
