<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Postern Labs -->

# NoporIS — Google-Play persona flavor (Dev N-play)

The **Google-Play flavor (flavor B)** of NoporIS's *one* second persona. It lets the
**user** install and sign into **Google Play** *inside* the isolated managed profile,
with **GMS quarantined behind its own FBE boundary** so it never sits next to the
wallet — and with **no wallet / signing keys on this side** at all.

> **This is a SCAFFOLD. DESIGN ONLY · UNAUDITED · reference-prototype.** Nothing here
> was built with the Android SDK/NDK; nothing has ever been provisioned on a device.
> The one exception — the policy invariants in `policy/` — is real, node-testable code
> (`node --test`), the canonical contract the Kotlin consumes. `built ≠ booted`.

## The honest one-liner (keep verbatim)

The **Google-Play persona is the less-private side, by construction** — GMS phones
home. NoporIS sells **separation + convenience, not privacy** on this side, and cannot
make a Google-Android persona private. It is an app on **stock Android — NEVER "Postern
OS."** The profile's FBE + SELinux boundary is real, but a **rooted / kernel-compromised
host defeats it.** Attestation attests the **phone, not the persona**. BLCH is worthless
and is not a security; personal use is free; ownerless base ⟂ owned products.

## What's here

```
persona/play/
├── policy/
│   ├── play-flavor-policy.mjs        REAL, node-testable: enableSystemApp allowlist +
│   │                                 deny-by-default gate + no-wallet-keys invariant +
│   │                                 pinned honesty rails (less-private, no-redistribute,
│   │                                 no-circumvent, no-wallet-keys). The canonical contract.
│   └── test-play-flavor-policy.mjs   11 tests, `node --test` — pass in-repo.
└── app/src/main/java/labs/postern/persona/play/
    ├── PlayFlavorPolicy.kt           flavor-B post-provisioning policy: enableSystemApp(Play+GMS)
    │                                 inside the profile only, deny-by-default, wallet-exclusion
    │                                 assert first. Sibling of Porog's clean-flavor LockdownPolicy.
    ├── GmsPackages.kt                Google package IDs (NOMINATIVE use) + the "we do not
    │                                 redistribute GMS; enableSystemApp un-hides, never installs" note.
    ├── WalletKeyExclusion.kt         the "NO wallet keys on the Google side" invariant, as a
    │                                 fail-closed guard (ByConstruction honest label).
    └── PlayIntegrityDisclosure.kt    honest Play Integrity: optional signal, never a gate,
                                      never spoofed/bypassed; classify a real verdict, disclose it.
```

## Scope & seams (who owns what)

**Owned here (Dev N-play):** the Google-Play flavor's `enableSystemApp` path, the GMS
package allowlist + deny-by-default gate, the no-wallet-keys invariant, and honest Play
Integrity disclosure.

**Consumed as clearly-labeled seams — NOT edited/created here:**
- **The shared self-enrolled DPC + `ACTION_PROVISION_MANAGED_PROFILE` flow + the honest
  `EnforcementMode` labels** → `android-common` (consumed, never edited). NoporIS does
  **not** fork a second DPC; this flavor is applied by that shared profile-owner receiver
  when the user picked Google-Play at provisioning. The clean flavor is Porog's
  `LockdownPolicy` in `android-container`.
- **The persona switcher, bridge panel, and Google-account sign-in / onboarding hand-off**
  → `android-bridge/persona/` root (Dev N-persona). Cross-persona bridges are theirs and
  are **deny-by-default**; this flavor opens none.
- **The in-product "less-private" labeling copy / strings** → `android-bridge/config/`
  (Dev N-labeling). `PlayIntegrityDisclosure.DISCLOSURE` carries only the Integrity-specific
  clause for that module to reuse; the full card copy is theirs.

## How each HARD LICENSING rule is honored

| Rule | How this module honors it |
|---|---|
| **Postern does NOT redistribute Google Play / GMS** | `enableSystemApp` **un-hides** stock system apps the certified device already ships — installs no APK, ships no Google binary. On a de-Googled device the call is a **no-op** (`PlayFlavorPolicy.enableSystemApp` swallows it), so we plant nothing. The user brings their own Google account and installs from Play. Stated in `GmsPackages.kt` and `play-flavor-policy.mjs` (`REDISTRIBUTES_GMS` pinned false). |
| **Honor Play Developer Program + device-admin/EMM policy** | This is a **self-enrolled non-EMM DPC**; we do **not** silently add accounts or push apps (documented honest limit in `PlayFlavorPolicy.apply`). Distribution is F-Droid + signed direct APK, not Play (Play restricts non-EMM self-enrollment) — inherited from the Porog scaffold. It is *Play-in-a-profile*, **not Managed Google Play**. |
| **"Android" / "Google Play" in NOMINATIVE use only** | Every Google name appears to say *what we interoperate with* (`GmsPackages.kt` header). Never a NoporIS product name, never implying endorsement. The product is NoporIS/Porog; Google is the third party we name to describe interop. |
| **Do NOT circumvent SafetyNet / Play Integrity** | `PlayIntegrityDisclosure`: no spoofing, no verdict tampering, no bootloader-lock faking. Integrity is an **optional** signal, **never a gate** (`isPersonaAllowed` always true), and the code **discloses** honestly that STRONG reflects the whole device and fails on rooted/de-Googled. `CIRCUMVENTS_INTEGRITY` pinned false. |
| **microG / GApps / vanilla are USER choices, not bundled** | We bundle nothing. `enableSystemApp` only touches packages already on the device; if the user runs a de-Googled ROM (their choice), the flavor is a clean no-op. The Google-vs-Google-free choice is the user's, per the Trust-Boundary doc §4. |
| **NO wallet keys on this side** | `WalletKeyExclusion` force-denies wallet/signer packages and StrongBox key aliases; `PlayFlavorPolicy.apply` **asserts clean before enabling anything Google**. `HOSTS_WALLET_KEYS` pinned false. The wallet lives only in the clean flavor. |

## Build / test

The policy invariants are runnable in this repo:

```bash
node --test android-bridge/persona/play/policy/test-play-flavor-policy.mjs   # 11 pass
```

The Kotlin is a **scaffold** — building it needs the Android SDK/NDK (not in this repo's
CI) and the shared DPC module from `android-common`. It reads idiomatically; that is all.

## Rails (non-negotiable)

- UNAUDITED / reference-prototype; no security claims; `self-checked ≠ audited`.
- **Less-private by construction; separation + convenience, not privacy** — the fixed
  headline for the Google side.
- A **rooted / kernel-compromised host defeats** the boundary — say so.
- **NEVER "Postern OS."** NoporIS is an app on stock Android.
- Attestation attests the **phone, not the persona.**
- BLCH is worthless and is **not a security**; personal use is free; ownerless base ⟂
  owned products; **not legal advice** (GDPR/LGPD is a DPO/counsel decision).
- SPDX `MIT OR Apache-2.0` on every file. Do **not** git commit (the integrator does).
