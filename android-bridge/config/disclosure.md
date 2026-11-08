<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# NoporIS — disclosure copy (canonical, for the bridge surface)

**Status: DESIGN ONLY, not yet staffed. Reference-prototype thinking, UNAUDITED,
certifies nothing.** This file is the load-bearing disclosure copy any NoporIS
surface must carry. It mirrors the honesty the suite already ships: the Waydroid
gateway's honesty header (`apps/sloboda/README.md`), the consent gate's
fixed `TIER = "non-attestable"` and deny-by-default bridges
(`apps/sloboda-gate/index.html`), and the site's "what leaves your
machine" / "sells convenience, not privacy" disclosures (`site/products.html`).

> ## ⚠ HONESTY HEADER — read before trusting anything here
>
> - **The Google-Play persona is the LESS-PRIVATE side, by construction.** A
>   persona that runs Google Play Services (GMS) phones home to Google. NoporIS
>   sells **separation + convenience, not privacy on that side.** It cannot make
>   a Google-Android persona private.
> - **NoporIS is an app on stock Android. It is NEVER "Postern OS".** It does not
>   own the kernel, bootloader, baseband, or TEE. Its isolation is **Android's
>   own** work-profile mechanism, configured by an unprivileged app — only as
>   strong as the kernel underneath it. It is not Porog and not a "Seal".
> - **A rooted / unlocked / kernel-compromised host defeats the separation.**
> - **UNAUDITED reference-prototype when built.** Every on-device claim is an
>   unknown until proven on real hardware.
> - **Play Integrity STRONG fails** on both personas by design; banking, Wallet,
>   and DRM refuse. This is not a bug we can fix.
> - The coin is worthless by design and is **not a security**. The ownerless
>   base ⟂ the owned products; NoporIS is an *owned product*. Personal use is
>   free. **This is not legal advice.**

---

## Top-of-page strip (the headline — non-negotiable, no code path hides it)

Rendered as a permanent `role="note"` strip, mirroring the site's `beta-ribbon`
and the enterprise `legal-strip` that "no code path hides — that is the design":

> **The Google-Play persona is the less-private side of your device, by
> construction.** NoporIS lets a clean persona and a Google-Play persona coexist
> on one phone. It sells **separation and convenience — not privacy on the
> Google side.** A persona running Google Play Services phones home to Google,
> and NoporIS cannot change that. This is an app on stock Android; it is not an
> operating system and not a "Seal". A rooted or compromised phone defeats the
> separation. Reference-prototype, UNAUDITED. The coin is worthless and is not a
> security. Personal use is free. This is not legal advice.

## Google-side panel (mirror "how it works / what leaves your machine")

> **What the Google side means, plainly.** This persona is a real Google-Android
> system and it is the **less-private, non-attestable** side. It talks to Google
> and to its apps' own servers: your Google account, device and hardware
> identifiers, installed-app inventory, and — with permission — your location
> leave the device. If an app checks Play Integrity, that check reads your
> *whole device's* state. **NoporIS can't make a Google-Android persona private
> for you.** What NoporIS gives you is a *separate box* for this persona's data
> and accounts, off by default from your clean side. If a thing would be unsafe
> for Google to see, don't do it in this persona.

### The honest ledger — what leaves the device on the Google side

`◮` = leaves the device · `●` = stays local (mirrors the suite's per-app ledger).

| ◮/● | Data | Destination | Notes |
|---|---|---|---|
| ◮ | Google account + auth tokens | Google | the anchor Google joins everything to |
| ◮ | Device identifiers (GSF/registration ID, build fingerprint, model, GAID) | Google | Play Services is privileged; registration binds to the physical device |
| ◮ | Hardware identifiers (IMEI, SIM ICCID, phone number, serial) | Google / carrier | **device-wide; telephony is shared across profiles** |
| ◮ | App inventory | Google (Play Store + Play Protect) | scanned and reported for that persona |
| ◮ | Location | Google | if permitted; the location master toggle is device-wide |
| ◮ | Play Integrity / attestation verdict | Google + app server | reads **device-global** state, not the persona |
| ◮ | Network metadata (public IP, carrier, cell, SNI) | Google, app servers, carrier | same IP + cell as the clean persona unless separately routed |
| ◮ | Push (FCM), Maps, sign-in, ad/measurement traffic | Google | ordinary GMS chatter, continuous |
| ● | Clean persona's app data | stays local, separate `/data` | separated by Android's UID/SELinux sandbox — see limits below |

### The honest ceiling — what CANNOT be contained on stock Android

Never soften these:

1. **Device-wide hardware identity is shared.** One physical device, one
   SIM/telephony stack. GMS can read it. NoporIS cannot give the Google persona
   a separate hardware identity. **Google can always tell the two personas are
   one phone.**
2. **Attestation and verified-boot state are device-global.** Play Integrity /
   key attestation measure the *device*, not a persona — they attest the phone,
   not the workspace. It is **not** an attestation of NoporIS.
3. **The kernel, baseband, and TEE are shared.** NoporIS is an app above the
   framework; it cannot sandbox GMS below it, cannot inspect the baseband.
4. **Network egress correlates the personas** unless deliberately routed apart —
   and even then device identity correlates.
5. **GMS is already on the device** in the primary user; a second partitioned
   persona does not evict it.

> **The one-line ceiling (say it exactly):** *NoporIS separates two personas' app
> data and accounts on one phone. It does not, and on stock Android cannot, hide
> the device from Google, give the Google persona a separate hardware identity,
> or make anything running Play Services private.*

## The clean persona's isolation — real, but stated without inflation

- Separate Linux UID range; separate encrypted `/data` per profile; separate app
  instances and accounts; cross-profile controls that default closed.
- **The isolation is Android's, not Postern's.** NoporIS is an unprivileged app
  configuring AOSP's `DevicePolicyManager`. The fence is real, **but it is only
  as strong as the kernel — a kernel-level flaw crosses it. We call this
  sandboxed. We do not call it secure, private, or attested.**
- Shared kernel + baseband + TEE; side channels; device-wide identifiers
  correlate the personas. **NOT covered by any "Seal".** Root defeats NoporIS.

## What we won't claim (mirror `apps/postern-enterprise` `.pv-note`)

> **What we won't claim:** that the Google persona is private; that NoporIS hides
> your device from Google or gives it a separate hardware identity; that two
> personas on one phone are two phones; that a stock-Android app can contain Play
> Services the way a sealed base or a TEE would; or that any of this passes Play
> Integrity's STRONG verdict. It doesn't, by design.

## Default-off bridges (mirror the consent gate)

> Sharing between the two personas (clipboard, contacts, files) starts **OFF**.
> Each bridge is a hole you open on purpose — turn it off when you're done.
> NoporIS never opens a bridge you didn't open.

## microG / de-Googled alternatives — options, not promises

The Google-vs-Google-free choice is a **config input defaulting to Google-free**
(`NIS_CLEAN_PERSONA_SYSTEM_TYPE=VANILLA`), never hardcoded to Google. Presented
as options with real trade-offs — **compatibility vs contained** — not promises.
None unlock integrity-gated apps.

| Option | What you get | Honest trade-off |
|---|---|---|
| **Full GMS (GApps)** | Maximum app compatibility, push, Wallet-adjacent flows | **Least private.** Plants Google's blobs in the persona. Still won't pass STRONG — little gain. |
| **microG** | Most apps work; FCM push, maps, sign-in relayed | **Recommended when you want compatibility with less Google.** microG still contacts Google's servers for what it relays and can't reliably pass Play Integrity — no rescue for banking or Wallet. |
| **Vanilla (no Google, no microG)** | Maximum containment for the clean persona | **Most private, least compatible.** Many mainstream apps degrade or won't run. |

> *You can't have a private container and Google's services at once. microG is
> the closest to private; GApps is the closest to compatible. Neither unlocks
> integrity-gated apps.*

**The de-Googled-OS / container path is a different, stronger option — out of
NoporIS's stock-Android scope.** *If you want the Google side actually contained
rather than merely separated, that requires a container or a de-Googled system,
not a stock-Android app. NoporIS doesn't promise that; the container path does,
with its own trade-offs.* That path is the `apps/sloboda` escape hatch —
a **different product**, and it is **never "Postern OS"** in NoporIS's own copy.

---

*Design/reference-prototype only. UNAUDITED. No security claim. NoporIS/Nopor
needs formal trademark clearance before the mark is committed. Google, Android,
Google Play, and Play Integrity are trademarks of Google LLC, used nominatively
to describe interoperation; NoporIS neither circumvents nor modifies Google's
services and respects their licenses. Not legal advice — LGPD/GDPR/CCPA points
are decisions for a qualified DPO / Encarregado and legal counsel.*
