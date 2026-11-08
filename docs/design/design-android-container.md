# Postern Container (Android) — technical design

**Role:** designer/architect. **Status:** design/spec only. **Goal:** a hardened,
key-attested privacy workspace on the *stock Android a person already owns* — no OS
replacement, no root. This document is deliberately honest about what such a thing
can and cannot prove, and contrasts it with the attestable Postern OS (Nix) which
*does* control the OS.

The existing in-repo spec (`docs/specs/POSTERN-CONTAINER.md`) already picks the right
mechanism (self-enrolled managed profile + StrongBox key attestation). This design
confirms that against the real Android APIs, corrects a couple of overclaims, adds the
component/build/distribution detail, and pins the honest label for the site.

---

## 1. The options, evaluated (real, not hand-waved)

| Option | What it is | Verdict for "phone you already own" |
|---|---|---|
| **AOSP managed profile (work profile) via `DevicePolicyManager`** | A second Android *user* profile with its own FBE keys and SELinux boundary, provisioned by a self-enrolled Device Policy Controller (DPC). This is exactly what **Shelter / Island / Insular / Haven** do — no root, no MDM server. | **RECOMMENDED.** Only mechanism that gives real cryptographic + process isolation on unmodified stock Android with no root. |
| **Island / Shelter-style user-profile isolation** | Not a different mechanism — these *are* self-enrolled managed-profile apps. They prove the pattern is viable in the wild and ship on F-Droid. | Reference implementations to study/borrow from (all FOSS). |
| **Samsung Knox / Secure Folder / Knox Workspace** | Samsung's hardware-anchored container. Strong, but the **Knox SDK is distributed only to EMM vendors**, there is **no public API for a third-party app to create or launch a Knox container**, and third-party containers require Samsung to activate SEAMS domains on-demand. | **REJECTED as the base.** Samsung-only, gated behind Samsung's enterprise program; can't be self-serve or cross-vendor. (Could be an *optional* future hardening on Samsung devices, not the foundation.) |
| **Waydroid** | Runs a *full Android* inside an **LXC container on a GNU/Linux host** (Wayland, binder/ashmem kernel modules). | **NOT APPLICABLE to stock Android.** It needs a Linux host we control — i.e. it belongs to the Postern OS / desktop story, not "the phone you already own." Naming it here only to rule it out. |
| **Fully managed device (device owner)** | One DPC owns the whole device. | **REJECTED.** Requires factory reset + provisioning during setup (or ADB), can't be self-enrolled post-hoc on a phone in use, and takes over the personal side. Wrong product for a low-friction entry container. |

**Conclusion:** the container is an **AOSP managed profile created by a lightweight
self-enrolled DPC** — the Shelter/Island approach, but carrying the Postern apps,
wallet, StrongBox-attested keys, and a Tor-only per-profile VPN.

---

## 2. Recommended architecture

```
┌───────────────────────── the phone (stock Android, unchanged) ─────────────────────────┐
│                                                                                          │
│   PERSONAL PROFILE (user 0)                 POSTERN CONTAINER  (managed profile, user N) │
│   their normal apps, normal networking      ┌─────────────────────────────────────────┐ │
│                                             │  Separate FBE storage (own key, own lock) │ │
│                                             │  Postern DPC = PROFILE OWNER              │ │
│                                             │    · setScreenCaptureDisabled            │ │
│                                             │    · setPermittedInputMethods (no rogue  │ │
│                                             │      keyboards)                          │ │
│                                             │    · setAlwaysOnVpnPackage(Orbot,        │ │
│                                             │      lockdown=true)  → Tor-only          │ │
│                                             │    · cross-profile intents OFF by default│ │
│                                             │                                          │ │
│                                             │  Postern app surface (see §4)            │ │
│                                             │  Wallet core = bloch-core (Rust/UniFFI)  │ │
│                                             │  StrongBox key wraps wallet material     │ │
│                                             │  Key Attestation → Postern Seal (mobile) │ │
│                                             └─────────────────────────────────────────┘ │
│                                                                                          │
│   ══════════════════ Android kernel + SELinux profile boundary ══════════════════       │
│   (isolation is exactly as strong as this boundary — see §3)                             │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

### Components

1. **Postern DPC** — a `DeviceAdminReceiver` + provisioning flow. User taps
   "Create Postern Container"; the app fires
   `Intent(DevicePolicyManager.ACTION_PROVISION_MANAGED_PROFILE)` with
   `EXTRA_PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME` = our receiver. Android creates the
   managed profile and makes our app **profile owner** of it. No root, no EMM server.
   (This is the documented DPC-first BYOD path; Shelter/Island use it verbatim.)

2. **Lockdown policy** (profile-owner scope only): screenshot disable, permitted-IME
   allowlist, per-profile always-on lockdown VPN, disabled cross-profile clipboard/
   contacts/notifications, block install from unknown sources inside the profile,
   and a **container-only wipe** (`wipeData` targets just the profile).

3. **Wallet core** — `bloch-core` (the lean crypto/address/tx extraction of the `bloch`
   crate) cross-compiled to `aarch64-linux-android`, exported to Kotlin via **UniFFI**.
   PQ signing material lives in app storage **wrapped by** a StrongBox key.

4. **Key + attestation** — a non-exportable, user-auth-gated **StrongBox** EC (P-256)
   key generated with an **attestation challenge** = the verifier/node nonce. The
   Keystore returns an X.509 chain that a verifier checks with the `mobile` backend of
   `bloch::attestation::verify` (Postern Seal, mobile form). Optional Play Integrity
   verdict layered on top.

5. **Networking** — Orbot's `VpnService` set as the profile's always-on lockdown VPN, so
   **container traffic is Tor-only and cannot leak** outside the tunnel; the personal
   profile keeps normal networking.

---

## 3. Security properties — REAL vs NOT (no overclaim)

### What is REAL on stock Android

- **Storage separation is real.** The managed profile has its own file-based-encryption
  keys, unlocked by a separate work-profile challenge. The personal profile (and its
  apps) cannot read container files. Enforced by the kernel + SELinux, not by our code.
- **Process/app isolation is real.** Container apps run as a separate Android user;
  clipboard/contacts/notification bridging is off unless the user opts in.
- **Hardware key protection is real.** A StrongBox (discrete secure element) or TEE key
  is non-exportable and use-authenticated; extracting it off-device is hard (StrongBox
  adds side-channel resistance over TEE).
- **Device attestation is real (and bounded).** Key Attestation emits a Google-CA-rooted
  chain that proves the key is hardware-backed **and** records **verified-boot state, OS
  patch level, and the attesting app's package name + signing certificate**
  (`AttestationApplicationId`). A verifier can reject unlocked-bootloader or stale-patch
  devices.
- **Container-only remote wipe is real** (profile-scoped `wipeData`).

### What is NOT real — the honest ceiling

- **No measured boot of the workspace.** This is the crux. Key Attestation measures the
  **device** (bootloader, OS image, patch level) and **identifies the app** (package +
  signing key) — it does **NOT** measure the Postern container's code or contents. There
  is no dm-verity roothash of "the workspace" and no way to prove the workspace payload
  ran unmodified logic. On stock Android you do not control the OS, so you cannot produce
  a measured-boot chain *for your own environment*. **Contrast the Postern OS (Nix):**
  `os/ATTESTATION.md` chains a reproducible flake → immutable erofs rootfs → **dm-verity
  roothash** → UKI measured boot → SEV-SNP/TDX launch measurement, so a verifier can pin
  `os_roothash` + `image_digest` and know the *exact audited image* is running. The
  container attests the *phone*; the OS attests *itself*. Do not blur these.

- **Isolation is only as strong as the Android kernel + SELinux.** A kernel/hypervisor
  compromise, a malicious vendor system image, or a rooted device crosses the profile
  boundary. The container cannot defend against an OS it does not own.

- **StrongBox is classical, not post-quantum.** It is P-256 hardware. It protects the PQ
  key **at rest** (wrapping) and attests the device — it does **not** hold the PQ key
  *in* hardware and cannot do PQ signing in the SE. Same honest limit as
  `mobile/README.md`.

- **Attestation trusts Google + the vendor.** Key Attestation chains to Google's
  attestation CA; Play Integrity chains to Google's server. That is a real, and for an
  ownerless-protocol ethos an *ironic*, third-party trust dependency. (Note: Google
  rotated the RKP root cert on 2026-02-01, mandatory by 2026-04-10 — verifiers must track
  the current roots.) The self-sovereign answer is Postern OS Mobile with its own
  measured boot, not the container.

- **Play Integrity's strong verdict is unavailable to the users who most want this.**
  `MEETS_STRONG_INTEGRITY` requires a **locked bootloader + certified OEM image**; it will
  **never** pass on rooted / unlocked / custom-ROM / pre-Android-8 devices. So Play
  Integrity can *gate* to stock locked devices but cannot be a hard requirement without
  excluding privacy-conscious custom-ROM users — treat it as an optional signal, not a
  gate.

- **Not every device qualifies for the best tier.** StrongBox needs a hardware SE; many
  older/cheaper phones only have a TEE (weaker guarantee) — the design must degrade
  gracefully and *report the tier it actually got* rather than claim StrongBox
  everywhere.

- **Nothing here is audited.** Design only. No security claim until an audit gate.

---

## 4. App surface — what runs inside the container

The container hosts the sensitive Postern apps (source folders under `apps/` and
`mobile/`); the personal profile keeps everything else. Realistic in-container set:

- **Postern Wallet** (`bloch-mobile` / `bloch-core` via UniFFI) — the anchor; keys wrapped
  by StrongBox. **In-container: yes.**
- **Sotto** (`apps/sotto`) — messenger. **In-container: yes** (comms are the point).
- **Vedetta** (`apps/vedetta`) — metadata scrub / sentinel. **In-container: yes.**
- **Postern Login** (`apps/postern-login`) — passkeys / auth. **In-container: yes**
  (passkey keys can also be Keystore/StrongBox-backed).
- **Tolmach** (`apps/tolmach`, `tolmach-subscription`) — voice/interpreter tools.
  **In-container: optional** (belongs inside if it touches sensitive audio).
- **Postern Store** (`apps/postern-store`) — app store / installer. **In-container: yes**,
  as the curated source for adding apps to the profile (unknown-sources is blocked, so the
  store is the install path).
- **Postern Onboard** (`apps/postern-onboard`) — the "Create Container" + provisioning UX;
  runs partly *outside* (to trigger provisioning) and hands off inside.
- **Postern Enterprise** (`apps/postern-enterprise`) — enterprise edition; a real EMM/DPC
  variant is a separate track (managed by an org's MDM), not the self-enrolled consumer
  container.

UI: Jetpack Compose. All app cores that are Rust reuse the same UniFFI bridge as the
wallet.

---

## 5. Attestation story (honestly achievable)

**Claim we CAN make and verify today:**
"This key is non-exportable hardware-backed (StrongBox/TEE) on a device whose verified-boot
state, OS patch level, and attesting-app identity are as reported, and the attestation is
fresh (verifier nonce echoed)."

Flow: verifier issues nonce → container generates/uses the StrongBox key with
`setAttestationChallenge(nonce)` → `getCertificateChain()` → verifier runs the `mobile`
backend of `bloch::attestation::verify` against Google's attestation roots, checking
verified-boot = `Verified`, acceptable patch level, expected package + signing cert, and
nonce freshness → optional Play Integrity verdict as an extra device-integrity signal.

**Claim we must NOT make:** that the *workspace* is measured/attested end-to-end. It is
not. That property is exclusive to Postern OS Mobile (measured boot + verity roothash).

---

## 6. Build & distribution

**Build:**
1. Extract lean **`bloch-core`** (crypto + address + tx types; drop rocksdb/libp2p so it
   cross-compiles for `aarch64-linux-android`) — prerequisite, per `mobile/README.md`.
2. UniFFI-export the wallet core → Kotlin bindings.
3. Android app = **DPC** (`DeviceAdminReceiver` + `ACTION_PROVISION_MANAGED_PROFILE` +
   lockdown policy) + StrongBox key/attestation plumbing + Orbot always-on VPN + Compose
   UIs, all inside the managed profile.
4. Wire Key-Attestation verification into the `mobile` attestation backend.
5. Reproducible APK build (the repo already has `postern-apk-build.fly.toml` /
   `assemble-public.sh`) so the published binary is verifiable.

**Distribution — realistic path:**
- **Primary: F-Droid + signed direct APK.** Apps that use `DevicePolicyManager` device-
  admin/DPC APIs for self-enrolled profiles are the Shelter/Island class — those ship on
  **F-Droid**, not Play. **Google Play's device-admin / DPC policy restricts non-EMM use**
  of these APIs, so a self-enrolling consumer container is a poor fit for Play and risks
  removal. Plan for F-Droid + direct APK as the real channel; reproducible builds make
  this trustworthy.
- **Play (optional, constrained):** only a *non-DPC* companion or the *enterprise* EMM
  variant realistically belongs on Play. Don't design the core container assuming Play
  distribution.

---

## 7. Honest label to keep on the site

> **Postern Container** — a hardened, isolated privacy workspace on the **stock Android you
> already own** (no OS replacement, no root). Sensitive apps, keys and comms live in a
> **cryptographically separated managed profile**; the wallet's keys are **hardware-backed
> and key-attested** (StrongBox/TEE). It is **key-attested, NOT a measured-boot OS** — it
> attests the *phone*, not the *workspace*, and its isolation is bounded by Android's own
> kernel/SELinux and by trust in Google's + the vendor's attestation. For end-to-end
> measured boot of an audited image, that's **Postern OS Mobile**. *(Design only; unaudited.)*

Keep the "container first, OS later" framing, and always pair "attestable" with the
qualifier "key-attested device, not measured-boot workspace."

---

## 8. What needs a real Android dev + on-device testing

- **Self-enrolled provisioning across OEMs/versions.** `ACTION_PROVISION_MANAGED_PROFILE`
  behaviour varies by vendor and Android version (and some OEMs/Knox devices reject or
  alter it); must be tested on real hardware, multiple vendors, Android 13–16.
- **StrongBox availability + graceful TEE fallback**, and correctly reporting which tier
  was obtained.
- **Key Attestation chain parsing/verification** against *current* Google roots (RKP root
  rotation 2026) in the `mobile` backend — real cert-chain and revocation handling.
- **Orbot always-on lockdown VPN** interaction with the profile (leak testing, kill-switch
  behaviour, Orbot version compatibility).
- **`bloch-core` cross-compile + UniFFI** ABI/threading correctness on `aarch64`.
- **Play Integrity integration** and the policy decision of whether/how to gate.
- **Reproducible APK pipeline** verification and F-Droid packaging.
- **Container-only wipe** correctness (no personal-profile data loss).
- **Play Store policy review** for any Play-distributed component (expect friction on DPC
  APIs).

---

## Sources

- Employ work profiles / managed profiles — Android Open Source Project: https://source.android.com/docs/devices/admin/managed-profiles
- Provision for device management (DPC-first, `ACTION_PROVISION_MANAGED_PROFILE`) — AOSP: https://source.android.com/docs/devices/admin/provision
- Build a Device Policy Controller — Android Developers: https://developer.android.com/work/dpc/build-dpc
- `DevicePolicyManager` API reference — Android Developers: https://developer.android.com/reference/android/app/admin/DevicePolicyManager
- Shelter (self-enrolled work profile, FOSS) — F-Droid: https://f-droid.org/packages/net.typeblog.shelter/ ; source: https://github.com/PeterCxy/Shelter
- Island (managed-profile isolation): https://island.oasisfeng.com/
- Hardware-backed Keystore — AOSP: https://source.android.com/docs/security/features/keystore
- Key and ID attestation (records verified-boot state, OS version/patch, app identity) — AOSP: https://source.android.com/docs/security/features/keystore/attestation
- Verify hardware-backed key pairs with key attestation — Android Developers: https://developer.android.com/privacy-and-security/security-key-attestation
- TEE vs StrongBox secure element — Comviva/Medium: https://medium.com/@dfs.techblog/safeguarding-cryptographic-keys-implementing-tee-and-strongbox-in-android-applications-7894c800e43e
- Play Integrity verdicts (STRONG requires locked bootloader + certified image) — Android Developers: https://developer.android.com/google/play/integrity/verdicts
- Play Integrity hardware-attestation change / power-user impact — Android Authority: https://www.androidauthority.com/google-play-integrity-hardware-attestation-3561592/
- Samsung Knox — no third-party API to launch container; Knox/SEAMS SDK is EMM-gated: https://docs.samsungknox.com/dev/knox-sdk/faq/security/ ; SEAMS: https://docs.samsungknox.com/dev/knox-sdk/features/mdm-providers/security/seams/ ; container limits: https://docs.samsungknox.com/admin/knox-platform-for-enterprise/faq/
- Waydroid (Android in an LXC container on GNU/Linux — host-side, not stock Android): https://waydro.id/ ; https://github.com/waydroid/waydroid
- Contrast — Postern OS measured-boot/verity attestation chain: `os/ATTESTATION.md` (this repo)
- Existing in-repo spec this design refines: `docs/specs/POSTERN-CONTAINER.md`
