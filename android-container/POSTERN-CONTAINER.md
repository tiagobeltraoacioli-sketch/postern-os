<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Porog (Postern Container, Android) — Provisioning-Path Decision Record (A1)

> **Product name: Porog** *(PROPOSED, pending formal trademark clearance — a web
> check found it apparently clean; that is **not** a legal clearance).* "Postern" is
> the suite brand; **Porog** is this Android app. See §0 for the brand narrative.

**Owner:** Dev A-lead (F1 Android — managed-profile provisioning + work-profile lifecycle).
**Status: DESIGN ONLY. UNAUDITED. reference-prototype. No security claims.**
Nothing in this tree has been built, provisioned, or run on a device. Every code
reference under `android-container/profile/` is a **scaffold** — "reads idiomatically"
at best, never "built", never "booted on hardware", never "audited".

This is the **A1 architecture-lock** artifact: the written decision that the Postern
Container is an **AOSP managed profile provisioned by a self-enrolled Device Policy
Controller (DPC)** — *not* a custom OS, *not* Waydroid, *not* a device-owner/EMM
enrollment. It refines and holds to the two in-repo specs; where they and the code
disagree, trust the code:

- `docs/specs/POSTERN-CONTAINER.md` (product spec — "Status: design")
- `docs/design/design-android-container.md` (technical design — "design/spec only")
- `Postern-Android-Container-Design.md` (architect charter — "DESIGN ONLY. UNAUDITED.")

> **The one honest label — keep it verbatim on every surface:**
> Postern Container is a hardened, **key-attested** privacy workspace on the **stock
> Android you already own** — no OS replacement, no root. It attests the *phone*,
> **not** the *workspace*. It is **hardened, not anonymous; key-attested, not
> measured-boot.** For end-to-end measured boot of an audited image, that is **Postern
> OS Mobile**, a different product. *(Design only; unaudited; no security claim until
> an audit gate.)*

---

## 0. The name — Porog *(PROPOSED, pending trademark clearance)*

**Porog** is Slavic for the **threshold** — the *porog* (порог; soleira) of the
**Izbushka**, the guardian's hut.

In the Slavic tale, the hut on chicken legs — in Postern's brand it is
**Yagabona** (never write "Baba Yaga" on any shipping surface) — stands at the
forest edge, the boundary **between two worlds**. It spins and shows no door until
the traveller speaks the formula ("Izbushka, izbushka, turn your back to the forest
and your front to me"); only then does it turn and present its **threshold — the
porog**. You cross between worlds **only if you know the words** — a rite, a
credential.

**Porog is that threshold, on the phone you already carry:** the single guarded door
that **unites two worlds** — the personal side (ordinary Android) and the hardened
workspace — and it turns/opens only for the one who presents the credential
(authentication / attestation). **One guarded porog joining both sides, no second
device.** The provisioning flow (`ProvisioningActivity`, "Create Porog") is that
threshold made literal.

The honest caveat stays attached to the metaphor: the threshold is guarded by the
Android kernel + SELinux profile boundary, not by anything Postern controls — a
rooted host walks straight through it (§4). Hardened, not anonymous.

*(Name is **PROPOSED, pending formal trademark clearance**. "Postern" remains the
suite brand; "Porog" is this Android app.)*

---

## 1. Context — what decision this locks

The flagship Android front needs a mechanism to run sensitive apps, keys, and comms
**isolated** from the rest of a phone, on hardware **the user already owns**, with **no
root and no OS replacement**. Five mechanisms can plausibly deliver "an isolated space
on Android". This record picks one and states honestly what the choice does and does
**not** buy.

The choice is load-bearing for every downstream milestone (A2 provisioning PoC, A3
StrongBox attestation, A4 Tor/policy gate, A5 workspace apps) and for the honesty
rails: it decides **where the trust boundary is drawn** and therefore **what we are
allowed to claim**.

---

## 2. Options considered

| # | Option | Isolation mechanism | Root / OS control | Attestable? | Verdict |
|---|---|---|---|---|---|
| **A** | **AOSP managed profile via self-enrolled DPC** (Shelter/Island/Insular pattern) | A second Android user (work profile) with its own FBE key + SELinux boundary; our app is **profile owner** | **No root, stock OS** | **Device** key-attestation (StrongBox/TEE), **not** workspace measured-boot | **CHOSEN** |
| B | Custom OS — **Postern OS Mobile** | Its own measured, sealed image (Nix → erofs → dm-verity → UKI measured boot) | **Yes — it *is* the OS** | **Workspace** measured-boot (self-attesting) | Different product, different front (F2). Not this. |
| C | **Waydroid** LXC Android on a GNU/Linux host | Full Android in an LXC container on postmarketOS / Postern OS | Needs a Linux host Postern controls | **Non-attestable** (Play Integrity STRONG will fail — "not a bug we can fix") | Escape-hatch tier only; **never** the flagship, **never** "Postern OS". |
| D | **Device-owner** DPC (full-device management) | Same DPC APIs but owns the *whole* device | No root, but factory-reset / QR / EMM enrollment | Same key-attestation as A | Rejected — hostile UX (wipes device to enroll), reads as spyware, wrong ownership story. |
| E | **Single sandboxed app** (one app, no profile) | Just app-sandbox + our own at-rest AEAD | No root | Key-attestation of the app only | Rejected — no separate FBE key, no cross-profile firewall, no per-profile lockdown or container-only wipe. Weakest isolation. |

### Why not each rejected option (plainly)

- **B — Postern OS Mobile** is the *right* answer for anyone who wants measured boot of
  the workspace, but it requires an OS Postern builds and controls. It is a **separate
  product on a separate front**. Conflating it with the Container is the single worst
  naming error we can make. The Container is **NEVER "Postern OS"**.
- **C — Waydroid** cannot reach `MEETS_STRONG_INTEGRITY`: an uncertified LXC container
  with no hardware keymaster has no path to a hardware-rooted attestation. It is the
  *non-attestable escape-hatch* tier for hosts Postern controls (postmarketOS community
  edition), and it is **"Postern for postmarketOS — community edition," never "Postern
  OS."** Distinct host, distinct trust story — do not conflate with A.
- **D — device-owner** buys the same key-attestation as A but demands the user surrender
  their whole device (factory-reset-time / QR / EMM enrollment) and can wipe everything.
  That is the opposite of "meet the user where they are" and reads as corporate MDM /
  spyware. The **managed profile** is the no-EMM, self-enrolled, user-revocable path that
  Shelter/Island/Insular already ship on F-Droid.
- **E — single app** gives no separate FBE key, no SELinux user boundary, no per-profile
  policy (screenshots-off, IME allowlist, always-on VPN), and no container-only wipe. It
  is strictly weaker than A for the same distribution cost.

---

## 3. Decision

**Adopt Option A: the Postern Container is an Android managed profile, created by a
lightweight self-enrolled DPC via `DevicePolicyManager.ACTION_PROVISION_MANAGED_PROFILE`
— the same no-root, no-EMM path Shelter/Island/Insular use and ship on F-Droid.** Our
app becomes **profile owner** of a second Android user with its own FBE storage and
SELinux boundary. This is **isolation *within* stock Android's security model**, not a
new OS.

Concretely (scaffolded in `android-container/profile/`):

- The onboarding app (package `labs.postern.container`) requests provisioning with
  `ACTION_PROVISION_MANAGED_PROFILE`, naming `PosternDeviceAdminReceiver` as the admin
  component and keeping FBE (`EXTRA_PROVISIONING_SKIP_ENCRYPTION = false`).
- On `onProfileProvisioningComplete`, the DPC becomes profile owner, sets the profile
  name, applies a **baseline lockdown policy**, and enables the profile.
- Profile **lifecycle** (exists / provisioning / active / wiped) and **container-only
  wipe** (`wipeData`, profile-scoped — no personal-data loss) are owned here.
- **Distribution is F-Droid + signed direct APK.** Google Play is a poor fit for the
  DPC provisioning APIs (Play policy on device-admin/management); Play is reserved for a
  possible non-DPC companion / enterprise-EMM variant only.

**Minimum platform:** `minSdk` per the managed-profile + StrongBox floor (see the app
`build.gradle.kts`); provisioning support is gated at runtime via
`isProvisioningAllowed(ACTION_PROVISION_MANAGED_PROFILE)` and the
`FEATURE_MANAGED_USERS` system feature, never assumed.

---

## 4. The trust boundary — drawn honestly

The Container's isolation is **exactly as strong as the Android kernel + SELinux profile
boundary — no stronger.** We depend on that line; we do not own it and cannot audit it.

```
  UNTRUSTED / OUT OF SCOPE                    │  IN SCOPE (what the container controls)
 ──────────────────────────────────────────  │ ────────────────────────────────────────
  • The Android kernel + SELinux policy       │  • The managed profile's app set
  • The vendor system image / OEM firmware    │  • Per-profile FBE storage (own key/lock)
  • The bootloader & verified-boot chain      │  • DPC lockdown policy (baseline)
  • Google's attestation CA + Play Integrity  │  • StrongBox/TEE wrapping key + attestation
  • A rooted / compromised host               │  • Container-only wipe (profile-scoped)
  • The personal profile's apps               │  • The Rust cores' at-rest AEAD sealing
  • The cellular / carrier layer              │  • WYSIWYS approval in the signer core
 ═══════════ Android kernel + SELinux profile boundary (the trust line) ═══════════
        (the container's isolation is EXACTLY as strong as this line)
```

### What this path CAN honestly guarantee (real on stock Android)

- **Storage separation is real** — the profile has its own FBE key; the personal profile
  cannot read container files. Enforced by kernel + SELinux, not our code.
- **Process/app isolation is real** — container apps run as a separate Android user;
  clipboard/contacts/notification bridging is off unless the user opts in.
- **Per-profile lockdown is real** — screenshots off, IME allowlist, cross-profile off,
  unknown-sources blocked, always-on lockdown VPN (Tor-only — wired by Dev A-workspace).
- **Container-only remote wipe is real** — profile-scoped `wipeData`; no personal-data loss.
- **Device key-attestation is real and bounded** — a Google-CA-rooted X.509 chain proves
  a key is hardware-backed and records verified-boot state, OS patch level, and the
  attesting app's identity, with a verifier nonce echoed for freshness. (Generation +
  verify are owned by **Dev A-attest**; this tree only carries the nonce→chain→verdict
  seam.)

### What this path CANNOT guarantee — the honest ceiling

- **No measured boot of the workspace.** Key Attestation measures the **device** and
  **identifies the app** — it does **NOT** measure the container's code or contents.
  There is no dm-verity roothash "of the workspace." That property is exclusive to
  **Postern OS Mobile**. Always pair "attestable" with **"key-attested device, not
  measured-boot workspace."**
- **Isolation ≤ Android kernel + SELinux.** A kernel/hypervisor compromise, a malicious
  vendor image, or a **rooted device defeats the profile boundary entirely** — it can
  read container FBE storage once unlocked, key-log via the framework, and exfiltrate
  exported PQ key material. **The container cannot defend against an OS it does not own.**
- **StrongBox is classical, not post-quantum.** It is P-256 hardware that attests the
  device/app and **wraps the PQ key at rest**; it does **not** hold or sign with the
  Falcon‖ML-DSA key. PQ signing happens in the Rust core, in RAM (zeroized on drop).
- **Attestation trusts Google + the vendor.** The chain roots in Google's CA; Play
  Integrity chains to Google's servers — a real, and for an ownerless-protocol ethos
  ironic, third-party trust dependency. The self-sovereign answer is Postern OS Mobile.
- **Play Integrity STRONG is not a gate.** `MEETS_STRONG_INTEGRITY` needs a locked
  bootloader + certified image; it will never pass on rooted/unlocked/custom-ROM devices.
  Treat it as an **optional signal**, never a gate — gating excludes the privacy-conscious
  custom-ROM crowd we most want to serve.
- **Not every device gets the best tier.** Many phones have only a TEE, not StrongBox.
  Degrade gracefully and **report the tier actually obtained**, never claim StrongBox
  everywhere.
- **Not anonymous.** Tor-only egress reduces network metadata; it does not make the
  workspace anonymous against a compromised host, a coerced user, or on-device
  correlation. **Hardened, not anonymous.**
- **Nothing is audited.** Design only. No security claim until an audit gate.

### Adversary outcomes (plainly)

| Adversary | Container outcome |
|---|---|
| Another app in the **personal** profile | **Blocked** — separate user, separate FBE, no cross-profile bridge. |
| **Lost/stolen locked** device | **Protected at rest** — FBE + user-auth-gated key; container-only wipe. |
| **Network observer** | Metadata reduced — Tor-only lockdown VPN. Not anonymity. |
| **Malicious IME / screenshot grabber** in the profile | **Mitigated** — IME allowlist + screen-capture disabled. |
| **Rooted / kernel-compromised host** | **DEFEATED.** Out of scope; nothing on stock Android survives this. Only Postern OS Mobile (measured boot) addresses it. |
| **Malicious vendor system image** | **DEFEATED.** We trust the OS we run on. |
| **Coerced user (rubber-hose)** | **Out of scope** — Panic Lock re-locks but is explicitly not a duress/deniable feature. |
| **A verifier lying about attestation** | Bounded by trust in Google's CA — stated, not solved. |

---

## 5. Consequences

**Positive**
- No root, no OS replacement, no factory reset — installs on the phone the user owns.
- Real per-profile FBE + SELinux isolation and container-only wipe for near-zero
  distribution cost, via a well-trodden (Shelter/Island/Insular) mechanism.
- Clean interface seams: A↔attest meet only at "nonce → cert chain → verdict/tier"; the
  workspace apps load Rust cores only through the one `postern-sdk` UniFFI facade.

**Negative / accepted**
- Isolation is bounded by an OS we do not control — a rooted/compromised host defeats it,
  and we must say so on every surface.
- Third-party trust on Google's attestation CA + Play Integrity — ironic for an ownerless
  ethos, accepted and disclosed; the self-sovereign path is Postern OS Mobile.
- Play distribution is impractical for the DPC path → F-Droid + signed direct APK.
- Device fragmentation: StrongBox is not universal → tier-reporting, never tier-assuming.

**This decision stays DESIGN** until A2 provisions a real managed profile **on hardware
(QEMU ≠ hardware)** and A3 verifies a **live** StrongBox attestation chain. No
"attestable/hardened" headline ships before those gates.

---

## 6. Scope & seams for this tree (`android-container/profile/`)

**Dev A-lead owns (A1–A2):** the managed-profile provisioning flow, the DPC receiver +
becoming profile owner, baseline lockdown application, profile lifecycle + container-only
wipe, and this decision record.

**Explicitly NOT owned here (other devs / other paths):**
- **StrongBox key generation + the mobile Key-Attestation *verify* backend** → Dev
  A-attest (`crates/postern-seal-companion` mobile provider, `android-container/attest/`,
  and `StrongBoxKey.kt`). This tree consumes only the **`AttestationGateway`** seam
  (nonce in → cert chain out → verdict/tier back) and ships a NO-OP stub.
- **Tor always-on VPN + `postern-policy` consent gate + workspace apps** → Dev
  A-workspace. This tree exposes the always-on-VPN toggle as a **labeled seam** and does
  not implement Orbot wiring or leak testing.
- **The Rust cores / the `postern-sdk` UniFFI facade internals** → Dev-B. This tree
  consumes only the **`PosternSdkBridge`** seam (loads `libpostern_sdk.so` via the
  generated bindings) and ships a NO-OP stub.

See `android-container/profile/README.md` for the file-by-file scaffold map and the
(unrun) build chain.
