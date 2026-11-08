<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Porog — Wave-1 execution plan (make it FUNCTIONAL)

**Role of this doc:** the consolidated Wave-1 build plan for **Porog** — the
stock-Android, self-enrolled managed-profile "door." It says *what* gets built, *in
what order*, the *tier* (HOST / VM / device) each piece can be proven at, the
integration + test strategy, and a **strict 5-dev partition with non-overlapping
file ownership** so five developers run in parallel without collision.

**Branch:** `roadmap/wave1-base` (carries the Wave-0 foundation).
**Source specs (binding):** `docs/design/porog-01-dpc-enrollment.md` (A1 DPC lifecycle),
`porog-02-strongbox-attestation.md` (A2 attest), `porog-03-crossprofile-bridge.md`
(A3 cross-profile), `bridge-trust-boundaries.md` (A9 honesty), `bridge-build-test-infra.md`
(A10 toolchain/tiers), `bridge-google-compliance.md` (legal).

> ## Honesty rails (binding — `scripts/check-trust-labels.sh` enforces the absolutes)
> - Porog is a **key-attested device, not a measured-boot workspace** — it attests the
>   **phone**, NOT the workspace. Never claim the Postern Seal / measured-boot / `os_roothash`
>   covers Porog. Wherever `key-attested` appears, the qualifier **"not a measured-boot
>   workspace"** must ride within ±3 lines.
> - **Stock, un-rooted Android; self-enrolled profile-owner DPC** (never device-owner).
>   No OS replacement, no root, no EMM. **NEVER "Postern OS."**
> - Distribution = **sideload / F-Droid first** (operator decision); Play Store deferred
>   pending legal.
> - **No GMS redistribution, no Play-Integrity circumvention**; report verdicts honestly,
>   never spoof. Android/Google marks nominative only.
> - **SCAFFOLD · DESIGN ONLY · UNAUDITED · never provisioned on hardware.** `built ≠ booted`,
>   `emulator ≠ hardware`, `self-checked ≠ audited`, `vector-tested ≠ attested`. A rooted /
>   kernel-compromised host defeats the whole boundary.
> - **"Porog" / "NoporIS" are PROPOSED names, pending trademark clearance.**

---

## 0. What Wave-0 already provides (this is a DELTA plan, not greenfield)

Confirmed by inspection of `roadmap/wave1-base`. **Do not re-invent — extend.**

**Host-provable now (macOS, no Android SDK):**
- `apps/porog-crossprofile/reconcile-kernel.mjs` + `test-reconcile.mjs` — the **pure,
  DOM-free cross-profile decision kernel**. `reconcile(state)` → `{intentFilters,
  crossProfilePackages, copyPasteDisallowed, clipboardDirection, …}`. Enforces default-deny,
  fail-closed, anti-round-up, kill-switch, pinned `tier="key-attested-device"`. Node-tested.
- `apps/consent-contract/` — the **shared consent spine** (`consent-spine.mjs`,
  `consent-spine.schema.json`, `test-spine.mjs`) + Porog examples
  (`porog.state.json`, `porog.consented.state.json`). Porog product key + tier
  `"key-attested-device"`; crossings `{intents,clipboard,files,contacts,calendar,connectedApp}`.
- `crates/postern-seal-companion/src/mobile.rs` — the **StrongBox Key-Attestation verifier**,
  behind cargo feature `mobile-attest`. Entry points `verify_key_attestation` /
  `verify_key_attestation_detailed`, `MobileExpected`, `MobileAttestation`, `Verdict`
  (fail-closed). Builds + tests on macOS today: `cargo test -p postern-seal-companion --features mobile-attest`.

**Kotlin scaffold (compiles nowhere yet — no SDK on macOS; VM-blocked):**
- `android-common/` — the ONE shared, hardening-free DPC core (co-owned; changes need
  A-lead + N-lead sign-off): `ManagedProfileState` (`ABSENT/UNSUPPORTED/PROVISIONING/
  ACTIVE/WIPED` — **needs +PAUSED**), `ManagedProfileManager` (`isProfileOwner/canProvision/
  currentState/wipeProfileOnly` — **needs +lock/+quietMode/+suspend/+PAUSED reporting**),
  `ManagedProfileAdminReceiver` (abstract DPC), `ProvisioningResult/Preflight/Activity`.
- `android-container/profile/` — the Porog app: `PosternDeviceAdminReceiver`
  (profileName + `onProfileOwnerEstablished` → `LockdownPolicy.applyBaseline()`, with TODO
  seams for UI hand-off + attestation), `LockdownPolicy` (screenshot/IME/cross-profile/
  unknown-src baseline; Tor VPN seam — **needs +WorkChallenge call**), `ContainerProfileManager`
  (`wipeContainerOnly` — **needs +panicLock/pause/resume**), `ContainerState` (typealias),
  `AttestationGateway` (interface + NoOp stub — the A↔attest seam), `PosternSdkBridge`
  (NoOp — Dev-B seam, out of Wave-1 scope), `ProvisioningActivity` (subclass; **UI is TODO**),
  `AndroidManifest.xml` (ProvisioningActivity + DPC receiver), `device_admin_receiver.xml`
  (wipe-data / force-lock / limit-password / disable-keyguard-features — covers new policies).
- **Gradle is bootstrapped:** `android-container/profile/gradlew` wrapper + `gradle/libs.versions.toml`
  (AGP 8.5.0 · Kotlin 1.9.24 · Compose 1.5.14 · compileSdk 34 · minSdk 30 · JDK 17) are
  **already committed** (Wave-0 fixed the A10 "missing wrapper" prerequisite).
- `mobile/android/app/.../wallet/StrongBoxKey.kt` — StrongBox key gen (`generateAttestedKey`,
  `getCertificateChain`, `attestationChainDer` → `List<ByteArray>`, `generateTeeFallbackKey`);
  `minSdk 28`. **Needs +PlayIntegrity + AttestationTier siblings.**

**Design invariant carried forward:** *one* DPC core (`android-common`), *two* products.
Generic managed-profile ops live in the shared module; Porog adds **only** its vocabulary +
its **hardening** (`LockdownPolicy`). Nothing hardened leaks into the shared module or NoporIS.

---

## 1. Build order (phases; P0 unblocks the Kotlin tiers)

1. **P0 — Toolchain stand-up (Dev 5).** Nix devshell pinning Android SDK + `google_apis`
   API-34 image + KVM emulator; first-ever `./gradlew :app:assembleDebug` of the scaffold on
   the VM. *Exit:* the tree compiles; a work-profile-capable emulator boots. **Unblocks all
   Kotlin build/unit tiers.** (Host Rust + node tiers do not wait on P0.)
2. **P1 — Shared lifecycle core (Dev 1, `android-common`).** `+PAUSED`; `lockProfileNow` /
   `setPaused` / `suspendPackages` + `PAUSED` reporting on `ManagedProfileManager`.
3. **P2 — Porog lifecycle + work challenge (Dev 1, Porog tree).** `WorkChallengePolicy`;
   wire into `LockdownPolicy.applyBaseline()`; `panicLock`/`pauseContainer`/`resumeContainer`.
4. **P3 — Onboarding UI (Dev 2).** `OnboardingScreen` Compose + `ProvisioningActivity`
   wiring; honesty banner; honest `Dispatched`-vs-complete rendering; personal-side Suspend/Resume tile.
5. **P3′ — Cross-profile enforcement (Dev 3, parallel).** `CrossProfileReconciler` +
   audit log + boot/state-change trigger, driven by the (already host-proven) kernel.
6. **P3″ — Attestation binding (Dev 4, parallel).** Real `AttestationGateway` impl +
   `AttestationTier` (StrongBox→TEE fallback) + `PlayIntegrity`; ratify `mobile.rs` as the A↔C wire.
7. **P4 — T1 functional smoke (Dev 5).** `ProfileLifecycleE2ETest` + `provision-lifecycle.sh`
   adb harness; wire the VM CI tier. *Exit:* every §5 assertion green on the emulator.
8. **P5 — Integration (Dev 1 wires the seams).** `PosternDeviceAdminReceiver` + manifest
   pick up Dev 3's reconciler trigger and Dev 4's attestation call at the labeled sites.
9. **P6 — T2 real-device acceptance (device tier; out-of-CI).** Stock Pixel: real one-tap
   provisioning, StrongBox `Genuine`, Panic Lock / quiet-mode / container wipe; Samsung + Xiaomi
   OEM matrix. **The only tier that substantiates the on-device claims.**

Devs **write** their code in parallel from day one; the phase numbers order *integration + proof*,
not authoring. Only the VM/device *proof* is gated.

---

## 2. Tier map — where each piece is PROVABLE

Per A10's T0/T1/T2 model. A result is only trustworthy about the tier it ran in; CI must never
let a HOST pass imply a VM/device truth.

| Piece | HOST (macOS, now) | VM (Linux+Nix, Android SDK) | Device (real hardware) |
|---|---|---|---|
| Cross-profile **kernel** (`reconcile-kernel.mjs`) | ✅ `node test-reconcile.mjs` — default-deny, fail-closed, anti-round-up, kill-switch, direction flags | — | — |
| Rust **attestation verifier** (`mobile.rs`) | ✅ `cargo test --features mobile-attest` — every Genuine/Mismatch/Unverified branch on hand-built DER vectors | — | — |
| **Kotlin** lifecycle / UI / reconciler / gateway **build + JVM unit** | ❌ no SDK | ✅ `./gradlew :app:assembleDebug :app:testDebugUnitTest` (flips G1 "built") | — |
| **Provision→lock→suspend→wipe** state machine | ❌ | ✅ T1 emulator (`google_apis` image) via adb/dpm — control path + policy application | ✅ true one-tap consent flow |
| **Cross-profile enforcement** (filters/copy-paste/allowlists apply) | ❌ | ✅ T1 emulator — §6.3 scenario green | ✅ OEM behaviour variance |
| **StrongBox attestation** (`SecurityLevel=2`, Google-rooted chain) | ❌ (`vector-tested ≠ attested`) | ❌ emulator keymaster is software → TEE/NONE, correctly fails/falls back | ✅ **only here** — Pixel 3+/Samsung (Tier C) |
| **Play Integrity** STRONG/DEVICE/BASIC reality | ❌ | ❌ | ✅ real device + Play services (STRONG *fails* on unlocked/custom-ROM — a required honest result) |

**Headline:** two pieces are **HOST-provable today** (the JS kernel + the Rust verifier). Every
Kotlin surface is **VM-blocked** on the incoming Linux+Nix VM. StrongBox + Play Integrity +
OEM matrix are **irreducibly device-only** — devs still WRITE the code; the *proof* is labeled
`UNTESTED-until-hardware`.

---

## 3. Integration strategy — how five trees compose without a shared edit

The two **integration hotspots** are single-owner files; everyone else reaches them through a seam:

- **`PosternDeviceAdminReceiver.kt` (owned by Dev 1)** — the DPC entry. `onProfileOwnerEstablished`
  calls (a) `LockdownPolicy.applyBaseline()` [Dev 1], (b) **Dev 3's** `CrossProfileReconciler`
  first reconcile, (c) **Dev 4's** attestation kick. Dev 3 and Dev 4 deliver self-contained classes
  with agreed constructor/method signatures; **Dev 1 writes the one-line call sites.**
- **`AndroidManifest.xml` (owned by Dev 1)** — Dev 3's boot/state-change `BridgeStateReceiver`
  needs a `<receiver>` declaration; Dev 3 hands Dev 1 the exact XML stanza to paste. No new
  activity from Dev 2 (Compose renders inside the existing `ProvisioningActivity`).
- **All Gradle build files + `libs.versions.toml` (owned by Dev 5)** — any new dependency
  (Compose extras for Dev 2, test-runner/espresso for the E2E, x509/JNA, etc.) is requested from
  Dev 5, who edits the catalog + module `build.gradle.kts`. This is the classic "shared catalog,
  one owner" rule.
- **Consent-spine seam (owned by Dev 3 for Wave-1)** — `apps/consent-contract/*` is shared across
  Porog/NoporIS/Waydroid; within Wave-1 Porog scope Dev 3 owns it and coordinates any schema
  change cross-product (with N-lead) before touching `consent-spine.schema.json`.
- **`android-common/*` sign-off** — the shared DPC core still requires **A-lead + N-lead**
  sign-off per the module contract; Dev 1 is the Porog-side owner and must get the NoporIS lead's
  ack on the `ManagedProfileState`/`ManagedProfileManager` additions (they are generic + additive).

**Semantic (not file) coordination:** `LockdownPolicy.blockCrossProfileSharing()` [Dev 1] sets the
baseline `DISALLOW_CROSS_PROFILE_COPY_PASTE` (default-deny); `CrossProfileReconciler` [Dev 3] is
authoritative afterward. They agree because the default gate state = full-deny. Documented, no file collision.

---

## 4. The 5-dev partition — STRICT non-overlapping file ownership

No two devs edit the same file. Shared files have exactly one owner; others coordinate through them.

### Dev 1 — DPC Lifecycle & Work-Challenge (A1 / A-lead)
**Owns (exclusive):**
- `android-common/src/main/java/labs/postern/common/profile/lifecycle/ManagedProfileState.kt` (edit: `+PAUSED`)
- `android-common/src/main/java/labs/postern/common/profile/lifecycle/ManagedProfileManager.kt` (edit: `+lockProfileNow/+setPaused/+suspendPackages/+PAUSED` reporting)
- `android-container/profile/app/src/main/java/labs/postern/container/dpc/WorkChallengePolicy.kt` **(new)**
- `android-container/profile/app/src/main/java/labs/postern/container/dpc/LockdownPolicy.kt` (edit: call `WorkChallengePolicy.require()`)
- `android-container/profile/app/src/main/java/labs/postern/container/lifecycle/ContainerProfileManager.kt` (edit: `+panicLock/pauseContainer/resumeContainer`)
- `android-container/profile/app/src/main/java/labs/postern/container/dpc/PosternDeviceAdminReceiver.kt` (edit: wire Dev 3 + Dev 4 seam call sites)
- `android-container/profile/app/src/main/AndroidManifest.xml` (edit: paste Dev 3's `<receiver>` stanza)
- `android-container/profile/app/src/main/res/xml/device_admin_receiver.xml` (verify-only)
**Shared coordination:** owns the two integration hotspots (DPC receiver + manifest) — Dev 3/Dev 4
hand it seam signatures + XML. `android-common` edits need N-lead sign-off. Gradle deps via Dev 5.

### Dev 2 — Onboarding & Provisioning Compose UI (A2)
**Owns (exclusive):**
- `android-container/profile/app/src/main/java/labs/postern/container/provision/OnboardingScreen.kt` **(new)**
- `android-container/profile/app/src/main/java/labs/postern/container/provision/ProvisioningActivity.kt` (edit: `setContent{}`, honest result rendering, personal-side Suspend/Resume tile)
- `android-container/profile/app/src/main/java/labs/postern/container/provision/ui/**` **(new dir — theme/banner/components)**
- `android-container/profile/app/src/main/res/values/strings.xml` (edit: UI copy + honesty banner strings)
**Shared coordination:** Suspend/Resume tile calls Dev 1's `ContainerProfileManager.pauseContainer()`
(personal/parent-context) — coordinate signature. Compose deps requested from Dev 5.

### Dev 3 — Cross-Profile Enforcement (A3)
**Owns (exclusive):**
- `apps/porog-crossprofile/reconcile-kernel.mjs` (extend if needed — already host-proven)
- `apps/porog-crossprofile/test-reconcile.mjs`
- `apps/consent-contract/**` (Wave-1 Porog owner; cross-product schema change needs N-lead ack)
- `android-container/profile/app/src/main/java/labs/postern/container/dpc/CrossProfileReconciler.kt` **(new)** — reads `files/porog-gate/state.json`, maps kernel directives → §2 DPM calls, idempotent
- `android-container/profile/app/src/main/java/labs/postern/container/dpc/CrossProfileAuditLog.kt` **(new)** — local, append-only, non-telemetry policy-transition log
- `android-container/profile/app/src/main/java/labs/postern/container/dpc/BridgeStateReceiver.kt` **(new)** — boot-completed + state-change (FileObserver) reconcile trigger
**Shared coordination:** hands Dev 1 the `<receiver>` manifest stanza + the reconciler call
signature for `onProfileOwnerEstablished`. Semantic coordination with Dev 1 on the copy-paste restriction.

### Dev 4 — StrongBox Attestation Binding (A-attest / Dev-C)
**Owns (exclusive):**
- `crates/postern-seal-companion/src/mobile.rs` (edit: ratify the A↔C wire; add any missing negative vectors; document root-pinning/rotation) — **HOST-provable now**
- `android-container/profile/app/src/main/java/labs/postern/container/attest/**` (edit `AttestationGateway.kt`; **new** `StrongBoxAttestationGateway.kt` real impl + `AttestationTier.kt`)
- `mobile/android/app/src/main/java/labs/postern/wallet/StrongBoxKey.kt` (edit: key-gen + chain export)
- `mobile/android/app/src/main/java/labs/postern/wallet/PlayIntegrity.kt` **(new)** — obtain token, server-side decode only, never client-trust
- `mobile/android/app/src/main/java/labs/postern/wallet/AttestationTier.kt` **(new)** — StrongBox→TEE fallback + honest "tier you actually got" surface
**Shared coordination:** provides Dev 1 the attestation-kick signature for `onProfileOwnerEstablished`
(nonce → chain → verdict). Rust/mobile Gradle deps via Dev 5.

### Dev 5 — Toolchain & Test Harness (VM/test dev — A10)
**Owns (exclusive):**
- All Gradle build config: `android-common/build.gradle.kts`, `android-container/profile/build.gradle.kts`, `android-container/profile/app/build.gradle.kts`, `android-container/profile/settings.gradle.kts`, `android-container/profile/gradle.properties`
- `android-container/profile/gradle/libs.versions.toml` (the version catalog — **single owner; all dep additions route here**)
- `android-container/profile/gradle/wrapper/**`, `gradlew`, `gradlew.bat`
- `android-container/profile/toolchain/flake.nix` **(new)** + `toolchain/README.md`
- `android-container/profile/app/src/androidTest/java/labs/postern/container/ProfileLifecycleE2ETest.kt` **(new)** — the instrumented functional test
- `android-container/profile/test/e2e/provision-lifecycle.sh` **(new)** — adb-driven harness
- CI: the `t1:*` VM job deltas in `.gitlab-ci.yml` (coordinate with existing CI owner)
**Shared coordination:** the E2E test exercises Dev 1's lifecycle + Dev 3's reconciler public APIs
(integration test, appropriately owned by the test dev — coordinate method names). Everyone requests
dependency additions from Dev 5.

---

## 5. The FUNCTIONAL-proof tests (per tier)

**HOST (provable today, gates every change):**
- `node apps/porog-crossprofile/test-reconcile.mjs` — default-deny, unknown/corrupt/partial →
  full-deny, anti-round-up, kill-switch clears all, correct direction→flag mapping. *(Dev 3)*
- `cargo test -p postern-seal-companion --features mobile-attest` — Genuine + every named Mismatch
  + empty-chain/no-root → Unverified. `vector-tested ≠ attested`. *(Dev 4)*

**VM / T1 (Linux+Nix emulator; gates Kotlin changes):** `provision-lifecycle.sh` +
`ProfileLifecycleE2ETest` enroll the same `PosternDeviceAdminReceiver` via adb (the consent UI is
not headless) and assert against OS ground truth:
1. `pm create-user --profileOf 0 --managed`; install APK; `dpm set-profile-owner`.
2. Broadcast `PROFILE_PROVISIONING_COMPLETE` → assert name/enable ran + `LockdownPolicy` applied
   (`dumpsys device_policy`: screen-capture off, IME allowlist, `DISALLOW_CROSS_PROFILE_COPY_PASTE`
   + `DISALLOW_INSTALL_UNKNOWN_SOURCES`, work-challenge complexity required).
3. **Cross-profile:** write gate state `files={open:true,direction:"w2p"}` → reconcile → assert
   `ACTION_SEND` resolves managed→personal only; flip `killSwitch` → all filters cleared, copy-paste
   re-disallowed; corrupt state → full-deny (§6.3 of porog-03).
4. **Lock:** `panicLock()` → profile locked, CE storage sealed. **Suspend:** `requestQuietModeEnabled(true)`
   → `isQuietModeEnabled==true` && `currentState()==PAUSED`; resume → `ACTIVE`. **Wipe:**
   `wipeContainerOnly()` → user N gone, user 0 untouched.
5. **Negative:** image lacking `FEATURE_MANAGED_USERS` → `ProvisioningPreflight` → `Unsupported`.
Green T1 proves state machine + policy application + fail-closed enforcement on the SDK. It proves
**nothing** about StrongBox or OEM behaviour — labeled so.

**Device / T2 (out-of-CI, signed manual log — the true product claim):** stock un-rooted Pixel —
real one-tap `ACTION_PROVISION_MANAGED_PROFILE`; `AttestationGateway` reports `Tier.STRONGBOX` with a
valid Google-rooted chain via `verify_key_attestation_detailed`; Panic Lock / quiet-mode / container
wipe; Play Integrity real verdict (STRONG *fails* honestly on unlocked/custom-ROM). Samsung One UI +
Xiaomi MIUI/HyperOS passes fill the porog-01 §2.4 OEM matrix. **Ship-gate:** T1 green **and** T2 on
≥1 stock Pixel before any surface drops "SCAFFOLD / DESIGN ONLY." Until then: **UNAUDITED**.

---

## 6. Honesty constraints (verbatim on every surface)
- **Key-attested device, not a measured-boot workspace.** Never Postern Seal / measured-boot / `os_roothash` for Porog.
- **Stock Android, no root, self-enrolled profile-owner DPC. NEVER "Postern OS."** Never device-owner.
- **Hardened, not anonymous.** A rooted / kernel-compromised host defeats the whole boundary.
- **No GMS redistribution, no Play-Integrity circumvention;** report verdicts, never spoof; nominative marks only. StrongBox is classical P-256 — no PQ in hardware.
- **Sideload / F-Droid first;** Play Store deferred pending legal.
- **"Porog" / "NoporIS" proposed names, pending trademark clearance.**
- **SCAFFOLD · DESIGN ONLY · UNAUDITED · never provisioned on hardware** until the §5 ship-gate.
