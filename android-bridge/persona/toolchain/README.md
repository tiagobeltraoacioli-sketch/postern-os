<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# NoporIS Android toolchain (bucketA, Dev B)

The pinned Nix devshell that gives NoporIS its **first-ever real build** and its
(pending) T1 functional harness a place to run. Forked from Porog's toolchain
(`android-container/profile/toolchain/flake.nix`) per `docs/bucketA/PARTITION.md` —
NoporIS had no toolchain flake at all before this commit. Everything here is
authored on a non-Nix macOS host: **WRITTEN, NOT BUILT.** `built ≠ booted ·
emulator ≠ hardware · self-checked ≠ audited`. UNAUDITED reference-prototype.

## What it pins (identical to Porog's — same SDK/NDK, no second fork of the pins)

| Component | Pin | Why |
|-----------|-----|-----|
| SDK platform | `android-34` | matches `compileSdk`/`targetSdk = 34` |
| build-tools | `34.0.0` | matches the app module |
| platform-tools | `34.0.5` | `adb` / `dpm` / `pm` used by the T1 driver |
| NDK | `26.1.10909125` (r26b) | same pin as Porog's and `android-common`'s |
| Emulator image | `system-images;android-34;google_apis;x86_64` | **work-profile capable** |
| JDK | 17 | AGP 8.5 requirement |
| Gradle | 8.9 (wrapper) | matched to AGP 8.5.0; reconciled to Porog's pin (was 8.7 — PMO-flagged drift, bucketA/PARTITION.md) |

### Why `google_apis` and NOT `google_apis_playstore`

Same rationale as Porog: a self-enrolled Device Policy Controller provisions a
managed profile via `ACTION_PROVISION_MANAGED_PROFILE`. The **Play-store** system
image ships GMS device-policy that makes `isProvisioningAllowed(...)` return
**false** for a non-EMM app — it *blocks* exactly the flow NoporIS's persona
mechanism is. The plain `google_apis` image (Google APIs, no Play) leaves
managed-profile provisioning open. This choice is load-bearing, not incidental,
and applies identically to NoporIS's `CLEAN` and `GOOGLE_PLAY` flavors — the
flavor selection happens *inside* the already-provisioned profile
(`NoporIsDeviceAdminReceiver.onProfileEnrolled`), not at the image layer.

## Host verification status (what the macOS authoring host HAS now proven)

Partial unblock landed: the pure persona-policy **JVM unit tests now host-compile
and pass green** on the macOS authoring host — no Nix, no emulator, no KVM. This
is the `./gradlew :app:testDebugUnitTest` slice only, run offline against the
pre-populated Gradle 8.9 caches, with **JDK 17** (`brew openjdk@17`) and the
already-installed **Android SDK** (`platforms;android-34` + `build-tools;34.0.0`,
pointed at via a machine-local, git-ignored `local.properties` `sdk.dir`).

What that run proves (host-verified):

| Verified on host | How |
|------------------|-----|
| `:android-common` + `:app` **main** source-sets compile against `android-34` (AGP 8.5.0 / Kotlin 1.9.24, `jvmTarget=17`) | `./gradlew :app:testDebugUnitTest` builds the debug variant before it can run the tests |
| `PersonaFlavorTest` (7) — fail-closed flavor parse, `google-play` selects the less-private side by exact tag ONLY | green |
| `PersonaSlotPolicyTest` (5) — single managed-profile slot, EMPTY is the sole provisionable state, FOREIGN/OWNED/UNSUPPORTED refuse | green |
| `CrossingBearerPolicyTest` (6) — dumb-bearer screen fail-closes on empty/oversize, 64 KiB bearer ceiling ≥ Rust 16 KiB payload ceiling | green |

What is **NOT** host-verified and stays deferred-to-VM (honesty gate — do not
conflate with the above):

- **The `google_apis` (NOT `google_apis_playstore`) emulator flavor policy** — the
  load-bearing claim documented just above ("Why `google_apis` and NOT
  `google_apis_playstore`", that a Play-store image makes
  `isProvisioningAllowed(...)` return **false** and blocks the DPC). That is a
  claim about *emulator/device runtime behaviour*; it is **documentation only,
  host-verified NOT AT ALL** — it is provable only by cold-booting the
  work-profile AVD and running `../test/e2e/persona-lifecycle.sh`. The host JVM
  unit tests touch none of the Android provisioning APIs, so they can neither
  confirm nor refute it. `built ≠ booted · emulator ≠ hardware`.
- **APK assembly** (`:app:assembleDebug`) and the **instrumented** persona
  lifecycle (androidTest) — still first-run-on-the-box, see the "Honest gap"
  section below.

So: the persona-policy *logic* is now host-proven; the *image-layer flavor
policy* remains a written claim awaiting the KVM box. UNAUDITED reference-prototype.

## Use it (on a Linux host with Nix + flakes + KVM)

```bash
cd android-bridge/persona/toolchain
nix flake lock                 # freeze inputs → commit flake.lock (do once, on a Nix host)
nix develop                    # enter the toolchain shell

# First-ever build — from the persona project root:
cd .. && gradle wrapper --gradle-version 8.9 --distribution-type bin   # refresh gradle-wrapper.jar
./gradlew :app:assembleDebug   # → app/build/outputs/apk/debug/app-debug.apk

# T1 functional harness (script ready, NOT YET RUN — see ../test/e2e/persona-lifecycle.sh):
nix run .#avd &                 # in another shell: cold-boot the work-profile AVD ("noporis-api34-gapis")
./test/e2e/persona-lifecycle.sh --apk app/build/outputs/apk/debug/app-debug.apk \
                                 --test-apk app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
```

## KVM requirement (honest gate)

Same as Porog: the x86_64 emulator needs `/dev/kvm`. GitLab's `bloch-mac` shell
runner has **no Nix, no SDK, no KVM** — so NoporIS's `t1:*` Android jobs are
pinned to the `bloch-android-vm` runner tag, which does not exist yet. Until that
KVM Linux runner is provisioned, those jobs surface as
**`UNTESTED-until-hardware`**, never faked green. The `t0:android-static` gate
(extended to NoporIS, see `.gitlab-ci.yml`) *does* run on `bloch-mac` because it
needs no SDK.

## Honest gap this file does NOT close

This toolchain flake and its Gradle wiring are box-ready, but there is currently
**no instrumented `app/src/androidTest/` Kotlin source for NoporIS in this repo**
(unlike Porog's `ProfileLifecycleE2ETest.kt`). The `androidTestImplementation`
dependencies in `../app/build.gradle.kts` are wired so that source resolves the
moment it lands (UI-bridge devs' file, out of Dev B's build-file-only scope per
`docs/bucketA/PARTITION.md`) — this README does not claim that test exists yet.
`../test/e2e/persona-lifecycle.sh` honestly SKIPS its instrumented step when no
`--test-apk` is given, the same way Porog's driver does.

## Trust boundary (keep verbatim)

NoporIS attests the **phone**, not the **workspace** — hardened (`CLEAN` flavor)
or Google-Play-enabled (`GOOGLE_PLAY` flavor, the less-private side), never
anonymous; key-attested, not measured-boot. A rooted / kernel-compromised host
defeats the profile boundary. This toolchain builds an app on stock Android; it
is **NEVER "Postern OS."** No security claims until an audit gate.
