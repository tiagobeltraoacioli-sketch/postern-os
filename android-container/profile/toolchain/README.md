<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Porog Android toolchain (Wave-1, Dev 5)

The pinned Nix devshell for a reproducible Porog build and its T1 functional
harness. The **debug APK now builds for real** — `./gradlew :app:assembleDebug`
succeeds on any host with the Android SDK (`android-34` + build-tools `34.0.0`)
and a JDK 17 (the profile ships `build-and-verify.sh`, which assembles then asserts
the DeviceAdminReceiver + minSdk 30 / targetSdk 34 via `aapt`). What is **still
deferred** is the **instrumented T1 lifecycle** (needs a work-profile AVD / KVM,
below) and hardware provisioning. `built ≠ booted · emulator ≠ hardware ·
self-checked ≠ audited`. UNAUDITED reference-prototype.

## What it pins

| Component | Pin | Why |
|-----------|-----|-----|
| SDK platform | `android-34` | matches `compileSdk`/`targetSdk = 34` |
| build-tools | `34.0.0` | matches the app module |
| platform-tools | `34.0.5` | `adb` / `dpm` / `pm` used by the T1 driver |
| NDK | `26.1.10909125` (r26b) | `cargo-ndk` builds Dev-B's `libpostern_sdk.so`; same pin as the version catalog |
| Emulator image | `system-images;android-34;google_apis;x86_64` | **work-profile capable** |
| JDK | 17 | AGP 8.5 requirement |
| Gradle | 8.9 (wrapper) | matched to AGP 8.5.0 |

### Why `google_apis` and NOT `google_apis_playstore`

A self-enrolled Device Policy Controller provisions a managed profile via
`ACTION_PROVISION_MANAGED_PROFILE`. The **Play-store** system image ships GMS
device-policy that makes `isProvisioningAllowed(...)` return **false** for a
non-EMM app — it *blocks* exactly the flow Porog is. The plain `google_apis`
image (Google APIs, no Play) leaves managed-profile provisioning open, so the T1
harness can drive `pm create-user --managed` → `dpm set-profile-owner` →
`PROFILE_PROVISIONING_COMPLETE`. This choice is load-bearing, not incidental.

## Use it (on a Linux host with Nix + flakes + KVM)

```bash
cd android-container/profile/toolchain
nix flake lock                 # freeze inputs → commit flake.lock (do once, on a Nix host)
nix develop                    # enter the toolchain shell

# First-ever build — from the profile project root:
cd .. && gradle wrapper --gradle-version 8.9 --distribution-type bin   # mint gradle-wrapper.jar (once)
./gradlew :app:assembleDebug   # → app/build/outputs/apk/debug/app-debug.apk

# T1 functional harness (boots the AVD, enrolls the DPC, asserts the lifecycle):
nix run .#avd &                # in another shell: cold-boot the work-profile AVD
./test/e2e/provision-lifecycle.sh --apk app/build/outputs/apk/debug/app-debug.apk \
                                  --test-apk app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
```

## KVM requirement (honest gate)

The x86_64 emulator needs `/dev/kvm`. GitLab's `bloch-mac` shell runner has **no
Nix, no SDK, no KVM** — so the `t1:*` Android jobs are pinned to a runner tag
(`bloch-android-vm`) that does not exist yet. Until that KVM Linux runner is
provisioned, those jobs surface as **`UNTESTED-until-hardware`**, never faked
green. The `t0:android-static` gate (below) *does* run on `bloch-mac` because it
needs no SDK — it lints the shell driver, parses the catalog, and checks this
flake's brace balance.

## Trust boundary (keep verbatim)

Porog attests the **phone**, not the **workspace** — hardened, not anonymous;
key-attested, not measured-boot. A rooted / kernel-compromised host defeats the
profile boundary. This toolchain builds an app on stock Android; it is **NEVER
"Postern OS."** No security claims until an audit gate.
