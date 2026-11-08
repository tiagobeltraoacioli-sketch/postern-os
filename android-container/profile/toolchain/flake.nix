# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Porog (Postern Container) — Android DPC build & test toolchain (Wave-1, Dev 5).
#
# A pinned, reproducible Nix devshell that provides the FIRST environment in which
# `./gradlew :app:assembleDebug` (from ../, the profile project) and the T1
# instrumented harness (../test/e2e/provision-lifecycle.sh) can actually run.
#
# ── Why these exact pins ──────────────────────────────────────────────────────
#   * SDK platform 34 + build-tools 34.0.0 + platform-tools  → matches
#     compileSdk/targetSdk 34 in ../app/build.gradle.kts.
#   * NDK r26b (26.1.10909125)                               → matches the `ndk`
#     pin in ../gradle/libs.versions.toml; cargo-ndk builds Dev-B's
#     libpostern_sdk.so against THIS NDK (the housing embeds no cores; in-profile
#     wallet/workspace apps do).
#   * System image `system-images;android-34;google_apis;x86_64`               →
#     WORK-PROFILE CAPABLE. We deliberately AVOID `google_apis_playstore`: the
#     Play-store image ships GMS device policy that BLOCKS a self-enrolled DPC
#     from provisioning a managed profile (`isProvisioningAllowed` → false), which
#     is exactly the flow the T1 harness must drive. `google_apis` (no Play)
#     leaves managed-profile provisioning open. AOSP `default` images lack the
#     Google APIs some of the surface expects, so `google_apis` is the sweet spot.
#   * x86_64 ABI + KVM emulator                              → fast enough for CI;
#     the emulator needs /dev/kvm on the runner (see toolchain/README.md).
#
# ── Honest status ─────────────────────────────────────────────────────────────
# Authored on a NON-Nix macOS host: WRITTEN, NOT BUILT. No `flake.lock` is
# committed (nix cannot run here to generate one). On a Linux host with nix +
# flakes + KVM: `nix flake lock` to freeze inputs, then `nix develop` to enter.
#   built ≠ booted · emulator ≠ hardware · self-checked ≠ audited
# The entire Kotlin/emulator path this shell enables is `deferred-to-VM` and
# `UNTESTED-until-hardware`. UNAUDITED reference-prototype.
{
  description = "Porog Android DPC toolchain — pinned SDK 34 + google_apis work-profile emulator + NDK r26b";

  inputs = {
    # Align nixpkgs with the repo-root flake (nixos-24.05) for a single channel.
    # Freeze the exact rev with `nix flake lock` on a Nix host.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        # Android SDK components are unfree; the devshell must opt in explicitly.
        pkgs = import nixpkgs {
          inherit system;
          config = {
            allowUnfree = true;
            android_sdk.accept_license = true;
          };
        };

        # ── The pinned Android SDK composition ────────────────────────────────
        # `composeAndroidPackages` resolves a fixed set of SDK components into one
        # derivation, so every dev + CI runner gets byte-identical tooling.
        androidComposition = pkgs.androidenv.composeAndroidPackages {
          cmdLineToolsVersion = "11.0";
          platformToolsVersion = "34.0.5";
          buildToolsVersions = [ "34.0.0" ];
          platformVersions = [ "34" ];

          # Emulator + a WORK-PROFILE-CAPABLE system image. google_apis (NOT
          # google_apis_playstore) so a self-enrolled DPC can provision.
          includeEmulator = true;
          emulatorVersion = "34.1.20";
          includeSystemImages = true;
          systemImageTypes = [ "google_apis" ];
          abiVersions = [ "x86_64" ];

          # NDK r26b for cargo-ndk (Dev-B's libpostern_sdk.so). Matches the catalog.
          includeNDK = true;
          ndkVersions = [ "26.1.10909125" ];
          cmakeVersions = [ "3.22.1" ];

          includeSources = false;
          useGoogleAPIs = true;
        };

        androidSdk = androidComposition.androidsdk;
        sdkRoot = "${androidSdk}/libexec/android-sdk";
      in
      {
        # `nix develop` (or `nix develop ../toolchain`) → the build/test shell.
        devShells.default = pkgs.mkShell {
          name = "porog-android-toolchain";

          buildInputs = [
            androidSdk
            pkgs.jdk17          # AGP 8.5 needs JDK 17 (matches jvmTarget = "17").
            pkgs.gradle         # bootstrap Gradle (also lets `gradle wrapper` mint the jar).
            pkgs.cargo-ndk      # builds the wallet .so against the pinned NDK.
            pkgs.rustup         # rust toolchain host for cargo-ndk (add aarch64/x86 targets).
            pkgs.shellcheck     # t0 static gate for provision-lifecycle.sh.
            pkgs.coreutils
            pkgs.gnugrep
          ];

          # Point every tool at the pinned SDK/NDK. aapt2 override avoids Gradle
          # re-downloading a build-tools aapt2 that would violate the pin.
          ANDROID_HOME = sdkRoot;
          ANDROID_SDK_ROOT = sdkRoot;
          ANDROID_NDK_ROOT = "${sdkRoot}/ndk/26.1.10909125";
          JAVA_HOME = "${pkgs.jdk17}";
          GRADLE_OPTS =
            "-Dorg.gradle.project.android.aapt2FromMavenOverride=${sdkRoot}/build-tools/34.0.0/aapt2";

          shellHook = ''
            echo "── Porog Android toolchain (Wave-1, Dev 5) ────────────────────"
            echo "  ANDROID_SDK_ROOT = $ANDROID_SDK_ROOT"
            echo "  JDK              = $(java -version 2>&1 | head -1)"
            echo "  Build:  (cd .. && ./gradlew :app:assembleDebug)   # deferred-to-VM"
            echo "  T1:     ../test/e2e/provision-lifecycle.sh         # needs KVM emulator"
            echo ""
            echo "  KVM check: $([ -e /dev/kvm ] && echo '/dev/kvm present' \
              || echo 'NO /dev/kvm — emulator UNTESTED-until-hardware')"
            echo "  Emulator uses the google_apis image (NOT playstore) so the DPC"
            echo "  can provision a managed profile. built ≠ booted; UNAUDITED."
            echo "────────────────────────────────────────────────────────────────"
          '';
        };

        # A convenience app that creates + cold-boots the work-profile-capable AVD
        # the T1 harness targets. `nix run .#avd` on a KVM Linux host. It is a thin
        # wrapper over avdmanager/emulator — deferred-to-VM (no emulator here).
        apps.avd = {
          type = "app";
          program = "${pkgs.writeShellApplication {
            name = "porog-avd";
            runtimeInputs = [ androidSdk pkgs.coreutils ];
            text = ''
              set -euo pipefail
              AVD_NAME="porog-api34-gapis"
              SYS_IMG="system-images;android-34;google_apis;x86_64"
              echo "no" | avdmanager create avd -n "$AVD_NAME" -k "$SYS_IMG" --force
              # Headless, KVM, cold boot. writable-system so `dpm`/`pm` work fully.
              exec emulator -avd "$AVD_NAME" -no-window -no-audio -no-boot-anim \
                -gpu swiftshader_indirect -writable-system -no-snapshot
            '';
          }}/bin/porog-avd";
        };
      });
}
