# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Root flake for the Bloch-SIS / Postern reference prototype.
#
# STATUS: UNAUDITED reference-prototype. This flake is authored on a non-Nix
# macOS workstation and is therefore "written, not built".
#   - built ≠ booted            : `nix build` producing ./result proves nothing runs
#   - QEMU ≠ hardware           : an emulated boot says nothing about a PinePhone
#   - reproducible-by-design ≠ reproduced : nobody has rebuilt these to a matching hash
#
# flake.lock (honesty, item #19): the committed `flake.lock` is an EMPTY SEED
# with ZERO input revisions frozen — it fabricates no narHash (a fabricated hash
# is a lie a JSON lock cannot even carry a disclaimer for). It is FAIL-CLOSED for
# reproducibility: an empty lock re-resolves the moving branch refs on every eval,
# so nothing is pinned until frozen. On a Linux host with Nix + flakes, run
# `scripts/flake-lock.sh` to freeze the exact `nixpkgs` (24.05) + `mobile-nixos`
# revisions into the lock, commit THAT filled lock FROM THE VM, then run
# `scripts/flake-check.sh` (`nix flake check`). `scripts/flake-check.sh`
# fail-closes if the lock is still the empty seed — an unpinned check never gets
# to masquerade as a reproducible one. Two-builder bit-for-bit procedure:
# docs/plan/FLAKE-REPRO.md.
#
# The Bloch-SIS-PoW base is ownerless; the coin is worthless by design and is
# not a security. "Postern OS" / "Postern OS Mobile" name ONLY the reproducible
# Mobile-NixOS image below — the Alpine/postmarketOS build in `pmos-overlay/` is
# "Postern for postmarketOS — community edition" and is NEVER "Postern OS".
{
  description = "Bloch-SIS node + Postern OS images (node / mobile / cloud-Chiostro)";

  inputs = {
    # Pinned to the 25.05 release channel. Freeze the exact rev with
    # `nix flake lock` on a Nix host (see header). Align this channel with
    # whatever nixpkgs the pinned `mobile-nixos` rev expects.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

    # Rust-toolchain nixpkgs for the bloch package ONLY. The workspace's real
    # MSRV is rustc 1.91 (arti/tor-* 0.44 declare `rust-version = "1.91"`;
    # lopdf 0.43/weezl 0.2 need 1.88) but nixos-25.05 ships rustc 1.86 — the
    # first real ISO build on a Nix host (postern-os-build, 2026-07-14) failed
    # exactly there ("weezl@0.2.1 requires rustc 1.88.0"). nixos-25.11 ships
    # rustc 1.91, the minimum that satisfies the whole lockfile. The OS/image
    # layers stay on the 25.05 `nixpkgs` above (mobile-nixos alignment); only
    # `blochPkgFor` builds from this newer set.
    nixpkgs-rust.url = "github:NixOS/nixpkgs/nixos-25.11";

    # nixpkgs for the MOBILE IMAGE ONLY. mobile-nixos is actively maintained and
    # its CI tracks `nixos-unstable` (see .github/workflows/ci.yml on the pinned
    # rev) — NOT a stable release. That is why the stable channels fail: 25.05 and
    # 24.11 removed the libinput override args (luaSupport/wacomSupport/…) that
    # mobile-nixos uses, and 24.05 predates the `services.eg25-manager` module the
    # PinePhone device needs — NO single stable release satisfies both. VERIFIED on
    # the Fly Nix builder (postern-os-build): with nixos-unstable the whole
    # mobile-nixos cascade resolves and `nix build --dry-run` reaches "777
    # derivations will be built" (eval rc=0). Pinned to an explicit unstable rev
    # for determinism. Contained by design — ONLY `evalMobile` imports this; the
    # node/desktop/cloud layers stay on 25.05 `nixpkgs`, `blochPkgFor` on
    # `nixpkgs-rust` (25.11). Bump this rev to re-track unstable when you bump
    # mobile-nixos. See os/boot-harness/evidence/aarch64-mobile-boot.evidence.
    nixpkgs-mobile.url = "github:NixOS/nixpkgs/18b9261cb3294b6d2a06d03f96872827b8fe2698";

    # Mobile-NixOS is IMPORTED as a source tree, not consumed as a flake — hence
    # `flake = false`. It ships NixOS stage-1 (device boot), the device modules
    # (kernel + DTB + firmware pins) and the image builders. Its evaluation API
    # evolves across revisions: PIN A REVISION and re-verify the output attribute
    # path (see `evalMobile` below) whenever you bump it.
    mobile-nixos = {
      url = "github:mobile-nixos/mobile-nixos";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, nixpkgs-rust, nixpkgs-mobile, mobile-nixos }:
    let
      # Systems we expose the plain node package + module on. The mobile image is
      # aarch64-only (phones); it is cross-built or built natively on an aarch64
      # Linux host — never on the macOS workstation.
      allSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs allSystems (system: f system);

      # The reproducible Bloch-SIS node package (node + bloch-wallet + bloch-cli),
      # built from the self-contained workspace (vendored pqcrypto, committed
      # Cargo.lock). Same derivation the node/desktop/cloud profiles consume.
      # Built from `nixpkgs-rust` (25.11, rustc 1.91) because the workspace's
      # MSRV exceeds 25.05's rustc 1.86 — see the input comment above. The
      # result is a self-contained store path; the 25.05-based systems below
      # consume it unchanged.
      blochPkgFor = system:
        (import nixpkgs-rust { inherit system; }).callPackage ./os/package.nix { };

      # ── Postern OS Mobile — Mobile-NixOS image for the PinePhone ──────────────
      # Layers `os/mobile.nix` (the wallet-first app/system layer) on top of the
      # Mobile-NixOS device config for `pine64-pinephone` (which supplies the
      # kernel, DTB, firmware and stage-1). `blochPkg` is threaded in as a module
      # arg so `os/mobile.nix` can ship the wallet engine without a global overlay.
      #
      # NOTE (honesty): the attribute that yields the flashable artifact differs
      # across Mobile-NixOS revisions (`outputs.default`, or
      # `config.system.build.default`/`disk-image`, …). This uses the documented
      # top-level `.outputs.default`; if `nix build .#mobile-image` fails to find
      # it on your pinned rev, adjust the selector here — this is exactly the
      # "APIs evolve; pin its revision" caveat from os/MOBILE.md.
      evalMobile = { device, extraModules ? [ ] }:
        import "${mobile-nixos}/lib/eval-with-configuration.nix" {
          inherit device;
          # Pin nixpkgs so the image is not built against an ambient <nixpkgs>.
          # Uses `nixpkgs-mobile` (nixos-unstable) — the channel mobile-nixos's CI
          # tracks; the stable `nixpkgs` (25.05) does not eval the image. Contained:
          # only this eval sees unstable. Verified: eval rc=0, 777 derivations.
          pkgs = import nixpkgs-mobile { system = "aarch64-linux"; };
          configuration = [
            ./os/mobile.nix
            { _module.args.blochPkg = blochPkgFor "aarch64-linux"; }
          ] ++ extraModules;
        };

      mobilePinephone = evalMobile { device = "pine64-pinephone"; };

      # ── x86_64 NixOS ISOs + attested image ──────────────────────────────────
      # These layer the existing os/*.nix profiles onto stock nixpkgs image
      # builders so `nix build .#iso` / `.#desktop-iso` / `.#attested-image`
      # resolve to a real derivation on a Nix host. HONEST STATUS: authored on a
      # non-Nix macOS workstation — WRITTEN, NOT BUILT and NOT BOOTED here. The
      # artifacts hosted on R2 were built off-repo on a Linux/Nix host; these
      # attrs are how you reproduce them. built ≠ booted.
      #
      # NixOS module option paths on the installer/repart/verity surface drift
      # across nixpkgs releases; if an output attr fails to evaluate on your
      # pinned `nixpkgs`, adjust the imported module / build attribute here (same
      # "APIs evolve; pin the revision and re-verify" caveat as the mobile image).
      nixosX86 = modules:
        nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          specialArgs = { blochPkg = blochPkgFor "x86_64-linux"; };
          inherit modules;
        };
      # `installation-cd-minimal` supplies the live/installer ISO machinery
      # (isoImage.*, the live squashfs root, the installer environment).
      installerCd = "${nixpkgs}/nixos/modules/installer/cd-dvd/installation-cd-minimal.nix";
    in
    {
      # Plain node package: `nix build .#bloch` → ./result/bin/bloch.
      # aarch64 also exposes `.#mobile-image`; x86_64 also exposes `.#cloud-image`.
      packages = forAllSystems (system:
        {
          bloch = blochPkgFor system;
          default = blochPkgFor system;
        }
        # Phone image is aarch64-only.
        // nixpkgs.lib.optionalAttrs (system == "aarch64-linux") {
          # Rung-0 artifact for the NixOS mobile tier. DoD: this produces a
          # flashable image / boot.img on a Linux host. It has NEVER been built
          # on this workstation (no Nix here) — "written, not built".
          mobile-image = mobilePinephone.outputs.default;
        }
        # Chiostro confidential-VM guest image is x86_64-only.
        // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          # `nix build .#cloud-image` on a Nix host. NEVER built/booted here.
          cloud-image =
            self.nixosConfigurations.postern-cloud.config.system.build.image;

          # Node appliance ISO: os/configuration.nix (mines on boot) on the live
          # installer CD. `nix build .#iso` → ./result/iso/*.iso on a Nix host.
          # WRITTEN, NOT BUILT/BOOTED here — the R2 ISO was built off-repo.
          iso =
            self.nixosConfigurations.postern-node-iso.config.system.build.isoImage;

          # Desktop ISO: os/desktop.nix (hardened GNOME + Tor + FDE + Postern
          # Browser) on the live installer CD. `nix build .#desktop-iso`.
          # WRITTEN, NOT BUILT/BOOTED here.
          desktop-iso =
            self.nixosConfigurations.postern-desktop-iso.config.system.build.isoImage;

          # Immutable + measured (dm-verity) image: os/attested.nix over the base
          # node. `nix build .#attested-image` → a repart disk image on a Nix
          # host. WRITTEN, NOT BUILT/BOOTED; the roothash is a design reference,
          # not a verified value (see os/attested.nix + os/ATTESTATION.md).
          attested-image =
            self.nixosConfigurations.postern-attested.config.system.build.image;

          # ── Seal gate (integration stub requested by Dev O1 / CS-5) ──────────
          # `nix build .#seal-gate` → postern-seal-gate + postern-seal-verify on
          # a Nix host. O2 owns ONLY this output attribute; the derivation body
          # (`os/seal-gate.nix`, `{ lib, rustPlatform }` signature) is O1/Cloud's.
          # HONEST STATUS: FAIL-CLOSED until a Nix host fills the 5 `lib.fakeHash`
          # `cargoLock.outputHashes` sentinels — the first `nix build .#seal-gate`
          # is DESIGNED to fail and print the real `sha256-…` for each git-sourced
          # crate (O1's `os/seal-gate/fill-outputhashes.sh`). Therefore
          # `nix flake check` is not fully green until O1 fills those hashes — a
          # documented, intentional cross-dev gate, not a defect here.
          seal-gate =
            (import nixpkgs { inherit system; }).callPackage ./os/seal-gate.nix { };
        });

      # Reusable NixOS module so an existing host can `services.bloch.enable`.
      # (The cloud config below and os/*.nix profiles consume this.)
      nixosModules.bloch = import ./os/bloch-node.nix;

      # `nix run .#boot-qemu` — the QEMU-aarch64 first-boot harness (Rung 1).
      # It builds `.#mobile-image`, boots it under qemu-system-aarch64 (TCG, no
      # KVM), captures the serial console to a log, and greps for the success
      # markers. Proves the SOFTWARE boot chain only — QEMU ≠ hardware.
      apps.aarch64-linux.boot-qemu =
        let pkgs = import nixpkgs { system = "aarch64-linux"; };
        in {
          type = "app";
          program = "${pkgs.writeShellApplication {
            name = "postern-boot-qemu-aarch64";
            runtimeInputs = [ pkgs.qemu pkgs.coreutils pkgs.gnugrep pkgs.nix ];
            text = builtins.readFile ./os/boot-harness/boot-qemu-aarch64.sh;
          }}/bin/postern-boot-qemu-aarch64";
        };

      # ── x86_64 harness apps (integration stubs for Dev O3 + Dev O5) ───────────
      # O2 owns ONLY these output attributes; the wrapped scripts are owned by
      # their requesting devs and live in dirs O2 does NOT create:
      #   .#boot-qemu-x86     → os/boot-harness-x86/boot-qemu-x86_64.sh  (Dev O3)
      #   .#attested-roothash → os/attested/extract-roothash.sh          (Dev O5)
      # Per the dependency order (O2 merges attr stubs FIRST), these are wired
      # BEFORE the owners land their scripts. Each attr is therefore guarded by
      # `builtins.pathExists`: until the owner's file exists the app EVALUATES
      # cleanly (so `nix flake check` is not blocked for O1/O5 by a missing O3
      # file, and vice-versa) but at RUN time prints a fail-closed "not yet
      # provided by its owner" message and exits 2. When the owner commits the
      # real harness the app lights up with zero further edits here.
      apps.x86_64-linux =
        let
          pkgs = import nixpkgs { system = "x86_64-linux"; };
          # Wrap a harness script as a runnable app, fail-closed if absent.
          mkHarnessApp = { name, script, runtimeInputs }: {
            type = "app";
            program = "${pkgs.writeShellApplication {
              inherit name runtimeInputs;
              text =
                if builtins.pathExists script
                then builtins.readFile script
                else ''
                  echo "${name}: harness script (${toString script}) not yet provided" >&2
                  echo "by its owning dev. The flake output attr is wired; awaiting the file." >&2
                  echo "This is a fail-closed integration stub, not a boot/extraction result." >&2
                  exit 2
                '';
            }}/bin/${name}";
          };
        in
        {
          # `nix run .#boot-qemu-x86` — Dev O3's x86_64 QEMU first-boot harness.
          # Builds .#iso/.#desktop-iso, boots qemu-system-x86_64 (TCG), captures
          # serial, grades against O4's shared check-boot-log.sh. QEMU ≠ hardware.
          boot-qemu-x86 = mkHarnessApp {
            name = "postern-boot-qemu-x86_64";
            script = ./os/boot-harness-x86/boot-qemu-x86_64.sh;
            runtimeInputs = [ pkgs.qemu pkgs.coreutils pkgs.gnugrep pkgs.nix ];
          };

          # `nix run .#attested-roothash` — Dev O5's dm-verity roothash extractor.
          # Builds .#attested-image and reads the systemd-repart roothash. The
          # roothash stays a design-reference PLACEHOLDER until this runs on a Nix
          # host; TPM2 PCR binding is HW-gated (cannot be faked in a VM).
          attested-roothash = mkHarnessApp {
            name = "postern-attested-roothash";
            script = ./os/attested/extract-roothash.sh;
            runtimeInputs = [ pkgs.coreutils pkgs.jq pkgs.nix ];
          };
        };

      # ── Cloud edition — Chiostro confidential-VM guest (Dev C-vm, C1–C2) ───────
      # Layers os/cloud.nix onto the shared bloch module + systemd-repart, for the
      # attested image consumed by `packages.x86_64-linux.cloud-image` above.
      # Build on a Nix host: `nix build .#cloud-image`.
      # HONEST STATUS: written on a non-Nix dev host — NOT built, NOT booted.
      # Chiostro is a TEE the customer can VERIFY (SEV-SNP/TDX remote attestation);
      # the managed-node service is a promise with NO cryptography. Hosting is
      # less private than self-hosting; running it makes Postern a data processor.
      nixosConfigurations.postern-cloud = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        specialArgs = { blochPkg = self.packages.x86_64-linux.bloch; };
        modules = [
          "${nixpkgs}/nixos/modules/image/repart.nix"
          self.nixosModules.bloch
          ./os/cloud.nix
        ];
      };

      # ── Node appliance ISO (consumed by packages.x86_64-linux.iso) ────────────
      # The live installer CD + the hardened node service, mining on boot.
      # Build: `nix build .#iso`. WRITTEN, NOT BUILT/BOOTED on this host.
      nixosConfigurations.postern-node-iso = nixosX86 [
        installerCd
        self.nixosModules.bloch
        ./os/configuration.nix
      ];

      # ── Desktop ISO (consumed by packages.x86_64-linux.desktop-iso) ───────────
      # The live installer CD + os/desktop.nix (hardened GNOME/GDM, LUKS machinery,
      # Tor, the Postern Browser). Build: `nix build .#desktop-iso`. The graphical
      # profile on a live ISO is exactly the surface the "iterate on a Nix host"
      # note in os/desktop.nix refers to — WRITTEN, NOT BUILT/BOOTED here.
      nixosConfigurations.postern-desktop-iso = nixosX86 [
        installerCd
        self.nixosModules.bloch
        ./os/desktop.nix
      ];

      # ── Attested image (consumed by packages.x86_64-linux.attested-image) ─────
      # Immutable + measured: os/attested.nix (dm-verity erofs root, UKI/measured
      # boot, systemd-repart) over the base node. Build: `nix build .#attested-image`.
      # WRITTEN, NOT BUILT/BOOTED; os_roothash is a design reference, not verified.
      nixosConfigurations.postern-attested = nixosX86 [
        "${nixpkgs}/nixos/modules/image/repart.nix"
        self.nixosModules.bloch
        ./os/configuration.nix
        ./os/attested.nix
      ];

      # ── Sloboda VM — NON-ATTESTABLE Waydroid bring-up host (Dev C, Wave-1) ─────
      # A throwaway x86_64 DEV/VM that imports os/sloboda-vm.nix → os/sloboda-compat.nix
      # (binder-enabled kernel + virtualisation.waydroid + headless Weston). It is
      # the Phase-0/1 boot target for the Waydroid tier: boot in QEMU and reach
      # `Session: RUNNING`. Build + run on a Linux+Nix host:
      #   nix build .#nixosConfigurations.sloboda-vm.config.system.build.vm
      #   ./result/bin/run-sloboda-vm-vm
      #
      # SEAL EXCLUSION (deliberate, structural): this entry is NOT in the attested
      # `postern-cloud` closure and MUST NOT be added to it. Its root is a mutable
      # qcow2 image — the OPPOSITE of the sealed read-only dm-verity root — and the
      # Android image is pulled from the network at `waydroid init`, so it can
      # never be measured, reproducible, or hardware-backed. `os_roothash` does not
      # and cannot cover this host. It carries its own bloch-free minimal profile
      # and does NOT thread the bloch node in. WRITTEN, NOT BUILT/BOOTED here.
      nixosConfigurations.sloboda-vm = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [ ./os/sloboda-vm.nix ];
      };

      # ── `nix flake check` targets ─────────────────────────────────────────────
      # A deliberately CHEAP smoke check so `nix flake check` always has a
      # definitely-buildable target that proves the flake evaluates end-to-end on
      # each system, independent of the heavy image builds. `nix flake check` also
      # evaluates every other output (packages/apps/nixosConfigurations) and builds
      # the packages — so a FULLY green check on the VM additionally requires:
      #   • O1/CS-5 to have filled the 5 seal-gate fakeHash sentinels (else
      #     `.#seal-gate` fail-closes by design), and
      #   • a frozen (non-seed) flake.lock (scripts/flake-check.sh enforces this).
      # This smoke check does NOT assert any image booted — built ≠ booted.
      checks = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; };
        in {
          flake-eval-smoke = pkgs.runCommand "flake-eval-smoke-${system}" { } ''
            printf 'flake outputs evaluated for %s\n' "${system}" > "$out"
          '';
        });
    };
}
