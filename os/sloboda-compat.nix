# SPDX-License-Identifier: MIT OR Apache-2.0
#
# os/sloboda-compat.nix — Waydroid NixOS wiring (Phase 0 of the Waydroid bring-up).
# A Postern Labs product-tier: "Postern for postmarketOS — community edition."
#
# ===========================================================================
# NON-ATTESTABLE TIER — EXCLUDED FROM THE POSTERN SEAL / os_roothash CLOSURE
# ===========================================================================
# READ THIS BEFORE WIRING THE MODULE ANYWHERE.
#
# This module stands up a WAYDROID container: a full AOSP/Google Android userland
# running in LXC against the host kernel. It is the deliberate NON-ATTESTABLE
# escape hatch. It is NOT Porog (the stock-Android managed-profile product) and it
# is NEVER "Postern OS."
#
#   - This tier is NOT attested and MUST NOT be sealed. `os_roothash` (the
#     dm-verity roothash from os/attested.nix / the Chiostro cloud image) says
#     NOTHING about what runs inside Waydroid. The Android system+vendor image is
#     MUTABLE state pulled over the network at `waydroid init` — it can never be
#     part of a measured, reproducible closure, so it is NOT hardware-backed and
#     carries NO attestation guarantee.
#   - HOW IT IS EXCLUDED (by construction, not by convention):
#       * This file is NOT imported by os/configuration.nix, os/attested.nix,
#         os/cloud.nix, os/mobile.nix, or any module in the attested
#         `nixosConfigurations.postern-cloud` list in flake.nix. The sealed image
#         is `config.system.build.toplevel` of THAT closure; a module that is
#         never imported into it is never measured into the verity roothash.
#       * It is imported by EXACTLY ONE host: os/sloboda-vm.nix (the throwaway
#         DEV/VM bring-up host, `nixosConfigurations.sloboda-vm`), whose root is
#         a mutable, writable qcow2 image and is deliberately NOT sealed.
#       * DO NOT add `./sloboda-compat.nix` to the imports of any sealed/attested
#         profile. Import it ONLY into a non-attested DEV/VM host whose image is
#         explicitly non-attested.
#       * Entering Android = data leaves the sealed base. Treat the boundary as a
#         one-way door, the same way apps/sloboda (the wrapper) is treated
#         as NONATTEST by scripts/check-trust-labels.sh. Keep this Nix wiring on
#         the same side of that line.
#   - Play Integrity STRONG is EXPECTED to FAIL here (uncertified container, no
#     hardware TEE keymaster). We DISCLOSE that; we never spoof it. StrongBox /
#     keymaster attestation is NOT available in this tier.
#
# STATUS (honesty gates G1–G4): SCAFFOLD · DESIGN ONLY · UNAUDITED ·
# reference-prototype · deferred-to-VM. Authored on a non-Nix macOS host: this
# expression is idiomatic but has NEVER been evaluated or built here (`nix` cannot
# run on the build host). Nothing here has booted an Android container. Eval +
# first boot are deferred to the Linux+Nix VM
# (docs/design/waydroid-01-boot-bringup.md, Phase 0):
#   nix flake check  →  build the non-attested os/sloboda-vm.nix host that imports
#   this module  →  zgrep ANDROID_BINDER /proc/config.gz  →  waydroid init -s
#   VANILLA  →  Session: RUNNING.
# "written, not built" — do not read this file as proof that Waydroid works.
#
# The consentGate wiring below carries the same caveat, with these proofs
# explicitly VM-BLOCKED (listed, not claimed):
#   - `nix build .#nixosConfigurations.sloboda-vm.config.system.build.vm` eval +
#     VM boot (nix cannot run on this build host);
#   - the boot-ordering race: the /run projection exists BEFORE the first
#     wrapper read (Before=/RequiredBy= edges honoured by waydroid-container);
#   - waydroid-container stop privileges for the kill path on a live host;
#   - tmpfiles dir modes (0700 canonical / 0755 projection) on a real boot.
# What IS proven on this host: the gate writer's node suites and the byte-parity
# of the installed unit text with systemdUnit() (os/test-sloboda-gate-boot-unit.mjs).
# ===========================================================================
{ config, lib, pkgs, ... }:

let
  cfg = config.postern.slobodaCompat;
  # A dedicated runtime dir for the headless compositor. Kept off any user's
  # $XDG_RUNTIME_DIR so the service is self-contained and seat-less.
  westonRuntimeDir = "/run/sloboda-weston";

  # ── Consent-gate packaging (opt-in via cfg.consentGate.enable) ──────────────
  # The gate WRITER ships EXACTLY as authored in apps/sloboda-gate: the POSIX-sh
  # shim + the node ESM writer + its store module, wrapped only to guarantee
  # node on PATH. Nothing is patched at package time — what the node suites
  # prove (test-store/test-gated/test-ui-parity) is byte-for-byte what the host
  # runs. The shim execs `node <its own dir>/sloboda-gated.mjs`, so all three
  # files land in one libexec dir and $out/bin carries only the PATH wrapper.
  gateSrc = ../apps/sloboda-gate;
  slobodaGated = pkgs.runCommand "sloboda-gated"
    { nativeBuildInputs = [ pkgs.makeWrapper ]; } ''
    install -Dm755 ${gateSrc}/sloboda-gated     $out/libexec/sloboda-gate/sloboda-gated
    install -Dm644 ${gateSrc}/sloboda-gated.mjs $out/libexec/sloboda-gate/sloboda-gated.mjs
    install -Dm644 ${gateSrc}/gate-store.mjs    $out/libexec/sloboda-gate/gate-store.mjs
    makeWrapper $out/libexec/sloboda-gate/sloboda-gated $out/bin/sloboda-gated \
      --prefix PATH : ${lib.makeBinPath [ pkgs.nodejs ]}
  '';

  # The operator wrapper (apps/sloboda) — the READ side of the gate. Packaged
  # verbatim; `sloboda` sources paw-lib.sh from its own bin dir, so both live in
  # $out/bin and stay siblings through the systemPackages symlink farm.
  slobodaWrapper = pkgs.runCommand "sloboda-wrapper" { } ''
    install -Dm755 ${../apps/sloboda/bin/sloboda}    $out/bin/sloboda
    install -Dm644 ${../apps/sloboda/bin/paw-lib.sh} $out/bin/paw-lib.sh
  '';

  # sloboda-gate-boot.service — installed from the CHECKED-IN template so the
  # unit text is byte-consistent with what `sloboda-gated systemd-unit`
  # (sloboda-gated.mjs systemdUnit()) emits; the parity is pinned by
  # os/test-sloboda-gate-boot-unit.mjs (`node os/test-sloboda-gate-boot-unit.mjs`,
  # runnable on any host with node). ONLY the @sloboda-gated@ ExecStart
  # placeholder is substituted here — the ordering contract
  # (Before=waydroid-container.service, `<bin> boot`, Type=oneshot +
  # RemainAfterExit=yes, RequiredBy=waydroid-container.service) is owned by the
  # node-tested writer, never hand-edited in nix.
  gateBootUnitText = builtins.replaceStrings
    [ "@sloboda-gated@" ] [ "${slobodaGated}/bin/sloboda-gated" ]
    (builtins.readFile ./sloboda-gate-boot.service.in);

  # ── package "sloboda-tor-egress-loop" → runs as the sloboda-tor-watch unit ──
  # Feeds the LIVE "is Tor usable?" signal into the gate (`sloboda-gated tor
  # up|down` → egress.torBootstrapped). The gate is fail-closed: until a `tor
  # up` is recorded, the projection says egress=held and the wrapper must hold
  # container traffic. The probe is LOCAL-ONLY (no clearnet, no telemetry).
  #
  # HONESTY — the default probe is a COARSE proxy, disclosed, not hidden:
  # `systemctl is-active tor.service` relies on tor's sd_notify readiness
  # (Type=notify fires at initial bootstrap), so it is a fair "came up" signal
  # but a WEAK "still has circuits" signal — a later circuit loss does not flip
  # the unit inactive. A strong probe (control-port GETINFO
  # status/circuit-established) is VM/device work; point torProbeCommand at one
  # there. The skew is bounded either way: this flag can never open a data
  # bridge (bridges are separate consent levers) and can never widen egress off
  # Tor (torOnly is pinned true by gate-store.normalize()).
  slobodaTorEgressLoop = pkgs.writeShellScriptBin "sloboda-tor-egress-loop" ''
    # sloboda-tor-egress-loop — Tor liveness → consent-gate recorder.
    # NON-ATTESTABLE Sloboda tier; UNAUDITED; local probe only, no clearnet.
    set -eu
    prev=""
    while :; do
      if ${cfg.consentGate.torProbeCommand} >/dev/null 2>&1; then
        cur=up
      else
        cur=down
      fi
      # Record only transitions; if the recorder fails, keep prev unset so the
      # write is retried next tick (fail-closed: an unrecorded 'up' only HOLDS
      # egress, never opens it).
      if [ "$cur" != "$prev" ]; then
        if ${slobodaGated}/bin/sloboda-gated tor "$cur"; then
          prev="$cur"
        fi
      fi
      sleep ${toString cfg.consentGate.torWatchIntervalSec}
    done
  '';
in
{
  options.postern.slobodaCompat = {
    enable = lib.mkEnableOption ''
      the NON-ATTESTABLE Waydroid Sloboda tier (LXC + Android userland on
      the host kernel). Never enable this inside a sealed/attested profile'';

    compositor = lib.mkOption {
      type = lib.types.enum [ "weston" "phosh" "none" ];
      default = "weston";
      description = ''
        Which Wayland compositor to make available for the Android display path.
        Waydroid renders the Android surface into a Wayland surface; the container
        can reach `Session: RUNNING` with NOTHING on screen unless a compositor is
        live (see docs/design/waydroid-01-boot-bringup.md §2.4).
          * "weston" — minimal headless-capable compositor for the x86_64 VM
            (`weston --backend=headless-backend.so`). The bring-up default.
          * "phosh"  — the mobile shell for a real aarch64 phone (postmarketOS /
            Mobile-NixOS target). Provided as a package hook only; the device port
            wires the actual session.
          * "none"   — provide no compositor (container control-flow only; the
            display path is intentionally unproven).
      '';
    };

    westonHeadless = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Run a headless Weston compositor as a system service so the Android
        display path (`sloboda ui` → `waydroid show-full-ui`, matrix item 5) has a
        live Wayland socket without a seat/GPU. Software GL only (llvmpipe /
        SwiftShader) — this proves ONLY the software fallback render path, NEVER
        Lima/Panfrost hardware GL (matrix item 11 is device-only). Requires
        `compositor = "weston"`. Reaching `Session: RUNNING` (Phase 1) does NOT
        depend on this; the compositor is the Phase-2 display proof. Off by
        default; the DEV/VM host (os/sloboda-vm.nix) turns it on. deferred-to-VM:
        the exact `weston` backend flag has drifted across releases
        (`headless-backend.so` vs `--backend=headless`) — tune on the VM.
      '';
    };

    mountBinderfs = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Provide an explicit systemd mount unit for binderfs at /dev/binderfs
        (`mount -t binder binder /dev/binderfs`). OFF by default because the
        nixpkgs `virtualisation.waydroid` module + `waydroid-container` already
        mount binderfs on container start; enabling this as well can double-mount.
        This is a belt-and-suspenders hook for kernels/setups where waydroid does
        NOT auto-mount (see docs/design/waydroid-01-boot-bringup.md §1.3). Never a
        substitute for the kernel actually carrying CONFIG_ANDROID_BINDERFS.
      '';
    };

    consentGate = {
      enable = lib.mkEnableOption ''
        the on-host consent-gate wiring for the NON-ATTESTABLE Sloboda tier:
        installs the gate writer (`sloboda-gated`, apps/sloboda-gate), the
        boot-ordering oneshot (sloboda-gate-boot.service) that re-derives the
        /run projection and re-asks session consent BEFORE
        waydroid-container.service starts, the sloboda-tor-watch egress loop
        (package sloboda-tor-egress-loop), and the canonical/projection dirs
        (tmpfiles). The gate certifies nothing — it records operator consent;
        deferred-to-VM: the boot-ordering race (projection present before the
        first wrapper read) is unproven until the VM boots it'';

      torWatchIntervalSec = lib.mkOption {
        type = lib.types.ints.positive;
        default = 10;
        description = ''
          Seconds between sloboda-tor-watch probe polls. Each poll is local;
          only up/down TRANSITIONS are recorded into the gate.
        '';
      };

      torProbeCommand = lib.mkOption {
        type = lib.types.str;
        default = "${pkgs.systemd}/bin/systemctl is-active --quiet tor.service";
        defaultText = lib.literalExpression
          ''"''${pkgs.systemd}/bin/systemctl is-active --quiet tor.service"'';
        description = ''
          LOCAL command whose exit status is the "is Tor usable?" signal the
          sloboda-tor-watch loop records via `sloboda-gated tor up|down`. The
          default is a coarse, DISCLOSED proxy (tor's sd_notify readiness):
          good for "came up", weak for "still has circuits". On the VM/device,
          point this at a control-port `GETINFO status/circuit-established`
          probe. Must never touch the clearnet: a probe that needs the network
          to prove the network defeats the point. Fail-closed either way — a
          wrong 'down' only HOLDS egress; a stale 'up' cannot open a bridge or
          widen egress off Tor (both pinned by gate-store.normalize()).
        '';
      };
    };

    systemType = lib.mkOption {
      type = lib.types.enum [ "VANILLA" "FOSS" "GAPPS" ];
      default = "VANILLA";
      description = ''
        Documentation-only default for the wrapper's PAW_SYSTEM_TYPE (the image
        `waydroid init` pulls). VANILLA = AOSP, no Google, no microG — the private
        base and the ONLY default. This module does NOT redistribute any GMS; it
        records the intended default so the bring-up runbook is explicit. FOSS
        (microG) images are frequently 404 per-arch — verify at init, never assume.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      # Seal-exclusion tripwire: refuse to coexist with the sealed profile in one
      # config. If os/attested.nix's read-only sealed root is active
      # (fileSystems."/".options = [ "ro" ]), this NON-ATTESTABLE tier must not be.
      # (Belt-and-suspenders on top of "never import it into the attested module
      # list" — the real exclusion is structural, see the header.)
      {
        assertion = !(config.fileSystems ? "/"
          && (config.fileSystems."/".options or [ ]) != [ ]
          && lib.elem "ro" (config.fileSystems."/".options or [ ]));
        message = ''
          os/sloboda-compat.nix (NON-ATTESTABLE Waydroid tier) was enabled on a
          host whose "/" is mounted read-only — the signature of the sealed
          os/attested.nix profile. This tier must NEVER be part of the attested /
          Postern-Seal closure. Import it only into a non-attested DEV/VM host.
        '';
      }
      # The headless compositor service only makes sense with the weston backend.
      {
        assertion = cfg.westonHeadless -> (cfg.compositor == "weston");
        message = ''
          postern.slobodaCompat.westonHeadless = true requires compositor =
          "weston" (the headless service runs weston). Set compositor = "weston"
          or disable westonHeadless.
        '';
      }
    ];

    # ── Binder: the single hardest gate ────────────────────────────────────────
    # Waydroid is NOT an emulator; the Android userland speaks Android IPC against
    # the HOST kernel, which must provide binder + binderfs. On a mainline/desktop
    # x86_64 kernel (the VM case) these are available; we force the symbols ON so a
    # custom/VM kernel build cannot silently drop them. This triggers a FULL kernel
    # rebuild (structured-config override) — budget the VM's first build for it. On
    # a trimmed aarch64 phone kernel they are usually OFF and need a device-kernel
    # rebuild (that is a T2/DEV concern; the VM proves the mechanism only).
    boot.kernelPatches = [
      {
        name = "postern-waydroid-binder";
        patch = null; # config-only override, no source patch
        extraStructuredConfig = {
          ANDROID_BINDER_IPC = lib.kernel.yes; # CONFIG_ANDROID_BINDER_IPC=y
          ANDROID_BINDERFS = lib.kernel.yes; # CONFIG_ANDROID_BINDERFS=y
          # memfd replaces the legacy ashmem on modern kernels; ashmem is NOT a
          # hard gate (modern Waydroid uses memfd). binder/binderfs are the gate.
          MEMFD_CREATE = lib.kernel.yes;
        };
      }
    ];
    # Load the binder module early (harmless if built-in as =y). Waydroid's own
    # units mount binderfs at /dev/binderfs; the nixpkgs waydroid module also sets
    # the binder device names via modprobe options.
    boot.kernelModules = [ "binder_linux" ];

    # ── Waydroid + LXC (the nixpkgs module pulls LXC, the waydroid-container
    #    systemd service, and the binderfs mount) ────────────────────────────────
    virtualisation.waydroid.enable = true;
    virtualisation.lxc.enable = lib.mkDefault true;

    # ── Optional explicit binderfs mount (§1.3) ─────────────────────────────────
    # OFF by default (waydroid-container mounts it); opt-in belt-and-suspenders.
    systemd.mounts = lib.mkIf cfg.mountBinderfs [
      {
        description = "Android binderfs for Waydroid (NON-ATTESTABLE Sloboda tier)";
        what = "binder";
        where = "/dev/binderfs";
        type = "binder";
        wantedBy = [ "multi-user.target" ];
        before = [ "waydroid-container.service" ];
      }
    ];

    # ── Wayland compositor for the display path (§2.4) ──────────────────────────
    environment.systemPackages =
      lib.optionals (cfg.compositor == "weston") [ pkgs.weston ]
      ++ lib.optionals (cfg.compositor == "phosh") [ pkgs.phosh ]
      ++ [
        # The wrapper (apps/sloboda) drives waydroid; ship it + waydroid on
        # PATH so the bring-up runbook can run it against REAL waydroid (PAW_DRYRUN=0).
        pkgs.waydroid
        slobodaWrapper
      ]
      # The consent-gate writer (+ the tor-watch loop binary, so an operator can
      # run one iteration by hand while debugging on the VM).
      ++ lib.optionals cfg.consentGate.enable [ slobodaGated slobodaTorEgressLoop ];

    # ── Headless Weston as a service (opt-in; the VM host turns it on) ───────────
    # Gives the Android surface a live Wayland socket at ${westonRuntimeDir}. This
    # is SOFTWARE GL only (llvmpipe/SwiftShader) — it proves the software fallback
    # render path, NEVER hardware GL (Lima/Panfrost is device-only, matrix #11).
    systemd.services.sloboda-weston = lib.mkIf cfg.westonHeadless {
      description = "Headless Weston compositor — Sloboda/Waydroid display path (NON-ATTESTABLE tier, software GL only)";
      wantedBy = [ "multi-user.target" ];
      after = [ "systemd-user-sessions.service" ];
      serviceConfig = {
        Type = "simple";
        # Own dynamic user + runtime dir so the compositor needs no seat/login.
        DynamicUser = true;
        SupplementaryGroups = [ "video" "render" ];
        RuntimeDirectory = "sloboda-weston";
        RuntimeDirectoryMode = "0700";
        Environment = [
          "XDG_RUNTIME_DIR=${westonRuntimeDir}"
          "WAYLAND_DISPLAY=wayland-1"
          # Force software rendering; there is no GPU on the bring-up VM.
          "LIBGL_ALWAYS_SOFTWARE=1"
          "WLR_RENDERER=pixman"
        ];
        # NOTE (deferred-to-VM): headless backend flag drifted across weston
        # releases. `--backend=headless-backend.so` matches the bring-up runbook
        # (docs §5.2); on a newer weston use `--backend=headless`. Tune on the VM.
        ExecStart = "${pkgs.weston}/bin/weston --backend=headless-backend.so --socket=wayland-1 --idle-time=0";
        Restart = "on-failure";
        RestartSec = 2;
      };
    };

    # ── Consent gate (opt-in; cfg.consentGate.enable) ────────────────────────────
    # The /run projection lives on tmpfs and EVAPORATES on reboot, so this oneshot
    # re-derives it from the persistent canonical (and clears scope:"session"
    # consent — the re-ask) BEFORE waydroid-container.service can start. Installed
    # VERBATIM from the checked-in template that mirrors sloboda-gated.mjs
    # systemdUnit() byte-for-byte (pinned: node os/test-sloboda-gate-boot-unit.mjs)
    # — hence systemd.units (raw text), NOT systemd.services (which would re-render
    # the text and break the byte contract). wantedBy/requiredBy below re-state the
    # unit's own [Install] section because NixOS acts on these attrs, not on
    # [Install] in raw text. deferred-to-VM (matrix #13): that no wrapper read can
    # land before this unit has run — the projection-before-first-read race — and
    # that waydroid-container honours the Before=/RequiredBy= edges are UNPROVEN
    # until the VM boots this. A failed gate unit keeps the container DOWN
    # (RequiredBy): fail-closed, never fail-open.
    systemd.units."sloboda-gate-boot.service" = lib.mkIf cfg.consentGate.enable {
      text = gateBootUnitText;
      wantedBy = [ "multi-user.target" ];
      requiredBy = [ "waydroid-container.service" ];
    };

    # sloboda-tor-watch — the sloboda-tor-egress-loop package as a system unit.
    # Ordered after the boot re-projection (which clears torBootstrapped: Tor is
    # definitionally down at boot until re-signalled). Runs as root: the canonical
    # state dir is 0700 root-owned. Restart=always so a crashed watch cannot
    # silently freeze a stale 'up' — though even frozen, a stale 'up' opens no
    # bridge and never widens egress off Tor (pinned rails).
    systemd.services.sloboda-tor-watch = lib.mkIf cfg.consentGate.enable {
      description = "Sloboda consent-gate: Tor egress watch (records tor up|down; non-attestable tier)";
      wantedBy = [ "multi-user.target" ];
      after = [ "sloboda-gate-boot.service" "tor.service" ];
      wants = [ "tor.service" ];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${slobodaTorEgressLoop}/bin/sloboda-tor-egress-loop";
        Restart = "always";
        RestartSec = 5;
      };
    };

    # Pre-create the two gate dirs with the EXACT modes the writer pins
    # (sloboda-gated.mjs: CANON_DIR_MODE = 0o700, PROJECTION_DIR_MODE = 0o755).
    # Belt-and-suspenders: atomicWrite() mkdirs + chmods the same modes on every
    # write, so a missing tmpfiles pass cannot loosen anything — but pre-creating
    # them makes the 0700 canonical dir exist before ANY consumer looks, and
    # tmpfiles is the idiomatic owner of /run entries. On-device verification of
    # the resulting modes is VM work.
    systemd.tmpfiles.rules = lib.mkIf cfg.consentGate.enable [
      "d /var/lib/postern/sloboda-gate 0700 root root -"
      "d /run/postern/consent 0755 root root -"
    ];

    # Egress is Tor-only by design (gate rail), so the tier needs a local tor
    # client for the watch loop to observe. mkDefault: a host that runs its own
    # tor arrangement can override without fighting this module.
    services.tor = lib.mkIf cfg.consentGate.enable {
      enable = lib.mkDefault true;
      client.enable = lib.mkDefault true;
    };

    # Network egress is required at `waydroid init` (the Android image is PULLED,
    # not in the rootfs). This is the first real network trust surface of the tier
    # and another reason it can never be part of a sealed, offline-measured closure.
    networking.firewall.enable = lib.mkDefault true;

    # A loud, machine-visible marker that this profile is the non-attestable tier,
    # so an operator on the console cannot mistake it for the sealed Postern OS.
    users.motd = lib.mkDefault ''
      ▲ Sloboda (Waydroid) — NON-ATTESTABLE tier · NOT sealed · UNAUDITED

      This host runs an Android userland in LXC on the host kernel. It is
      never covered by the Postern Seal, and os_roothash cannot measure it. Play
      Integrity STRONG is expected to FAIL here — that is disclosed, not a defect.
      Entering Android means data leaves any sealed base. Do not attest this tier.
    '';
  };
}
