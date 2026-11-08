# SPDX-License-Identifier: MIT OR Apache-2.0
# enterprise-profile.nix — self-hosting Nix profile SKELETON for the Postern
# Enterprise edition.
#
# REPRODUCIBLE-BY-DESIGN, NOT REPRODUCED. Nix gives content-addressed, pinned
# inputs and a deterministic build graph by construction — but no independent
# bit-for-bit reproduction is claimed or attested here. "Reproducible" is a
# property you can check (nix build --rebuild, diffoscope), not one we have
# discharged for you.
#
# NOTE: written on a non-Nix host — NOT built here. It mirrors the style of the
# repo's os/*.nix modules (see ../../../os/cloud.nix). Iterate on a real Nix
# host. Nothing here is hardened, audited, or production-ready.
#
# Flake wiring sketch (operator-run, on a Nix host):
#   nixosConfigurations.postern-enterprise = nixpkgs.lib.nixosSystem {
#     inherit system;
#     modules = [ ./enterprise-profile.nix ];
#   };
{ config, lib, pkgs, ... }:

let
  cfg = config.services.postern-enterprise;
in
{
  options.services.postern-enterprise = {
    enable = lib.mkEnableOption "the Postern Enterprise edition (self-hosted)";

    package = lib.mkOption {
      type = lib.types.package;
      description = ''
        The enterprise artifact to run. Supply a package you built from source
        (strongest verification) or one you verified with
        ../signing/verify-build.sh. No default: this is a skeleton.
      '';
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 8080;
      description = "Loopback port the service listens on; front it with your own TLS.";
    };

    stateDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/postern";
      description = "Persistent data directory (operator-owned).";
    };

    telemetry = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Off by construction. No analytics, no phone-home. Leave false.";
    };
  };

  config = lib.mkIf cfg.enable {
    # Dedicated, unprivileged, dynamic system user — no login, minimal surface.
    users.users.postern = {
      isSystemUser = true;
      group = "postern";
      home = cfg.stateDir;
      createHome = true;
    };
    users.groups.postern = { };

    systemd.services.postern-enterprise = {
      description = "Postern Enterprise edition (self-hosted, reproducible-by-design)";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      environment = {
        POSTERN_TELEMETRY = if cfg.telemetry then "on" else "off";
        TZ = "UTC";
      };

      serviceConfig = {
        # Replace ExecStart with the real service entrypoint from cfg.package.
        ExecStart = "${cfg.package}/bin/postern-enterprise --port ${toString cfg.port}";
        User = "postern";
        Group = "postern";
        StateDirectory = "postern";
        WorkingDirectory = cfg.stateDir;

        # Privacy/hardening posture (sandbox defaults; tune to the real binary).
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
        ReadWritePaths = [ cfg.stateDir ];
        CapabilityBoundingSet = "";
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
      };
    };
  };
}
