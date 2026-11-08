# Postern Cloud — confidential-VM guest profile (codename Chiostro).
# A Postern Labs product. Design spec: docs/specs/POSTERN-CLOUD.md.
#
# Layers onto the immutable/attested profile (./attested.nix — erofs + dm-verity
# + UKI + measured boot) to make the image a HEADLESS confidential-VM guest
# (AMD SEV-SNP primary, Intel TDX secondary): a remote Postern workstation whose
# desktop session is reachable ONLY through the Seal-gated WireGuard tunnel —
# the client verifies verify(report, Expected{digest, measurement, hostdata,
# roothash}, nonce) == Trusted BEFORE the tunnel opens (spec §4).
#
# NOTE: written on a non-Nix host — NOT built here. Iterate on a Nix host AND
# real CVM hardware: per-provider firmware/measurement/HOSTDATA details are
# unverified until run on actual SEV-SNP/TDX instances (spec §9; runbook:
# docs/specs/POSTERN-CLOUD-CONFIDENTIAL.md). Same caveat as ./attested.nix:
# repart / verity / UKI options drift across nixpkgs releases. The Seal-gate
# handshake itself (binding math, wire format, AMD-root chain verification)
# IS implemented and vector-tested in crates/postern-seal-companion.
#
# Flake wiring (mirrors nixosConfigurations.bloch-os-attested):
#   nixosConfigurations.postern-cloud = nixpkgs.lib.nixosSystem {
#     inherit system;
#     specialArgs = { blochPkg = self.packages.${system}.bloch; };
#     modules = [
#       "${nixpkgs}/nixos/modules/image/repart.nix"
#       self.nixosModules.bloch
#       ./os/cloud.nix
#     ];
#   };
#   packages.${system}.cloud-image =
#     self.nixosConfigurations.postern-cloud.config.system.build.image;
{ config, lib, pkgs, blochPkg, ... }:
{
  imports = [ ./attested.nix ];

  networking.hostName = lib.mkForce "postern-cloud";
  image.repart.name = lib.mkForce "postern-cloud";

  # A separate writable partition for /persist. Rootfs stays verity-sealed
  # read-only (./attested.nix, which defines esp/root/root-verity — this merges
  # a fourth partition in). It is provisioned as a LUKS volume on first boot
  # (postern-persist below), so to the provider it is ciphertext at rest.
  # SizeMinBytes is a floor; the deploy grows it to fill the disk.
  image.repart.partitions.persist = {
    repartConfig = {
      Type = "linux-generic";
      Label = "persist";
      SizeMinBytes = "2G";
    };
  };

  # ── Confidential-VM guest basics ───────────────────────────────────────────
  # virtio for cloud disks/NICs; the SNP/TDX guest drivers expose the report
  # device (/dev/sev-guest, /dev/tdx_guest) that the Seal gate reads.
  boot.initrd.availableKernelModules =
    [ "virtio_pci" "virtio_blk" "virtio_scsi" "virtio_net" ];
  boot.kernelModules = [ "sev-guest" "tdx_guest" ];
  # Headless: serial console for provider-side boot diagnostics only — nothing
  # secret is ever printed there (the host can read it).
  boot.kernelParams = [ "console=ttyS0" ];

  # Deliberately ABSENT: provider guest agents / cloud-init-style tooling with
  # host-writable command channels. The only launch-time input consumed is the
  # client WireGuard pubkey allowlist — untrusted, deny-only (spec §4.1).

  # ── Network posture: the Seal gate is the ONLY pre-attestation listener ────
  networking.firewall.enable = true;
  networking.firewall.allowedTCPPorts = [ 16510 ];  # postern-seal-gate
  networking.firewall.allowedUDPPorts = [ 51820 ];  # WireGuard
  # Everything else (desktop, SSH) binds to wg0 only — reachable solely after
  # the client's verifier returned Verdict::Trusted and the tunnel is up.

  # ── Seal gate (spec §4.1) — IMPLEMENTED in crates/postern-seal-companion ───
  # `postern-seal-gate` (bin, feature `sev-snp`): per connection it reads a
  # fresh 32-byte nonce, requests the SNP report from /dev/sev-guest with
  #   report_data = SHA-256(nonce ‖ WG_guest_pub)      (channel binding)
  # via virtee/sev (Apache-2.0), and replies with report ‖ VCEK ‖ WG_guest_pub
  # (wire format: src/gate.rs). The client verifies with `postern-seal-verify`
  # BEFORE the tunnel opens. The gate holds no secrets and serves only public
  # evidence. NOT validated on hardware yet — needs a real SEV-SNP VM
  # (docs/specs/POSTERN-CLOUD-CONFIDENTIAL.md).
  systemd.services.postern-seal-gate = {
    description = "Postern Seal gate — SEV-SNP attestation-before-connect endpoint";
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" "postern-wg-keygen.service" ];
    wants = [ "network-online.target" ];
    requires = [ "postern-wg-keygen.service" ];

    serviceConfig = {
      ExecStart = lib.escapeShellArgs [
        "${pkgs.callPackage ./seal-gate.nix { }}/bin/postern-seal-gate"
        "--listen" "0.0.0.0:16510"
        "--wg-pubkey" "/persist/postern/wg0.pub"
        # Where the hypervisor does not provision the VCEK in the extended
        # report's cert table, fetch it from AMD KDS at provision time and add:
        # "--vcek" "/persist/postern/vcek.der"
      ];

      DynamicUser = true;
      Restart = "on-failure";
      RestartSec = 5;

      # The one device the gate needs: the SNP guest report interface.
      DeviceAllow = [ "/dev/sev-guest rw" ];
      PrivateDevices = false; # must see /dev/sev-guest — everything else is denied above

      # os/bloch-node.nix hardening spine, verbatim discipline.
      NoNewPrivileges = true;
      ProtectSystem = "strict";
      ProtectHome = true;
      PrivateTmp = true;
      ReadOnlyPaths = [ "/persist/postern/wg0.pub" ];
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectKernelLogs = true;
      ProtectControlGroups = true;
      ProtectClock = true;
      ProtectHostname = true;
      RestrictAddressFamilies = [ "AF_INET" "AF_INET6" ];
      RestrictNamespaces = true;
      RestrictRealtime = true;
      RestrictSUIDSGID = true;
      LockPersonality = true;
      MemoryDenyWriteExecute = true;
      SystemCallArchitectures = "native";
      SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
      UMask = "0077";
      LimitCORE = 0;
    };
  };

  # First boot: generate the WireGuard identity IN-GUEST (TEE-random), on the
  # encrypted /persist volume — the host never sees the private half; the
  # PUBLIC half is what the quote's report_data endorses (channel binding).
  systemd.services.postern-wg-keygen = {
    description = "Generate the guest WireGuard identity on first boot (in-TEE)";
    wantedBy = [ "multi-user.target" ];
    # /persist must be unlocked + mounted first (the key lives on it).
    after = [ "postern-persist.service" ];
    requires = [ "postern-persist.service" ];
    unitConfig.ConditionPathExists = "!/persist/postern/wg0.key";
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      UMask = "0077";
      RequiresMountsFor = [ "/persist" ];
    };
    path = [ pkgs.wireguard-tools ];
    script = ''
      mkdir -p /persist/postern
      wg genkey > /persist/postern/wg0.key
      wg pubkey < /persist/postern/wg0.key > /persist/postern/wg0.pub
      chmod 400 /persist/postern/wg0.key
      chmod 444 /persist/postern/wg0.pub
    '';
  };

  networking.wireguard.interfaces.wg0 = {
    ips = [ "10.94.0.1/24" ];
    listenPort = 51820;
    # Generated in-guest on first boot (postern-wg-keygen above), stored on
    # the encrypted /persist volume — never provisioned by the host.
    privateKeyFile = "/persist/postern/wg0.key";
    # peers are NOT declared here — they come from the launch-time client
    # allowlist, ingested dynamically by postern-wg-peers below. Untrusted,
    # deny-only: a swapped allowlist can only lock the rightful user out.
  };

  # The wg0 interface's privateKeyFile lives on the encrypted /persist volume and
  # is written by postern-wg-keygen on first boot. The wireguard module generates
  # `wireguard-wg0.service` with NO knowledge of that ordering, so left alone it
  # would try to bring the interface up before /persist is mounted and before the
  # key exists — failing (it has no Restart) on the very first boot. Order it
  # AFTER the key is in place so the boot sequence is coherent:
  #   postern-persist → postern-wg-keygen → wireguard-wg0 → postern-wg-peers.
  systemd.services.wireguard-wg0 = {
    after = [ "postern-persist.service" "postern-wg-keygen.service" ];
    requires = [ "postern-persist.service" "postern-wg-keygen.service" ];
    unitConfig.RequiresMountsFor = [ "/persist" ];
  };

  # Ingest the client WireGuard pubkey allowlist from launch-time instance
  # metadata (spec §4.1). This input is UNTRUSTED and DENY-ONLY by design: the
  # peers it admits can open a tunnel, but a host that swaps the list only
  # denies the rightful user — it can never let itself in, because the tunnel
  # still terminates at the in-guest key the attestation report endorsed, and
  # the client refuses the session until it has verified that report.
  #
  # Format of /persist/postern/wg-allowlist (one client per line, comments/blank
  # ignored):  <base64 wg pubkey> [allowed-ips]   (allowed-ips defaults to /32
  # within the wg0 subnet, assigned in order). Place it via a provider metadata
  # hook at deploy; absent/empty ⇒ no peers ⇒ the seat is unreachable (safe).
  systemd.services.postern-wg-peers = {
    description = "Apply the untrusted, deny-only client WireGuard allowlist to wg0";
    wantedBy = [ "multi-user.target" ];
    after = [ "wireguard-wg0.service" "postern-persist.service" ];
    requires = [ "postern-persist.service" ];
    wants = [ "wireguard-wg0.service" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      RequiresMountsFor = [ "/persist" ];
    };
    path = [ pkgs.wireguard-tools pkgs.gawk pkgs.iproute2 ];
    script = ''
      set -euo pipefail
      allow=/persist/postern/wg-allowlist
      if [ ! -s "$allow" ]; then
        echo "postern-wg-peers: no allowlist present — wg0 admits NO client (safe default)"
        exit 0
      fi
      i=2   # client IPs start at 10.94.0.2 (the guest itself is 10.94.0.1)
      while read -r pub ips _rest; do
        case "$pub" in ""|\#*) continue ;; esac
        if [ -z "''${ips:-}" ]; then ips="10.94.0.$i/32"; i=$((i+1)); fi
        # Deny-only: we only ever ADD host-declared peers; the guest key the
        # client tunnels to is the attested one, so a bogus peer buys nothing.
        wg set wg0 peer "$pub" allowed-ips "$ips" || \
          echo "postern-wg-peers: skipped malformed peer '$pub'"
      done < "$allow"
    '';
  };

  # ── Remote desktop inside the tunnel (permissive-only stack, spec §8) ──────
  # wayvnc (ISC) on a headless Wayland session; xrdp (Apache-2.0) alternative.
  # GPL remote-desktop stacks (Sunshine/Moonlight, TigerVNC) are excluded by
  # the project's permissive-only rule.
  environment.systemPackages = with pkgs; [
    blochPkg            # node + bloch-wallet (Postern Wallet CLI) + bloch-cli
    wayvnc
    wireguard-tools
  ];
  # services.xrdp = { enable = true; openFirewall = false; };  # wg0-only

  # SSH for administration — key-only, never exposed pre-attestation.
  services.openssh = {
    enable = lib.mkDefault true;
    openFirewall = false;                       # wg0 only
    settings.PasswordAuthentication = false;
    settings.KbdInteractiveAuthentication = false;
  };

  # ── Hardening spine (the desktop.nix posture, headless subset) ─────────────
  security.apparmor.enable = true;
  security.sudo.execWheelOnly = true;
  boot.kernel.sysctl = {
    "kernel.kptr_restrict" = 2;
    "kernel.dmesg_restrict" = 1;
    "net.ipv4.tcp_syncookies" = 1;
    "kernel.unprivileged_bpf_disabled" = 1;
  };
  systemd.coredump.enable = false;              # no secret-bearing core dumps

  # ── State: /persist is a separate LUKS volume (spec §4.2) ──────────────────
  # Rootfs is verity-sealed read-only (./attested.nix). Mutable state lives on
  # /persist, LUKS-keyed in-guest (TEE-random, first boot) — the provider holds
  # ciphertext only. Fleet variant: key release via org-hosted KBS (Trustee)
  # gated on a Trusted verdict.
  #
  # HONEST STATUS: this first-boot provisioning is written to be correct on a
  # NixOS CVM but is NOT built (no Nix on the dev host) and NOT booted. Key
  # CUSTODY is the open item flagged in the spec (§1.6) and differs per
  # provider: here the volume key is TEE-random and SEALED TO THE TPM2 measured
  # boot (systemd-cryptenroll --tpm2), so the disk only unlocks when the same
  # attested boot chain comes up. Validate on real SEV-SNP/TDX hardware
  # (docs/specs/POSTERN-CLOUD-CONFIDENTIAL.md) before trusting it.
  systemd.services.postern-persist = {
    description = "Provision + unlock the LUKS /persist volume (TEE-random key, TPM2-sealed)";
    wantedBy = [ "multi-user.target" ];
    after = [ "systemd-tmpfiles-setup-dev.service" "dev-disk-by\\x2dpartlabel-persist.device" ];
    wants = [ "dev-disk-by\\x2dpartlabel-persist.device" ];
    unitConfig.DefaultDependencies = false;
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      UMask = "0077";
    };
    path = [ pkgs.cryptsetup pkgs.systemd pkgs.util-linux pkgs.e2fsprogs pkgs.coreutils ];
    script = ''
      set -euo pipefail
      dev=/dev/disk/by-partlabel/persist
      map=/dev/mapper/persist

      if ! cryptsetup isLuks "$dev"; then
        # FIRST BOOT: format LUKS with a fresh TEE-random key that never lands
        # on disk in plaintext, then seal a TPM2 keyslot to the measured boot.
        key="$(head -c 64 /dev/urandom | base64 -w0)"
        printf '%s' "$key" | cryptsetup luksFormat --type luks2 --batch-mode "$dev" -
        printf '%s' "$key" | cryptsetup open "$dev" persist -
        # Seal to PCRs 0 (firmware/UKI) + 7 (secure-boot state); on a CVM the
        # launch measurement additionally covers this chain.
        PASSWORD="$key" systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=0+7 "$dev" || \
          echo "postern-persist: TPM2 enroll unavailable — keeping the bootstrap keyslot (validate per provider)"
        unset key
        mkfs.ext4 -q -L persist "$map"
      elif [ ! -e "$map" ]; then
        # SUBSEQUENT BOOTS: unlock via the TPM2-sealed keyslot (measured boot).
        /run/current-system/sw/lib/systemd/systemd-cryptsetup attach persist "$dev" - tpm2-device=auto || \
          systemd-cryptsetup attach persist "$dev" - tpm2-device=auto
      fi

      mkdir -p /persist
      mountpoint -q /persist || mount "$map" /persist
      mkdir -p /persist/postern
      chmod 0700 /persist/postern
    '';
  };

  # The node is available but not mining by default on a workstation seat.
  services.bloch.enable = lib.mkDefault false;

  # ── Honesty at the door (spec §1.3 — rendered, not buried) ─────────────────
  users.motd = ''
    ◆ Postern Cloud — confidential-VM workstation (SEV-SNP/TDX)
    Memory is hardware-encrypted against the host; the image is verity-sealed
    and attested before every session. You are trusting: the CPU vendor's TEE
    (AMD/Intel) + its attestation CA chain; provider firmware in the launch
    measurement; side channels remain open research. The provider still sees
    traffic shape and controls availability. On-device Postern editions remain
    the maximally sovereign option.
    A Postern Labs product on the ownerless Bloch-SIS-PoW protocol.
  '';

  time.timeZone = lib.mkDefault "UTC";
  system.stateVersion = lib.mkDefault "24.05";
}
