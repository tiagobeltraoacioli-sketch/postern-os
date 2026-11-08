# SPDX-License-Identifier: MIT OR Apache-2.0
#
# os/terem-compat.nix — Terem guest-runtime NixOS wiring (OS Portal v2, Path A).
# A Postern Labs product-tier: "run another OS in a sandbox on your Postern OS
# desktop." Modeled directly on os/sloboda-compat.nix's structure and honesty
# discipline, per docs/os-portal-v2/01-architecture.md §2.7's brief.
#
# Design references (read these before changing anything here):
#   docs/os-portal-v2/01-architecture.md   — the merged architecture (§2 Guest Mode,
#                                             §2.7 names this exact file)
#   docs/os-portal-v2/A-virtualization.md  — Architect 1's full pass (§0 license
#                                             gate, §1.6 the seal-exclusion precedent)
#   docs/os-portal-v2/LICENSE-DECISION.md  — the resolved permissive-only decision:
#                                             Cloud Hypervisor IN by default,
#                                             QEMU/Wine OPT-IN only, libvirt/SPICE/
#                                             Proton/Distrobox OUT entirely.
#
# ===========================================================================
# RED-TEAM CORRECTION (this file's own honesty fix — read before wiring)
# ===========================================================================
# `01-architecture.md` §2.7 / `A-virtualization.md` §1.6 argue that Terem needs
# NO seal-exclusion tripwire on the host side, unlike Waydroid/Sloboda, because
# "a KVM guest is hardware-isolated and does not touch the host's read-only
# root at all." That claim is TRUE, but it is true ONLY of the KVM/Cloud-
# Hypervisor/QEMU **VM** backend (§2.1 of that doc). It does NOT generalize to
# the WHOLE module: this file also wires an opt-in `systemd-nspawn`/Podman
# **container** backend for lightweight Linux guests (`A-virtualization.md`
# §2's third tier), and a container SHARES THE HOST KERNEL — there is no
# hardware boundary between it and the host, exactly the Waydroid/Sloboda
# shape (`os/sloboda-compat.nix`'s own header). Generalizing the VM-only
# property to this whole file would have been a real, load-bearing honesty
# bug: an operator reading "no tripwire needed" could reasonably assume the
# container tier is just as isolated as the VM tier, and it categorically is
# not. The fix applied below: the seal-exclusion assertion + non-attestable
# labeling discipline from `sloboda-compat.nix` is reproduced VERBATIM, but
# scoped ONLY to `postern.terem.enableContainerBackend` (§ "container tripwire"
# below) — never to `postern.terem.enable` on its own, which stays true to the
# VM-backend's actually-correct claim: enabling default Terem (Cloud
# Hypervisor + opt-in QEMU + wayvnc/FreeRDP display) on the real, attested
# `os/desktop.nix` + `os/attested.nix` host does NOT require disabling the
# seal, because those backends never share the host kernel with the guest.
# ===========================================================================
#
# ===========================================================================
# GUEST CONTENT IS ALWAYS NON-ATTESTABLE — REGARDLESS OF BACKEND
# ===========================================================================
# Independent of the VM-vs-container distinction above: NOTHING that runs
# *inside* a Terem guest (a VM's qcow2 disk, a container's rootfs tree) is
# ever measured. `os_roothash` (`os/attested.nix`'s dm-verity roothash) is a
# measurement of the HOST's sealed root filesystem; it says NOTHING about
# guest content and NEVER can, because guest content is mutable, vendor- or
# user-supplied media fetched/installed after the host image is built — the
# same reasoning `sloboda-compat.nix` already states for Waydroid's Android
# image. Guest disk images and container rootfs trees live under
# `postern.terem.dataDir`, which is NEVER imported into `os/attested.nix`'s
# sealed closure and NEVER referenced by `os_roothash`.
#
#   - For the VM backend: this is a SIMPLER honesty story than Sloboda's —
#     the host's own measurement is untouched (structural hardware isolation,
#     see the correction above), so enabling Terem's VM path does not itself
#     unseal anything. The host stays attestable; Terem only adds the
#     *capability* to run non-attestable guests beside it.
#   - For the container backend: this is the SAME honesty story as Sloboda —
#     shared-kernel, non-attestable, and (per the correction above) it also
#     structurally refuses to coexist with a sealed/read-only host root,
#     exactly like `sloboda-compat.nix` does.
#
# STATUS (honesty gates G1–G4): SCAFFOLD · DESIGN ONLY · UNAUDITED ·
# reference-prototype · not-yet-wired-into-any-host. Authored on a non-Nix
# macOS host: this expression is idiomatic Nix but has NEVER been evaluated
# (`nix flake check`/`nix-instantiate --parse`), built, or booted here — `nix`
# itself is not present on this build host. Package attribute names
# (`cloud-hypervisor`, `OVMF`, `swtpm`, `wineWowPackages.stable`, `wayvnc`,
# `freerdp`, `podman`) are believed correct against current nixpkgs but are
# UNVERIFIED against this repo's pinned nixpkgs revision — verify at eval
# time on a Linux+Nix host, the same "deferred-to-VM" posture
# `sloboda-compat.nix` already carries. `written ≠ built`, `built ≠ booted`.
# This file is not imported by any host module yet (§2.7's own open item #2 —
# wiring it into `os/desktop.nix` is a separate, future change, out of scope
# here).
# ===========================================================================
{ config, lib, pkgs, ... }:

let
  cfg = config.postern.terem;
in
{
  options.postern.terem = {
    enable = lib.mkEnableOption ''
      the Terem guest-runtime (OS Portal v2, Path A): Cloud Hypervisor
      (Apache-2.0) as the default in-box VMM, plus a local-loopback
      wayvnc/FreeRDP guest display. Safe to enable on the real, attested
      Postern OS Desktop host (os/desktop.nix + os/attested.nix) — the VM
      backend is hardware-isolated and never touches the sealed root. QEMU,
      Wine, and the lightweight container backend are SEPARATE opt-ins
      below, each for its own reason (license for QEMU/Wine, shared-kernel
      attestation honesty for the container backend) — enabling this option
      alone pulls in NO GPL/LGPL code and NO shared-kernel guest tier'';

    dataDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/postern-terem";
      description = ''
        Storage pool for guest state: VM disk images (qcow2/raw) under
        `''${dataDir}/vms/` and, if `enableContainerBackend` is set,
        container rootfs trees under `''${dataDir}/containers/`. Lives on
        the host's already-LUKS-encrypted filesystem
        (`os/desktop.nix`'s "Full-disk encryption" section) — a plain
        writable directory, NEVER a raw host block device handle (no guest
        ever gets one, per `01-architecture.md` §2.4) and NEVER part of the
        `os/attested.nix` sealed closure. `os_roothash` never describes
        anything under this path, for either backend.
      '';
    };

    networkMode = lib.mkOption {
      type = lib.types.enum [ "nat" "isolated" ];
      default = "nat";
      description = ''
        Default guest network posture (`01-architecture.md` §2.4): "nat" —
        the guest reaches the internet via QEMU/Cloud-Hypervisor user-mode
        NAT or a managed isolated bridge, the host's LAN does NOT reach the
        guest, and the guest is never bridged onto the client's real LAN
        by default. "isolated" — no guest network access at all. Bridging
        onto the real LAN is a separate, explicit, consent-gated crossing
        (`02-security-consent-privacy.md` §3), never a value of this option.
      '';
    };

    display = {
      enableWayvnc = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Ship `wayvnc` (ISC) for a local-loopback VNC session into a
          Linux/software-composited guest display. Part of the permissive
          pair `docs/specs/POSTERN-CLOUD.md` §8 already vetted for exactly
          this remote-display role (reused here for a local guest instead
          of a WireGuard-tunneled remote CVM). Never the SPICE display path
          — SPICE client libs are LGPL and explicitly ruled out
          (`LICENSE-DECISION.md` §1).
        '';
      };
      enableFreerdp = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Ship `freerdp` (Apache-2.0) as the RDP client used to connect to
          a Windows guest's own built-in RDP server over the local-loopback
          network — the other half of the vetted permissive display pair
          (`LICENSE-DECISION.md` §1). Not an RDP *server*; `xrdp` is the
          server-side component and is not needed here (Terem connects
          into guests, it does not expose the host over RDP).
        '';
      };
    };

    enableQemu = lib.mkEnableOption ''
      the OPT-IN QEMU/KVM VMM (GPL-2.0), driven directly over its QMP JSON
      socket, NEVER via libvirt (LGPL-2.1, ruled out in full,
      `LICENSE-DECISION.md` §1). Per `LICENSE-DECISION.md` §2: Postern's
      default, attested Terem build ships ZERO GPL/LGPL/AGPL code: QEMU is
      pulled into this machine's own closure ONLY when an operator flips
      this option and rebuilds, exactly the same "opt-in, never in the
      default closure" posture Fedora's RPM Fusion or Debian's contrib/
      non-free already use. Needed today for a graphical Windows 11 guest
      (TPM 2.0 + UEFI) — Cloud Hypervisor's Windows-guest/graphics support
      does not yet cover that case (`LICENSE-DECISION.md` §4). Enabling
      this does NOT enable the container backend and does NOT require
      disabling the host seal — QEMU/KVM is still a hardware-isolated VM
      backend, same isolation shape as Cloud Hypervisor, just a different,
      GPL-licensed, opt-in userspace VMM driving the same /dev/kvm'';

    enableWine = lib.mkEnableOption ''
      the OPT-IN Wine/Winetricks compatibility layer (LGPL-2.1) for OS
      Portal v2 Path B (App Mode — one Windows .exe, no guest at all,
      `01-architecture.md` §3). Same "opt-in, never in the default closure"
      posture as `enableQemu` above and the same reasoning
      (`LICENSE-DECISION.md` §2): Wine is invoked as a plain external
      process (`wine app.exe`), never linked (`libwine` is not embedded).
      Proton is NOT shipped by this module at all, independent of this
      toggle — see `LICENSE-DECISION.md` §3 (Valve's build redistribution
      is a separate, unresolved rights question with a clean fallback:
      vanilla Wine + independently-built DXVK/VKD3D-Proton, both already
      covered by nixpkgs). This toggle is unrelated to attestation honesty
      (Wine is a host process, not a guest of any kind) — it exists purely
      for the LGPL opt-in reason, unlike `enableContainerBackend` below'';

    enableContainerBackend = lib.mkEnableOption ''
      the OPT-IN lightweight Linux-guest tier: `systemd-nspawn` (ships with
      systemd, already present on every NixOS host here) / Podman
      (Apache-2.0) driven directly, no Distrobox wrapper
      (`LICENSE-DECISION.md` §1, `A-virtualization.md` §2). READ THE
      RED-TEAM CORRECTION AT THE TOP OF THIS FILE BEFORE ENABLING: unlike
      every other backend this module wires (Cloud Hypervisor, opt-in
      QEMU), a container SHARES THE HOST KERNEL — there is no hardware
      isolation boundary between guest and host, the EXACT SAME shape as
      Waydroid/Sloboda (`os/sloboda-compat.nix`). This tier is therefore
      NEVER attestable, is offered ONLY for trusted Linux-only userlands
      the operator already trusts (never Windows/RHEL as a
      security-equivalent alternative to the VM backends,
      `01-architecture.md` §2.1/§2.2), and — the concrete tripwire below —
      structurally REFUSES to coexist with a sealed, read-only host root,
      the same belt-and-suspenders assertion `sloboda-compat.nix` carries.
      This is a licensing-CLEAN opt-in (systemd-nspawn/Podman are both
      already-present/Apache-2.0, no GPL/LGPL question at all) gated for an
      entirely different reason than `enableQemu`/`enableWine`: shared-
      kernel attestation honesty, not license purity — the two opt-in axes
      of this module are independent and must not be conflated'';
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      # ── Container tripwire (the red-team fix) ─────────────────────────────
      # Reproduces os/sloboda-compat.nix's seal-exclusion assertion VERBATIM
      # in shape, scoped ONLY to the shared-kernel container backend — NEVER
      # to this module's VM backends (Cloud Hypervisor / opt-in QEMU), which
      # are hardware-isolated and correctly need no such tripwire
      # (`01-architecture.md` §2.7, `A-virtualization.md` §1.6). Belt-and-
      # suspenders on top of "never wire enableContainerBackend = true into
      # any host that also imports os/attested.nix" — the real exclusion is
      # the operator's own host config, this is the structural backstop.
      {
        assertion = cfg.enableContainerBackend -> !(config.fileSystems ? "/"
          && (config.fileSystems."/".options or [ ]) != [ ]
          && lib.elem "ro" (config.fileSystems."/".options or [ ]));
        message = ''
          postern.terem.enableContainerBackend = true (the systemd-nspawn/
          Podman lightweight Linux-guest tier) was enabled on a host whose
          "/" is mounted read-only — the signature of the sealed
          os/attested.nix profile. EXACTLY LIKE os/sloboda-compat.nix's
          Waydroid tier, this container backend SHARES THE HOST KERNEL and
          has NO hardware isolation from it — it must never be part of the
          attested / Postern-Seal closure's runtime surface. This is
          DIFFERENT from postern.terem's default Cloud-Hypervisor/opt-in-
          QEMU VM backends, which ARE hardware-isolated and are fine on a
          sealed host (see the RED-TEAM CORRECTION header in
          os/terem-compat.nix for why the two backends are NOT the same
          claim). Disable enableContainerBackend on a sealed/attested host,
          or run the lightweight Linux-guest tier on a non-attested host
          instead, the same way sloboda-compat.nix is confined to
          os/sloboda-vm.nix.
        '';
      }
    ];

    # ── /dev/kvm access — needed by Cloud Hypervisor (default) and, if
    #    enabled, QEMU. Both are userspace VMMs driving the same in-kernel
    #    KVM module (GPL-2.0, but "ships with Linux, not our distributed
    #    component" — the same exception os/cloud.nix's SNP/TDX work and
    #    POSTERN-CLOUD.md §8 already grant the kernel itself). Group
    #    membership for the interactive desktop user is the HOST config's
    #    job (e.g. os/desktop.nix would add its user to "kvm"), not this
    #    module's — mirrors how sloboda-compat.nix leaves per-user group
    #    membership to sloboda-vm.nix's own throwaway dev user.
    users.groups.kvm = { };

    # ── Runtime dir for the Tauri backend's per-guest QMP sockets
    #    (01-architecture.md §2.6/§2.7: /run/postern/terem/<id>.sock) —
    #    the thin "postern-terem" runtime-directory owner named in §2.7,
    #    implemented as a tmpfiles rule (idiomatic NixOS shape for "a
    #    service owns a runtime dir with fixed perms") rather than a
    #    long-running daemon, since the actual per-guest process lifecycle
    #    is owned by the Tauri shell (desktop/src-tauri), not a system
    #    service — no verb here is "run arbitrary command"
    #    (01-architecture.md §2.6).
    systemd.tmpfiles.rules = [
      "d /run/postern/terem 0770 root kvm - -"
      "d ${cfg.dataDir} 0750 root kvm - -"
      "d ${cfg.dataDir}/vms 0750 root kvm - -"
    ] ++ lib.optionals cfg.enableContainerBackend [
      # Container rootfs pool — separate subtree, same non-attestable
      # discipline as the VM pool, called out on its own line so the
      # non-attestable surface is grep-able independent of the VM one.
      "d ${cfg.dataDir}/containers 0750 root kvm - -"
    ];

    # ── The VMM/display packages ───────────────────────────────────────────
    environment.systemPackages = with pkgs;
      [
        cloud-hypervisor # Apache-2.0 — the default, always-in-box VMM (LICENSE-DECISION.md §1/§4)
      ]
      ++ lib.optionals cfg.display.enableWayvnc [ wayvnc ] # ISC
      ++ lib.optionals cfg.display.enableFreerdp [ freerdp ] # Apache-2.0
      ++ lib.optionals cfg.enableQemu [
        qemu # GPL-2.0 — OPT-IN ONLY, see enableQemu's description
        OVMF # UEFI firmware for Windows 11 guests (BSD-2-Clause-Patent, TianoCore)
        swtpm # emulated TPM 2.0 for Windows 11's setup requirement (BSD-3-Clause)
      ]
      ++ lib.optionals cfg.enableWine [
        wineWowPackages.stable # LGPL-2.1 — OPT-IN ONLY, see enableWine's description
        winetricks # LGPL-2.1, same opt-in boundary — bootstraps common WINEPREFIX deps
      ]
      ++ lib.optionals cfg.enableContainerBackend [
        podman # Apache-2.0 — licensing-clean; opt-in is for the shared-kernel
        # honesty reason (see enableContainerBackend's description), not
        # license. systemd-nspawn ships with systemd already, no package here.
      ];

    # KVM userspace VMMs are hardware-isolated from the host regardless of
    # which one runs (Cloud Hypervisor or opt-in QEMU) — no seal-exclusion
    # assertion needed for THIS half of the module, matching
    # `01-architecture.md` §2.7's correctly-scoped claim (see the RED-TEAM
    # CORRECTION header: the claim is right here, wrong only if generalized
    # to enableContainerBackend above).

    networking.firewall.enable = lib.mkDefault true;

    # A loud, machine-visible marker whenever Terem is on, with an EXTRA,
    # separate warning line for the container backend specifically — never
    # collapse the two into one claim, per the red-team correction.
    users.motd = lib.mkDefault (''
      ◆ Postern Terem — guest-runtime enabled (os/terem-compat.nix)

      Host measurement (os_roothash) is UNTOUCHED by Terem: no guest — VM or
      container — is ever attested, and none is imported into the sealed
      os/attested.nix closure. The default Cloud-Hypervisor (and, if enabled,
      opt-in QEMU) VM backend is hardware-isolated: this host's own seal
      stays fully intact even while running an attested-nothing guest.
    '' + lib.optionalString cfg.enableContainerBackend ''

      ▲ Container backend (systemd-nspawn/Podman) is ALSO enabled on this
      host. Unlike the VM backend above, this tier SHARES THE HOST KERNEL —
      exactly like Sloboda's Waydroid tier — and has NO hardware isolation
      from it. Never treat a container guest here as security-equivalent to
      a VM guest. This tier structurally refuses to run on a sealed/
      read-only host root (see os/terem-compat.nix's assertions).
    '');
  };
}
