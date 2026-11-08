# Postern OS — immutable + attestable profile (the Postern Seal attestation).
#
# Layers onto the base Postern OS to make the image measurable and tamper-evident:
#   • immutable, read-only rootfs sealed with dm-verity (systemd-repart image);
#   • systemd in the initrd + a UKI (kernel+initrd+cmdline in one signed PE) so
#     the boot chain has a stable, measurable identity;
#   • TPM2 measured boot (PCRs) — and, inside a SEV-SNP/TDX confidential VM, the
#     launch measurement, verified by the L3 attestation layer.
#
# The dm-verity roothash is passed on the kernel cmdline (`roothash=`), which the
# node reads (`attestation::read_os_roothash`) and reports via `getattestation`,
# so a verifier can require the node run the audited reproducible image
# (Expected.os_roothash).
#
# NOTE: systemd-repart/verity/UKI options drift across nixpkgs releases — treat
# this as the profile to iterate on a Nix host (`nix build .#attested-image`),
# not a frozen recipe.
{ config, lib, pkgs, ... }:
{
  # systemd in the initrd — required for verity setup + TPM2 unlock + a clean
  # measured-boot chain.
  boot.initrd.systemd.enable = true;

  # UKI + measured boot: one signed kernel image, measured into the TPM (and, in
  # a CVM, covered by the launch measurement).
  boot.loader.systemd-boot.enable = lib.mkDefault true;
  boot.loader.efi.canTouchEfiVariables = lib.mkDefault false;
  boot.initrd.systemd.tpm2.enable = lib.mkDefault true;

  # Read-only, immutable rootfs. The store is already immutable; this seals the
  # whole root and forbids in-place mutation. Mutable state lives on a separate
  # writable partition mounted at the node's data dir.
  #
  # DESIGN REFERENCE ONLY — written, not built, not booted. `/dev/mapper/root`
  # is the device-mapper name systemd-veritysetup creates when it activates the
  # verity target from the `roothash=` value the repart build stamps onto the
  # kernel cmdline; nothing here has run that activation, so this mapping (and
  # the erofs+dm-verity chain it describes) is a plan, not a verified fact.
  # Nothing in this file claims the verity chain is secure or that k=8 is
  # active — see os/ATTESTATION.md for the current, honest k=4 status.
  fileSystems."/" = {
    device = "/dev/mapper/root";
    fsType = "erofs";
    options = [ "ro" ];
  };

  # Kernel modules needed in the initrd to activate dm-verity on the erofs
  # root before pivoting — required for the fileSystems."/" mapping above to
  # actually resolve on a real boot. Still DESIGN REFERENCE: not exercised on
  # this non-Nix dev host.
  boot.initrd.availableKernelModules = [ "dm_verity" "erofs" ];

  # Build an immutable disk image with a dm-verity-protected root partition.
  # `Verity = "data"` + a paired `root-verity` partition produce the roothash
  # that seals the image; systemd-repart writes `roothash=` onto the cmdline.
  image.repart = {
    name = "bloch-os";
    version = "0.1.0";
    partitions = {
      "esp" = {
        contents = {
          # UKI(s) placed by systemd-boot / the bootloader install.
        };
        repartConfig = {
          Type = "esp";
          Format = "vfat";
          SizeMinBytes = "128M";
        };
      };
      "root" = {
        storePaths = [ config.system.build.toplevel ];
        repartConfig = {
          Type = "root";
          Format = "erofs"; # read-only fs → deterministic + verity-friendly
          Verity = "data";
          VerityMatchKey = "root";
          Label = "bloch-root";
          Minimize = "best";
        };
      };
      "root-verity" = {
        repartConfig = {
          Type = "root-verity";
          Verity = "hash";
          VerityMatchKey = "root";
          Label = "bloch-root-verity";
        };
      };
    };
  };

  # Persist node state on a writable partition (the rest of the OS is read-only).
  # Point the node's data dir here; provision this partition at first boot.
  services.bloch.dataDir = lib.mkDefault "/persist/bloch";

  # Bake the image digest for the attestation report (set at build/deploy).
  # environment.variables.BLOCH_IMAGE_DIGEST is populated by the deploy pipeline.
  #
  # Confidential-VM deployments (./cloud.nix): the L1 binding is pinned at VM
  # LAUNCH, not in the image — the launch policy writes the admission-policy
  # hash P (which admits only this image's digest D) into SNP HOSTDATA /
  # TDX MR_CONFIG_ID, and the guest's report carries it back for the verifier
  # (postern-seal-verify --host-data P). Flow: POSTERN-CLOUD.md §7 + the
  # runbook docs/specs/POSTERN-CLOUD-CONFIDENTIAL.md.
}
