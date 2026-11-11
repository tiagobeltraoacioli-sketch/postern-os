# SPDX-License-Identifier: MIT OR Apache-2.0
# Ephemeral live medium: nothing is written to the machine's disks by default.
{ config, lib, pkgs, modulesPath, ... }:
{
  imports = [
    (modulesPath + "/installer/cd-dvd/installation-cd-minimal.nix")
    ./base.nix
  ];
  postern.imageType = "live-development";
  networking.hostName = lib.mkForce "postern-live";
  boot.initrd.systemd.enable = lib.mkForce false;
  image.fileName = lib.mkForce "postern-os-${config.postern.profileName}-${config.postern.version}-x86_64.iso";
  isoImage.squashfsCompression = "zstd -Xcompression-level 6";
}
