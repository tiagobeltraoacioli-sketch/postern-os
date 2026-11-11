{ lib, ... }:
{
  services.xserver.enable = lib.mkForce false;
  services.displayManager.enable = lib.mkForce false;
  postern.profileName = "compute";
}
