# SPDX-License-Identifier: MIT OR Apache-2.0
# Look and defaults shared by the graphical profiles (desktop and mobile):
# fonts, icons, pointer, wallpaper, and the GNOME privacy defaults. These are
# defaults only; the user can change each one in Settings.
{ lib, pkgs, ... }:
let
  statusApp = pkgs.callPackage ../../nix/postern-status-gui.nix { };
  # Original artwork (os/assets/wallpaper.svg), rendered once at build time.
  wallpaper = pkgs.runCommand "postern-wallpaper.png" { nativeBuildInputs = [ pkgs.librsvg ]; } ''
    rsvg-convert --width 2560 --height 1440 ${../assets/wallpaper.svg} --output $out
  '';
  pointer = "Bibata-Modern-Classic";
in
{
  imports = [ ./firefox.nix ];

  # The minimal live base turns these off; a graphical session needs them.
  # Without fontconfig the terminal falls back to a proportional font.
  fonts.fontconfig.enable = true;
  fonts.enableDefaultPackages = true;
  fonts.packages = with pkgs; [ inter jetbrains-mono dejavu_fonts ];
  fonts.fontconfig.defaultFonts = {
    sansSerif = [ "Inter" "DejaVu Sans" ];
    monospace = [ "JetBrains Mono" "DejaVu Sans Mono" ];
  };
  xdg.icons.enable = true;
  xdg.mime.enable = true;
  xdg.sounds.enable = true;

  # Quiet boot text. A graphical boot splash (Plymouth) was tried and left the
  # display on the login greeter's terminal after autologin, so it is not used.
  boot.consoleLogLevel = 3;
  boot.kernelParams = [ "quiet" ];

  services.printing.enable = lib.mkForce false;
  services.gnome.gnome-online-accounts.enable = lib.mkForce false;
  services.gnome.gnome-remote-desktop.enable = lib.mkForce false;
  hardware.bluetooth.powerOnBoot = lib.mkDefault false;

  environment.systemPackages = with pkgs; [
    statusApp tela-icon-theme adwaita-icon-theme bibata-cursors
  ];
  environment.variables = {
    XCURSOR_THEME = pointer;
    XCURSOR_SIZE = "24";
  };

  programs.dconf.enable = true;
  programs.dconf.profiles.user.databases = [{
    settings = {
      "org/gnome/desktop/background" = {
        picture-uri = "file://${wallpaper}";
        picture-uri-dark = "file://${wallpaper}";
        picture-options = "zoom";
        primary-color = "#0b1026";
      };
      "org/gnome/desktop/screensaver" = {
        picture-uri = "file://${wallpaper}";
        picture-options = "zoom";
      };
      "org/gnome/desktop/interface" = {
        color-scheme = "prefer-dark";
        accent-color = "blue";
        icon-theme = "Tela-dark";
        cursor-theme = pointer;
        cursor-size = lib.gvariant.mkInt32 24;
        font-name = "Inter 11";
        document-font-name = "Inter 11";
      };
      "org/gnome/desktop/media-handling" = {
        automount = false;
        automount-open = false;
        autorun-never = true;
      };
      "org/gnome/desktop/privacy" = {
        remember-recent-files = false;
        remove-old-temp-files = true;
        remove-old-trash-files = true;
        old-files-age = lib.gvariant.mkUint32 1;
        report-technical-problems = false;
        send-software-usage-stats = false;
      };
      "org/gnome/system/location".enabled = false;
    };
  }];
}
