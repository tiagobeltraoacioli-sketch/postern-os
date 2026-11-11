# SPDX-License-Identifier: MIT OR Apache-2.0
# GNOME desktop on Wayland with the Postern look: a fixed translucent dock,
# blurred bar and overview, window controls on the left, one icon family.
{ lib, pkgs, ... }:
let
  terminalProfile = "b1dcc9dd-5262-4d8d-a863-c897e6d979b9";
  dock = "org/gnome/shell/extensions/dash-to-dock";
  blur = "org/gnome/shell/extensions/blur-my-shell";
in
{
  imports = [ ./graphical.nix ];
  services.xserver.enable = true;

  programs.dconf.profiles.user.databases = [{
    settings = {
      "org/gnome/shell" = {
        disable-user-extensions = false;
        enabled-extensions = [
          pkgs.gnomeExtensions.dash-to-dock.extensionUuid
          pkgs.gnomeExtensions.blur-my-shell.extensionUuid
        ];
        favorite-apps = [
          "firefox.desktop" "torbrowser.desktop" "org.gnome.Nautilus.desktop"
          "org.gnome.Terminal.desktop" "org.keepassxc.KeePassXC.desktop"
          "fr.romainvigier.MetadataCleaner.desktop" "org.postern.Status.desktop"
          "org.gnome.Settings.desktop"
        ];
      };
      "${dock}" = {
        dock-position = "BOTTOM";
        dock-fixed = true;
        extend-height = false;
        dash-max-icon-size = lib.gvariant.mkInt32 52;
        transparency-mode = "FIXED";
        background-opacity = 0.28;
        custom-theme-shrink = false;
        running-indicator-style = "DOTS";
        show-trash = false;
        show-mounts = false;
        show-show-apps-button = true;
        show-apps-at-top = false;
        click-action = "minimize-or-previews";
        disable-overview-on-startup = true;
        hot-keys = false;
      };
      "${blur}/panel".blur = true;
      "${blur}/overview".blur = true;
      "${blur}/dash-to-dock" = {
        blur = true;
        style-dash-to-dock = lib.gvariant.mkInt32 0;
      };
      "${blur}/applications".blur = false;
      "org/gnome/desktop/interface" = {
        monospace-font-name = "JetBrains Mono 11";
        clock-show-weekday = true;
        enable-hot-corners = false;
        show-battery-percentage = true;
      };
      "org/gnome/desktop/wm/preferences" = {
        # Close, minimize, maximize at the left edge of the title bar.
        button-layout = "close,minimize,maximize:appmenu";
        titlebar-font = "Inter Bold 11";
      };
      "org/gnome/mutter" = {
        center-new-windows = true;
        edge-tiling = true;
      };
      "org/gnome/terminal/legacy/profiles:" = {
        default = terminalProfile;
        list = [ terminalProfile ];
      };
      "org/gnome/terminal/legacy/profiles:/:${terminalProfile}" = {
        visible-name = "Postern";
        default-size-columns = lib.gvariant.mkInt32 108;
        default-size-rows = lib.gvariant.mkInt32 28;
        use-theme-colors = false;
        background-color = "rgb(13,17,34)";
        foreground-color = "rgb(226,232,245)";
        bold-is-bright = false;
        palette = [
          "rgb(27,33,58)" "rgb(240,98,120)" "rgb(72,208,160)" "rgb(240,190,110)"
          "rgb(110,150,250)" "rgb(190,130,240)" "rgb(60,200,215)" "rgb(205,212,230)"
          "rgb(88,98,134)" "rgb(250,130,150)" "rgb(110,230,185)" "rgb(250,210,140)"
          "rgb(140,175,255)" "rgb(210,160,250)" "rgb(110,220,232)" "rgb(240,244,252)"
        ];
        scrollbar-policy = "never";
        cursor-blink-mode = "off";
        audible-bell = false;
      };
      "org/gnome/terminal/legacy".theme-variant = "dark";
    };
  }];

  services.displayManager.gdm.enable = true;
  services.desktopManager.gnome.enable = true;
  services.displayManager.autoLogin = {
    enable = true;
    user = "nixos";
  };
  services.gnome.gnome-initial-setup.enable = lib.mkForce false;
  # One terminal and one browser; GNOME Console and Web would duplicate them.
  environment.gnome.excludePackages = with pkgs; [ gnome-tour epiphany geary gnome-console ];
  # The password-locked live account cannot unlock a GNOME screen lock.
  # Installed systems must configure a password and retain normal screen locks.
  services.desktopManager.gnome.extraGSettingsOverrides = ''
    [org.gnome.desktop.screensaver]
    lock-enabled=false
    [org.gnome.desktop.lockdown]
    disable-lock-screen=true
    [org.gnome.desktop.media-handling]
    automount=false
    automount-open=false
    autorun-never=true
  '';

  environment.systemPackages = with pkgs; [
    gnome-terminal keepassxc gnome-disk-utility
    # Tor Browser is included but never started automatically; it protects only
    # the traffic inside that browser. No system-wide Tor daemon runs.
    tor-browser
    # Removes embedded metadata (author, location, device) from files.
    metadata-cleaner
    gnomeExtensions.dash-to-dock gnomeExtensions.blur-my-shell
  ];
  postern.profileName = "desktop";
}
