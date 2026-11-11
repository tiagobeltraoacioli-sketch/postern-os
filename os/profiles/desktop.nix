{ lib, pkgs, ... }:
let
  statusApp = pkgs.callPackage ../../nix/postern-status-gui.nix { };
  # Original artwork (os/assets/wallpaper.svg), rendered once at build time.
  wallpaper = pkgs.runCommand "postern-wallpaper.png" { nativeBuildInputs = [ pkgs.librsvg ]; } ''
    rsvg-convert --width 2560 --height 1440 ${../assets/wallpaper.svg} --output $out
  '';
  terminalProfile = "b1dcc9dd-5262-4d8d-a863-c897e6d979b9";
  dock = "org/gnome/shell/extensions/dash-to-dock";
  blur = "org/gnome/shell/extensions/blur-my-shell";
in
{
  imports = [ ./firefox.nix ];
  services.xserver.enable = true;
  # The minimal live base turns these off; a desktop needs them. Without
  # fontconfig the terminal falls back to a proportional font in fixed cells.
  fonts.fontconfig.enable = true;
  fonts.enableDefaultPackages = true;
  fonts.packages = with pkgs; [ inter jetbrains-mono dejavu_fonts ];
  fonts.fontconfig.defaultFonts = {
    sansSerif = [ "Inter" "DejaVu Sans" ];
    monospace = [ "JetBrains Mono" "DejaVu Sans Mono" ];
  };

  # Quiet boot text. A graphical boot splash (Plymouth) was tried and left the
  # display on the login greeter's terminal after autologin, so it is not used.
  boot.consoleLogLevel = 3;
  boot.kernelParams = [ "quiet" ];

  # Postern look: a fixed translucent dock, blurred bar and overview, original
  # wallpaper, Inter and JetBrains Mono. Defaults only; the user can change
  # every one of them in Settings.
  programs.dconf.profiles.user.databases = [{
    settings = {
      "org/gnome/shell" = {
        disable-user-extensions = false;
        enabled-extensions = [
          pkgs.gnomeExtensions.dash-to-dock.extensionUuid
          pkgs.gnomeExtensions.blur-my-shell.extensionUuid
        ];
        favorite-apps = [
          "firefox.desktop" "org.gnome.Nautilus.desktop" "org.gnome.Terminal.desktop"
          "org.keepassxc.KeePassXC.desktop" "org.postern.Status.desktop"
          "org.gnome.Settings.desktop"
        ];
      };
      "${dock}" = {
        dock-position = "BOTTOM";
        dock-fixed = true;
        extend-height = false;
        dash-max-icon-size = lib.gvariant.mkInt32 54;
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
        font-name = "Inter 11";
        document-font-name = "Inter 11";
        monospace-font-name = "JetBrains Mono 11";
        clock-show-weekday = true;
        enable-hot-corners = false;
        show-battery-percentage = true;
      };
      "org/gnome/desktop/wm/preferences" = {
        button-layout = "appmenu:minimize,maximize,close";
        titlebar-font = "Inter Bold 11";
      };
      "org/gnome/mutter" = {
        center-new-windows = true;
        edge-tiling = true;
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
        audible-bell = false;
      };
      "org/gnome/terminal/legacy".theme-variant = "dark";
    };
  }];
  xdg.icons.enable = true;
  xdg.mime.enable = true;
  xdg.sounds.enable = true;
  services.displayManager.gdm = {
    enable = true;
  };
  services.desktopManager.gnome.enable = true;
  services.displayManager.autoLogin = {
    enable = true;
    user = "nixos";
  };
  services.gnome.gnome-online-accounts.enable = lib.mkForce false;
  services.gnome.gnome-initial-setup.enable = lib.mkForce false;
  # One terminal and one browser; GNOME Console and Web would duplicate them.
  environment.gnome.excludePackages = with pkgs; [ gnome-tour epiphany geary gnome-console ];
  networking.networkmanager.enable = true;
  networking.networkmanager.wifi.macAddress = "random";
  networking.networkmanager.connectionConfig."ipv6.ip6-privacy" = 2;
  networking.networkmanager.settings.connectivity.enabled = false;
  networking.wireless.enable = lib.mkForce false;
  services.printing.enable = lib.mkForce false;
  services.gnome.gnome-remote-desktop.enable = lib.mkForce false;
  hardware.bluetooth.powerOnBoot = lib.mkDefault false;
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
    gnome-terminal keepassxc statusApp
    gnomeExtensions.dash-to-dock gnomeExtensions.blur-my-shell
  ];
  postern.profileName = "desktop";
}
