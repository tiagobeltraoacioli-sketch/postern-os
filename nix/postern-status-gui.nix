{ lib, stdenvNoCC, python3, wrapGAppsHook4, gobject-introspection, gtk4
, libadwaita, makeDesktopItem, copyDesktopItems }:

let
  pythonEnv = python3.withPackages (packages: [ packages.pygobject3 ]);
in
stdenvNoCC.mkDerivation {
  pname = "postern-status-gui";
  version = "0.2.0";
  src = ../tools/postern-status;
  nativeBuildInputs = [ wrapGAppsHook4 gobject-introspection copyDesktopItems ];
  buildInputs = [ gtk4 libadwaita pythonEnv ];

  installPhase = ''
    runHook preInstall
    mkdir -p $out/lib/postern-status $out/bin
    cp postern_status.py $out/lib/postern-status/
    { echo '#!${pythonEnv}/bin/python3'; tail -n +2 postern_status_gui.py; } > $out/bin/postern-status-gui
    chmod 755 $out/bin/postern-status-gui
    install -Dm644 org.postern.Status.svg $out/share/icons/hicolor/scalable/apps/org.postern.Status.svg
    runHook postInstall
  '';

  desktopItems = [
    (makeDesktopItem {
      name = "org.postern.Status";
      desktopName = "Postern Status";
      comment = "Show the observable privacy baseline of this system";
      exec = "postern-status-gui";
      icon = "org.postern.Status";
      categories = [ "System" "Security" ];
      keywords = [ "privacy" "firewall" "postern" ];
      startupWMClass = "org.postern.Status";
      # The window adapts to a phone-width screen; phone shells list it as such.
      extraConfig."X-Purism-FormFactor" = "Workstation;Mobile;";
    })
  ];

  meta = with lib; {
    description = "Desktop window for the read-only Postern privacy status report";
    license = with licenses; [ mit asl20 ];
    mainProgram = "postern-status-gui";
    platforms = platforms.linux;
  };
}
