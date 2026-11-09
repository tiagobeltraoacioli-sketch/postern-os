{
  description = "Postern OS: private live Linux images and bounded parallel data processing";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      parallelData = pkgs.callPackage ./nix/parallel-data.nix { };
      common = [
        ./os/profiles/privacy.nix
        ./os/profiles/performance.nix
        { environment.systemPackages = [ parallelData ]; }
      ];
      image = profile: nixpkgs.lib.nixosSystem {
        inherit system;
        modules = common ++ [ ./os/profiles/live.nix profile ];
      };
      compute = image ./os/profiles/compute.nix;
      desktop = image ./os/profiles/desktop.nix;
      lockedPassword = user:
        user.initialHashedPassword == "!"
        && user.initialPassword == null
        && user.hashedPassword == null
        && user.password == null
        && user.hashedPasswordFile == null;
      privateImage = imageConfig:
        let c = imageConfig.config; in
        c.security.apparmor.enable
        && !c.services.openssh.enable
        && c.networking.firewall.enable
        && c.networking.firewall.allowedTCPPorts == [ ]
        && c.networking.firewall.allowedUDPPorts == [ ]
        && c.networking.firewall.allowedTCPPortRanges == [ ]
        && c.networking.firewall.allowedUDPPortRanges == [ ]
        && lockedPassword c.users.users.root
        && lockedPassword c.users.users.nixos
        && !c.services.dleyna.enable
        && !c.services.gnome.rygel.enable
        && !c.services.gnome.gnome-user-share.enable
        && !c.services.gnome.gnome-remote-desktop.enable;
    in {
      nixosModules = {
        privacy = import ./os/profiles/privacy.nix;
        performance = import ./os/profiles/performance.nix;
        bloch-pos = import ./os/modules/bloch-pos.nix;
      };
      nixosConfigurations = {
        postern-compute = compute;
        postern-desktop = desktop;
      };
      packages.${system} = {
        default = parallelData;
        parallel-data = parallelData;
        iso = compute.config.system.build.isoImage;
        compute-iso = compute.config.system.build.isoImage;
        desktop-iso = desktop.config.system.build.isoImage;
      };
      checks.${system} = {
        parallel-data = parallelData;
        privacy = pkgs.callPackage ./os/tests/privacy.nix { inherit parallelData; };
        image-policy =
          assert privateImage compute;
          assert privateImage desktop;
          assert !desktop.config.services.gnome.gnome-online-accounts.enable;
          assert desktop.config.programs.firefox.policies.DisableTelemetry;
          assert compute.config.boot.kernel.sysctl."kernel.core_pattern" != "core";
          pkgs.runCommand "postern-image-policy" { } ''
            mkdir -p "$out"
            echo 'Both image configurations satisfy the evaluated baseline.' > "$out/result.txt"
          '';
      };
      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          nix bashInteractive python3 coreutils qemu xorriso git jq
          parallelData
        ];
      };
    };
}
