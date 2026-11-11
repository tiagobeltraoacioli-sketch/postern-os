{
  description = "Postern OS: private live Linux images and bounded parallel data processing";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      parallelData = pkgs.callPackage ./nix/parallel-data.nix { };
      posternStatus = pkgs.callPackage ./nix/postern-status.nix { };
      posternVault = pkgs.callPackage ./nix/postern-vault.nix { };
      common = [
        ./os/profiles/privacy.nix
        ./os/profiles/hardening.nix
        ./os/profiles/performance.nix
        { environment.systemPackages = [ parallelData posternStatus posternVault ]; }
      ];
      image = profile: nixpkgs.lib.nixosSystem {
        inherit system;
        modules = common ++ [ ./os/profiles/live.nix profile ];
      };
      compute = image ./os/profiles/compute.nix;
      desktop = image ./os/profiles/desktop.nix;
      mobile = image ./os/profiles/mobile.nix;
      # Persistent, unencrypted development disks for virtual machines only.
      vmSystem = profile: nixpkgs.lib.nixosSystem {
        inherit system;
        modules = common ++ [ ./os/profiles/disk.nix profile ];
      };
      computeVm = vmSystem ./os/profiles/compute.nix;
      desktopVm = vmSystem ./os/profiles/desktop.nix;
      vmImage = name: vm: import "${nixpkgs}/nixos/lib/make-disk-image.nix" {
        inherit pkgs;
        lib = nixpkgs.lib;
        config = vm.config;
        format = "qcow2";
        partitionTableType = "hybrid";
        diskSize = "auto";
        additionalSpace = "2G";
        baseName = "postern-os-${name}-${vm.config.postern.version}-x86_64";
        copyChannel = false;
      };
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
        && c.swapDevices == [ ]
        && c.zramSwap.writebackDevice == null
        && lockedPassword c.users.users.root
        && lockedPassword c.users.users.nixos
        && c.security.protectKernelImage
        && builtins.elem "init_on_free=1" c.boot.kernelParams
        && c.networking.networkmanager.enable
        && c.networking.networkmanager.wifi.macAddress == "random"
        && c.networking.networkmanager.ethernet.macAddress == "random"
        && !c.services.tor.enable
        && !c.services.dleyna.enable
        && !c.services.gnome.rygel.enable
        && !c.services.gnome.gnome-user-share.enable
        && !c.services.gnome.gnome-remote-desktop.enable;
    in {
      nixosModules = {
        privacy = import ./os/profiles/privacy.nix;
        performance = import ./os/profiles/performance.nix;
        hardening = import ./os/profiles/hardening.nix;
        bloch-pos = import ./os/modules/bloch-pos.nix;
      };
      nixosConfigurations = {
        postern-compute = compute;
        postern-desktop = desktop;
        postern-mobile = mobile;
        postern-compute-vm = computeVm;
        postern-desktop-vm = desktopVm;
      };
      packages.${system} = {
        default = parallelData;
        parallel-data = parallelData;
        postern-status = posternStatus;
        postern-vault = posternVault;
        compute-vm-image = vmImage "compute-vm" computeVm;
        desktop-vm-image = vmImage "desktop-vm" desktopVm;
        iso = compute.config.system.build.isoImage;
        compute-iso = compute.config.system.build.isoImage;
        desktop-iso = desktop.config.system.build.isoImage;
        mobile-iso = mobile.config.system.build.isoImage;
      };
      checks.${system} = {
        parallel-data = parallelData;
        postern-status = posternStatus;
        postern-vault = posternVault;
        privacy = pkgs.callPackage ./os/tests/privacy.nix { inherit parallelData posternStatus posternVault; };
        image-policy =
          assert privateImage compute;
          assert privateImage desktop;
          assert privateImage mobile;
          assert mobile.config.programs.firefox.policies.DisableTelemetry;
          assert privateImage computeVm;
          assert privateImage desktopVm;
          assert compute.config.postern.imageType == "live-development";
          assert computeVm.config.postern.imageType == "vm-development";
          assert !desktop.config.services.gnome.gnome-online-accounts.enable;
          assert desktop.config.programs.firefox.policies.DisableTelemetry;
          assert compute.config.boot.kernel.sysctl."kernel.core_pattern" != "core";
          pkgs.runCommand "postern-image-policy" { } ''
            mkdir -p "$out"
            echo 'All five image configurations satisfy the evaluated baseline.' > "$out/result.txt"
          '';
      };
      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          nix bashInteractive python3 coreutils qemu xorriso git jq
          ffmpeg-headless librsvg
          parallelData posternStatus
        ];
        # Fonts for the frames that scripts/postern-demo.py renders around the
        # captured screen (rsvg-convert resolves them through fontconfig).
        FONTCONFIG_FILE = pkgs.makeFontsConf { fontDirectories = [ pkgs.inter ]; };
      };
    };
}
