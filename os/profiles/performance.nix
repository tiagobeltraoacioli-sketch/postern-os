# SPDX-License-Identifier: MIT OR Apache-2.0
# Responsiveness and throughput without giving up kernel security mitigations.
{ lib, pkgs, ... }:
{
  # Compressed swap in RAM: up to half of memory, never a storage device.
  zramSwap = {
    enable = true;
    algorithm = "zstd";
    memoryPercent = 50;
    priority = 100;
  };
  boot.kernel.sysctl = {
    # Values suited to swap that lives in compressed memory: swapping is cheap,
    # read-ahead of swap pages is useless.
    "vm.swappiness" = 180;
    "vm.page-cluster" = 0;
    "vm.watermark_boost_factor" = 0;
    "vm.watermark_scale_factor" = 125;
    # Fair queueing with BBR congestion control for steadier transfers.
    "net.core.default_qdisc" = "fq";
    "net.ipv4.tcp_congestion_control" = "bbr";
  };
  boot.kernelModules = [ "tcp_bbr" ];

  # Under memory pressure, stop the offending group of processes before the
  # whole session freezes.
  systemd.oomd = {
    enable = true;
    enableRootSlice = true;
    enableUserSlices = true;
  };
  services.irqbalance.enable = true;

  environment.systemPackages = with pkgs; [
    htop btop numactl time sysstat jq ripgrep fd tree file
    cryptsetup age gnupg
    zstd pv parallel rsync git tmux
    pciutils usbutils lm_sensors smartmontools nvme-cli
    wireguard-tools
  ];
  # Do not multiply BLAS/OpenMP threads inside each worker process.
  environment.sessionVariables = {
    OMP_NUM_THREADS = "1";
    OPENBLAS_NUM_THREADS = "1";
    MKL_NUM_THREADS = "1";
    NUMEXPR_NUM_THREADS = "1";
  };
  nix.settings = {
    max-jobs = lib.mkDefault 2;
    cores = lib.mkDefault 2;
    sandbox = true;
    require-sigs = true;
  };
}
