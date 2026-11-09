{ lib, pkgs, ... }:
{
  # Keep kernel security mitigations; use bounded user-space parallel work.
  zramSwap = {
    enable = true;
    algorithm = "zstd";
    memoryPercent = 25;
  };
  environment.systemPackages = with pkgs; [
    htop btop numactl time sysstat jq ripgrep cryptsetup
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
