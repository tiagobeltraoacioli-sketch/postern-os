{ lib
, rustPlatform
, pkg-config
, openssl
, rocksdb
, glib
, clang
, llvmPackages
, stdenv
}:

# Reproducible build of the Bloch-SIS node (+ its CLI/wallet bins) from the
# workspace. The workspace is fully self-contained (pqcrypto-internals is
# vendored, Cargo.lock is committed), so no network / git fetches are needed.
rustPlatform.buildRustPackage {
  pname = "bloch";
  version = "0.1.0";

  # Repo root (this file lives in ./os). cleanSource drops .git; the sandbox
  # builds fresh so a stray ./target is only copy bloat.
  src = lib.cleanSource ../.;

  cargoLock = {
    lockFile = ../Cargo.lock;
    # HONEST CORRECTION: the workspace pulls the ownerless Bloch-SIS-PoW protocol
    # from GIT (Cargo.lock: `source = "git+…blochsispow-group/BlochSISPoW-project…"`),
    # so these crates are NOT crates.io/path deps and DO need fixed-output hashes.
    # `lib.fakeHash` is the fail-closed sentinel: the first `nix build .#bloch` on
    # a Nix host FAILS and prints the correct `sha256-…` to paste in. We do not
    # fabricate hashes on this non-Nix host. See os/seal-gate.nix for the same
    # note — including the pre-box dual-git-rev dedupe fix (Cargo.lock now pins
    # bloch/bloch-crypto/bloch-sis-pow/coherence-core/pqcrypto-internals to a
    # SINGLE rev each; `cargo metadata --locked` verified coherent).
    outputHashes =
      # All five crates resolve to the SAME git source (blochsispow-group/
      # BlochSISPoW-project @ dd8df35), so they share ONE fixed-output hash.
      # Filled from the real `nix build` failure on the postern-os-build host
      # (2026-07-14): specified fakeHash, got the value below.
      {
        "bloch-0.1.0-genesis" = "sha256-+qw8Boo1l0fVuo51EQC3qZ+y2KM0MKUll3mGfYOGAXs=";
        "bloch-crypto-0.1.0-genesis" = "sha256-+qw8Boo1l0fVuo51EQC3qZ+y2KM0MKUll3mGfYOGAXs=";
        "bloch-sis-pow-0.1.0" = "sha256-+qw8Boo1l0fVuo51EQC3qZ+y2KM0MKUll3mGfYOGAXs=";
        "coherence-core-0.1.0" = "sha256-+qw8Boo1l0fVuo51EQC3qZ+y2KM0MKUll3mGfYOGAXs=";
        "pqcrypto-internals-0.2.11" = "sha256-+qw8Boo1l0fVuo51EQC3qZ+y2KM0MKUll3mGfYOGAXs=";
      };
  };

  nativeBuildInputs = [ pkg-config clang ];
  # glib: a workspace dep pulls `glib-sys` (needs glib-2.0.pc via pkg-config).
  # Native aarch64 build on Graviton surfaced this — it was masked before by the
  # qemu-user rustc crash aborting the build earlier (2026-07-15).
  buildInputs = [ openssl rocksdb glib ];

  # librocksdb-sys: link the system rocksdb instead of recompiling it, and point
  # bindgen at libclang.
  ROCKSDB_LIB_DIR = "${rocksdb}/lib";
  ROCKSDB_INCLUDE_DIR = "${rocksdb}/include";
  LIBCLANG_PATH = "${llvmPackages.libclang.lib}/lib";

  # Build the node + its companion bins (wallet/cli); skip the heavy test suite
  # in the image build (it runs in CI).
  doCheck = false;

  meta = with lib; {
    description = "Bloch-SIS post-quantum, pure-PoW BlockDAG node";
    longDescription = ''
      The Bloch-SIS node: SHAKE-256 hashcash Proof-of-Work with a Module-SIS
      structural gate, hybrid Falcon+ML-DSA signatures, GhostDAG-Q consensus.
      Testnet is zero-security by design — do not attach value.
    '';
    license = with licenses; [ mit asl20 ];
    platforms = platforms.linux;
    mainProgram = "bloch";
  };
}
