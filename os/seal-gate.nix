{ lib
, rustPlatform
}:

# Reproducible build of the Postern Seal gate + verifier CLI from the
# products workspace (crates/postern-seal-companion, feature `sev-snp`):
#   postern-seal-gate   — the guest-side attestation endpoint (POSTERN-CLOUD.md §4.1)
#   postern-seal-verify — the client-side verifier (chains the report to the AMD root)
#
# HONEST STATUS: written on a non-Nix host — expression is idiomatic but NOT
# built here; validate with `nix build .#seal-gate` on a Nix host. The gate's
# /dev/sev-guest path additionally needs a real SEV-SNP VM (see
# docs/specs/POSTERN-CLOUD-CONFIDENTIAL.md).
rustPlatform.buildRustPackage {
  pname = "postern-seal-gate";
  version = "0.1.0";

  src = lib.cleanSource ../.;

  cargoLock = {
    lockFile = ../Cargo.lock;
    # The workspace consumes the ownerless Bloch-SIS-PoW protocol from GIT (see
    # Cargo.lock: `source = "git+https://gitlab.com/blochsispow-group/…"`), so
    # Nix needs a fixed-output hash for every git-sourced crate below.
    #
    # HONEST NOTE: `lib.fakeHash` is the canonical FAIL-CLOSED sentinel — it is
    # NOT a real hash. It deliberately makes the first `nix build .#seal-gate`
    # on a Nix host FAIL and print the correct `sha256-…` for each crate, which
    # you then paste in (or run `os/seal-gate/fill-outputhashes.sh`, which parses
    # that fail-closed output and rewrites these 5 keys — VM-only; see
    # `os/seal-gate/README.md` for the runbook + dual-rev dedupe). We cannot
    # compute these on a non-Nix host and will not
    # fabricate a plausible-looking value (a made-up hash is a lie that fails
    # the build anyway). Until they are filled on a Nix host, the build is
    # honestly un-buildable — built ≠ booted, and unpinned ≠ pinned.
    #
    # DUAL-REV COLLISION: FIXED pre-box. Was: Cargo.lock pinned bloch-crypto /
    # bloch-sis-pow / coherence-core / pqcrypto-internals at TWO git revs —
    # `?branch=main#ce85756…` alongside `?rev=dd8df35…` — because
    # desktop/src-tauri/Cargo.toml pulled the `bloch` crate via the floating
    # `branch = "main"` ref while every other consumer pinned `bloch-crypto`
    # directly to `rev = "dd8df3526…"`. `importCargoLock` keys outputHashes by
    # `name-version` and cannot hold two revs of one crate, so the first
    # `fill-outputhashes.sh` run would have hit the documented exit-3 dual-rev
    # abort. Root-caused and deduped: `desktop/src-tauri/Cargo.toml`'s `bloch`
    # dep and the root `Cargo.toml`'s `[patch.crates-io] pqcrypto-internals`
    # are now both pinned to the same `rev = "dd8df3526518ba792057708a6aa0efd5a91d8e40"`
    # (verified a strict descendant of `ce85756…`, workspace still vendors all
    # 5 crates at that rev), then the lock was regenerated for real
    # (network-reachable gitlab.com, no Nix needed) with a SINGLE `cargo update`
    # naming all 5 affected PackageIdSpecs together:
    #   cargo update -p bloch \
    #     -p 'git+…BlochSISPoW-project.git?branch=main#bloch-crypto@0.1.0-genesis' \
    #     -p 'git+…BlochSISPoW-project.git?branch=main#bloch-sis-pow@0.1.0' \
    #     -p 'git+…BlochSISPoW-project.git?branch=main#coherence-core@0.1.0' \
    #     -p pqcrypto-internals
    # NON-OBVIOUS PITFALL found empirically (matters if this needs to be redone):
    # updating only a SUBSET of these 5 (e.g. just `-p bloch -p pqcrypto-internals`,
    # or `-p bloch` alone) silently DROPS the `[patch.crates-io] pqcrypto-internals`
    # override — cargo resolves it back to the plain crates.io registry crate
    # instead of the seeded-RNG fork, with NO error or warning. That would quietly
    # break `Wallet::from_seed`/`with_seeded_rng` while still producing a
    # green-looking Cargo.lock. Verified this both ways: the 5-name scoped update
    # above keeps `pqcrypto-internals` git-sourced (correct); a fully unscoped
    # `cargo update` also keeps it git-sourced but additionally drifts ~15
    # unrelated transitive deps (sha1/uuid/winnow/rand/…) — avoided here in favor
    # of the minimal 5-crate scope. `git diff Cargo.lock` now shows exactly one
    # source line per crate (all `rev=dd8df3526…`), zero `branch=main` refs, and
    # `cargo metadata --locked` exits 0 (1032 packages, 18 workspace members,
    # fully coherent — re-confirmed after the corrected scoped update). The 5
    # `lib.fakeHash` sentinels below are unchanged — a Nix host still has to
    # compute the real FOD hashes — but `fill-outputhashes.sh`'s exit-3 dual-rev
    # guard should no
    # longer trigger on first run.
    outputHashes = {
      "bloch-0.1.0-genesis" = lib.fakeHash;
      "bloch-crypto-0.1.0-genesis" = lib.fakeHash;
      "bloch-sis-pow-0.1.0" = lib.fakeHash;
      "coherence-core-0.1.0" = lib.fakeHash;
      "pqcrypto-internals-0.2.11" = lib.fakeHash;
    };
  };

  buildAndTestSubdir = "crates/postern-seal-companion";
  buildFeatures = [ "sev-snp" ];
  cargoBuildFlags = [ "--bins" ];

  # The SNP vector tests are pure-compute and could run here; the image build
  # skips them like os/package.nix does (they run in CI on the dev host).
  doCheck = false;

  meta = with lib; {
    description = "Postern Seal gate — SEV-SNP attestation endpoint + verifier (attestation-before-connect)";
    license = with licenses; [ mit asl20 ];
    platforms = platforms.linux;
    mainProgram = "postern-seal-gate";
  };
}
