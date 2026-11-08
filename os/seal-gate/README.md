# `os/seal-gate/` — filling the reproducible-build hashes

> **HONEST STATUS (SCAFFOLD / UNAUDITED):** everything in this directory and in
> `os/seal-gate.nix` was **written on a non-Nix macOS host and NOT built there.**
> No `nix build`, no filled cargo hash, and no booted gate has happened on the
> workstation. The only static validation done on macOS is `shellcheck` on the
> filler script and a brace-balance check on the `.nix`. Everything below marked
> **VM-only** must run inside a Nix host / SEV-SNP VM — treat any claim otherwise
> as false.

`os/seal-gate.nix` is the reproducible build of the Postern Seal gate + verifier
(`postern-seal-gate`, `postern-seal-verify`) from
`crates/postern-seal-companion` with the `sev-snp` feature. Its function
signature `{ lib, rustPlatform }` is **FROZEN** because `os/cloud.nix` calls it
as `pkgs.callPackage ./seal-gate.nix { }`. Do not change the signature.

The workspace pulls the ownerless Bloch-SIS-PoW protocol from **git**, so Nix
needs a fixed-output hash for each git-sourced crate. Until those are filled,
the 5 entries in `cargoLock.outputHashes` are the fail-closed sentinel
`lib.fakeHash` — the build is honestly **un-buildable** on purpose.

## The 5 sentinels (must match Cargo.lock git-sourced `name-version`s)

| outputHashes key            | Cargo.lock git rev(s)                          |
|-----------------------------|------------------------------------------------|
| `bloch-0.1.0-genesis`       | `?branch=main#ce85756…` (single rev)           |
| `bloch-crypto-0.1.0-genesis`| `?branch=main#ce85756…` **AND** `?rev=dd8df35…`|
| `bloch-sis-pow-0.1.0`       | `?branch=main#ce85756…` **AND** `?rev=dd8df35…`|
| `coherence-core-0.1.0`      | `?branch=main#ce85756…` **AND** `?rev=dd8df35…`|
| `pqcrypto-internals-0.2.11` | `?branch=main#ce85756…` (single rev)           |

These 5 keys were cross-checked against `Cargo.lock` on macOS (static grep only).
Three of them (`bloch-crypto`, `bloch-sis-pow`, `coherence-core`) are pinned at
**two** git revs — see the dedupe section below.

## Prerequisite: O2 must wire the flake output first

`seal-gate.nix` is only reachable today via `os/cloud.nix`. To build it directly
you need `.#seal-gate`, which **OS Dev O2 owns `flake.nix`** and must add. The
snippet O1 is requesting from O2 (model it on the existing `bloch` package):

```nix
# inside `packages = forAllSystems (system: { … })`, next to `bloch`:
#   seal-gate is linux-only (meta.platforms = platforms.linux) but, like `bloch`,
#   builds on both linux systems, so it can live in the base attrset.
seal-gate = (import nixpkgs { inherit system; }).callPackage ./os/seal-gate.nix { };
```

If O2 prefers to scope it to x86_64 only (the cloud/SNP target), place it in the
existing `optionalAttrs (system == "x86_64-linux")` block instead. Either works;
the filler script only needs `.#seal-gate` to evaluate.

## VM runbook — fill the hashes and build (VM-only)

Run **on a Nix host** (the macOS workstation cannot do any of this):

```sh
# 0. confirm O2's flake wiring is live:
nix eval .#seal-gate.name          # must succeed

# 1. one command does the fill:
./os/seal-gate/fill-outputhashes.sh
#    - runs `nix build .#seal-gate --keep-going` (first run FAILS by design),
#    - parses the printed real sha256- values,
#    - rewrites the 5 lib.fakeHash sentinels in os/seal-gate.nix (backup .bak kept).

# 2. build for real (the script does NOT do this — it refuses to claim success):
nix build .#seal-gate
#    -> ./result/bin/postern-seal-gate  and  ./result/bin/postern-seal-verify

# 3. review + commit the pin:
git diff os/seal-gate.nix              # confirm 5 real sha256- values, no fakeHash
```

If you prefer to fill by hand: run `nix build .#seal-gate --keep-going`, copy
each `got:    sha256-…` into the matching `outputHashes` key, delete the `.bak`.

Only after step 2 builds cleanly may the pin be called **built**. The gate's
`/dev/sev-guest` runtime path additionally needs a real SEV-SNP VM (see
`docs/specs/POSTERN-CLOUD-CONFIDENTIAL.md`) — building ≠ booting ≠ attesting.

## §Dual-rev dedupe — FIXED pre-box (was the documented caveat)

`importCargoLock`/`buildRustPackage` keys `cargoLock.outputHashes` by
`name-version` and **cannot hold two git revs of the same crate**. `Cargo.lock`
used to pin `bloch-crypto`, `bloch-sis-pow`, `coherence-core`, and
`pqcrypto-internals` at **two** git revs (`?branch=main#ce85756…` *and*
`?rev=dd8df35…`), which would have made `nix build` report a
duplicate/conflicting git source and made `fill-outputhashes.sh` abort
fail-closed with `exit 3` on its first VM run.

**Root cause, found by inspection (macOS, no Nix needed):**
`desktop/src-tauri/Cargo.toml` was the *only* workspace member pulling the
`bloch` crate itself, via the floating `branch = "main"` ref — while every
other consumer (`postern-courier`, `postern-seal-companion`,
`postern-consiglio-auth`, `mobile/core`, `mobile/signer`, `desktop/src-tauri`'s
sibling deps, etc.) pinned `bloch-crypto` directly to `rev =
"dd8df3526518ba792057708a6aa0efd5a91d8e40"`. Because `bloch`'s internal
path-deps (`bloch-crypto`/`bloch-sis-pow`/`coherence-core`) and the root
`[patch.crates-io]` pin for `pqcrypto-internals` all resolved through that same
`branch=main` git source qualifier, they produced a second, older
(`#ce85756…`) copy of each crate alongside the `rev`-pinned one.

**Fix applied (pre-box, on macOS — this is a plain `cargo`/network operation,
not a Nix/QEMU one):**

1. Verified `dd8df3526…` is a strict descendant of `ce85756…`
   (`git merge-base --is-ancestor` against the live upstream repo — network
   access to gitlab.com was available) and that the upstream workspace at
   `dd8df3526…` still vendors all 5 needed crates. A safe forward-only re-pin,
   not a downgrade.
2. Repointed `desktop/src-tauri/Cargo.toml`'s `bloch` dependency and the root
   `Cargo.toml`'s `[patch.crates-io] pqcrypto-internals` from `branch = "main"`
   to `rev = "dd8df3526518ba792057708a6aa0efd5a91d8e40"` — the same rev already
   used everywhere else.
3. Ran a single `cargo update` for real (network-reachable gitlab.com git
   remote + crates.io index; no Nix required), naming all 5 affected
   PackageIdSpecs together in one invocation:
   ```sh
   cargo update -p bloch \
     -p 'git+https://gitlab.com/blochsispow-group/BlochSISPoW-project.git?branch=main#bloch-crypto@0.1.0-genesis' \
     -p 'git+https://gitlab.com/blochsispow-group/BlochSISPoW-project.git?branch=main#bloch-sis-pow@0.1.0' \
     -p 'git+https://gitlab.com/blochsispow-group/BlochSISPoW-project.git?branch=main#coherence-core@0.1.0' \
     -p pqcrypto-internals
   ```
   Cargo removed the duplicate `branch=main#ce85756…` entries for
   `bloch-crypto`, `bloch-sis-pow`, `coherence-core`, and `pqcrypto-internals`,
   and re-resolved `bloch` onto the single canonical rev.

   **Pitfall found empirically — do not shortcut this to a partial `-p` list.**
   Updating only a subset (e.g. `-p bloch -p pqcrypto-internals`, or `-p bloch`
   alone) *silently drops* the `[patch.crates-io] pqcrypto-internals` override:
   cargo quietly falls back to resolving `pqcrypto-internals` from the plain
   crates.io registry instead of the seeded-RNG fork, with **no error or
   warning**, still producing a green-looking `Cargo.lock`. That would break
   `Wallet::from_seed`/`with_seeded_rng` invisibly. Verified two ways: this
   5-name scoped update keeps `pqcrypto-internals` git-sourced (correct); a
   fully unscoped `cargo update` also keeps it git-sourced but additionally
   drifts ~15 unrelated transitive deps (sha1/uuid/winnow/rand/…) — the scoped
   5-name form above is the minimal correct fix and is what was actually run.
4. Confirmed: `grep -c 'branch=main' Cargo.lock` → `0`; each of the 5 sentinel
   crates now has exactly one `[[package]]` / one `source = "git+…"` line
   (all `?rev=dd8df3526…`); `pqcrypto-internals`'s source is still the git
   fork (not the crates.io registry — the seeded-RNG patch survived); and
   `cargo metadata --locked` exits `0` (1032 packages, 18 workspace members) —
   the whole dependency graph is coherent under the deduped lock.

The 5 `lib.fakeHash` sentinels in `os/seal-gate.nix` are **unchanged** — a Nix
host still has to compute the real fixed-output hashes — but
`fill-outputhashes.sh`'s dual-rev `exit 3` guard (§ above) should no longer
trigger on the first VM run, since there is now only one git source per crate
for it to hash.

> **Scope note:** `Cargo.lock` is repo-wide; this fix touched the root
> `Cargo.toml` and `desktop/src-tauri/Cargo.toml` (not `os/seal-gate.nix`'s
> `{ lib, rustPlatform }` signature, which stays frozen) to resolve a
> collision that would otherwise have blocked every OS-image Rust build on
> first box-day run, not just the seal gate.
