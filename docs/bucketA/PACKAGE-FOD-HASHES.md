# `os/package.nix` — the 5 FOD hashes (found, not guessed)

> **SUPERSEDED — the OS build now uses the protocol repo's own flake
> (`blochsispow-group/BlochSISPoW-project`), which has zero git-sourced
> crates and no FOD-hash step; this doc is retained for history only.** The
> hash recorded below is real — genuinely observed in a real remote build
> log, not fabricated (see "Source of the hash" below) — but it was never
> applied to the working tree, and the FOD-hash problem it documents no
> longer exists for the current build path. Do not treat this doc as
> describing the live build.

## Result: 5/5 known — one real hash, recorded (NOT applied)

All 5 `outputHashes` entries in `os/package.nix` point at the **same** git
source string in `Cargo.lock`:

```
git+https://gitlab.com/blochsispow-group/BlochSISPoW-project.git?rev=dd8df3526518ba792057708a6aa0efd5a91d8e40#dd8df3526518ba792057708a6aa0efd5a91d8e40
```

(verified by reading each of the 5 `[[package]]` blocks in `Cargo.lock` on
2026-07-13 — `bloch`, `bloch-crypto`, `bloch-sis-pow`, `coherence-core`,
`pqcrypto-internals` all carry this exact `source =` line, post the
`47d4ba5 fix(cargo): dedupe the pre-box dual-git-rev Cargo.lock collision`
commit that unified them onto one rev.)

Because all 5 crates come from the **same git url + same rev**, Nix's
`cargoLock.outputHashes` machinery does a **single** `fetchgit` for the whole
repo checkout (nixpkgs manual: crates sharing a repo must share one hash) —
confirmed empirically in the build log: only **one** `hash mismatch in
fixed-output derivation` block appears, for a derivation named after the repo
itself (`BlochSISPoW-project-dd8df35`), not per-crate:

```
s3://postern-os-build-1783966602/logs/build.log, lines 10552-10554:
error: hash mismatch in fixed-output derivation '/nix/store/gs3hd87xq1ihvfafiil7hkpr06xi6sc9-BlochSISPoW-project-dd8df35.drv':
         specified: sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
            got:    sha256-+qw8Boo1l0fVuo51EQC3qZ+y2KM0MKUll3mGfYOGAXs=
```

The build's own summary block (lines 82977-82984) confirms this is the
*only* hash Nix ever computed, and shows why the automated
`fill-outputhashes.sh`-style script filled **0/5**: it parses the FOD
derivation name and expects it to equal one of the 5 sentinel keys
(`bloch-0.1.0-genesis`, `bloch-crypto-0.1.0-genesis`, `bloch-sis-pow-0.1.0`,
`coherence-core-0.1.0`, `pqcrypto-internals-0.2.11`) — but the shared-repo FOD
is named `BlochSISPoW-project-dd8df35`, which matches none of them, so every
sentinel was left unfilled:

```
parsed hashes:
BlochSISPoW-project-dd8df35	sha256-+qw8Boo1l0fVuo51EQC3qZ+y2KM0MKUll3mGfYOGAXs=
WARN: no hash parsed for bloch-0.1.0-genesis (target=os/package.nix)
WARN: no hash parsed for bloch-crypto-0.1.0-genesis (target=os/package.nix)
WARN: no hash parsed for bloch-sis-pow-0.1.0 (target=os/package.nix)
WARN: no hash parsed for coherence-core-0.1.0 (target=os/package.nix)
WARN: no hash parsed for pqcrypto-internals-0.2.11 (target=os/package.nix)
filled 0/5 sentinels in os/package.nix
```

**Source of the hash:** directly observed in
`s3://postern-os-build-1783966602/logs/build.log` (a real `nix build .#bloch`
run on a Nix host, `git rev dd8df3526…`). Cross-checked against `Cargo.lock`
in this repo (git blob, `HEAD` / `47d4ba5`) to confirm all 5 crates share the
one git source that produced this hash. This is the only place the value
was found — it was not fabricated.

`build-attempt1-FAILED.log` was a separate, earlier, unrelated failure (an
`amazonlinux`/`dnf` `curl` package conflict during base-image provisioning,
before the Nix build stage was ever reached) — it contains **no** `got:
sha256-` lines and contributes nothing here.

**Git history check (path 2):** `git log -p --all -- os/package.nix` across
every local branch shows the 5 keys have **always** been `lib.fakeHash` in
this file — no prior commit ever had them filled with real values in
`os/package.nix` itself, and a full-history search for the discovered hash
string (`+qw8Boo1l0fVuo51EQC3qZ+y2KM0MKUll3mGfYOGAXs`) returns zero hits
anywhere in git history. So the only confirmed source is the S3 build log,
combined with the Cargo.lock same-repo/same-rev fact.

## The exact `os/package.nix` edit

```nix
    outputHashes = {
      "bloch-0.1.0-genesis" = "sha256-+qw8Boo1l0fVuo51EQC3qZ+y2KM0MKUll3mGfYOGAXs=";
      "bloch-crypto-0.1.0-genesis" = "sha256-+qw8Boo1l0fVuo51EQC3qZ+y2KM0MKUll3mGfYOGAXs=";
      "bloch-sis-pow-0.1.0" = "sha256-+qw8Boo1l0fVuo51EQC3qZ+y2KM0MKUll3mGfYOGAXs=";
      "coherence-core-0.1.0" = "sha256-+qw8Boo1l0fVuo51EQC3qZ+y2KM0MKUll3mGfYOGAXs=";
      "pqcrypto-internals-0.2.11" = "sha256-+qw8Boo1l0fVuo51EQC3qZ+y2KM0MKUll3mGfYOGAXs=";
    };
```

i.e. every `lib.fakeHash` → the single literal
`"sha256-+qw8Boo1l0fVuo51EQC3qZ+y2KM0MKUll3mGfYOGAXs="`.

Not applied to the working tree (no commit/push per instructions) — this doc
records the edit to make so a future `nix build .#bloch` can be pre-filled
deterministically instead of iterating.

## Note: `os/seal-gate.nix` has the identical 5-key block

`os/seal-gate.nix` (the Postern Seal gate build) pins the exact same 5
sentinel keys against the exact same `Cargo.lock` git source. The same
reasoning and the same hash almost certainly apply there too, but this was
not asked for and the log only shows a `.#bloch` build, not `.#seal-gate` —
flagging it as a likely follow-up, not asserting it as verified.

## Still needed before calling this "built"

The hash above is real and traceable to a genuine `nix build` FOD mismatch,
but it has **not** been confirmed to produce a fully green `nix build
.#bloch` (the captured log only shows the first `--keep-going` pass through
the hash-mismatch stage; later, unrelated errors — e.g. the
`pqcrypto-internals-0.2.11.drv` "Cannot build" failure at build.log:39457 —
happen downstream of the FOD and were not diagnosed here, since they are
compile-stage errors, not hash-stage ones). After pasting in this hash,
a real Nix host still needs to run `nix build .#bloch` again to confirm no
further errors remain.
