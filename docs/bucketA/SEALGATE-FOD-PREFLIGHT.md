<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# `os/seal-gate.nix` FOD-hash fill — pre-flight (before the box touches `.#seal-gate`/`.#cloud-image`)

> **STATUS: PRE-FLIGHT ONLY. No Nix here.** Written on a non-Nix macOS host.
> The only validation performed is static: reading the four source files,
> diffing the two `outputHashes` blocks, `shellcheck` + `sh -n` on
> `fill-outputhashes.sh`, and running its exact `awk` parser against a
> **synthetic** Nix-error fixture built by hand to match the format the
> script's own comments assume. No real `nix build` ran anywhere to produce
> this document — `nix` is not installed on this host (confirmed:
> `which nix` → not found). Nothing here is a claim that the fill will
> succeed on the box; it is a claim about what the tooling does and does not
> already handle, ahead of that run.

> **⚠ ENTIRE FLOW SUPERSEDED — this whole document describes the dead FOD path.**
> `os/seal-gate.nix`'s 5 `lib.fakeHash` sentinels, `fill-outputhashes.sh`, the
> paste-then-verify reuse strategy, and the box run order below all assume the
> OS build fills `cargoLock.outputHashes` for git-sourced crates. That path is
> **dead**: the OS build now sources the `bloch` node (and the seal gate) from
> the **protocol repo's own flake**
> (`gitlab.com/blochsispow-group/BlochSISPoW-project`), which has **zero
> git-sourced crates and no FOD-hash step at all** — so there are no sentinels
> to fill and `fill-outputhashes.sh` has nothing to parse on the live path. See
> [`PACKAGE-FOD-HASHES.md`](PACKAGE-FOD-HASHES.md) (supersession header) and
> dossier item 7 ([`../design/RESUME-DOSSIER-2026-07-16.md`](../design/RESUME-DOSSIER-2026-07-16.md)).
> **This pivot is a recorded decision, NOT yet implemented in the tree** —
> `os/seal-gate.nix` still carries the FOD block, `flake.lock` is still the
> empty seed, and **no OS image (`.#seal-gate`/`.#cloud-image` included) has
> ever been built.** Retained below for history until the pivot lands.

## Files read

- `os/seal-gate.nix`
- `os/seal-gate/fill-outputhashes.sh`
- `os/seal-gate/README.md`
- `os/package.nix` (for comparison — this is the file whose inline
  hash-fill attempt reportedly scored 0/5)
- `flake.nix` (to confirm `.#seal-gate` and `.#bloch` wiring)
- `docs/bucketA/IMAGE-TARGETS.md` (existing prep doc that already flags the
  identical-revs opportunity, §3)

## 1. Does `fill-outputhashes.sh`'s parser actually work?

**Static checks — both clean:**

```
$ shellcheck os/seal-gate/fill-outputhashes.sh
(no output, exit 0)

$ sh -n os/seal-gate/fill-outputhashes.sh
(no output, exit 0)
```

**Fixture test.** The script's step 4 comment (`fill-outputhashes.sh:98-103`)
documents the exact Nix output shape it expects per mismatched FOD:

```
error: hash mismatch in fixed-output derivation '/nix/store/<h>-<name>.drv':
         specified: sha256-AAAA…   (our fakeHash)
            got:    sha256-<REAL>
```

I built a synthetic log (`fixture-nix-fod-log2.txt`, in the session scratch
dir, not committed) with 5 such blocks — one per sentinel — each using a
32-character store-hash prefix drawn only from Nix's real base32 alphabet
(`0-9a-df-np-sv-z`, i.e. excluding `e`, `o`, `t`, `u`, which real Nix store
hashes never contain), and derivation names set literally to the 5
`SENTINEL_KEYS` values (`bloch-0.1.0-genesis.drv`,
`bloch-crypto-0.1.0-genesis.drv`, `bloch-sis-pow-0.1.0.drv`,
`coherence-core-0.1.0.drv`, `pqcrypto-internals-0.2.11.drv`). I then ran the
script's `awk` block (copied verbatim from the file, not reimplemented)
against it, followed by the same `SENTINEL_KEYS`-matching loop the script
uses in step 5.

**Result: 5/5 parsed, 5/5 matched to sentinel keys, 5/5 "filled".** The
mechanical parsing logic (quote extraction, `.drv` suffix strip, 32-char
base32 store-hash-prefix strip, `got:`/`sha256-` token scan, and the final
exact-string match against `SENTINEL_KEYS`) is internally correct and does
what its own comments claim — **against a fixture built to match those
comments.**

One thing the fixture run incidentally demonstrated: I first wrote a
throwaway version of the fixture using placeholder store-hash prefixes like
`u0000000000000000000000000000005-` for readability. The prefix-strip regex
(`^[0-9a-df-np-sv-z]{32}-`) correctly **failed** to strip that prefix,
because `u` is outside Nix's real base32 alphabet — so that entry survived
into `PARSED` as `u0000…0005-pqcrypto-internals-0.2.11` instead of
`pqcrypto-internals-0.2.11`, and would not have matched its sentinel key.
That's not a bug in the script; it's the regex correctly rejecting an
invalid store hash — but it shows the parser is **exact-format-fragile**:
anything that makes the real Nix output deviate from the documented shape
(store-hash alphabet, `.drv` suffix present, quote characters, the literal
`<name>-<version>` derivation-name convention) will silently drop that
entry to a `WARN: no got-hash reported` rather than a fill.

**So: works, conditionally.** The parser is correct against the format it
assumes. Whether that format still matches current `nix build` output on
the actual box (Nix version/message-format drift, or `--keep-going`
producing a different ordering/wrapping under load) cannot be confirmed
without a Nix host — the task's "no real Nix here, don't fake" constraint
applies squarely here. I did not find, in this repo, the actual log or code
of `os/package.nix`'s "inline attempt" that scored 0/5, so I can't diff its
parse logic against this script's directly. What I can say with confidence:

- **There is no committed script for `os/package.nix`** anywhere in this
  repo (`find … -iname "*fill*outputhash*"` returns only
  `os/seal-gate/fill-outputhashes.sh`). Whatever produced the 0/5 for
  `package.nix` was an ad hoc/inline attempt, not this tested, committed
  parser — so "same or different logic" can't be answered by direct code
  diff; it has to be answered by what's testable, which is what's above.
- **The single most plausible shared failure mode** between an inline
  package.nix attempt and this seal-gate script is the `<name>-<version>`
  derivation-naming assumption baked into both `SENTINEL_KEYS` and any
  hand-rolled `outputHashes` key lookup: `cargoLock.outputHashes` in
  nixpkgs is keyed by that exact string, and the parser only works if the
  FOD `.drv`'s basename in the real error text is literally that string. If
  the box's nixpkgs revision names these fetch derivations differently
  (e.g. an added suffix, or a name that isn't `<name>-<version>` at all),
  **both** an inline attempt and this script would score low/zero for the
  same structural reason — because they're both consuming the same
  nixpkgs `importCargoLock` convention on the same `Cargo.lock`. This is a
  hypothesis, not a confirmed root cause of the package.nix 0/5 — flagging
  it as the first thing to check if `fill-outputhashes.sh` also comes back
  0/5 on the box: `grep "hash mismatch" <build.log>` and eyeball whether the
  quoted `.drv` basename actually equals one of the 5 `SENTINEL_KEYS` before
  assuming the script itself is broken.

## 2. Are the seal-gate crate revs identical to `package.nix`'s?

**Yes — confirmed two ways, both static:**

1. `diff <(grep -A8 "outputHashes = {" os/package.nix) <(grep -A8 "outputHashes = {" os/seal-gate.nix)` → **empty diff**. The two `outputHashes` blocks (5 keys, `lib.fakeHash` placeholders, same order) are byte-for-byte identical.
2. Both files point `cargoLock.lockFile` at the same `../Cargo.lock` (repo-root, one lockfile, not per-package copies), and both header comments cross-reference the same pre-box dedupe fix — `os/package.nix:29-32` says "See os/seal-gate.nix for the same note — including the pre-box dual-git-rev dedupe fix ... pins bloch/bloch-crypto/bloch-sis-pow/coherence-core/pqcrypto-internals to a SINGLE rev each"; `os/seal-gate.nix:37-74` documents that single rev as `dd8df3526518ba792057708a6aa0efd5a91d8e40` for all 5 crates.

This matches what `docs/bucketA/IMAGE-TARGETS.md` §3 already says explicitly:
`.#cloud-image`'s extra `outputHashes` map is "a **separate `outputHashes`
map from `os/package.nix`'s**, even though it pins the identical 5 crates at
the identical rev" — and recommends trying the package.nix hashes in
seal-gate.nix first, falling back to the filler script only if that guess
doesn't verify.

**Conclusion: yes, the same 5 real hashes are reusable once found** — same
crate, same rev, same source ⇒ same NAR content ⇒ same `sha256-…` FOD hash
is the correct expectation (not a certainty worth skipping the verification
build, per IMAGE-TARGETS.md's own framing — paste, then confirm with a real
`nix build .#seal-gate`, don't just assume).

## 3. Exact run order on the box

Both `.#seal-gate` and `.#bloch` are already wired into `flake.nix`
(`flake.nix:113-114` for `bloch`/`default`, `flake.nix:158-159` for
`seal-gate`) — the "O2 must wire the flake output first" prerequisite in
`os/seal-gate/README.md` §"Prerequisite" is **stale**; no flake-wiring step
is needed before either fill.

Dependency shape that drives the order: `os/package.nix` (`blochPkg`) is
threaded into `.#iso`, `.#desktop-iso`, `.#attested-image`, and
`.#cloud-image` (via `specialArgs`/module args) — everything needs it.
`os/seal-gate.nix` is pulled in only by `os/cloud.nix`'s
`postern-seal-gate` systemd unit, i.e. only `.#cloud-image` (and
`.#seal-gate` itself) need it.

Recommended order:

1. **Fill `os/package.nix`'s 5 sentinels first.** No committed script exists
   for this file; run `nix build .#bloch --keep-going` (or `.#iso`, which
   forces the same dependency) and parse/paste the 5 real `sha256-…`
   values by hand — or, if the earlier inline attempt's 0/5 turns out to be
   a fixable format issue (§1), adapt `fill-outputhashes.sh`'s awk logic
   (swap `NIX_FILE`/`SENTINEL_KEYS` target) rather than re-inventing it.
   This step is the actual prerequisite for everything else — `.#iso`
   itself cannot build clean without it, and it's the one this session
   cannot pre-flight further (it's the reported 0/5 wall).
2. **`nix build .#bloch`** clean, to confirm the 5 pasted/filled hashes are
   real and correct before trusting them anywhere else.
3. **`nix build .#iso`** — the existing baseline target; per
   `docs/bucketA/IMAGE-TARGETS.md` §3 this is expected to just work once
   step 1–2 are done, since `.#iso` needs no hashes beyond `package.nix`'s 5.
4. **Paste the same 5 real hashes from step 1 into `os/seal-gate.nix`**
   (since §2 above confirms identical crates/rev ⇒ identical NAR hash is
   expected) as a first attempt, skipping a redundant fail-and-parse cycle.
5. **`nix build .#seal-gate`** to verify the pasted guess.
   - If it builds clean: done, no need to run the filler script at all.
   - If it does **not** verify (a `got:` hash differs from the pasted
     guess — possible if some environment/build-input difference between
     the two derivations affects the fetch, even for "the same" source):
     run **`./os/seal-gate/fill-outputhashes.sh`** to redo the
     fail-and-parse loop specifically against `os/seal-gate.nix`, then
     re-run `nix build .#seal-gate` clean.
6. **`nix build .#cloud-image`** — needs both `package.nix`'s hashes (for
   `blochPkg`) and `seal-gate.nix`'s hashes (its systemd unit calls
   `pkgs.callPackage ./seal-gate.nix { }` directly in `os/cloud.nix:91`,
   which is part of `config.system.build.toplevel`), so this is the
   earliest point both must be done.
7. `.#desktop-iso` and `.#attested-image` need no new hashes beyond
   `package.nix`'s 5 (per IMAGE-TARGETS.md §3) and can run any time after
   step 2/3, in parallel with steps 4–6 if the box has spare capacity.

In short: **package first (it's the hard blocker and the only one with a
reported failure), `.#bloch`/`.#iso` to confirm it, then seal-gate
(paste-then-verify, filler script only as fallback), then `.#cloud-image`.**

## 4. Fixture test result (summary)

- `shellcheck os/seal-gate/fill-outputhashes.sh` → clean, exit 0.
- `sh -n os/seal-gate/fill-outputhashes.sh` → clean, exit 0.
- Synthetic 5-block Nix-FOD-error fixture (valid nix32 store-hash prefixes,
  `<name>-<version>.drv` naming, `specified:`/`got:` lines) → the script's
  own `awk` parser: **5/5 parsed**, then the `SENTINEL_KEYS` match loop:
  **5/5 filled**. Confirms the parser is internally correct against the
  format it documents. Does not and cannot confirm it will still match
  whatever `nix build .#seal-gate --keep-going` actually prints on the real
  box — that's the one thing only a Nix host can answer, and is exactly the
  wall `os/package.nix`'s inline attempt hit at 0/5 (root cause of that 0/5
  not found in this repo — no log or script for it is committed here).

## RETURN

- **seal-gate fill parser works or not (vs package.nix's):** The committed
  `fill-outputhashes.sh` parser is mechanically correct — `shellcheck`/
  `sh -n` clean, and scores 5/5 against a fixture matching its own
  documented Nix-output format. There is no committed script for
  `package.nix` to diff it against (its "inline attempt" isn't in this
  repo), so I can't confirm whether it used the same logic. The most likely
  shared risk for both is the `<name>-<version>` FOD-derivation-naming
  assumption baked into `SENTINEL_KEYS` — if that's what broke package.nix's
  attempt, seal-gate's script would hit the identical wall, since both key
  off the same nixpkgs `cargoLock.outputHashes` convention on the same
  `Cargo.lock`.
- **Revs identical, hashes reusable?** Yes — confirmed by an empty `diff` of
  the two `outputHashes` blocks and by both files' header comments pointing
  at the same `Cargo.lock` and the same single rev
  (`dd8df3526518ba792057708a6aa0efd5a91d8e40`) for all 5 crates. Reuse
  strategy: paste package.nix's filled hashes into seal-gate.nix first,
  verify with `nix build .#seal-gate`, fall back to
  `fill-outputhashes.sh` only if that guess doesn't verify.
- **Box run order:** fill `os/package.nix` (no script, manual/adapted parse)
  → `nix build .#bloch` clean → `nix build .#iso` clean → paste same 5
  hashes into `os/seal-gate.nix` → `nix build .#seal-gate` (fallback:
  `./os/seal-gate/fill-outputhashes.sh` if the paste doesn't verify) →
  `nix build .#cloud-image`. `.#desktop-iso`/`.#attested-image` need no new
  hashes and can run any time after the package.nix step.
- **Fixture test result:** `shellcheck` clean, `sh -n` clean, synthetic
  5-block fixture → 5/5 parsed and 5/5 filled by the script's actual awk
  logic (copied verbatim, not reimplemented). No real Nix was run; this
  validates the parser's internal correctness against its documented
  format assumption only, not against the live box's actual Nix output.
