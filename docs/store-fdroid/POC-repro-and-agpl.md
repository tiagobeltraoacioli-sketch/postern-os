<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# POC — reproducible-build verifier mechanism + AGPL resolver

**Status:** design + box-gated POC. Nothing here was deployed or committed as
a repo change beyond this doc. Part 1's Nix commands were **not run** on this
host — see the honesty banner below before reading further. Part 2 is a
decision, made concretely, not a design option left open.

**Feeds:** `docs/store-fdroid/B-repro-verifier.md` (the verifier design this
POC exercises the mechanism of) and closes the "Open questions for 03"
sections left dangling in `docs/store-fdroid/01-architecture.md` §8 and
`docs/store-fdroid/02-reproducible-builds.md` §6 (no `03-honesty-license.md`
exists yet in this repo — this doc answers the AGPL question those two docs
deferred to it, scoped to exactly what was asked here).

---

## Part 1 — reproducible-build POC

### 0. Honesty banner (read before the script below)

```
$ which nix
nix not found
$ nix --version
(eval):1: command not found: nix
```

This host (macOS 14.8.7, x86_64, this working directory) has **no Nix
installation**. Per the repo's own discipline
(`docs/plan/FLAKE-REPRO.md`'s "STATUS — SCAFFOLD / UNAUDITED / WRITTEN, NOT
EVALUATED" banner, `os/seal-gate.nix`'s `lib.fakeHash` sentinels, `flake.lock`
committed as the empty seed with zero fabricated `narHash` values), **no store
path hash below is real**. Where a hash would appear, this doc writes
`<HASH-...>` as a placeholder and says so — never a plausible-looking value
standing in for a computed one. This is a **script + expected shape**, not a
result. Installing Nix on this host to force a real run was considered and
deliberately **not done**: the task scope is "HOST-testable," meaning
runnable on a Nix-capable host by someone else (or this host, later, with Nix
installed) reading this doc — not "make this host Nix-capable right now" as a
side effect of writing documentation.

### 1. Why a purpose-built minimal artifact, not the workspace derivations

Three candidates exist in this repo for "one small Nix-built artifact":

| Candidate | Why not it |
|---|---|
| `os/package.nix` (`.#bloch`) | Not small — full Rust workspace, `rocksdb`/`openssl`/`clang` inputs, and **fail-closed today**: 5 `outputHashes` are `lib.fakeHash` sentinels that make the *first* build deliberately fail (see `os/package.nix`'s own comment). A POC that "builds" this would either lie about the fakeHash gate or spend its first run just discovering real hashes — not a repro demo. |
| `os/seal-gate.nix` (`.#seal-gate`) | Same fakeHash gate, plus SEV-SNP-specific build surface — heavier, same problem. |
| root `flake.nix` (any of `.#iso`, `.#mobile-image`, …) | `flake.lock` at repo root is the **empty seed** (`{ "nodes": { "root": {} }, "root": "root", "version": 7 }`) — zero pinned revs. `FLAKE-REPRO.md` §1 is explicit that an empty seed "re-resolves the moving branch refs … on every evaluation," so two evaluations of *this* lock are not even a rigorous test of the two-builder procedure until it's frozen on a VM. Using it here would silently violate the exact "a moving lock is not a pin" rule `B-repro-verifier.md` §1 cites from this same doc. |

So the POC below is a **new, minimal, self-contained flake** — small enough
to build in seconds, with its own real pinned `flake.lock` (frozen for real,
on whatever Nix host runs this script — not fabricated here), demonstrating
the **identical mechanism** `B-repro-verifier.md` §1 and `FLAKE-REPRO.md` §4
specify (content-addressed store path, same pinned lock, independent
builders, `nix path-info --json` comparison) at negligible cost. This is a
smaller instance of the same check, not a different one — the store path's
content-addressing property (`/nix/store/<hash>-name`, hash = f(full input
closure)) is what's under test, and that property doesn't change with the
size of the derivation.

### 2. The artifact

Create `flake.nix` (e.g. in a scratch directory on a Nix-capable host — not
added to this repo by this POC):

```nix
# POC artifact — demonstrates the two-builder reproducibility check
# (docs/store-fdroid/B-repro-verifier.md §1, docs/plan/FLAKE-REPRO.md §4)
# at minimal cost. Not part of the product build graph.
{
  description = "Postern repro-verifier POC — minimal artifact";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
  outputs = { self, nixpkgs }:
    let
      system = builtins.currentSystem;
      pkgs = import nixpkgs { inherit system; };
    in {
      packages.${system}.poc = pkgs.writeTextFile {
        name = "postern-repro-poc";
        text = ''
          Postern reproducible-build POC artifact
          mirrors: postern.catalog/v1 reproducible_build interface
        '';
      };
    };
}
```

`writeTextFile`'s output path is a pure function of `name`, `text`, the
pinned `nixpkgs` revision, and the builder — the same content-addressing
property `B-repro-verifier.md` §2 describes for `os/package.nix` at scale,
just with no compiler, no network fetch, and a sub-second build.

### 3. Exact runnable script (Nix + flakes, any host — Linux or macOS)

```sh
mkdir -p /tmp/postern-repro-poc && cd /tmp/postern-repro-poc
# 1. write flake.nix (contents above)

# 2. freeze the lock — a REAL rev + narHash computed by Nix, never hand-written
#    (same discipline as FLAKE-REPRO.md §1: a hand-written lock is a lie
#    JSON cannot carry a disclaimer for)
nix flake lock

# pin the commit itself, same as FLAKE-REPRO.md §4's "SAME commit incl. the
# SAME flake.lock" requirement — a moving lock is not a pin
git init -q && git add flake.nix flake.lock && git commit -q -m "poc: freeze lock"

# ---- Builder A ----
nix build .#poc --print-out-paths | tee builderA.out
nix path-info --json ./result | tee builderA.json

# ---- Builder B (independent invocation) ----
# True independence = a second machine/container/user checking out the SAME
# commit (git clone from the commit above) and running the same two commands.
# A single-host rebuild after wiping ./result is the "weaker fallback"
# 02-reproducible-builds.md §1b names when only one builder is available —
# labeled as such here, not passed off as the real bar.
rm -rf result
nix build .#poc --print-out-paths | tee builderB.out
nix path-info --json ./result | tee builderB.json

# ---- Compare (the whole trick — B-repro-verifier.md §1 step 5) ----
HASH_A=$(jq -r '.[0].path' builderA.json)
HASH_B=$(jq -r '.[0].path' builderB.json)
if [ "$HASH_A" = "$HASH_B" ]; then
  echo "PASS: store paths identical — $HASH_A"
else
  echo "FAIL: mismatch — $HASH_A vs $HASH_B"
fi
```

**Expected PASS output** (shape only — no hash is fabricated here; the real
value is whatever `nix flake lock` + `nix build` compute on the host that
actually runs this):

```
builderA.out:  /nix/store/<HASH>-postern-repro-poc
builderB.out:  /nix/store/<HASH>-postern-repro-poc   # same <HASH>
PASS: store paths identical — /nix/store/<HASH>-postern-repro-poc
```

### 4. Forced FAIL — mutate, rebuild, hashes differ, badge denied

```sh
# mutate the artifact's content — the smallest possible source change
sed -i.bak 's/POC artifact/POC artifact v2/' flake.nix

nix build .#poc --print-out-paths | tee builderA-mutated.out
HASH_MUT=$(nix path-info --json ./result | jq -r '.[0].path')

if [ "$HASH_A" = "$HASH_MUT" ]; then
  echo "PASS (unexpected — would indicate a Nix bug)"
else
  echo "FAIL: mismatch — badge denied per B-repro-verifier.md §3"
fi
```

**Expected FAIL output:**

```
builderA.out:          /nix/store/<HASH-1>-postern-repro-poc
builderA-mutated.out:  /nix/store/<HASH-2>-postern-repro-poc   # different
FAIL: mismatch — badge denied per B-repro-verifier.md §3
```

This FAIL is not a probabilistic expectation — it follows from the
definition of a content-addressed derivation: `$out` is derived from the hash
of the full input closure, `text` is part of that closure, so changing `text`
necessarily changes the derivation hash and therefore `$out`. There is no
scenario where step 4 could spuriously PASS here (unlike a real-world
nondeterminism FAIL, §1d of `02-reproducible-builds.md`, which *can* be a
false negative from a flaky upstream build — this POC's artifact has no such
surface: no compiler, no timestamps, no parallelism-dependent ordering).

Applying `B-repro-verifier.md` §3's decision table: `tier == attestable-nix
AND last attempt was a mismatch/FAIL → NOT attestable`. The mutated build is
correctly denied the badge; nothing renders `attestable` for it.

### 5. What this does and does not prove

- **Proves, once actually run on a Nix host:** the exact two-builder /
  store-path-diff mechanism specified in `FLAKE-REPRO.md` §4 and
  `B-repro-verifier.md` §1 works end-to-end — pin, build, build again
  independently, compare, PASS; mutate, rebuild, compare, FAIL — at a scale
  cheap enough to run in CI on every PR.
- **Does not prove:** that `os/package.nix` or `os/seal-gate.nix` are
  reproducible today. Those remain gated behind the 5 unfilled
  `lib.fakeHash` sentinels each and the root `flake.lock`'s empty seed,
  exactly as `FLAKE-REPRO.md`'s status banner already states. This POC
  validates the *mechanism* the real per-app verifier will run; it is not a
  substitute for running that mechanism against the actual workspace
  derivations on a Nix host — that is still VM-gated, unchanged by this doc.
- **Is genuinely HOST-testable** in the sense the task asked: it needs only
  Nix + flakes, no QEMU, no aarch64 cross-build, no SEV-SNP hardware — unlike
  `.#mobile-image` / `.#attested-image` / `.#seal-gate`, which stay VM/HW-gated
  per `FLAKE-REPRO.md` §4.1's table.

---

## Part 2 — AGPL resolver

### The problem, stated precisely

`fdroidserver` (the toolkit F-Droid uses to build and sign repo indexes) is
licensed **AGPL-3.0**. This repo's own policy — `deny.toml`'s comment
("permissive licenses only… AGPL/GPL/LGPL remain excluded") and
`docs/POSTERN-APPS-ROADMAP.md`'s explicit note ("F-Droid GPL/AGPL — no
code") — is **permissive-only** for anything Postern builds, forks, or
embeds. `01-architecture.md` §8 and `02-reproducible-builds.md` §6 both
flagged this and deferred the ruling to a `03-honesty-license.md` that does
not yet exist in this repo. This section makes that ruling.

### Option (a): fdroidserver as external, build-time-only tooling (never shipped)

**Verdict: clean, under three hard constraints — but see the recommendation
below for why this repo mostly doesn't need it anyway.**

The legal shape that matters: AGPL-3.0 imposes copyleft obligations on (i)
*distributing* the covered Program (source or binary) and (ii) — AGPL's
distinguishing clause, §13 — letting users interact *remotely, over a
network* with a *modified* version of the covered Program, in which case
those users must be offered the modified Program's source. Neither is
triggered by:

- running an **unmodified** `fdroidserver` as a subprocess purely inside
  Postern's own CI/build infrastructure,
- to produce a **data file** (an index/repo JSON, or an APK-signing
  artifact) that is then served to Store users,
- where **fdroidserver itself is never distributed** (not bundled in any
  Postern product, image, or package) and **never exposed as a
  network-reachable service** that outside users interact with directly.

This is the same category of thing as building software with `gcc`/`make`/
`bash` (all GPL or GPL-adjacent) without the *output* becoming GPL — using a
copyleft *tool* to produce *data* does not make the data a derivative work of
the tool, absent the tool's own copyrightable code being embedded verbatim in
the output. An index JSON file fdroidserver emits is data Postern's own
pipeline reshapes into `postern.catalog/v1` (per `01-architecture.md` §1a);
it is not fdroidserver's source code.

The three constraints that must hold for this to stay clean, operationally
(not just in theory):

1. **Never distribute or bundle** the `fdroidserver` binary, its source, or
   any of its Python modules with any Postern product — app, OS image,
   Store client, or any package a user installs. It stays entirely inside
   CI, never crosses into `dist/`.
2. **Never modify-and-expose.** If fdroidserver is ever patched for
   Postern's CI needs, that modified version must never become a
   network-reachable service outside code someone can `git clone` today —
   i.e. it can't become "the thing users' Store clients talk to over the
   network." The moment a modified fdroidserver is what remote users
   interact with, AGPL §13 requires offering them its source — survivable,
   but a real obligation this repo's "no fork" posture should just avoid by
   not modifying it at all, or not using it at all (see recommendation).
3. **Output is data, not code.** Spot-check that generated index files don't
   carry fdroidserver's own copyrightable boilerplate/templates verbatim
   (typical index-v2 output is plain JSON + a detached JAR/PGP signature —
   data, not code — but this should be verified for whatever exact
   `fdroidserver` subcommand is invoked before relying on it).

`deny.toml` itself doesn't mechanically catch this either way — it audits
the Rust/Cargo dependency graph (`cargo deny check`), and a Python CLI tool
invoked as a CI subprocess never enters `Cargo.lock`. The ruling above is
about the *project's stated policy* (roadmap's "no fork, no embed"), which is
broader than what `deny.toml` can technically enforce, not about closing a
gap in `deny.toml` itself.

### Option (b): permissive reimplementation of the repo-format + verifier scope

**Verdict: this is already what `01-architecture.md` and
`B-repro-verifier.md` design — there's very little left to "reimplement"
because the scope this task asks about was never fdroidserver-shaped to
begin with:**

- **Repo/index format:** `01-architecture.md` §1 explicitly extends
  Postern's own `postern.catalog/v1` schema in place, not F-Droid's
  `index-v2.json`. It's already permissively-licensed by construction — it's
  this repo's own JSON schema plus the Ed25519-detached-signature scheme
  `apps/postern-store/SIGNING.md` already ships (`openssl pkeyutl`, MIT/
  Apache tooling throughout). Zero fdroidserver code is needed to produce or
  consume it.
- **Verifier:** `B-repro-verifier.md` §1 and §2 are explicit that the
  mechanism is `nix build` + content-addressed store-path / `nix path-info`
  comparison — structurally nothing like fdroidserver's Gradle-era
  reproducibility pipeline (per-app patches, `disabled_algorithm`, `srclibs`,
  diffoscope triage). §2 of that doc makes the point directly: Nix removes
  *by construction* the exact problems fdroidserver solves *by hand-written
  policy*. There is no fdroidserver logic to port because the verifier this
  repo needs is a different, simpler mechanism, already fully specified in
  Nix terms.

So (b) isn't a large reimplementation project — the "reimplementation" is
close to zero marginal work because the design in this repo already never
adopted F-Droid's shape for either the format or the verifier. This is the
important nuance: it's not "reimplement fdroidserver permissively," it's
"recognize the scope named in this repo's own docs was never fdroidserver's
scope."

### Recommendation

**Primary path: (b).** Ship the repo-format + verifier exactly as
`01-architecture.md` and `B-repro-verifier.md` already design them — a
from-scratch, permissively-licensed, Nix-native mechanism with zero
fdroidserver dependency, build-time or otherwise. This is not a compromise;
it's cheaper and better-fitted than reaching for fdroidserver would have
been, because Postern's build substrate (Nix) already gives most of what
fdroidserver's Python tooling has to hand-build for Gradle.

**Reserve (a) as a narrow, explicitly-scoped fallback**, only if a distinct
future need shows up that the native design doesn't cover: **consuming a
genuine upstream F-Droid repo** — parsing F-Droid's own `index-v2.json` +
JAR-signature envelope for `sloboda-compat`/`link` catalog entries that point
at F-Droid itself (the open question `01-architecture.md` §8 flags: "should
the client ever become a genuine consumer of F-Droid's own index-v2/
JAR-signed format"). Even there, prefer a small from-scratch permissive
parser first: `index-v2.json` is public, documented JSON, and JAR-signature
verification is a well-understood, standard format — neither requires
fdroidserver's actual code, only its *format*, which is not copyrightable in
the way its implementation is. Only fall back to invoking real
`fdroidserver` as an external subprocess (under the three constraints above)
if that narrow interop need turns out to require behavior too
underdocumented to reimplement cheaply — and even then, keep it scoped to
that one interop path, never to the repo-format or verifier this doc's Part 1
and `B-repro-verifier.md` already own natively.

**Net:** this repo does not need fdroidserver for the scope asked about
(repo format + verifier). If it's ever needed at all, it's for a narrower,
separate job (consuming upstream F-Droid indexes) and stays legally clean as
external, unmodified, build-time-only, never-shipped, never-network-exposed
tooling under the three constraints in Option (a).

### Closing the deferred questions

This resolves the three items `01-architecture.md` §8 and
`02-reproducible-builds.md` §6 left open for "03":

- **Generator tooling** (`01-architecture.md` §8, `02-reproducible-builds.md`
  §6): permissive, from-scratch, Nix-native — see recommendation above.
  `deny.toml`'s permissive-only rule is satisfied because nothing AGPL is
  forked, embedded, or shipped.
- **Whether AGPL tooling can run as an arm's-length subprocess at all**
  (`01-architecture.md` §8): yes, under the three constraints in Option (a) —
  but the recommendation is to not need it for this scope in the first
  place.
- **Verifier tooling's own license** (`02-reproducible-builds.md` §6): the
  build orchestrator / diff / CI glue for `B-repro-verifier.md`'s pipeline is
  original Postern code (Nix expressions + a thin comparison script) — not a
  fork or derivative of `fdroidserver`, so it carries this repo's own
  MIT/Apache-2.0 header discipline (`LICENSE-MIT` / `LICENSE-APACHE`), same
  as every other file in this repo.
