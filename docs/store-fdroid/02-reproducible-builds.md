# Reproducible-build verifier — design

Scope: how a submitted `tier: attestable-nix` app gets built from source, how
that build is diffed against the binary the Store would actually ship, and how
a PASS/FAIL result maps onto the Store's existing badge vocabulary
(`apps/postern-store/CURATION.md`). This is the piece that turns "attestable"
from a claim about the tier into a verified fact about one specific artifact.

Companion docs: `01-architecture.md` (repo index format, self-hostable repos,
client, postmarketOS install path — owns the schema this doc's output slots
into) and `03-honesty-license.md` (what a reproducible build does and doesn't
prove about the *safety* of the code, and the licensing of the verifier
tooling itself — this doc states the honesty point but defers ownership of
that framing).

## 0. Where things stand today (baseline, not aspiration)

Every entry in `catalog.json`, including all six `attestable-nix` apps
(`postern-vault`, `postern-courier`, `postern-os-desktop`, `keepassxc`,
`syncthing`, `gimp`), carries `distribution.signing.state: "unpublished"` and
`distribution.checksum: null`. `normalizeEntry` in `index.html` enforces this:
it only reveals a `checksum` to the renderer when `signing.state ===
"published"`, and it strips the `attestable` security tag from any entry whose
`tier !== "attestable-nix"` regardless of what else is in the JSON. So today
the `attestable` badge is a *tier-eligibility* claim ("this app is packaged in
a way that *could* be verified"), not a *build-result* claim ("this specific
artifact *was* verified"). No `nix build .#attested-image`, and no per-app Nix
build, has run anywhere in this repo — `os/attested.nix` is explicit that
`os_roothash` is a placeholder until a real Nix host produces
`repart-output.json`. This design does not change that honest fallback
rendering; it defines the pipeline that eventually fills it in with a real
`"published"` state backed by an actual PASS.

## 1. The verifier pipeline

Input to the pipeline is a **submission**: a source repo URL, a pinned
commit/tag (not a floating branch), and a Nix expression that builds it —
either a flake output already in this repo (first-party apps) or a reference
to an existing nixpkgs package (third-party apps). Output is one
**attestation record** (schema in §5) with a PASS or FAIL verdict.

### 1a. Two submission shapes

**First-party (`postern-vault`, `postern-courier`, `postern-os-desktop`).**
The build expression already lives in this repo's `flake.nix` — these are
Rust/Cargo crates (`crates/postern-vault`, `crates/postern-courier`) built as
Nix derivations and composed into the attested image
(`os/attested.nix`, consumed via `nix build .#attested-image`). The verifier's
job for these three is: build the crate's derivation in isolation (not just as
part of the whole-image build) so a single app's reproducibility can be
checked without paying for a full image build every time, then separately
confirm it appears correctly inside the composed attested image.

**Third-party (`keepassxc`, `syncthing`, `gimp`).** Postern does not maintain
build recipes for these — it points at **nixpkgs' own existing package
derivation** (`nixpkgs#keepassxc`, `nixpkgs#syncthing`, `nixpkgs#gimp`, pinned
to the `flake.lock` revision already vendored in this repo). This is a large,
deliberate shortcut worth naming plainly: nixpkgs already carries a
substantial, continuously-exercised reproducibility effort for these packages
(nixpkgs' own CI rebuilds and hash-checks derivations across contributors and
architectures as a matter of course). Postern's verifier is not re-inventing
that work — it is **consuming** nixpkgs' packaging and **layering Postern's
own build-and-diff-and-attest step on top**, plus pinning the exact nixpkgs
revision via `flake.lock` so "which nixpkgs" is itself part of the pinned,
reproducible input set. The honest framing: Postern attests "this artifact was
built, unmodified, via nixpkgs' own recipe at commit `X`, and reproduces" — it
is not independently re-deriving GIMP's build system from scratch. This is
consistent with `deny.toml`: Postern doesn't fork or embed KeePassXC/GIMP's
GPL code, it packages it unmodified via someone else's (nixpkgs') Nix
expression, same as any Nix consumer would.

### 1b. Pipeline steps

1. **Fetch, pinned.** Resolve the submission to an exact source revision (git
   commit hash for first-party; nixpkgs revision + package attribute path for
   third-party). No branch names, no `latest`, no floating semver ranges in
   the record — the input to a reproducibility claim must itself be
   unambiguous, or the claim is meaningless.
2. **Build, hermetically, twice, on independent hosts.** Run `nix build
   <flake-ref>#<attr>` in the Nix sandbox — no network access during build,
   fixed build UID/GID, fixed timestamps (`SOURCE_DATE_EPOCH`-style pinning
   baked into the Nix build model) — on at least two independent build hosts
   (or the same host in two independent sandboxed invocations as a weaker
   fallback if only one builder is available; independent hosts is the
   real bar, since a single-host bug or compromised builder wouldn't be
   caught by rebuilding on itself). This "build twice, diff" step is the part
   that actually earns the word "reproducible" rather than merely "we built it
   once and trust our own output."
3. **Hash the build output.** Compute a content hash of the Nix store output
   path — the derivation output hash (`nix-store -q --hash` / the store path's
   NAR hash), not a re-hash of some downstream packaging step. This is the
   artifact-identity value: same derivation + same inputs → same store path
   hash, by construction, if the build is actually deterministic.
4. **Compare build output hash across the two independent builds.**
   Byte-identical store paths across hosts → **reproducibility confirmed**
   (step 5 continues). Mismatch → **FAIL: nondeterminism**, see §1d — this is
   a different failure mode from step 5's mismatch and must be labeled
   differently in the record.
5. **Compare against the artifact the Store would actually ship.** This is
   the F-Droid-derived core insight, adapted: it is not enough that a build is
   internally reproducible across two independent runs of the *verifier's
   own* pipeline — the verifier must also diff its build output hash against
   the hash of the binary that ends up inside the published attested image
   (the artifact that reaches `os/attested.nix`'s `systemd-repart` step and
   ultimately the dm-verity-sealed rootfs). Match → **PASS**. Mismatch →
   **FAIL: source/binary divergence** (§1d) — this is the case that would
   catch a compromised release pipeline shipping something other than what
   the pinned source actually produces, which is the entire point of the
   exercise: don't trust the publisher's binary, verify it against an
   independent build of the stated source.
6. **Record and stop.** Whatever the outcome, emit exactly one attestation
   record (§5). A FAIL is a first-class, permanently recorded outcome, not a
   silent retry-until-green — see §1d for what happens next.

### 1c. Why two independent comparisons, not one

Step 4 (rebuild-vs-rebuild) and step 5 (rebuild-vs-shipped) catch different
things. Step 4 alone would only prove "our own pipeline is internally
consistent" — it says nothing about whether the *published* artifact matches.
Step 5 alone (build once, diff once against shipped) would not distinguish "we
have a genuinely nondeterministic build that happened to match this one time"
from "we have a truly deterministic build." Both checks are needed for the
PASS verdict to mean what it claims to mean.

### 1d. On mismatch: FAIL, and which kind

A mismatch is not automatically evidence of tampering — Nix substantially
narrows the nondeterminism surface but does not eliminate it (§3). The
pipeline must distinguish, and record which it found:

- **Nondeterminism-suspected FAIL** (step 4 mismatch: the verifier's own two
  independent rebuilds disagree with each other). Diagnostic path: diff the
  two output store paths with a tool that ignores known-benign nondeterminism
  classes (build-path strings, embedded timestamps — see §4) versus real
  content differences. If the diff is confined to known-benign classes, this
  is a **build-environment bug to fix** (the upstream project or the Nix
  expression needs a determinism fix), not a security incident — but it still
  blocks PASS until fixed. This case should never silently become a PASS by
  picking one of the two builds as "the" output.
- **Divergence FAIL** (step 5 mismatch: rebuild disagrees with the actual
  shipped artifact, even though step 4 passed — i.e. the verifier's own build
  is internally reproducible but doesn't match what's published). This is the
  serious case: either the published binary was built from different source
  than the pinned commit claims (accidental drift or real tampering), or the
  publish pipeline itself introduced a difference (e.g. a post-build
  repackaging step). Treat as a security-relevant FAIL by default, do not
  auto-classify as "probably fine," and do not badge the app `attestable`
  until resolved.

Either FAIL keeps `signing.state: "unpublished"` (or a new explicit `"failed"`
state, see §5) — it never produces a false PASS. This matches the Store's
existing discipline of never rendering a fake verified state (the
`UNSIGNED/VERIFIED/TAMPERED/UNVERIFIED` catalog-signature machine in
`SIGNING.md` already refuses to guess; this pipeline follows the same rule at
the per-artifact layer).

## 2. Verdict → badge mapping

This maps directly onto `CURATION.md`'s existing distribution-model table —
no new badge vocabulary is introduced, this section only defines **when the
existing `ATTESTED` badge is earned versus asserted**.

| Verifier outcome | `tier` | `distribution.model` | Resulting badge | Notes |
|---|---|---|---|---|
| No build has ever run | `attestable-nix` | `attest` | *(none — renders "· unpublished")* | Today's actual state for all six `attestable-nix` apps. Not a gap in this design; this is the correct honest rendering pre-verification, unchanged. |
| PASS (step 4 + step 5 both match) | `attestable-nix` | `attest` | **ATTESTED** | `signing.state → "published"`, real `checksum` populated. This is the only path that unlocks the badge. |
| FAIL (either kind, §1d) | `attestable-nix` | `attest` | *(none — stays "· unpublished", or an explicit `"failed"` state, §5)* | The tier claim (`attestable-nix`) does not change — the app is still packaged the Nix way — but the per-artifact claim does not upgrade until a PASS exists. A tier can sit at "eligible but unverified" indefinitely; that is honest, not a bug. |
| N/A — `pmos-overlay` tier | `pmos-overlay` | `mirror` / `overlay-build` | **MIRRORED · SIGNED** / **OVERLAY · SIGNED** | Out of scope for this verifier entirely — see §4a. These badges come from apk-repo signing (`pmos-overlay`'s own Ed25519 signing scheme, System A RSA per `HONESTY.md`), never from a build-reproducibility check, because the underlying Alpine/apk substrate is not reproducible (`pmos-overlay/HONESTY.md`). `normalizeEntry` already enforces this by tier, not by verifier outcome — this design does not touch that enforcement, only feeds the one tier that *can* earn more. |
| N/A — `sloboda-compat` tier | `sloboda-compat` | `link` / `proxy` | **LINK ONLY** / **PROXY ONLY** | Out of scope — see §4a. Postern hosts nothing and verifies nothing; if the app is reached via F-Droid itself, F-Droid's own reproducible-build program (where the app opted in) is the trust anchor, not this pipeline. |

The important asymmetry: **`attestable-nix` is necessary but not sufficient**
for the `ATTESTED` badge going forward. It already gates eligibility
(`normalizeEntry` strips `attestable` from any other tier, unconditionally).
This design adds the missing second gate — a recorded PASS — as the thing
that actually flips `signing.state` to `"published"` for a specific version.
Nothing about `normalizeEntry`'s existing tier-based stripping logic needs to
change; this pipeline is what should eventually populate the `signing`/
`checksum` fields it already reads.

## 3. The Nix advantage, concretely

F-Droid's reproducible-build effort targets Android/Gradle/Java builds run on
Debian-based buildservers. Its own documentation is candid that this is
hard-won and incomplete: environment pinning (JDK version, Android SDK/NDK
version, Gradle version, Gradle plugin versions) has to be manually
replicated between the developer's original build and F-Droid's buildserver,
and any drift — a JDK patch release, a Gradle cache behavior change — can
break reproducibility for reasons unrelated to the app's actual source code.
Coverage of "verified reproducible" apps in F-Droid remains a subset of the
catalog, not the default.

Nix structurally removes several of F-Droid's hardest-fought problems by
construction rather than by discipline:

- **Content-addressed derivations.** A Nix derivation's output path is (in the
  content-addressed model, and effectively via the input-addressed model's
  hash-of-inputs today) a function of its exact inputs — source hash, every
  dependency's store path, the builder script. Two builds of the *same*
  derivation are builds of the *same* input closure by definition; there is no
  "close enough" version match to eyeball, because a single input change is a
  different derivation with a different path, not a silent variance in the
  same one.
- **Hermetic sandboxed builds.** `nix build` disables network access during
  the build phase (with narrow, explicit fixed-output-derivation exceptions
  for source fetches, which are themselves hash-pinned). This removes an
  entire class of F-Droid-style problems: a build silently pulling a slightly
  different transitive dependency version at build time because a registry
  mirror served something new, or a `pip install`/`npm install`/Gradle
  dependency-resolution step floating between runs.
- **No floating dependency resolution.** `flake.lock` pins the exact
  `nixpkgs` revision (and any other flake inputs) as a hash-locked input, not
  a version range. There is no separate "which Gradle plugin resolved this
  time" question — the entire dependency graph is fixed before the build
  starts.
- **Fixed build UID/GID and timestamps.** The Nix sandbox runs builds under a
  fixed synthetic user/group and normalizes filesystem timestamps, removing
  two common sources of non-reproducibility (embedded `$USER`/`$HOME` paths,
  file mtimes leaking into archives or embedded build metadata) that Debian
  buildservers have to work around by convention rather than by sandbox
  guarantee.

Net effect: Nix reduces the *number of distinct nondeterminism sources the
verifier has to fight* — floating deps, network-fetched build inputs, leaked
build-host identity, filesystem-timestamp leakage — from "things a human has
to notice and pin one by one" (F-Droid's actual operational experience) to
"things the sandbox forecloses by default." This is why Postern's verifier
can be a comparatively thin build-and-diff tool rather than F-Droid's
much heavier buildserver-environment-replication apparatus.

## 4. What is still hard, even with Nix

This is not a claim that Nix makes reproducibility free. Concrete remaining
risk classes, inside the Nix sandbox:

- **Compiler-embedded build-path strings.** Some toolchains bake the absolute
  build directory path into debug info or panic/backtrace strings even under
  a hermetic sandbox (Nix's `/build/` convention mitigates but does not
  universally eliminate this across every compiler and every debug-info
  format). This can produce a real byte-level diff that is not a security
  problem, just noise the verifier must be able to classify (§1d).
- **LTO / codegen nondeterminism.** Link-time optimization and some codegen
  backends have documented non-determinism in output byte layout across
  otherwise-identical invocations, independent of the outer sandbox — a
  compiler-internal source of drift Nix cannot fix by sandboxing harder.
- **Upstream build systems embedding real timestamps or hostnames.** Some
  projects' own build scripts call `date`, embed a version string derived
  from wall-clock time, or otherwise leak host identity into the output
  regardless of how hermetic the outer build environment is — the sandbox
  controls the *environment*, not what the *upstream build system chooses to
  read and embed*. GIMP, KeePassXC, and Syncthing are all upstream projects
  Postern does not control; each may or may not have already solved this
  themselves (nixpkgs' packaging may already patch around known cases, which
  is part of why reusing nixpkgs' derivation, §1a, is valuable — that
  patching work is already someone else's prior art, not something this
  verifier reinvents).
- **Parallel build non-determinism in some C/C++ projects.** Object-file
  link order or archive-member order can vary with build parallelism in
  projects that don't control for it, producing byte-different-but-
  behaviorally-identical output.
- **Rust incremental compilation.** `cargo`'s incremental-compilation cache
  is a known reproducibility hazard if not explicitly disabled for release
  builds; first-party crates (`postern-vault`, `postern-courier`) must build
  with `cargo build --release` under Nix with incremental compilation off,
  and this is a build-expression correctness requirement, not something the
  verifier can fix after the fact.
- **Non-Nix apps are entirely out of scope, permanently, by design — not a
  gap to close.** The `sloboda-compat` tier (NewPipe, Aegis, Briar, Organic
  Maps, Signal, WhatsApp) is Android/Gradle-built, reached via F-Droid itself,
  Waydroid, or a vendor APK. These will never be Nix-packaged upstream, and
  this verifier does not attempt to reproduce them. Where reached via
  F-Droid, F-Droid's own reproducible-build program is the trust anchor for
  the apps that opt into it — Postern is explicitly not duplicating work
  F-Droid already does. Where reached via Waydroid or a vendor APK directly,
  there is no reproducible-build trust anchor at all, and the Store should
  say so rather than imply one exists (`LINK ONLY` / `PROXY ONLY` already
  says this structurally by never claiming `attestable`).
- **`pmos-overlay` is a documented ceiling, not a todo.** Per
  `pmos-overlay/HONESTY.md`, Alpine/postmarketOS packages are not bit-for-bit
  reproducible as a distro property, and postmarketOS's own attempt at a
  reproducible binary repo was abandoned for lack of benefit given Alpine's
  own non-reproducibility. Pinning `Cargo.lock`/apk indices/pmbootstrap
  versions there makes builds "repeatable-ish," explicitly not attestable.
  This verifier does not extend to that tier and should not be asked to —
  those apps top out at `MIRRORED · SIGNED` / `OVERLAY · SIGNED`
  (apk-repo-signing badges, a different and weaker guarantee than build
  reproducibility) permanently, by the Store's own honesty rule.
- **A reproducible build proves `binary == source`, nothing about whether
  `source` is safe, correct, or non-malicious.** This pipeline's PASS means
  "the artifact you're about to install is provably the output of building
  the stated, pinned source with the stated, pinned build environment" — it
  says nothing about whether that source itself contains a bug or a
  deliberately malicious change committed upstream. That is a distinct
  question (code review, provenance of the commit, trust in the upstream
  maintainers) that this verifier does not answer. `03-honesty-license.md`
  owns the fuller framing of this distinction for the badge's user-facing
  copy; this document is not attempting to resolve it, only flagging that the
  badge must not be worded in a way that implies more than "verified match to
  stated source."
- **Reproducible build and device attestation are two different
  guarantees, and mobile needs both.** A PASS from this pipeline proves what
  the *correct build* is — a claim about a build artifact sitting in a repo.
  It says nothing about what is actually *running on a given device* right
  now. That second claim is `os/attested.nix`'s job: the dm-verity-sealed
  erofs rootfs binds the build's `os_roothash` into a measured-boot UKI,
  checked via TPM2 PCR11 (or, inside a confidential VM, the SEV-SNP/TDX launch
  measurement) — that is the mechanism that turns "we can prove what the
  correct build is" into "we can prove your device booted that exact build."
  This verifier feeds the first guarantee; it is not a substitute for the
  second, and a complete attestable claim to an end user ultimately needs
  both layers, not just this one.

## 5. Attestation record schema (interface for 01-architecture.md)

Per app version, the verifier emits exactly one record. This is the
build-attestation the other architect's repo/index format should carry as a
first-class field (naming and nesting are theirs to decide; the field
*content* below is this design's contract). It also names the fields the
`SIGNING.md` "Depot" future (TUF metadata + Falcon-1024‖ML-DSA-65 PQ hybrid
signing + per-artifact build hashes anchored to the chain) should be able to
consume without redesign — this record is meant to slot directly into that
target, not be replaced by it.

```
{
  "app_id": "keepassxc",                     // matches catalog.json app id
  "version": "2.7.x@<pinned-commit-or-tag>", // exact upstream version + pin
  "source": {
    "repo_url": "https://github.com/keepassxreboot/keepassxc",
    "commit": "<full git sha>",              // never a branch or floating tag
    "build_expr": "nixpkgs#keepassxc",       // flake ref + attr path
    "build_expr_source": "nixpkgs",          // "nixpkgs" | "first-party"
    "flake_lock_rev": "<nixpkgs commit pinned in this repo's flake.lock>"
  },
  "build_env": {
    "nix_version": "<nix --version>",
    "system": "x86_64-linux",                // Nix system string; build target
    "sandbox": "hermetic",                   // always this today; field exists
                                              // to make the guarantee explicit
                                              // and inspectable per-record
    "builder_hosts": ["<host-id-a>", "<host-id-b>"]  // the ≥2 independent
                                              // builders used for the step-4
                                              // rebuild-vs-rebuild check
  },
  "output": {
    "store_path": "/nix/store/<hash>-keepassxc-2.7.x",
    "nar_hash": "sha256:<...>",              // content hash of the build output
    "shipped_artifact_hash": "sha256:<...>"  // hash of the binary actually
                                              // published inside the attested
                                              // image, for the step-5 diff
  },
  "result": {
    "rebuild_match": true,                   // step 4: independent builds agree
    "shipped_match": true,                   // step 5: rebuild == shipped artifact
    "verdict": "PASS",                       // "PASS" | "FAIL_NONDETERMINISM" |
                                              // "FAIL_DIVERGENCE"
    "diagnostic": null                       // populated on any FAIL (§1d):
                                              // which known-benign classes (if
                                              // any) explain a byte diff, or
                                              // "unexplained" if not classified
  },
  "run": {
    "timestamp": "2026-07-13T00:00:00Z",
    "run_by": "postern-ci@<runner-id>",      // who/what ran this — a CI
                                              // identity today, not a person
    "verifier_version": "<this pipeline's own version/commit>"
  },
  "signature": {
    // Not yet implemented — named here so 01/Depot can reserve the shape.
    // Today: no PQ signature exists for build-attestation records; only the
    // Consiglio login path (crates/postern-consiglio-auth) uses the
    // Falcon-1024‖ML-DSA-65 hybrid today. This field is a placeholder for
    // when the Depot anchors this record's hash to the chain and signs it.
    "scheme": null,                          // future: "falcon1024+mldsa65"
    "signature_b64": null,
    "chain_anchor": null                     // future: tx/commitment id
  }
}
```

Mapping onto today's `catalog.json` fields (for continuity, not a schema
change this doc owns): a `PASS` verdict is what should flip
`distribution.signing.state` from `"unpublished"` to `"published"` and
populate `distribution.checksum` with `output.shipped_artifact_hash`; a FAIL
of either kind keeps `state: "unpublished"`, or — if `01-architecture.md`'s
index format wants to distinguish "never attempted" from "attempted and
failed" — a new explicit `signing.state: "failed"` value, which
`normalizeEntry`-equivalent logic in the new client should treat identically
to `"unpublished"` for badge purposes (never render `checksum`, never render
`attestable` as earned) while still surfacing the FAIL for curator visibility.
This document recommends adding that third state; whether to actually add it
to the enum is `01-architecture.md`'s call since it owns the index schema.

## 6. Open questions for 03 (license/honesty)

- Exact user-facing wording for "reproducible build ≠ safe/correct/
  non-malicious code" (§4) — this doc states the distinction exists and must
  not be blurred, but the badge tooltip/help copy itself is `03`'s to write.
- Whether the verifier tooling (the build orchestrator, the diff/comparison
  tool, any CI glue) should be released as its own permissively-licensed
  artifact, and what license header discipline applies — this doc assumes
  (per the roadmap's explicit "F-Droid GPL/AGPL — no code" note and
  `deny.toml`'s permissive-only rule for Postern's own tooling) that none of
  it is a fork or derivative of F-Droid's AGPL `fdroidserver`, but does not
  itself resolve licensing/attribution details for any third-party
  comparison/diffing utility the pipeline might use.
- How to word the distinction between "PASS was witnessed by Postern's CI"
  (today's only realistic model — see `run.run_by` in §5) versus a genuinely
  third-party-reproducible claim (independent parties outside Postern running
  the same build and agreeing) — F-Droid and some other reproducible-build
  efforts treat multi-party independent reproduction as the stronger bar;
  this design's step-4 "two independent hosts" is Postern-operated hosts, not
  yet third-party hosts, and whether/how to disclose that distinction on the
  badge is an honesty-framing question for `03`, not resolved here.
