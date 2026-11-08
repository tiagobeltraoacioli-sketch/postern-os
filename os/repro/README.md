<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# `os/repro/` — the two-builder ISO reproducibility PROOF (backlog #19)

> **HONEST STATUS (STAGED / NOT RUN):** everything in this directory was
> written on a non-Nix macOS host. No `nix build`, no two-builder run, no
> comparison has ever happened. The only validation done here is
> `shellcheck` (clean) and `bash -n` (clean) on both scripts. Until this
> actually runs on two independent Nix hosts and produces a committed PASS
> (or a diagnosed FAIL), there is **no reproducibility claim for the Postern
> OS ISO** — only a ready procedure to earn one.
>   `built != booted` · `QEMU != hardware` · `reproducible-by-design !=
>   reproduced` — this directory turns `docs/plan/FLAKE-REPRO.md` §4 from a
>   narrative runbook into runnable tooling; it does not shortcut earning it.

This is the OS-tier twin of `docs/plan/FLAKE-REPRO.md` — read that file
first (`flake.lock` pinning model, §1–§3: why the committed lock is an empty
seed, `scripts/flake-lock.sh` / `scripts/flake-check.sh`). This directory is
the runnable implementation of that doc's §4 ("Two-builder bit-for-bit
reproduction").

## Files

| File | What it is |
|---|---|
| `repro-verify-iso.sh` | The core tool. `build` mode: run on a Nix host, builds `.#<attr>`, writes a JSON manifest (commit, `flake.lock` sha256, store path, narHash, build env). `compare` mode: diffs two manifests, PASS/FAIL/SETUP-FAIL, prints a diffoscope-style next step on divergence. Needs no AWS/EC2 — usable on any Nix host, bare or in CI. |
| `repro-verify-iso-builder-userdata.sh` | EC2 user-data for an independent, self-terminating **second builder**. Self-provisions Nix, checks out the exact pinned commit, runs `repro-verify-iso.sh build`, ships the manifest to S3. One script provisions either builder (`role` instance tag selects `builder-a`/`builder-b`). |

## The procedure

### 0. Prerequisite the current repo has NOT yet met

`docs/plan/FLAKE-REPRO.md` §1 explains why `flake.lock` is committed as the
**empty seed**:

```json
{ "nodes": { "root": {} }, "root": "root", "version": 7 }
```

Checked directly against the integration HEAD used to author this directory
(`git show 0ee1af648c698babf866e770f7b326ad6b10d0f8:flake.lock`) — still the
empty seed. **This two-builder ISO proof cannot start at `0ee1af6` itself.**
Step 1 below (`scripts/flake-lock.sh`, on a Nix host) must run and its
resulting commit — call it `<LOCK_COMMIT>`, a child of `0ee1af6` — is what
"the same pinned `flake.lock`" actually refers to. Both builders share
`<LOCK_COMMIT>`, not "0ee1af6, each re-locked independently" — see
`repro-verify-iso.sh`'s header ("WHY THIS CANNOT JUST BE...") for why that
distinction matters: `nixpkgs.url` and `mobile-nixos` are floating refs, so
two independent `nix flake lock` runs at different moments could freeze to
different upstream revisions and produce a meaningless comparison.

### 1. Freeze the lock once, commit it (on any one Nix host)

```sh
scripts/flake-lock.sh
git add flake.lock && git commit -m "flake.lock: freeze nixpkgs 24.05 + mobile-nixos"
# note the resulting sha — this is <LOCK_COMMIT>
```

### 2. Both builders check out `<LOCK_COMMIT>` and build independently

Builder A (any Nix host — a dev box, a CI runner, or a manually launched EC2
instance):

```sh
git checkout <LOCK_COMMIT>
./os/repro/repro-verify-iso.sh build --attr iso --role builder-a \
    --commit <LOCK_COMMIT> --out builder-a-iso.json
```

Builder B (fresh, independent Nix host — the point of this proof is that A
and B share nothing but the pinned source):

```sh
git checkout <LOCK_COMMIT>
./os/repro/repro-verify-iso.sh build --attr iso --role builder-b \
    --commit <LOCK_COMMIT> --out builder-b-iso.json
```

...or launch builder B as an ephemeral, self-terminating EC2 instance via
`repro-verify-iso-builder-userdata.sh` (fill in `REPO_URL`, `EXPECT_COMMIT`,
`RESULTS_S3_PREFIX` first — the script fail-closes on the placeholders). See
that script's header for the exact `aws ec2 run-instances` invocations for
both A and B (deliberately different instance family + AZ — `c6i.2xlarge`
Intel in `us-west-2a` for A, `c6a.2xlarge` AMD in `us-west-2b` for B — so
"independent" means more than "two processes on the same rack").

### 3. Compare

```sh
./os/repro/repro-verify-iso.sh compare --a builder-a-iso.json --b builder-b-iso.json
# or, if builder B shipped to S3:
./os/repro/repro-verify-iso.sh compare --a builder-a-iso.json \
    --b s3://<bucket>/repro-verify-iso/<LOCK_COMMIT>/builder-b-iso.json
```

- **PASS** (exit 0): identical store path AND identical `narHash`, same
  commit, same `flake.lock` bytes on both sides. The strongest *build*
  reproducibility signal Nix gives.
- **FAIL_SETUP** (exit 8): the two manifests aren't a valid comparison at all
  (different commit, different `flake.lock` fingerprint, or a dirty
  worktree on either side) — fix the setup, this is not evidence about
  reproducibility either way.
- **FAIL_DIVERGENCE** (exit 9): same commit, same lock, **different**
  output. `compare` prints the diffoscope-style next step: pull both store
  paths onto one machine (`nix copy --to file://...`), run
  `nix store diff-closures` for a cheap closure-level pass, then
  `nix run nixpkgs#diffoscope -- <A> <B>` for the byte-level report, and
  classify the first differing bytes as known-benign nondeterminism (embedded
  timestamp, unrewritten self-reference, locale-dependent ordering) or
  unexplained (escalate; do not sign, do not publish).

Repeat for `.#desktop-iso`, `.#mobile-image` (aarch64 builder), `.#attested-
image`, `.#cloud-image` — `docs/plan/FLAKE-REPRO.md` §4 names the same list;
`--attr` accepts all five.

## Honest interpretation

**A PASS proves `binary == source` for the pinned input closure at
`<LOCK_COMMIT>`. It proves nothing about whether that source is safe,
correct, or non-malicious.** This is the exact distinction
`docs/store-fdroid/02-reproducible-builds.md` §4 draws for the app-store
verifier tier — worth quoting directly because the same discipline applies
here unchanged:

> A reproducible build proves `binary == source`, nothing about whether
> `source` is safe, correct, or non-malicious. ... it says nothing about
> whether that source itself contains a bug or a deliberately malicious
> change committed upstream. That is a distinct question (code review,
> provenance of the commit, trust in the upstream maintainers) that this
> verifier does not answer.

Concretely, for the Postern OS ISO:

- A PASS means: two builders that share nothing but the git commit and the
  frozen `flake.lock` independently derived the **identical** ISO bytes.
  That rules out a large class of supply-chain risk (a compromised builder
  silently substituting a different artifact, an unpinned dependency
  drifting between two builds, a non-hermetic build leaking host state into
  the output).
- A PASS does **not** mean: the code at `<LOCK_COMMIT>` is free of bugs; the
  code at `<LOCK_COMMIT>` is free of a deliberately malicious change an
  upstream or first-party contributor committed; the ISO **boots**
  (`built != booted` — that's `os/boot-harness-x86/`, a separate proof); the
  boot behaves correctly on **real hardware** (`QEMU != hardware`); or that
  the running system is **attested** (`os/ATTESTATION.md` — a third,
  separate chain: dm-verity roothash + measured boot, proving what's
  *running on a device*, not what the *correct build* is).
- These are layered, independent guarantees, not a single "trustworthy"
  bit. `os/boot-harness-x86/README.md` and `docs/store-fdroid/
  02-reproducible-builds.md` §4 both make the same point for their own
  tiers: reproducibility, boot evidence, and attestation each answer a
  different question and none substitutes for another.
- A FAIL is likewise not automatically a tamper signal — Nix substantially
  reduces but does not eliminate nondeterminism sources (embedded
  timestamps, build-path leaks, locale/PATH-dependent ordering). The
  diffoscope step exists specifically to tell "explained, low-severity
  nondeterminism" apart from "unexplained — treat as a real incident" before
  anyone draws a conclusion either way.

## What's needed to actually run this

1. **A Nix host** (Linux; flakes enabled) for step 1 (`scripts/flake-lock.sh`)
   — none exists in this environment (macOS, no Nix).
2. **`<LOCK_COMMIT>`** — does not exist yet; it's the child of `0ee1af6` that
   step 1 produces and commits.
3. **Two independent Nix hosts** at `<LOCK_COMMIT>` for the actual builds —
   this repo staged an EC2 path (`repro-verify-iso-builder-userdata.sh`) as
   one option, but any two independent Nix machines work (a second dev's
   box + CI, two CI runners on different providers, etc.). Building `.#iso`
   needs disk (tens of GiB for the Nix store) and CPU/RAM headroom but,
   unlike the boot-harness path, **no `/dev/kvm` and no `*.metal` instance**
   — a plain `c6i.2xlarge`/`c6a.2xlarge` (8 vCPU) fits inside the account's
   existing 16-vCPU on-demand quota (checked 2026-07-13, account
   184353710627, us-west-2, read-only `service-quotas` call — unchanged from
   the metal-boot-verify blocker; no increase request needed for this path).
4. **An S3 (or equivalent) bucket** to stage manifests between builders if
   they aren't on hosts that can directly exchange files —
   `RESULTS_S3_PREFIX` in the userdata script is a TODO placeholder; the
   existing `postern-os-build-1783966602` bucket (us-west-2, confirmed
   reachable with the provided credentials, read-only `head-bucket` check —
   no writes made) is a reasonable default under a new
   `repro-verify-iso/<LOCK_COMMIT>/` prefix, kept separate from its existing
   `os/v0.1` release-artifact usage.
5. **Nothing was launched, built, or uploaded to produce this directory** —
   every command above is staged, not executed. The only network calls made
   while preparing this were read-only: `aws sts get-caller-identity`,
   `aws service-quotas get-service-quota`, `aws s3api head-bucket`.
