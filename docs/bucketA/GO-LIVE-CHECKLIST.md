<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Postern OS — GO-LIVE checklist (the day `.#iso` builds successfully)

> **STATUS OF THIS DOCUMENT: PREP ONLY.** Nothing below has been run. This is
> the exact ordered sequence to execute — with no fumbling, no re-reading of
> five scripts under time pressure — the moment a real `.#iso` build lands in
> the S3 build-artifact bucket (`postern-os-build-1783966602`, us-west-2) with
> a known SHA-256. It is assembled from `os/publish-iso.sh`,
> `os/download-page-snippet.html.tmpl`, `os/boot-harness-x86/boot-verify.sh` +
> `boot-verify-metal-userdata.sh`, `os/repro/repro-verify-iso.sh` +
> `repro-verify-iso-builder-userdata.sh`,
> `os/build-all-image-targets-userdata-snippet.sh`, `site/downloads.html`, and
> `functions/dl/[[path]].js` — read those for the full rationale; this file is
> the runbook, not a replacement for their header comments.
>
> **This document does not commit or deploy anything by itself.** Every step
> below is something a human/operator runs by hand, in order, once the
> prerequisites in §0 are met.

> **⚠ FOD-HASH PATH SUPERSEDED — point at the protocol-repo flake instead.**
> Wherever this checklist refers to filling `os/seal-gate.nix`'s 5
> `lib.fakeHash` sentinels via `os/seal-gate/fill-outputhashes.sh` (Step 6),
> that is the **dead path**. The OS build now sources the `bloch` node from the
> **protocol repo's own flake**
> (`gitlab.com/blochsispow-group/BlochSISPoW-project`), which has **zero
> git-sourced crates and no FOD-hash step** — so there are no sentinels to fill
> on the live path. See [`PACKAGE-FOD-HASHES.md`](PACKAGE-FOD-HASHES.md) and
> dossier item 7 ([`../design/RESUME-DOSSIER-2026-07-16.md`](../design/RESUME-DOSSIER-2026-07-16.md)).
> **This pivot is a recorded decision, NOT yet implemented in the tree** —
> `os/package.nix` / `os/seal-gate.nix` still carry the FOD block, and — as §0
> blocker 0a already states — **no `.#iso` (or any OS image) has ever been
> built.** The go-live sequence itself is unchanged; only the FOD-fill sub-step
> is retired.

---

## 0. Before step 1 can even start — hard blockers today (2026-07-13)

These are not part of the go-live *sequence* — they are things that must
already be true before step 1 is meaningful. None of them are done yet.

| # | Blocker | Needed for | Status |
|---|---|---|---|
| 0a | A `.#iso` build actually exists in `s3://postern-os-build-1783966602/…` with a known SHA-256 | everything below | **Not yet — this whole document is "the day it does."** |
| 0b | A Linux + Nix host to run `scripts/flake-lock.sh` and freeze `flake.lock` (currently the empty seed) | step 3 (repro) | **No Nix host exists in this environment (macOS dev workstation).** |
| 0c | EC2 vCPU quota bump for a `*.metal` instance (`L-1216C47A` → ≥96, or ≥48 if defaulting to `m5zn.metal`, us-west-2, account `184353710627`) | step 2 (boot-verify) | **Requested? No — request drafted in `boot-verify-metal-userdata.sh`, not filed.** |
| 0d | `REPO_URL` filled into both `boot-verify-metal-userdata.sh` and `repro-verify-iso-builder-userdata.sh` (currently `TODO-git-remote-for-bp-wt-buckets`) | steps 2 & 3 | **Placeholder, not filled.** |
| 0e | AMI id, `--key-name`, and a scoped IAM instance profile (S3 read on the build bucket, S3 write on the results prefix — not broad access) for both EC2 launches | steps 2 & 3 | **Not chosen yet.** |

None of 0b–0e are the three items the go-live itself is blocked on operationally (§2), but skipping them will make steps 2 and 3 below fail at launch time, not at the interesting part — fill them in first.

---

## 1. Ordered GO-LIVE sequence

### Step 1 — Fetch + verify (no network write, no creds beyond S3 read)

Run `os/publish-iso.sh` in **dry-run mode** against the real S3 key, with the
expected SHA-256 from the build log:

```sh
./os/publish-iso.sh -k builds/<date>/postern-os-<variant>-x86_64.iso \
    -o postern-os-<variant>-x86_64.iso \
    -B UNBOOTED \
    -c <sha256-from-build-log> \
    -s ~/.postern-signing/postern-os.key \
    -n            # dry run: fetch + hash + local sign only, NO R2 network
```

This is the honest "does the artifact actually match what CI says it built"
gate before anything else touches it: it re-derives Content-Length from S3,
refuses on a truncated transfer, hashes the file, and refuses on a SHA-256
mismatch against `-c`. `-B UNBOOTED` here is a placeholder for the dry run —
the real boot-status is decided in step 2 and used for the real publish in
step 4, not this step.

**Exit here with a verified local copy + verified hash before doing anything
else.** Do not proceed to step 2/3 against an ISO whose hash you have not
cross-checked.

### Step 2 — boot-verify (QEMU/KVM on a metal box, once quota approves)

Blocked on **0c** (quota) and **0d/0e** (userdata placeholders) above.

1. File the quota increase (documented, not filed):
   ```sh
   aws service-quotas request-service-quota-increase \
     --service-code ec2 --quota-code L-1216C47A --desired-value 96 \
     --region us-west-2
   ```
   Wait for AWS approval (this is asynchronous, sometimes manual review).
2. Fill in `os/boot-harness-x86/boot-verify-metal-userdata.sh`'s TODOs:
   `REPO_URL`, `REPO_REF`, `ISO_S3_URI_NODE`, `ISO_S3_URI_DESKTOP`,
   `RESULTS_S3_PREFIX` — point the two `ISO_S3_URI_*` vars at the exact S3
   key(s) verified in step 1.
3. Launch the metal instance (`c5.metal` / `m5.metal` / `m5zn.metal`,
   us-west-2) with that user-data — see the `aws ec2 run-instances` example
   in the script's own header. It self-provisions Nix + QEMU/KVM, runs
   `os/boot-harness-x86/boot-verify.sh` under **real KVM** (refuses a silent
   TCG fallback), grades the boot ladder via the shared
   `check-boot-log.sh` markers, cross-checks the dm-verity roothash if
   applicable, ships the serial log + `.evidence` sidecar + summary to
   `RESULTS_S3_PREFIX`, and self-terminates.
4. Pull the evidence down and read the grade:
   - **PASS** → the honest boot-status label for step 4 becomes
     `QEMU-PASS:<S3-or-local-path-to-evidence>@<YYYY-MM-DD>`.
   - **FAIL** (ladder or roothash) → do **not** advance the boot-status past
     `QEMU-PENDING`; fix and re-run before publishing anything stronger.
5. **Hardware boot is a separate, later rung** (`HARDWARE-BOOTED:<device>@<date>`)
   — not part of this go-live pass; nothing here provisions or claims one.

### Step 3 — two-builder repro (needs the filled-lock commit)

Blocked on **0b** (a Nix host to run `scripts/flake-lock.sh`).

1. On any one Linux + Nix host:
   ```sh
   scripts/flake-lock.sh
   git add flake.lock && git commit -m "flake.lock: freeze nixpkgs 24.05 + mobile-nixos"
   ```
   Note the resulting commit sha — this is `<LOCK_COMMIT>`. It does not exist
   yet; nothing before this point can be `<LOCK_COMMIT>`.
2. Both builders check out `<LOCK_COMMIT>` exactly (not "the same day" — the
   same git sha, carrying the byte-identical `flake.lock`) and build
   independently:
   ```sh
   # Builder A
   git checkout <LOCK_COMMIT>
   ./os/repro/repro-verify-iso.sh build --attr iso --role builder-a \
       --commit <LOCK_COMMIT> --out builder-a-iso.json

   # Builder B — independent host, different instance family/AZ recommended
   git checkout <LOCK_COMMIT>
   ./os/repro/repro-verify-iso.sh build --attr iso --role builder-b \
       --commit <LOCK_COMMIT> --out builder-b-iso.json
   ```
   …or launch Builder B (or both) via `os/repro/repro-verify-iso-builder-userdata.sh`
   once its `REPO_URL` and `EXPECT_COMMIT` TODOs are filled with
   `<LOCK_COMMIT>` (`RESULTS_S3_PREFIX` too). This path does **not** need
   `/dev/kvm` or a `*.metal` instance — a plain `c6i.2xlarge`/`c6a.2xlarge`
   (8 vCPU) fits inside the existing 16-vCPU on-demand quota; **no quota bump
   needed for this step**, unlike step 2.
3. Compare:
   ```sh
   ./os/repro/repro-verify-iso.sh compare --a builder-a-iso.json --b builder-b-iso.json
   ```
   - **PASS** (exit 0): identical store path + narHash. This is the strongest
     *build*-reproducibility signal Nix gives — it proves `binary == source`
     for `<LOCK_COMMIT>`, nothing else (not boot, not hardware, not "the
     source is safe").
   - **FAIL_SETUP** (exit 8): not a valid comparison (different commit/lock) —
     fix and re-run; draw no conclusion.
   - **FAIL_DIVERGENCE** (exit 9): same source, different output — run the
     diffoscope-style next step the script prints before concluding anything;
     do **not** publish until this is resolved or classified benign.

### Step 4 — publish to R2 via `publish-iso.sh` with the honest boot-status label

Real (non-dry-run) publish, using the boot-status determined in step 2:

```sh
./os/publish-iso.sh -k builds/<date>/postern-os-<variant>-x86_64.iso \
    -o postern-os-<variant>-x86_64.iso \
    -B QEMU-PASS:<evidence-path-or-url>@<YYYY-MM-DD> \
    -c <verified-sha256> \
    -s ~/.postern-signing/postern-os.key
```

(Substitute `-B UNBOOTED` or `-B QEMU-PENDING` — with no `-e`/`--boot-evidence`
— if step 2 hasn't produced a PASS yet; never round the label up.)

This is the honesty-gated step: it refuses unless `--product` is exactly
"Postern OS", refuses a boot claim (`QEMU-PASS`/`HARDWARE-BOOTED`) without
`--boot-evidence`, refuses a truncated transfer or SHA mismatch, refuses to
sign with the wrong minisign key, and always prints the "UNAUDITED —
mainnet-beta" line with no flag to suppress it. Fail-safe upload order:
image → `.sha256` sidecar → `SHA256SUMS` → `SHA256SUMS.minisig` (the
authenticating flip, uploaded last).

At the end it prints the exact download+verify block for the page and,
if `--allow-new-name` was needed, the required `functions/dl/[[path]].js` +
`site/downloads.html` follow-ups (see step 5).

### Step 5 — the download-page edit + deploy

Using `os/download-page-snippet.html.tmpl` and the real values
`publish-iso.sh` just printed:

1. If the artifact name is new (not already in
   `functions/dl/[[path]].js`'s `ALLOW` set — currently
   `postern-os-node-x86_64.iso`, `postern-os-desktop-x86_64.iso`,
   `postern-os-mobile-pinephone-aarch64.img`): add it there first, or `/dl/`
   404s on the new name even though the bytes are already on R2.
2. Edit `site/downloads.html`'s "3 · The reproducible OS" table row (or a new
   section for a genuinely new product line) with the real SHA-256, and pick
   the badge class/text **exactly** matching the boot-status published in
   step 4 — never round up:
   | boot-status | badge class | exact prose |
   |---|---|---|
   | `UNBOOTED` | `proto` | "built · hosted + signed · not yet boot-tested (QEMU or hardware)" |
   | `QEMU-PENDING` | `built` | "built · hosted + signed · QEMU boot pending" |
   | `QEMU-PASS:<ev>@<date>` | `built` | "built · hosted + signed · QEMU-boot-validated \<date\> (hardware boot still pending)" |
   | `HARDWARE-BOOTED:<d>@<date>` | `built` | "built · hosted + signed · boots on \<device\> hardware (\<date\>)" |
   If a boot is claimed, also add the boot-evidence link line to the "Before
   you install" warnpanel — do not ship a badge implying a boot with a dead
   evidence link.
3. Run the mechanical honesty gates over the edited tree before shipping:
   ```sh
   scripts/check-trust-labels.sh
   scripts/ci-honesty-products.sh
   ```
4. Deploy:
   ```sh
   ./assemble-public.sh && wrangler pages deploy --branch main
   ```
   (Project `posternlabs`, `pages_build_output_dir = public`, per
   `wrangler.toml`.)

### Step 6 — build the other x86 image targets

Append `os/build-all-image-targets-userdata-snippet.sh` to the same build
user-data that already runs `nix build .#iso`, on the **same x86_64-linux
instance** (no new host, no emulation):

```sh
stage_result "desktop-iso"    "./result/iso/*.iso"            "postern-os-desktop-x86_64.iso"
stage_result "attested-image" "./result/*.raw ./result/*.img" "postern-os-attested-x86_64.raw"
stage_result "seal-gate"      "./result/bin/postern-seal-gate" "postern-seal-gate-x86_64"
stage_result "cloud-image"    "./result/*.raw ./result/*.img" "postern-cloud-x86_64.raw"
```

Fill `BUILD_S3_BUCKET` / `BUILD_S3_PREFIX` / `FLAKE_DIR` first (script
TODOs). **(FOD sub-step superseded — see the banner at the top of this file:**
under the protocol-repo-flake path `os/seal-gate.nix` has no `lib.fakeHash`
sentinels to fill, so the `os/seal-gate/fill-outputhashes.sh` step is retired;
the old text below is left for history.) `.#cloud-image` was, on the dead FOD
path, **expected to fail** until `os/seal-gate.nix`'s 5 `lib.fakeHash`
sentinels were filled (`os/seal-gate/fill-outputhashes.sh`) — a designed gap,
not a bug in this step. `.#mobile-image` is **aarch64-linux
only** and must run on a separate (Graviton) host — not part of this x86
sweep; `mobile-nixos` is also still an unpinned `flake = false` input until
`scripts/flake-lock.sh` freezes a rev (same step-3 prerequisite).

Nothing in this step publishes to R2 or touches the download page — for
anything that succeeds, loop back to **steps 1–5** per artifact, with an
honest `--boot-status` (`UNBOOTED` at minimum; a real boot claim needs its
own step-2-equivalent evidence per target).

---

## 2. Operator inputs still needed — exactly these, nothing implied

1. **R2 destination credentials** — an R2 API token's `AWS_ACCESS_KEY_ID` /
   `AWS_SECRET_ACCESS_KEY`, plus **`R2_ACCOUNT_ID`** (or `R2_ENDPOINT_URL`
   directly). Required for the real publish leg of step 4 only (the dry run
   in step 1 never touches R2). None of these are set in this environment.
2. **The minisign passphrase** for `~/.postern-signing/postern-os.key` — the
   secret key file exists on disk, but signing in step 4 needs either the
   passphrase typed interactively at the `minisign` prompt, or exported as
   `MINISIGN_PASSWORD` for a non-interactive run. Not provided/known here.
3. **The EC2 vCPU quota approval** — `L-1216C47A` in us-west-2 (account
   `184353710627`) must be raised to ≥96 (or ≥48 for `m5zn.metal`) before
   *any* `*.metal` instance can launch for step 2. The request command is
   drafted in `boot-verify-metal-userdata.sh`'s header but has not been filed
   or approved.

Secondary, not named in the original ask but genuinely required to execute
the sequence above without re-discovering them mid-run:

4. **`SRC_AWS_ACCESS_KEY_ID` / `SRC_AWS_SECRET_ACCESS_KEY`** — real AWS
   creds scoped (ideally read-only) to `postern-os-build-1783966602`
   (us-west-2). Needed for step 1's dry-run fetch and step 4's real fetch —
   a *different* credential pair from #1, and `publish-iso.sh` is explicit
   that confusing the two (both via plain exported `AWS_*` vars) will send
   the fetch to R2 or the upload to S3.
5. **`REPO_URL`** for both EC2 user-data scripts (`boot-verify-metal-userdata.sh`,
   `repro-verify-iso-builder-userdata.sh`) — currently the literal placeholder
   string; both scripts fail closed on it.
6. **AMI id, `--key-name`, and a scoped IAM instance profile** for both EC2
   launch commands (S3 read on the build bucket, S3 write on the results
   prefix — not broad S3 access).
7. **A Linux + Nix host** to run `scripts/flake-lock.sh` and produce
   `<LOCK_COMMIT>` — a prerequisite for step 3 that doesn't exist in this
   (macOS) environment.
8. **`<LOCK_COMMIT>` itself** — cannot be filled into
   `repro-verify-iso-builder-userdata.sh`'s `EXPECT_COMMIT` until #7 has run
   and the filled `flake.lock` is committed.

---

## 3. Honesty rails — must hold at every step above, no exceptions

- **UNAUDITED / mainnet-beta.** `publish-iso.sh` always prints "UNAUDITED —
  mainnet-beta. Not a security or investment claim; the coin is worthless by
  design" on every real run — there is no flag to suppress it, and
  `site/downloads.html`'s beta ribbon (relaxed k=4 regime, trivially
  forgeable, 51%-attackable, very few nodes) must stay accurate at deploy
  time (step 5).
- **Product-name guard.** `publish-iso.sh` refuses anything but
  `--product "Postern OS"` — this pipeline never publishes under "Postern for
  postmarketOS" or "Postern Android" (that's `pmos-overlay/publish-to-r2.sh`,
  a different tier, different honesty rules, `pmos-overlay/HONESTY.md`).
- **Boot-status vocabulary is closed and literal.** Only `UNBOOTED`,
  `QEMU-PENDING`, `QEMU-PASS:<evidence>@<date>`, `HARDWARE-BOOTED:<device>@<date>`
  are accepted; `QEMU-PASS`/`HARDWARE-BOOTED` **require** `--boot-evidence` —
  no evidence, no claim. The download-page badge text/class (step 5) must
  map to the *exact* published label — never round `QEMU-PENDING` up to
  "boot-validated," never round `UNBOOTED` up to anything.
- **Boot-evidence-gated, and evidence must actually resolve.** A claimed
  boot needs a real, reachable boot log / `.evidence` sidecar from
  `os/boot-harness-x86/boot-verify.sh` (step 2) — don't ship a badge implying
  a boot with a dead evidence link. `os/boot-harness-x86/README.md` is
  explicit: "do not cite this directory as proof of a boot" until it has
  actually run and produced a graded PASS.
- **QEMU ≠ hardware; KVM narrows, does not close, that gap.** Even a KVM
  `PASS` in step 2 proves the software boot chain (BIOS/bootloader → kernel →
  stage-1 → systemd → getty/GDM) under real virtualization extensions — it
  models no specific firmware, TPM, or measured-boot chain. A physical-
  hardware boot is a distinct, later claim (`HARDWARE-BOOTED:<device>@<date>`),
  out of scope for this go-live pass.
- **Reproducible-by-design ≠ reproduced.** A step-3 `PASS` proves
  `binary == source` for the pinned closure at `<LOCK_COMMIT>` — nothing
  about whether that source is safe, correct, or non-malicious. A
  `FAIL_DIVERGENCE` is not automatically a tamper signal; classify it via the
  diffoscope-style steps the script prints before concluding anything either
  way, and record that evidence — don't silently re-run until it happens to
  match.
- **Attestation is never claimed by this pipeline.** `publish-iso.sh` refuses
  `--attestable` outright — attestation is a separate, unaudited chain
  (`os/ATTESTATION.md`) that this pipeline cannot certify.
- **Hosting + signing is not attestation; built is not booted.** Both
  disclaimers are load-bearing on `site/downloads.html` and must not drift
  when step 5 edits it.
- **Verify-the-SHA, always, both ends.** `publish-iso.sh` itself refuses a
  truncated transfer (Content-Length cross-check) or a SHA-256 mismatch
  against `-c` before it will sign or upload anything; the published page
  (step 5) must keep telling end users to run both `sha256sum -c SHA256SUMS`
  and `minisign -Vm SHA256SUMS -P <pubkey>` — the checksum proves the file is
  intact, the signature proves the checksum list came from Postern; neither
  is optional.
- **`/dl/` allowlist is a closed set.** A new artifact name 404s at the
  redirector until `functions/dl/[[path]].js`'s `ALLOW` set is explicitly
  extended (step 5.1) — publishing to R2 alone does not wire up the counted
  download link.
- **Mechanical tripwires must run clean before shipping.**
  `scripts/check-trust-labels.sh` and `scripts/ci-honesty-products.sh` gate
  the edited `site/` tree in step 5 — they are heuristics, not proof, and a
  clean run does not replace human review, but a dirty run blocks the ship.
- **No commit, no deploy, from this document itself.** Everything above is
  the runbook; executing it (git commits, `wrangler pages deploy`, `aws
  ec2 run-instances`, R2 uploads) is a separate, explicit human action per
  step, not something this checklist performs on its own.
