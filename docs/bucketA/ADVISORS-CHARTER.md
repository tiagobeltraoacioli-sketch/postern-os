<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- Bucket-A PMO deliverable. Charter for 2 pre-flight advisors: their job is
     to find what WILL fail on first real build BEFORE the box exists, purely
     by inspection on macOS. Neither advisor runs Nix/QEMU/Android SDK — they
     read code and predict failure, they do not reproduce it. -->

# Bucket A — Pre-flight ADVISORS-CHARTER

Both advisors work **before** the box exists, by inspection only, on the
`roadmap/fleet2-integrate` tree. Their output is a ranked defects list handed
to the operator BEFORE dispatching Dev A/B/C, so box-day time is spent
executing, not debugging trivially-discoverable-by-reading issues.

---

## Advisor 1 · will-it-build

**Mandate:** audit the Nix flake + Gradle configs by inspection — missing
inputs, wrong pins, unresolved deps, path/package mismatches (like the
import-path bug the fleet2 merge already hit once), CI targets that reference
nonexistent files.

**Concretely check:**
1. **`flake.nix` output-attribute reachability.** Walk every `packages.*`,
   `apps.*`, `nixosConfigurations.*` entry and confirm the `.nix` file it
   imports exists, its module signature matches how it's `callPackage`d /
   `import`ed, and any `{ config, lib, pkgs, ... }` args the file expects are
   actually threaded in. Special attention to `os/seal-gate.nix`'s FROZEN
   `{ lib, rustPlatform }` signature (frozen because `os/cloud.nix` calls it as
   `pkgs.callPackage ./seal-gate.nix { }`) — any drift here breaks Rung 3 silently.
2. **`mobile-nixos` output-attribute drift.** `flake.nix`'s `evalMobile` uses
   `mobilePinephone.outputs.default` — this is explicitly flagged in-repo as an
   attribute that "differs across Mobile-NixOS revisions." Since no
   `flake.lock` is frozen yet (empty seed), the box's first `nix build
   .#mobile-image` will resolve `mobile-nixos` HEAD at freeze time — pin a
   specific rev NOW (propose it in the defects list) so this isn't discovered
   live on box-day.
3. **Cargo.lock dual-git-rev collision** (`bloch-crypto`, `bloch-sis-pow`,
   `coherence-core` pinned at both `?branch=main#ce85756…` and
   `?rev=dd8df35…`). This is DOCUMENTED as a probable `fill-outputhashes.sh`
   blocker (exits 3 by design if hit). Confirm via static grep of `Cargo.lock`
   whether it's still live; if so, this is a P0-blocks-Rung-3 defect — propose
   the single canonical rev + the exact `cargo update -p …` invocation Dev A
   should run (but do not run it yourself; no Nix/cargo network access
   assumed reliable for a full resolve on this pass — flag it as a defect,
   let Dev A execute).
4. **Gradle version-catalog consistency.** `android-container/profile`'s
   `gradle/libs.versions.toml` (single source of truth per its own header) vs
   `android-bridge/persona/app/build.gradle.kts`'s HARDCODED versions
   (`compose-bom:2024.06.00`, `activity-compose:1.9.1`,
   `lifecycle-runtime-ktx:2.8.4`, `kotlinx-coroutines-android:1.8.1`, Compose
   compiler `1.5.14` inline) — NoporIS is NOT yet wired to a catalog at all.
   Flag the drift risk: if Porog's catalog bumps a Compose/Kotlin pin and
   NoporIS's hardcoded versions don't move in lockstep, the two apps can end up
   on incompatible Compose-compiler↔Kotlin pairs. Recommend NoporIS get its own
   `gradle/libs.versions.toml` (Dev B's job per PARTITION.md) before box-day.
5. **The commented-out `:android-common` dependency** in
   `android-bridge/persona/app/build.gradle.kts` — confirm whether
   `android-bridge/persona/settings.gradle.kts` even has a path to
   `android-common` (it lives outside `android-bridge/`, at repo-root-level
   `android-common/`) via `includeBuild` or a relative `include(":android-common")`
   with `project(":android-common").projectDir = file("../../android-common")`
   or similar. If the module path isn't wired in `settings.gradle.kts`,
   uncommenting the dependency line alone will NOT resolve on box-day — this is
   exactly the class of "import-path bug" the charter calls out by name.
6. **CI target file existence.** For every `script:` line in `.gitlab-ci.yml`'s
   Android jobs (`t0:android-static`, `t1:android-assemble-debug`,
   `t1:profile-lifecycle-e2e`), confirm the referenced file/path exists at the
   stated location (`android-container/profile/test/e2e/provision-lifecycle.sh`,
   `android-container/profile/toolchain/flake.nix`, the `libs.versions.toml`
   path). Also check the `changes:` glob rules actually match the directories
   that trigger these jobs (`android-container/**/*`, `android-common/**/*`) —
   NoporIS (`android-bridge/**/*`) is **not** in any `changes:` rule today, so
   its build is not CI-gated even statically; flag as a gap for Dev B/PMO.
7. **`os/seal-gate/fill-outputhashes.sh`'s SENTINEL_KEYS array** vs the actual
   `Cargo.lock` git-sourced crate `name-version`s — confirm the 5 hardcoded
   keys (`bloch-0.1.0-genesis`, `bloch-crypto-0.1.0-genesis`,
   `bloch-sis-pow-0.1.0`, `coherence-core-0.1.0`, `pqcrypto-internals-0.2.11`)
   still match by grepping `Cargo.lock` — if the protocol dep has moved to a
   different version tag since this was written, the script will silently
   `WARN: no got-hash reported` and under-fill, which the script itself
   catches (exits 4) — but confirm this pre-box rather than discover it live.

**Output:** a defects list, one row per finding, columns: `file:line`,
`what breaks`, `blocks which RUNBOOK rung`, `fix (copy-paste command or diff)`,
`severity (blocks-first-build / degrades / cosmetic)`. Rank by "blocks
first build" — a defect that stops Rung 0/1/3/7 cold outranks a cosmetic
version mismatch.

---

## Advisor 2 · reproducibility + honesty

**Mandate:** audit the repro knobs (determinism: `SOURCE_DATE_EPOCH`, sorted
inputs, pinned digests, no floating tags), the roothash/measured-boot claims
for over-statement, and confirm every bucket-A artifact carries the "not yet
run here" label + `scripts/check-trust-labels.sh` critical:0.

**Concretely check:**
1. **`flake.lock` empty-seed discipline.** Confirm it is still the literal
   `{"nodes":{"root":{}},"root":"root","version":7}` seed (no fabricated
   `narHash`), and that `scripts/flake-check.sh` genuinely refuses to run
   against it (fail-closed) rather than silently re-locking. This is the
   load-bearing honesty mechanic for Rung 0 — verify it hasn't regressed.
2. **`SOURCE_DATE_EPOCH` / digest pinning in `enterprise/cloud/image/`.**
   `build-image.sh` takes `-d <base-digest>` (required) and `-e <epoch>`
   (defaults to git commit time) — confirm no code path lets a floating tag
   (`:latest`) substitute for a digest, and that the default epoch fallback
   (`else 0`) is intentional and documented, not an accidental non-determinism
   hole.
3. **`os/seal-gate.nix`'s `lib.fakeHash` sentinels** — confirm all 5 are
   still the literal fail-closed sentinel (not accidentally pre-filled with a
   guessed hash by a well-meaning edit) and that `fill-outputhashes.sh` is the
   *only* code path that ever writes a real hash into that file.
4. **`os_roothash` placeholder discipline.** Grep the whole tree (SDK/companion
   fixtures, `os/ATTESTATION.md`, `flake.nix` comments, any Kotlin/Rust default
   `Expected.os_roothash`) for a fabricated-looking 64-hex value masquerading
   as real. Confirm every occurrence is either the documented design-reference
   placeholder or explicitly sourced from a VM run's `extract-roothash.sh`
   output with provenance (evidence sidecar) attached. A roothash with no
   corresponding `.evidence` file is a red flag.
5. **Boot-harness evidence-sidecar honesty.** For `os/boot-harness/` and
   `os/boot-harness-x86/`: confirm the `.evidence` sidecar format (image path +
   nix hash + sha256 + qemu version + timestamp + boot_rc + check_rc) cannot be
   hand-fabricated plausibly, and that the README's "NEVER RUN ON macOS"
   framing is repeated consistently (not softened) across every doc that
   references these harnesses.
6. **Measured-boot claim precision.** Confirm `verify-boot-binding.sh`'s three
   checks (A/cmdline, B/report, C/PCR) are never collapsed into a single
   "attested" verdict — C must stay explicitly `skip`/`TODO-HW` under QEMU/TCG,
   and no downstream doc (RUNBOOK, site copy, PARTITION) should describe a
   Rung-4 PASS as "measured boot proven" when only A+B (software chain) ran.
7. **`scripts/check-trust-labels.sh` critical:0.** Run it (it IS host-runnable,
   pure shell/grep/awk, no Nix needed) against the current tree and confirm
   `critical: 0`. Specifically re-verify:
   - CRITICAL 2 (attestation-grade words on `pmos-overlay`, `apps/sloboda`,
     `apps/sloboda-gate`, `os/sloboda-compat.nix`) — the Waydroid/Sloboda box-day
     work (Dev C) is exactly the surface most likely to accidentally introduce a
     "seal-covered" or "attested" word while writing bring-up notes; this is the
     single highest-risk regression point for bucket-A's box-day output.
   - CRITICAL 3 (`key-attested` missing its "not a measured-boot workspace"
     qualifier within ±3 lines) on the Porog/NoporIS qualified paths — any new
     box-day doc mentioning Porog's StrongBox key-attestation must carry the
     qualifier.
   - The WARN pass (bare `secure`/`audited` on `apps/`) — review, not blocking,
     but flag anything new.
8. **Bucket-A-specific label check (new surface this charter creates).** Every
   file this PMO round adds under `docs/bucketA/` (RUNBOOK.md, PARTITION.md,
   this charter, READINESS.md) must itself say "ready-to-run on the box, NOT
   YET RUN here" wherever it describes a command's expected outcome — confirm
   no sentence in any of the four docs reads as a completed-past-tense claim
   ("this booted", "this built") rather than a future/imperative one ("this
   will boot", "run this to build"). This is a self-check on the PMO's own
   deliverable, not just the code.

**Output:** a pass/fail table per check above, plus the raw
`scripts/check-trust-labels.sh` output appended verbatim. Any CRITICAL finding
blocks sign-off on box-day dispatch until fixed — this advisor's report is the
gate that keeps `critical:0` true going into Bucket A execution, not just
coming out of it.

---

## Sequencing

Both advisors run **now**, on macOS, in parallel with each other (they read
disjoint-enough surfaces — Advisor 1 is build-graph correctness, Advisor 2 is
label/determinism honesty — though both will legitimately touch `flake.nix`
and `os/seal-gate.nix` from different angles; that overlap is fine, it's
inspection not editing). Their combined defects list is triaged by the PMO
before Dev A/B/C are dispatched, so box-day starts with a known-clean plan
rather than discovering Advisor-catchable bugs live.
