<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- Bucket-A PMO deliverable. A checklist scoring each bucket-A item, as of
     2026-07-13, against roadmap/fleet2-integrate. Every score below reflects
     PREPARATION state only — nothing in bucket A has built, booted, or run
     on a real box. Where a check below is marked "verified", it means a
     HOST-runnable static check (shellcheck / trust-label grep / gradlew
     syntax / TOML parse / brace-balance) was actually executed on this
     macOS workstation just now — not that anything built or booted. -->

# Bucket A — READINESS snapshot

**Legend:** `prep-complete-ready-for-box` (nothing left to do except run it on
the box) · `prep-partial` (usable, but a known gap should be closed before or
early in box-day) · `blocked-needs-box-only` (fully prepared, the ONLY thing
missing is the box itself — no code/doc work remains).

Most items score **ready-for-box** — that is the intended win of this PMO
pass: the repo's own honesty discipline (SCAFFOLD/deferred-to-VM labeling,
harnesses, graders, fixtures) was already unusually far along before this
review even started.

---

## OS images

| Item | Score | Notes |
|---|---|---|
| Node ISO (`.#iso`) | **blocked-needs-box-only** | `flake.nix` wiring correct by inspection; only blocked on Nix. |
| Desktop ISO (`.#desktop-iso`) | **blocked-needs-box-only** | Same. |
| Mobile image (`.#mobile-image`) | **prep-partial** | Buildable by inspection, BUT `mobile-nixos` output-attribute (`outputs.default`) is self-documented as drift-prone across revs, and no rev is pinned yet (empty-seed `flake.lock`). Recommend Advisor 1 propose a specific `mobile-nixos` rev before box-day so the first `nix build .#mobile-image` isn't a live discovery process. |
| Attested/measured-boot image (`.#attested-image`) | **blocked-needs-box-only** | `os_roothash` pipeline (`extract-roothash.sh`, two-pass bind, `verify-boot-binding.sh`) is fully written and self-honest about what it proves (software chain) vs what stays hardware-gated (PCR). |
| Cloud/Chiostro image (`.#cloud-image`) | **blocked-needs-box-only** | Depends on seal-gate (below) via `os/cloud.nix`. |
| Seal gate (`.#seal-gate`) | **prep-partial** | `fill-outputhashes.sh` is well-built and fail-closed, but the documented dual-git-rev `Cargo.lock` collision (bloch-crypto/bloch-sis-pow/coherence-core at two revs) is a **likely first-run blocker** (exit 3) unless deduped pre-box. This is the single highest-value pre-box fix in bucket A — it is a `cargo update` away, touches a repo-wide file, and currently has no clear single owner (flagged to PMO in PARTITION.md/ADVISORS-CHARTER.md). |
| Two-builder reproduction (item #19) | **blocked-needs-box-only**, contingent on a **second** Nix host | RUNBOOK Rung 5 needs two machines; if the operator provisions only one box, this item stays open past box-day — plan for it explicitly, don't let it silently drop. |
| aarch64 QEMU boot harness | **blocked-needs-box-only** | Grader is HOST-self-tested already (`run-fixture-tests.sh`); the actual boot has never run (correctly labelled). |
| x86_64 QEMU boot harness | **blocked-needs-box-only** | This is the harness that specifically closes the one confirmed A1 overclaim (site says "boot-validated on QEMU x86_64," no harness existed before this branch). Fixture dry-run already passing on host; real boot is box-only. |
| Boot-binding verify (A/B software chain) | **blocked-needs-box-only** | Script correctly self-detects "not a booted Linux node" and exits 3 on macOS — cannot be faked here by construction. |
| PCR / measured-boot hardware rung | **out of bucket-A scope** | Explicitly HW-gated (real TPM2/SEV-SNP/TDX); the box alone does not close this even once provisioned — separate hardware rung, correctly labelled `TODO-HW` throughout. |

## Android bridge builds

| Item | Score | Notes |
|---|---|---|
| Porog (`android-container/profile`) — static gate (t0) | **verified now, host-runnable** | Re-ran on this workstation: `shellcheck` on `provision-lifecycle.sh` clean, `sh -n gradlew` OK, `libs.versions.toml` parses. Matches `.gitlab-ci.yml`'s `t0:android-static` job exactly. |
| Porog — `gradlew assemble` | **blocked-needs-box-only** | Toolchain flake (`toolchain/flake.nix`) is fully pinned (SDK 34, NDK r26b, `google_apis` non-Play image with the provisioning-block rationale documented) — nothing to fix, only Android SDK + Nix needed. |
| Porog — instrumented E2E (`ProfileLifecycleE2ETest`) | **blocked-needs-box-only** | Honestly `assumeTrue`-skips off-device; the AVD + KVM path is fully scripted (`nix run .#avd`). |
| NoporIS (`android-bridge/persona`) — static gate | **prep-partial** | No `t0`-equivalent CI job exists for this app yet (`.gitlab-ci.yml`'s `changes:` rules only watch `android-container/**` + `android-common/**`, not `android-bridge/**`). Re-ran the same static checks manually here (shellcheck, `sh -n gradlew`, TOML parse) — all clean — but this should be wired into CI, not left manual. |
| NoporIS — `:android-common` wiring | **prep-partial (concrete, verified defect)** | **Confirmed by direct inspection just now:** `android-bridge/persona/settings.gradle.kts` has `include(":android-common")` and the `projectDir` line **commented out** (Porog's equivalent file has the live, uncommented version). `app/build.gradle.kts` also has the corresponding `implementation(project(":android-common"))` commented out. Until both are uncommented, NoporIS's first box-day `./gradlew` will not resolve its shared DPC dependency — this is a pure text fix, no SDK needed, and should land pre-box (Dev B, per PARTITION.md). |
| NoporIS — toolchain flake | **blocked-needs-box-only, but missing the file** | Unlike Porog, `android-bridge/persona/` has **no `toolchain/flake.nix` at all**. Dev B's box-day plan (PARTITION.md) is to fork Porog's; until that lands NoporIS cannot even enter a pinned devshell. Scored partial rather than blocked because a repo-side action (adding the file) is needed, not just box time. |
| NoporIS — Gradle version catalog | **prep-partial** | Versions are hardcoded inline in `app/build.gradle.kts` rather than centralized in a `libs.versions.toml` (Porog has one, NoporIS doesn't). Not a blocker for a first build, but a drift risk flagged to Advisor 1/Dev B. |
| android-common (shared DPC module) | **blocked-needs-box-only** | Builds fine as a library module by inspection; consumed correctly by Porog today. |

## Waydroid (Sloboda)

| Item | Score | Notes |
|---|---|---|
| `os/sloboda-compat.nix` + `os/sloboda-vm.nix` | **blocked-needs-box-only** | Deliberately excluded from the sealed closure with a structural (not just conventional) assertion tripwire; written, never evaluated. |
| `apps/sloboda` wrapper (`bin/sloboda`, `paw-lib.sh`, etc.) | **verified now, host-runnable** | Re-ran `shellcheck -x -s sh` across the wrapper + test files here: clean. (README already documents a 39/39 `dry-run.sh` pass; not re-run in full here but the static gate that matters for box-day readiness — shellcheck — was re-confirmed.) |
| `scripts/vm/sloboda-waydroid-boot-smoke.sh` (the real T1 boot) | **blocked-needs-box-only** | Correctly SKIPs (exit 77) off-VM and refuses to run against the test mock — cannot be faked green; shellcheck clean here. |
| Waydroid → real device (T2: display, hardware GL, real Play Integrity) | **out of bucket-A scope** | Explicitly deferred to real aarch64 hardware in `apps/sloboda/README.md`'s own "only confirmable on a real device" list (13 items) — box-day proves T1 boot-to-`Session:RUNNING` only. |

## Tor (courier onion)

| Item | Score | Notes |
|---|---|---|
| `crates/postern-courier` default seal core | **already DONE (host-provable)** | Per the A4 gap doc, this is a real T1 host-test pass today — no box dependency. |
| `onion-transport` feature — live end-to-end | **blocked-needs-box-only, but NOT Nix/QEMU-gated** | `live_onion_drop_end_to_end` needs only `cargo` + network + minutes of live Tor bootstrap — it can run on ANY host with those, including in principle a separate machine from the Nix/QEMU box. Grouped into bucket A per the operator's framing (run it as part of the same box-day pass for coordination simplicity), but worth flagging: this item does not actually require the Linux+Nix+QEMU box specifically. |
| `postern-tor` in-process Arti wrapper | **blocked-needs-box-only** | Thin, already-tested dependency; no separate readiness concern beyond the courier test above. |

## Cross-cutting honesty gate

| Item | Score | Notes |
|---|---|---|
| `scripts/check-trust-labels.sh` critical:0 | **VERIFIED, PASSING, right now** | Actually executed against the full `roadmap/fleet2-integrate` tree on this workstation (exported via `git archive`, run read-only, no worktree touched): **`critical: 0, warn: 1`**. The one WARN is the heuristic "bare secure/audited" review pass surfacing ~40 lines across NoporIS/Porog/enterprise docs — none read as an over-claim on inspection (e.g. "audited quorum act" describing a governance process, "hardware-backed keystore" describing the phone's own StrongBox, not a Postern claim). This is the standing gate the operator asked to stay green; it is green today, before any box-day dev work has even started. Re-run it after Dev A/B/C's box-day changes land — Advisor 2's charter calls this out as the single highest-risk regression point (new Waydroid/Porog docs are the surfaces most likely to introduce an accidental attestation-grade word). |

---

## One-paragraph honest summary

Bucket A's prep state is better than "most items ready for box" — it is
close to all of it. The repo already ships purpose-built harnesses, graders,
fixtures, evidence-sidecar formats, and fail-closed scripts for nearly every
rung in RUNBOOK.md, all correctly self-labelled as unrun. The two concrete,
verified gaps worth closing before box-day are: (1) the documented
`Cargo.lock` dual-git-rev collision that will likely block the seal-gate's
first fill, and (2) NoporIS's commented-out `android-common` module wiring —
both are small, pre-box, non-Nix fixes. Beyond those, "ready for box" is not
optimism — it was checked here, on this workstation, with the exact
host-runnable tools (`shellcheck`, TOML parse, brace-balance, and a live run
of `check-trust-labels.sh` returning `critical: 0`) that this review had
available. Nothing above claims a build, a boot, or a roothash that did not
happen — those all still say, honestly, "blocked-needs-box-only."
