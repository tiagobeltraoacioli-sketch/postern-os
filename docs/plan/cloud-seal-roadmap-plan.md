<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: 2026 Postern Labs
CLOUD/CHIOSTRO + SEAL track — 5-dev roadmap-completion partition (fable5 track-lead).
Planning artifact only. No code changed by this document. Inputs:
docs/gap/cloud-chiostro-gaps.md, docs/gap/POSTERN-GAP-BACKLOG.md, and a direct
read of snp.rs / tdx.rs / gate.rs / mobile.rs / the seal binaries / os/cloud.nix /
enterprise/cloud/{services,control-plane,image}.
-->

# CLOUD / CHIOSTRO + SEAL — 5-dev partition

**Track-lead:** fable5 · **Date:** 2026-07-13 · **Repo:** `/Users/tiagoacioli/dev/bloch-protocol`

Five developers, **strict non-overlapping file ownership**, HOST-provable-first.
Real SEV-SNP/TDX *hardware* proof is out of reach on this fleet; hardware-gated
tasks **write + host-test against fixtures** and are labelled as such.

## Proof-tier legend
- **HOST-now** — provable on this dev host today (`cargo test` / `node` / local `curl`), no TEE, no Nix, no cloud.
- **VM-gated** — needs a Nix host to build and/or a booted VM to run.
- **hardware-gated** — code + host-fixture tests land now; the *Genuine/live* verdict needs real SEV-SNP/TDX silicon (see `HARDWARE-RUNBOOK.md`).

## Ownership map (one owner per path — no path appears twice)
| Path | Owner |
|---|---|
| `crates/postern-seal-companion/src/tdx.rs` | **DEV-1** |
| `crates/postern-seal-companion/tests/tdx_collateral.rs` | **DEV-1** |
| `crates/postern-seal-companion/src/snp.rs` | **DEV-2** |
| `crates/postern-seal-companion/src/lib.rs` | **DEV-2** |
| `crates/postern-seal-companion/tests/snp_crl.rs`, `tests/snp_vectors.rs` | **DEV-2** |
| `crates/postern-seal-companion/src/bin/seal_gate.rs`, `src/bin/seal_verify.rs` | **DEV-4** |
| `enterprise/cloud/services/**` (incl. `src/license-service.mjs`, `self-check.mjs`) | **DEV-3** |
| `enterprise/cloud/image/{Containerfile, fly.toml, compose.yaml, build-image.sh, smoke-test.sh, BUILD-AND-DEPLOY.md, config/, vendor/}` | **DEV-3** |
| `enterprise/cloud/image/cloud-image.nix` | **DEV-5** |
| `os/cloud.nix`, `os/attested.nix` | **DEV-5** |
| `enterprise/cloud/control-plane/**` | **DEV-5** |
| Untouched by this track: `src/gate.rs` (done), `src/binding.rs` (done), `src/mobile.rs` (Android backend, separate), `Cargo.toml` (coordinate via DEV-2 if a dep bump is unavoidable) | — |

---

## DEV-1 — TDX: paste the real pinned Intel SGX Root CA DER (unblock the TDX path)
- **Proof tier:** **HOST-now** (unblocks + validates the anchor/parse); the *live Genuine* verdict is hardware-gated (needs a real Intel TDX quote + matching collateral).
- **Scope:** `PINNED_INTEL_SGX_ROOT_CA_DER` is literally `&[]` (`tdx.rs` line ~306), so `verify_collateral_dcap` always short-circuits to `PinnedRootUnset` and TDX can *never* reach `Genuine`. Fetch Intel's real SGX Provisioning Certification Root CA, convert to DER, and paste it as the const's bytes (a `&[u8]` byte array or `include_bytes!` of a committed `.der`). Confirm the DER parses as a valid self-signed X.509 root and that the anchor equality gate (`verify_collateral_anchored` step 2, `root_der == anchor_root_der`) now engages instead of the empty-anchor early return.
- **Files/dirs OWNED:** `src/tdx.rs`, `tests/tdx_collateral.rs` (and, if using `include_bytes!`, a new committed DER fixture under `testdata/` — coordinate name with DEV-2/DEV-4 who also read `testdata/`, but DEV-1 owns any *new* TDX file it adds).
- **Proof steps (HOST-now):**
  - `cargo test -p postern-seal-companion --features tdx-verify` — the synthetic-anchor tests (`verify_collateral_anchored`) must stay green (they pass an explicit anchor, independent of the pinned const).
  - Add a test asserting `PINNED_INTEL_SGX_ROOT_CA_DER` is non-empty and `X509Certificate::from_der(...)` succeeds and is self-signed → proves the DER is real and well-formed.
  - Add a test that `verify_collateral_dcap` on a synthetic (non-Intel-rooted) quote now returns `RootNotAnchored`/`ChainInvalid` — **not** `PinnedRootUnset` — proving the placeholder no longer swallows the path.
  - `well_formed_full_match_still_fails_closed` and `tdx_stub_never_says_genuine` must remain green (no-collateral path is unchanged).
- **Deps:** none. Fully independent.
- **Shared-file coordination:** none on source. `tdx.rs` is DEV-1-exclusive. If a `testdata/` fixture is added, announce the filename (shared *directory* with DEV-2/DEV-4, non-overlapping files).

## DEV-2 — SNP: fix the revoked-VCEK footgun (enforce AMD-KDS CRL by default)
- **Proof tier:** **HOST-now** (fully testable with the vendored Milan fixture + synthetic CRL; no hardware).
- **Scope:** Today base `verify_snp_report` chains VCEK→ASK→ARK to the *pinned* 2020-era AMD roots and returns `Genuine` **without any revocation check** — a since-revoked VCEK passes unless the caller remembers the opt-in `verify_snp_report_with_crl`. Close the footgun so the *default* path is safe-by-construction. Recommended shape (DEV-2's call): make revocation-aware verification the ergonomically-named default and rename the CRL-less path to a loud opt-out (e.g. `verify_snp_report_without_revocation`), OR require a `KdsCrl`/explicit `RevocationPolicy` argument on the primary entry. Whatever the shape: a caller who does nothing special must not accept a revoked VCEK. Keep the crate network-free (CRL is still fed out of band); update `verify_gate_evidence` to thread the same policy.
- **Files/dirs OWNED:** `src/snp.rs`, `src/lib.rs` (re-exports), `tests/snp_crl.rs`, `tests/snp_vectors.rs`.
- **Proof steps (HOST-now):**
  - Extend `tests/snp_crl.rs`: the **default** verify entry, given a CRL whose (synthetic-issuer) list contains the fixture VCEK's serial, must return `Rejected("…revoked…")`; and given no CRL, the default must *refuse/flag* rather than silently accept.
  - `tests/snp_vectors.rs` (the real Milan `testdata/` fixture) must be migrated to the new API and stay green — the offline-vector literals are the regression guard.
  - `cargo test -p postern-seal-companion --features sev-snp` all green; `cargo build` with default features unaffected (CRL types already live under the SNP module).
- **Deps:** none upstream. **Downstream:** DEV-4 (`seal_verify` binary) consumes this API — DEV-2 publishes the final `snp.rs` signatures first, then DEV-4 adapts. Freeze the public API early and post it.
- **Shared-file coordination:** `snp.rs` is **DEV-2-exclusive** — DEV-4 only *calls* its functions from the binaries, never edits it. `lib.rs` re-exports are DEV-2-owned; DEV-1 needs no `lib.rs` change (TDX already re-exports via `tdx.rs`'s `pub use`). If `Cargo.toml` needs a dep touch, DEV-2 arbitrates.

## DEV-3 — Fix `/v1/crl` 404 on the deployed license service + redeploy
- **Proof tier:** **HOST-now** (route correctness provable locally with `node` + `curl`); the live-endpoint flip to 200 is **deploy-gated** on Fly credentials.
- **Scope:** `GET /v1/crl` (and `POST /v1/crl`) **are implemented** in `license-service.mjs` (`route()` dispatch, `handleGetCrl`/`handlePublishCrl`), but the deployed `postern-cloud-demo.fly.dev` build 404s — the running image predates the route (drift, not a code bug). Confirm locally that the current code serves `/v1/crl`, then rebuild + redeploy the license service so the live endpoint matches the code. Note the deploy hazard: `image/Containerfile`'s `ENTRYPOINT` is a placeholder that `exit 1`s and does not run `node src/license-service.mjs`; the real Fly deploy path must actually launch the service (reconcile Containerfile/fly.toml entrypoint with `start:license`). Fail-closed vendor-key behaviour (`requireVendorKey`) and `VENDOR_PUBLIC_KEY` Fly secret must be preserved.
- **Files/dirs OWNED:** `enterprise/cloud/services/**` (the service + `self-check.mjs` + `package.json`), and the **deploy** files in `enterprise/cloud/image/`: `Containerfile`, `fly.toml`, `compose.yaml`, `build-image.sh`, `smoke-test.sh`, `BUILD-AND-DEPLOY.md`, `config/`, `vendor/`.
- **Proof steps:**
  - HOST-now: `VENDOR_PUBLIC_KEY=<test> node src/license-service.mjs` then `curl localhost:8080/v1/crl` → 200 with `{crl:null, note:…}` (no CRL published) — proves the code path is correct.
  - HOST-now: `node self-check.mjs` green.
  - Deploy-gated: `flyctl deploy` (or the repo's deploy runbook) for app `postern-cloud-demo`, then `curl https://postern-cloud-demo.fly.dev/v1/crl` returns **200** (was 404). Re-probe `/healthz`, `/v1/posture`, `/v1/verify` still 200 (no regression). Update the gap doc's live-endpoint table.
- **Deps:** none in code. Needs Fly deploy access for the final flip (operational, not a code blocker).
- **Shared-file coordination:** `enterprise/cloud/image/` is **split by file**: DEV-3 owns the container/Fly *deploy* files; **DEV-5 owns only `cloud-image.nix`** in that same dir. No file overlaps; announce any `fly.toml`↔`compose.yaml` edits so DEV-5's Nix image assumptions stay aligned.

## DEV-4 — SNP guest-side live report path: dedupe the gate binary onto the library + host-test the fail-closed guards
- **Proof tier:** **HOST-now** for the dedupe/compile + fail-closed guard tests; **hardware-gated** for the live `/dev/sev-guest` fetch (needs a real SEV-SNP guest).
- **Scope:** The library guest-side fetch (`request_bound_evidence` / `request_ext_report` / `request_raw_report` / `sev_guest_device_present`) **already exists** in `snp.rs` and is fail-closed-tested off-TEE. The remaining real gap (gap-doc C2, flagged follow-up in `snp.rs`): the `postern-seal-gate` binary carries its **own inline copy** of the `/dev/sev-guest` ioctls. Dedupe it onto the library functions so there is one guest-side codepath. Then adapt `postern-seal-verify` to DEV-2's finalized `snp.rs` verifier API (thread the CRL/revocation policy; add a `--crl <der>` arg so the client can enforce revocation end-to-end). Host-test that both binaries fail closed off-TEE (non-Linux stub + Linux-without-`/dev/sev-guest`) and that the challenge/evidence round-trips through `gate.rs`.
- **Files/dirs OWNED:** `src/bin/seal_gate.rs`, `src/bin/seal_verify.rs`.
- **Proof steps:**
  - HOST-now: `cargo build -p postern-seal-companion --features sev-snp --bins` — both binaries compile against the library (no inline ioctl duplication remains in `seal_gate.rs`).
  - HOST-now: run `seal_gate` on this macOS host → exits with the named "not a confidential VM / fail closed" message (the `cfg(not(target_os="linux"))` arm), never fabricates evidence.
  - HOST-now: a small integration/e2e over `encode_challenge`/`GateEvidence` proving the client parses a well-formed evidence bundle and *rejects* a bundle whose `report_data` binding is wrong (reuses `gate.rs` + `binding` — read-only).
  - hardware-gated: live report fetch + Genuine handshake per `HARDWARE-RUNBOOK.md` on GCP N2D Milan — written, not run here.
- **Deps:** **DEV-2** (consumes final `snp.rs` verifier + guest API). Start on `seal_gate.rs` dedupe immediately (uses already-stable functions); do the `seal_verify.rs` API adaptation after DEV-2 freezes the signatures.
- **Shared-file coordination:** DEV-4 **never edits `snp.rs`** — it only calls it. Binaries are DEV-4-exclusive. Reads `gate.rs`/`binding.rs` (DEV-2/no-one edits them).

## DEV-5 — Chiostro CVM profile (`os/cloud.nix`) + managed-node control plane — complete & host/self-test
- **Proof tier:** **VM-gated** for the Nix image (needs a Nix host to build, real CVM to boot); **HOST-now** for the control-plane logic (`node self-check.mjs`).
- **Scope:** Two halves, one owner (kept together per roadmap direction):
  1. **`os/cloud.nix` + `os/attested.nix` + `image/cloud-image.nix`** — complete the confidential-VM guest profile (verity-sealed rootfs, seal-gate as sole pre-attestation listener, WG-only desktop/SSH, first-boot LUKS `/persist`, in-guest WG keygen). Written on a non-Nix host; the deliverable here is making it *build-ready* and internally consistent (repart/verity/UKI option drift resolved to a target nixpkgs), so a Nix host can `nix build .#cloud-image`. Produces the `os_roothash`/launch-measurement `M` the verifier pins.
  2. **`enterprise/cloud/control-plane/`** — complete the managed-node orchestrator: tenant isolation, license-bound lifecycle (revoke⇒deprovision via `license-binding.mjs`), and the injected operator `driver` interface. It provisions **no real infra** without a driver (`simulated: true`) — keep that honest; the deliverable is a clean, self-checked orchestration surface + driver contract, not a live provisioner.
- **Files/dirs OWNED:** `os/cloud.nix`, `os/attested.nix`, `enterprise/cloud/image/cloud-image.nix`, `enterprise/cloud/control-plane/**`.
- **Proof steps:**
  - HOST-now: `node enterprise/cloud/control-plane/self-check.mjs` green (tenant admission, isolation, revoke⇒deprovision, `simulated:true` flagged).
  - HOST-now: `nix-instantiate --parse os/cloud.nix` / `nixpkgs-fmt --check` style static validation where available (no Nix eval on this host — syntax/lint only).
  - VM-gated: `nix build .#cloud-image` on a Nix host → image builds (T2); boot + attest is hardware-gated (out of fleet reach), record as the standing gate.
- **Deps:** soft — control-plane `license-binding.mjs` mirrors the license semantics DEV-3 owns in the service; align the revocation contract but no shared files.
- **Shared-file coordination:** owns **only `cloud-image.nix`** inside `enterprise/cloud/image/` (DEV-3 owns the rest of that dir). No file overlap. `os/attested.nix` is a Chiostro dependency and DEV-5-exclusive.

---

## Cross-cutting summary
| Dev | Task | Tier | Owns (primary) | Depends on |
|---|---|---|---|---|
| DEV-1 | TDX pinned Intel root DER | **HOST-now** (Genuine=hw-gated) | `tdx.rs`, `tests/tdx_collateral.rs` | — |
| DEV-2 | SNP CRL-by-default footgun fix | **HOST-now** | `snp.rs`, `lib.rs`, `tests/snp_crl.rs`+`snp_vectors.rs` | — |
| DEV-3 | `/v1/crl` 404 fix + redeploy | **HOST-now** (flip=deploy-gated) | `enterprise/cloud/services/**`, image deploy files | — (Fly creds) |
| DEV-4 | Guest gate dedupe + client CRL wiring | **HOST-now** (live=hw-gated) | `src/bin/seal_gate.rs`, `seal_verify.rs` | DEV-2 API |
| DEV-5 | `os/cloud.nix` + control plane | **VM-gated** (ctrl-plane HOST-now) | `os/cloud.nix`, `os/attested.nix`, `cloud-image.nix`, `control-plane/**` | soft: DEV-3 |

**The three fully HOST-provable-now wins** (land + prove without any hardware/Nix/cloud): **DEV-1** (TDX DER unblock, validated by `--features tdx-verify` tests), **DEV-2** (SNP revoked-VCEK default fix, validated by the Milan fixture + synthetic CRL), **DEV-3** (`/v1/crl` route, validated by local `node`+`curl`; deploy is the only non-code step). **DEV-4** is HOST-now for the dedupe/guards, written-only for the live silicon path. **DEV-5** is written/build-ready now, its image build VM-gated and boot+attest hardware-gated.

**No two devs edit the same file.** The only shared *directories* are
`crates/postern-seal-companion/tests|testdata/` (files split by owner) and
`enterprise/cloud/image/` (deploy files → DEV-3, `cloud-image.nix` → DEV-5).
The single hard code dependency is **DEV-4 → DEV-2** (final `snp.rs` API); all
others are independent or soft-contract only.
