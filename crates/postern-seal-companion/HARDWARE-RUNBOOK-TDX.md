<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
-->

# Intel TDX live-attestation hardware runbook

**Status: reference-prototype / UNAUDITED. This is the procedure to move
`tdx.rs` from "real code, offline-vector-tested" to a *live* TD quote, and to
capture the proof.** As of this writing the TDX path is **verifier code that
has never been run against a TD quote from TDX hardware Postern launched**
(`vector-tested ≠ attested`, the same discipline `HARDWARE-RUNBOOK.md` §"What a
passing run proves" applies to SEV-SNP). Nothing here is a security claim;
nothing here is committed; no third-party audit exists. Where this doc and the
code disagree, the code wins.

This runbook is the TDX companion to `HARDWARE-RUNBOOK.md` (SEV-SNP, the
PRIMARY TEE per `POSTERN-CLOUD.md`; that runbook explicitly scopes TDX out).
It exercises only `crates/postern-seal-companion/src/tdx.rs`. TDX is
documented as the SECONDARY TEE — SEV-SNP is the one to validate first and the
one with a working end-to-end CLI (`postern-seal-gate`/`postern-seal-verify`);
no TDX-specific CLI exists yet (see §5 below for the library-call shape this
runbook drives instead).

## Two independent, stacked reasons TDX still cannot say `Genuine` here — read this before anything else

A late-2025/2026 change to this crate replaced the pinned Intel SGX Root CA
placeholder (`PINNED_INTEL_SGX_ROOT_CA_DER`, in `mod dcap`, feature
`tdx-verify`) with Intel's **real, published** root DER (self-signed,
`CN=Intel SGX Root CA`, SHA-256 fingerprint
`44A0196B2B99F889B8E149E95B807A350E7424964399E885A7CBB8CCFAB674D3`, asserted in
`tests/tdx_collateral.rs`). **Do not read that as "TDX is closer to working."**
Two independent gates stand between this crate and a real `Genuine` verdict,
and closing one does not touch the other:

1. **The default/primary entry points are unconditionally closed and do not
   even call the real path.** `verify_td_quote` and `verify_td_quote_bound` —
   the functions a caller reaches for by name — call the internal
   `verify_collateral` stub, which returns `Err` no matter what it is given: no
   collateral parameter exists in their signature, so there is nothing to
   authenticate against, by construction. Compiling `tdx-verify` in changes
   NOTHING about these two functions; that split is a deliberate, permanent API
   decision (see `tdx.rs`'s module-level "RESOLVED" note) — not a bug to fix on
   a hardware day.
2. **The real path is unaudited against real hardware.** Only
   `dcap::verify_td_quote_with_collateral` (feature `tdx-verify`) performs the
   real PCK → Intel processor CA → pinned Intel root chain check, QE-report
   binding, PCK cert-expiry window check, CRL freshness/revocation, and TCB
   floor. It has been exercised ONLY against a synthetic, self-minted DCAP
   chain (`tests/tdx_collateral.rs`, `verify_collateral_anchored` against a
   test root) — never against a quote or collateral from TDX silicon this
   project controls.

State BOTH facts together in any report from this runbook: *"the pinned root
is real" AND "TDX still cannot reach Genuine here, for a different, now-primary
reason."* Populating the root anchor was necessary, not sufficient.

## What a passing live run WOULD prove — and what it would not

A live `Verdict::Genuine` from `verify_td_quote_with_collateral`, carrying our
channel binding, would prove: *this exact TD image booted as measured (MRTD)
under the launch config we expect (MRCONFIGID), with runtime measured-boot
registers (RTMR[0..4]) at or matching the pinned values, inside a genuine Intel
TDX TEE whose PCK chain terminates at Intel's real root and whose TCB is at or
above our floor — and the report_data channel binding matches OUR fresh nonce
and the presented pubkey.* It would NOT prove availability, secrecy against a
determined physical/side-channel adversary, or Intel TCB-info/QE-identity JSON
collateral *signature* freshness (that signing-cert check is not folded in yet
— CRL `nextUpdate` + caller-supplied `now` cover freshness, but not the same
thing; documented in `tdx.rs`'s module header, not silently skipped).

## The code paths this runbook drives

- `tdx::parse_td_quote` — structural decode of a DCAP v4 TD quote (header + TD
  1.0 report body); authenticates nothing.
- `tdx::check_bound_fields` — MRTD / MRCONFIGID / RTMR / report_data comparison
  against `TdxExpected`; only sound once the chain is authenticated.
- `tdx::verify_td_quote` / `tdx::verify_td_quote_bound` — **the fail-closed
  default. Never returns `Genuine`, with `tdx-verify` compiled in or not.**
  `verify_td_quote_bound` recomputes `report_data` from a fresh nonce + guest
  pubkey via `crate::binding` (shared 64-byte layout with SNP) before calling
  `verify_td_quote`.
- `dcap::verify_collateral_anchored(quote, collateral, anchor_root_der)` (test
  hook — feature `tdx-verify`): the real crypto, anchored to an
  **explicitly-supplied** root. Production code should never call this
  directly with anything but `PINNED_INTEL_SGX_ROOT_CA_DER`; it exists so tests
  can exercise the real crypto against a synthetic anchor offline.
- `dcap::verify_collateral_dcap(quote, collateral)` (feature `tdx-verify`): the
  production entry — `verify_collateral_anchored` pinned to Intel's real root.
- `dcap::verify_td_quote_with_collateral(quote, expected, collateral)` (feature
  `tdx-verify`): **the ONLY function in this crate that can ever return
  `Genuine` for TDX.** Chain-authenticates first via `verify_collateral_dcap`,
  then compares bound fields via `check_bound_fields` — same
  authenticate-then-compare order as SNP.

> **The single most important operational note for whoever runs this:** call
> `verify_td_quote_with_collateral`, **not** `verify_td_quote` /
> `verify_td_quote_bound`. Using the wrong function silently "fails closed" for
> a reason that has nothing to do with the hardware in front of you — it is
> unreachable by construction, not a hardware or collateral problem.

## 0 · Pick the host

**Chip / machine:** a TDX-capable Xeon (4th/5th-gen Scalable, "Sapphire
Rapids"+) confidential VM/instance, or an on-prem Xeon host with `tdx_guest`
kernel support and a way to fetch Intel PCS/DCAP collateral (TCB-info,
QE-identity, CRLs) out of band. No provider has been validated yet (unlike
SNP's "GCP N2D first" recommendation) — record whichever cloud/on-prem host is
actually used in the proof bundle (§6), including whether it exposes DCAP quote
generation directly or requires a separate Quote Generation Service (QGS).

## 1 · Confirm the guard fails closed OFF hardware (baseline)

Before touching a TEE, prove BOTH fail-closed properties on an ordinary host,
so a later `Genuine` cannot be mistaken for a stub artifact, and so the
default-vs-real-path split is visibly exercised before it matters:

```
# On the macOS/Linux dev host (no TDX hardware):

# (a) the default build — collateral chain gate closed unconditionally
cargo test -p postern-seal-companion
# Expect: tdx_stub_never_says_genuine, well_formed_full_match_still_fails_closed,
# collateral_gate_is_unconditionally_closed all green — a PERFECTLY matching
# synthetic quote still returns Unverified.

# (b) tdx-verify compiled in — real crypto exercised, still offline
cargo test -p postern-seal-companion --features tdx-verify
# Expect (as of this runbook): the tdx_collateral vector suite green,
# including pinned_entry_fails_closed_against_a_non_intel_rooted_quote and
# synthetic_quote_now_hits_root_not_anchored_not_pinned_unset — proving the
# pinned-root path is reachable and correctly rejects a non-Intel-rooted
# synthetic quote, WITHOUT ever reaching Genuine on this host.
```

Both must pass before step 2. If (a) ever returns `Genuine`, or if (b)'s
pinned-entry test ever returns `Genuine` against a synthetic quote, STOP — that
is a regression in the fail-closed guarantee, not a hardware finding.

## 2 · Obtain a real DCAP v4 TD quote

On the TDX instance, request a TD quote via the `tdx_guest` device (or Intel's
DCAP quote-generation service/library), binding `report_data` to
`binding::report_data(nonce, guest_pubkey)` — the same 64-byte layout SNP uses,
so the same channel-binding discipline applies: generate the guest identity
key from TEE randomness, keep the private half in the guest, and feed only the
pubkey + a fresh verifier nonce into the binding.

```rust
// Illustrative — the actual call is via whatever TDX quote-generation
// mechanism the platform/cloud provides (tdx_guest ioctl, DCAP QGS client, …).
// This crate does no quote GENERATION, only verification.
let report_data = postern_seal_companion::binding::report_data(&nonce, &guest_pubkey);
// ... feed report_data into the platform's TD quote request, get back
// a raw DCAP v4 quote byte buffer ...
```

## 3 · Fetch real Intel PCS/DCAP collateral out of band

This crate does no network I/O — collateral is the operator's job:

- **Root CA CRL** and **PCK CRL** (DER) from Intel PCS, current for the
  platform's CA hierarchy.
- **`now_unix`** — the verifier's own clock, used for BOTH CRL `nextUpdate`
  freshness AND the PCK leaf/intermediate/root X.509 validity-window check
  (`notBefore`/`notAfter` — closed as of this runbook; previously only CRL
  freshness was checked, which is an independent property from whether the
  certs themselves are still inside their own validity window).
- **`tcb_svn_floor`** — an anti-rollback floor on `TEE_TCB_SVN`, read from a
  first trusted boot's report and floored at or below it (same discipline as
  SNP's `--min-tcb`: never above what genuine current firmware reports, or you
  reject good hosts; never so low that rolled-back firmware passes).

```rust
let collateral = postern_seal_companion::tdx::TdxCollateral {
    root_ca_crl_der: Some(root_crl_der),   // from Intel PCS
    pck_crl_der: Some(pck_crl_der),        // from Intel PCS
    now_unix: /* verifier's current time */,
    tcb_svn_floor: Some(floor_bytes),      // from a first trusted boot
};
```

## 4 · Determine the pinned expected values (release manifest)

`TdxExpected` is the MRTD/RTMR/report_data analogue of SNP's `SnpExpected`:

- **`mrtd`** — the TD build measurement (SHA-384), from the signed release
  manifest or a first trusted boot. *A verifier without a pinned MRTD proves
  only "some TDX guest somewhere" — always pin it.*
- **`mr_config_id`** — the launch-config binding (HOSTDATA analogue), if the
  provider lets you set it; `None` waives the check (document per deployment).
- **`rtmr`** — the runtime measured-boot registers, when pinned; `None` waives.
- **`report_data`** — set by `verify_td_quote_bound`'s binding recompute if
  using that path, or directly if calling `verify_td_quote_with_collateral`
  after computing it yourself with `binding::report_data`.

## 5 · Call the real entry point — directly, not through the stub

**No TDX-specific CLI exists yet** (unlike `postern-seal-verify` for SNP).
Building one, or at minimum wrapping this snippet in a small harness binary, is
in scope for whoever runs the hardware day — but the library call itself is
the actual verification step:

```rust
use postern_seal_companion::tdx::dcap::verify_td_quote_with_collateral;
// (or: use postern_seal_companion::tdx::verify_td_quote_with_collateral;
//  it is re-exported at the module root under feature `tdx-verify`.)

match verify_td_quote_with_collateral(&quote, &expected, &collateral) {
    postern_seal_companion::Verdict::Genuine => {
        eprintln!("Genuine — TD image, launch config, and runtime measurements match; \
                    chain authenticated to Intel's pinned root; channel binding fresh.");
    }
    postern_seal_companion::Verdict::Unverified(reason) => {
        eprintln!("REJECTED (unverified): {reason}");
    }
    postern_seal_companion::Verdict::Mismatch(reason) => {
        eprintln!("REJECTED (mismatch): {reason}");
    }
}
```

- **`Genuine`** → the only sound outcome to proceed on. Names nothing further
  (all checks passed); capture the proof bundle (§6) immediately.
- **`Unverified(reason)`** → the chain failed to authenticate. The underlying
  `TdxCollateralError` (surfaced in `reason`, or inspectable directly via
  `dcap::verify_collateral_dcap`) names the exact stage: `PinnedRootUnset`
  (should be unreachable now that the root is populated),
  `MalformedSig`, `BadPckChain`, `ChainInvalid`, `RootNotAnchored`,
  `CertExpired` (PCK leaf/intermediate/root outside its validity window),
  `CrlInvalid`, `Revoked`, `QeBindingMismatch`, `QeReportSignature`,
  `QuoteSignature`, or `TcbTooLow`.
- **`Mismatch(reason)`** → the chain authenticated but a bound field (MRTD,
  MRCONFIGID, RTMR, or report_data) did not match `expected`. Do **not**
  connect — this means the chain is genuine Intel silicon but not running the
  expected image/config, or the report_data is stale/relayed.

## 6 · Capture the proof bundle

Store these together (mirrors `HARDWARE-RUNBOOK.md` §6):

1. `quote.hex` — the raw live DCAP v4 TD quote bytes (from step 2).
2. `root_ca_crl.der`, `pck_crl.der` — the Intel PCS CRLs used (from step 3).
3. `nonce` and the guest pubkey used for the channel binding.
4. `verify.stdout` — the full verdict output, including the `TdxCollateralError`
   variant on any rejection.
5. `manifest.json` — `{git commit, mrtd, mr_config_id, rtmr, tcb_svn_floor,
   tool versions, PINNED_INTEL_SGX_ROOT_CA_DER fingerprint}`. Cross-check the
   root fingerprint against Intel's currently published root before trusting a
   hardware run — a stale local pin is a silent risk if Intel ever rotates it.
6. Environment: platform/chip (exact Xeon SKU), `tdx_guest` kernel presence,
   provider + region + machine shape, and however the quote-generation path
   (direct `tdx_guest` vs. QGS) was invoked.
7. `sha256sum` of items 1–2 and 5, recorded in the manifest.

Then confirm reproducibility of the *check* (not the silicon signature): drop
`quote.hex` + the CRLs into a `tests/tdx_collateral.rs`-style offline case with
the manifest's expected values and confirm it re-verifies `Genuine` off-host
(the offline fixture cannot mint *our* binding — that is exactly why the live
run is required; this only proves the captured evidence re-checks).

## 7 · Negative controls to record alongside the pass

A `Genuine` is only trustworthy next to failing controls proving the checks
bite on real hardware/collateral — the same discipline as SNP's §7, extended
with the TDX-specific chain checks:

- **Stale nonce / relayed quote** → `report_data` mismatch (re-run with a
  fresh nonce against a captured old quote).
- **Substituted guest pubkey (MITM)** → `report_data` mismatch.
- **Wrong MRTD** (one bit flipped, or a different build's measurement) →
  bound-field mismatch.
- **Wrong RTMR** (a stale or rolled-back runtime measurement) → bound-field
  mismatch.
- **Expired PCK certificate** — request a quote close to (or synthetically
  age-test with) a PCK cert whose `notAfter` has elapsed at the verifier's
  `now_unix` → `TdxCollateralError::CertExpired`.
- **Revoked PCK** — a PCK cert listed on the current PCK CRL → `Revoked`.
- **Wrong / stale PCK or root CRL** (`nextUpdate` elapsed) → `CrlInvalid`.
- **`tcb_svn_floor` one component above the reported `TEE_TCB_SVN`** →
  `TcbTooLow`.
- **Calling `verify_td_quote`/`verify_td_quote_bound` on a real, otherwise-good
  quote** → still `Unverified` — demonstrate this explicitly on hardware day so
  nobody mistakes the stub's rejection for a hardware problem.

## 8 · Do NOT

- Do **not** weaken any check in `tdx.rs`/`dcap` to make a stubborn host pass.
  A verifier that cannot check the chain must never say `Genuine`.
- Do **not** call `verify_td_quote` / `verify_td_quote_bound` and interpret
  their `Unverified` result as a hardware or collateral failure — they are
  unconditionally closed by design (§"Two independent, stacked reasons" above).
- Do **not** treat a synthetic-vector pass (`tests/tdx_collateral.rs`,
  `cargo test --features tdx-verify`) as a hardware result. Every test there
  chains to a test-minted root, never Intel's; label results
  **"hardware-gated, synthetic-vector-tested only"** until a real hardware run
  produces the proof bundle in §6.
- Do **not** market any of this as attested/audited/confidential until a real
  hardware `Genuine` is captured **and** an external audit lands. Until then:
  *"TDX verifier — software implemented and synthetic-vector-tested; NOT
  validated on TDX hardware."*
- Do **not** `git commit` hardware-day artifacts containing real Intel PCS
  collateral or real quote bytes into this repository without a documented,
  separate decision to do so (they are evidence, not fixtures).
