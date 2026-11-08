# Bucket B — 3-Dev Partition (file-ownership-disjoint)

Base: `roadmap/fleet2-integrate`. All work is HOST-runnable prep: verifier
logic, config/expected-value types, fixture/vector tests, docs. **No dev in
this partition calls real hardware** — every "hardware-day command" listed is
what the operator runs once real hardware exists, not something a dev runs
during bucket-B work.

Rails for all three: no deploy, no git commit, no fabricated attestation
output, no touching `bp-wt-fleet2` or any other worktree. `cargo test -p
postern-seal-companion` (default, no features) must stay green throughout —
this is the "lean default build" discipline already documented in the crate's
`Cargo.toml`. Re-run `scripts/check-trust-labels.sh` before calling any file
done; it must stay `critical:0`.

---

## Dev A · SEV-SNP

**Owns:**
- `crates/postern-seal-companion/src/snp.rs`
- `crates/postern-seal-companion/src/gate.rs`
- `crates/postern-seal-companion/src/binding.rs` — **owned but treat as
  frozen API**: Dev B's TDX code imports `crate::binding` read-only
  (`report_data`/`matches` share the same 64-byte layout across both TEEs).
  Any signature change here needs a heads-up to Dev B before merging.
- `crates/postern-seal-companion/tests/snp_vectors.rs`
- `crates/postern-seal-companion/tests/snp_crl.rs`
- `crates/postern-seal-companion/src/bin/seal_gate.rs`
- `crates/postern-seal-companion/src/bin/seal_verify.rs`
- `crates/postern-seal-companion/HARDWARE-RUNBOOK.md` (already exists, keep
  current)
- `testdata/` (the real Milan report+VCEK fixture, if present under this
  crate — verify path, do not touch the fixture bytes themselves)

**Scope of hardening work (all offline/fixture, no hardware):**
- Expand `SnpExpected` config coverage / doc comments for anything a real
  release manifest will need to supply (measurement per VM shape, HOSTDATA
  policy per deployment, TCB floor derivation notes).
- Add negative-vector tests mirroring HARDWARE-RUNBOOK.md §7's negative
  controls (stale nonce, substituted pubkey, wrong generation, bit-flipped
  measurement, TCB-floor violation, debug policy) — these should exist as
  OFFLINE fixture tests today, not only as a hardware-day checklist.
- Audit `RevocationPolicy` default-safety: confirm no call site in
  `seal_gate.rs`/`seal_verify.rs` silently selects
  `SkipRevocationCheckDangerously`; if either binary exposes a `--crl` flag,
  confirm omitting it prints the documented warning rather than silently
  defaulting to skip.
- Write the expected-measurement documentation the RUNBOOK references (how
  `sev-snp-measure` output maps into `SnpExpected::measurement`, per VM shape).

**Hardware-day command this bucket-B work exercises (operator runs later, on
a real GCP N2D Milan instance):**
```
postern-seal-verify --gate <guest-ip>:16510 --generation milan \
    --measurement <96 hex M> --host-data <64 hex P> \
    --min-tcb <bl,tee,snp,ucode> --vmpl 0 --crl <AMD-KDS CRL>
```
Success signal: exit 0, `Genuine`, prints the guest WireGuard pubkey as the
only sound tunnel peer.

---

## Dev B · TDX

**Owns:**
- `crates/postern-seal-companion/src/tdx.rs`
- `crates/postern-seal-companion/tests/tdx_collateral.rs`
- New: `crates/postern-seal-companion/HARDWARE-RUNBOOK-TDX.md` (does not exist
  yet — SNP's runbook explicitly scopes TDX out; write the TDX equivalent)

**Reads but does not modify:** `src/binding.rs` (Dev A owns it).

**Critical framing for this dev (state it in every doc/PR):** the pinned
Intel SGX Root CA is **no longer an empty placeholder** — it is Intel's real,
published root DER. This does NOT make TDX closer to `Genuine` in the way it
sounds: the primary/default entry points (`verify_td_quote`,
`verify_td_quote_bound`) are **unconditionally** fail-closed via
`verify_collateral()`, which is not feature-gated and does not call the real
chain code at all — even with `tdx-verify` compiled in and a real Intel-rooted
quote in hand, those two functions can never return `Genuine`. Only
`dcap::verify_td_quote_with_collateral` (feature `tdx-verify`) performs the
real chain-to-Intel-root verification, and it has never been exercised
against a real quote — only against a synthetic anchor
(`verify_collateral_anchored` in tests). Both facts must ship together in any
doc this dev writes: "root is real" AND "still cannot be Genuine here, for a
different, now-primary reason."

**Scope of hardening work (all offline/fixture, no hardware):**
- Decide and document (RFC-style note in the module header or a new doc) the
  intended long-term API shape: should `tdx-verify` change what
  `verify_td_quote_bound` does, or should the two-entry-point split
  (fail-closed stub vs. real DCAP path) be permanent, explicit, named
  differently so a caller cannot reach for the wrong one by accident? This is
  a design decision, not just code — flag it up rather than silently pick one.
- Certificate-expiry gap: `verify_collateral_anchored` checks CRL `nextUpdate`
  freshness but does **not** check the PCK leaf/intermediate/root X.509
  validity windows (`notBefore`/`notAfter`) the way `mobile.rs` does via
  `now_unix`. Add that check (mirroring mobile.rs's pattern) or explicitly
  document why it's waived — this is exactly the kind of gap Advisor 1 should
  independently confirm.
- Add negative-vector tests against the synthetic DCAP chain: expired cert,
  wrong root, revoked PCK, tampered QE binding, tampered quote signature, TCB
  floor violation — confirm each maps to its named `TdxCollateralError`.
- Write `HARDWARE-RUNBOOK-TDX.md` mirroring the SNP structure: platform/chip
  (TDX-capable Xeon), provisioning, quote+collateral acquisition, the exact
  "call `verify_td_quote_with_collateral`, not `verify_td_quote`" warning,
  proof-bundle checklist, negative controls.

**Hardware-day command this bucket-B work exercises (operator runs later, on
a real TDX Xeon instance):**
```rust
let collateral = TdxCollateral { root_ca_crl_der, pck_crl_der, now_unix, tcb_svn_floor };
dcap::verify_td_quote_with_collateral(&quote, &expected, &collateral)
```
Success signal: `Verdict::Genuine`. This is a library call today (no CLI
binary exists for TDX the way `postern-seal-verify` exists for SNP) — building
that CLI, or documenting the harness snippet, is in scope for the RUNBOOK.

---

## Dev C · StrongBox mobile + TPM2

**Owns:**
- `crates/postern-seal-companion/src/mobile.rs`
- New: fixture/harness additions for TPM2 PCR measurement (a new `tpm2/`
  fixtures directory under this crate, or a new small crate if the node-side
  `bloch::attestation` boundary makes more sense — coordinate placement with
  whoever owns `os/attested.nix`, since that file is outside this crate and
  outside this dev's write scope)
- Reads/references (does not own, no write access): `os/attested.nix`,
  `os/ATTESTATION.md` — this dev documents against them, does not edit them
  (they belong to the OS/images track, not Bucket B's crate-scoped work)

**Scope of hardening work (all offline/fixture, no hardware):**
- `mobile.rs` is already the most complete of the three verifiers (full
  ASN.1 `KeyDescription` parser, chain verify to a caller-pinned root, real
  `rcgen`-built end-to-end chain tests). Remaining hardening:
  - `MobileExpected::roots` config doc: write down the exact procedure to
    fetch Google's **current** Hardware Attestation root cert(s) (rotated
    2026-02-01, mandatory 2026-04-10) and pin more than one across a rotation
    window — this is the RUNBOOK's one open config item for mobile.
  - No CRL/revocation check exists for the Google attestation chain (stated
    limitation in the module docs). Design (don't necessarily implement) what
    an out-of-band revocation check would look like, mirroring
    `snp.rs`'s `RevocationPolicy` pattern, and document the gap precisely if
    not implementing it this bucket.
  - Add negative vectors: expired chain cert (the `now_unix` path is tested
    indirectly via hand-built vectors but add an explicit expired-cert rcgen
    case), OS-patch-level rollback beyond what's covered, StrongBox-required
    but only-TEE-reported (already covered — extend to a boundary value at
    exactly the floor).
- TPM2 side (net-new, honestly scoped as **prep only** — see RUNBOOK's
  platform-4 section for why this is a two-gate item):
  - Build `swtpm` + `tpm2-tools`-based fixture tests that exercise PCR-extend
    / quote *parsing and comparison logic* the same way `snp_vectors.rs` tests
    the SNP chain logic against a captured real fixture. Label these tests
    explicitly `swtpm — software TPM, NOT hardware evidence` in code comments
    and test names, so nobody mistakes a green `swtpm` run for a hardware
    result.
  - Document the PCR→`os_roothash` binding the way `os/ATTESTATION.md`
    diagrams it, and write the operator-facing steps to read back a real PCR
    quote once `os/attested.nix` builds and boots (this dev writes the doc;
    building/booting the image is the OS track's job, out of this bucket's
    file ownership).

**Hardware-day command this bucket-B work exercises (operator runs later, on
a real StrongBox Android device):**
```rust
mobile::verify_key_attestation_detailed(&chain_der, &expected)
```
Success signal: `Verdict::Genuine` / `MobileAttestation{security_level:
StrongBox, device_locked: true, verified_boot_state: Verified, ...}`.

And, once `os/attested.nix` is built and booted on a TPM2 host (a separate
gate, sequenced first):
```rust
verify(&report, &expected /* expected.os_roothash = value from `nix build .#attested-image` */, nonce)
```
Success signal: `Verdict::Trusted`.
