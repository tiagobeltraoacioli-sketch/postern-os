# Bucket B — Pre-flight Advisors Charter

Two advisors review the 3 devs' work (Dev A · SNP, Dev B · TDX, Dev C ·
StrongBox+TPM2) **before** any hardware day is scheduled. Both are read-only
review roles: they audit, they do not implement fixes. Findings go back to
the owning dev per PARTITION.md's file ownership.

---

## Advisor 1 · crypto-verifier-correctness

**Mandate:** audit the SNP/TDX/StrongBox verify logic against the actual
specs (AMD SEV-SNP ABI, Intel TDX DCAP quote format, Android Key Attestation
schema) — not against what the code's own comments claim about itself. Find
what would **wrongly pass or wrongly fail** on real evidence.

**Specific things to check, seeded from this review's reading of the current
code (verify independently, do not just confirm these):**

1. **Order of operations — authenticate before compare.** Confirm every path
   (`snp::verify_chain_and_fields`, `tdx::verify_collateral_anchored`,
   `mobile::verify_key_attestation_detailed`) authenticates the chain/
   signature FIRST and only THEN compares measurement/HOSTDATA/report_data/
   nonce fields. A reordering that compares first would let attacker-chosen
   bytes drive a rejection reason, or worse, short-circuit past a check.
2. **SNP chain trust boundary.** `snp.rs` delegates ARK self-signature +
   ARK→ASK→VCEK chaining to `virtee/sev`'s `Chain::verify()` — an external
   dependency, not code in this repo. Confirm that dependency's chain-order
   and algorithm assumptions (P-384 ECDSA for VCEK/report, RSA-PSS for
   ARK/ASK) actually match AMD's published SEV-SNP ABI for the pinned
   generation, and that `crypto_nossl` (pure-Rust) doesn't silently drop a
   check OpenSSL would have made.
3. **SNP revocation semantics.** `RevocationPolicy` has 4 variants
   (`Enforce`, `EnforceWithIssuer`, `RequireButMissing`, `SkipRevocationCheckDangerously`).
   Confirm `enforce_revocation` is only ever called AFTER
   `verify_chain_and_fields` returns `Genuine` (it is, per `verify_snp_report`'s
   `match` — confirm no other call site bypasses this), and that
   `RequireButMissing` really does fail closed rather than falling through to
   accept.
4. **SNP anti-rollback.** `MinTcb::satisfied_by` is component-wise `>=`
   across `bootloader/tee/snp/microcode`. Confirm this is the correct
   direction (floor, not ceiling) and that a `None` `min_reported_tcb`
   (waived) is clearly distinguishable in the RUNBOOK from "checked and
   passed" — a UI or log line that can't tell the difference is a downgrade
   risk in practice even if the code is correct.
5. **TDX QE-report binding.** Confirm
   `SHA-256(att_pub_key ‖ qe_auth) == qe_report.report_data[320..352]` is the
   correct Intel DCAP binding (not a locally-invented shortcut), and that the
   fixed byte offsets (`QE_REPORT_DATA_OFF = 320`, `TD_BODY_LEN = 584`, the
   `B_MRTD`/`B_MRCONFIGID`/`B_RTMR0`/`B_REPORTDATA` offsets) match
   `sgx_report2_body_t`/`sgx_ql_qe_report_info_t` exactly for DCAP **v4** —
   an off-by-one here would silently authenticate the wrong bytes.
6. **TDX certificate-expiry gap.** Confirm the finding already flagged in
   PARTITION.md for Dev B: `verify_collateral_anchored` checks CRL
   `nextUpdate` but not PCK chain cert `notBefore`/`notAfter`. Determine
   whether this is exploitable (an expired-but-not-yet-revoked leaf passing)
   and whether it's a must-fix before any hardware day or an acceptable
   documented gap.
7. **TDX chain order.** `leaf ← intermediate ← root` verified via
   `leaf.verify_signature(Some(inter.public_key()))` then
   `inter.verify_signature(Some(root.public_key()))`, with the root DER
   compared by byte-equality to the pinned anchor before its self-signature is
   even checked. Confirm the equality check happens on the RIGHT cert (the
   chain's actual terminal, `pems[pems.len()-1]`, not an attacker-insertable
   extra cert) and that a chain presenting extra/reordered certs can't confuse
   which one is "the root."
8. **Mobile chain direction + anchor.** `chain.windows(2)`: confirm
   `pair[0]` (closer to leaf) verified under `pair[1]`'s key is the correct
   leaf→...→root direction for a leaf-first input, and that the anchor check
   (`top_der == pinned` OR `top.verify_signature(pinned_root_pubkey)`) can't be
   satisfied by an attacker-supplied "root" that merely happens to be signed
   by something — confirm `top` really must be the chain's actual last
   element, not attacker-chosen.
9. **Mobile nonce/freshness + downgrade.** Confirm `kd.challenge !=
   expected.challenge` is checked (it is) and that `min_os_patch_level`/
   `min_security_level` being `Option`/comparable types can't be bypassed by
   an attestation that omits the field entirely — confirm `os_patch_level:
   None` with `min_os_patch_level: Some(_)` fails closed (it does, per
   `evaluate`'s `.ok_or(...)`) rather than treating "absent" as "any."
10. **Replay/downgrade across all three.** Confirm none of the three verifiers
    accept a report/quote/attestation whose freshness field was computed for
    a DIFFERENT nonce than the one just issued — i.e., a verifier bug that
    recomputes-and-compares against a STALE stored nonce instead of a
    fresh one per call. This is a caller-discipline risk more than a code
    bug; flag any call site in `seal_gate.rs`/`seal_verify.rs` that could
    reuse a nonce.

**Deliverable:** a findings list, each tagged `wrongly-passes` (a real forged/
downgraded/replayed report could reach `Genuine`) or `wrongly-fails` (a real
genuine report would be rejected), with the exact file:line and which dev
owns the fix.

---

## Advisor 2 · honesty + over-claim

**Mandate:** audit that nothing in the bucket-B deliverables, the crate docs,
or the fixture/test names claims Genuine/attested/measured-boot beyond what a
fixture or synthetic vector actually proves. Confirm the TDX empty-root and
SNP-fixture-only limits (as corrected — see RUNBOOK.md's "Correction to the
standing brief") are stated everywhere they're relevant, and that
`scripts/check-trust-labels.sh` stays `critical:0`.

**Specific things to check:**

1. **The stale-brief correction propagated correctly.** Confirm
   `RUNBOOK.md`, `PARTITION.md`, and `READINESS.md` all state the TWO-part
   TDX truth accurately: root DER is real, but (a) the default entry points
   are unconditionally closed regardless, and (b) the real path is UNAUDITED
   and never hardware-tested. A doc that says only "root is now pinned"
   without the closure caveat is an over-claim by omission.
2. **Module-doc honesty, spot-checked against the actual verdict logic.** For
   each of `snp.rs`, `tdx.rs`, `mobile.rs`: does the "What this proves / does
   NOT prove" doc comment match what `verify_*` actually returns on the
   tested paths? (E.g. `tdx.rs`'s header already says "this code has NEVER
   been run against a quote from TEE hardware we control" — confirm this
   sentence, or one just as explicit, survives any edits Dev B makes.)
3. **Test/fixture naming discipline.** Every test that exercises a synthetic
   or `rcgen`-built chain (SNP's `testdata/` Milan fixture partially excepted
   — it IS a real captured report+VCEK, just not one from hardware Postern
   launched) should be nameable as "vector-tested ≠ attested" in spirit. Flag
   any new test Dev A/B/C adds whose name or doc comment could be misread as
   a hardware claim (e.g. a TPM2 fixture test using `swtpm` must never be
   named/described in a way that implies real-hardware PCR extension).
4. **`check-trust-labels.sh` stays green.** Re-run it after every dev's
   changes land (`bash scripts/check-trust-labels.sh`); confirm `critical: 0`.
   Pay particular attention to CRITICAL 2 (attestation-grade word bleed onto
   non-attestable tiers — `pmos-overlay`, `apps/sloboda*`,
   `os/sloboda-compat.nix`) and CRITICAL 3 (Porog's "key-attested" claims
   must carry their "not a measured-boot workspace" qualifier within ±3
   lines) if Dev C's mobile/TPM2 docs touch anything Porog-adjacent.
5. **New docs don't invent a false "Genuine here."** Specifically re-read
   RUNBOOK.md's per-platform "Observable success signal" lines — confirm each
   one is phrased as what an operator with real hardware would see, never as
   something already observed in this bucket-B pass. Confirm no command in
   PARTITION.md's "hardware-day command" sections was actually executed
   against real hardware during bucket-B prep.
6. **StrongBox root-of-trust honesty.** Confirm `mobile.rs`'s framing —
   "attests the phone, not the workspace," rooted in Google + the OEM, a
   classical P-256 HSM that does not hold the PQ device key — is preserved
   verbatim or equivalently in Dev C's new docs, and that no doc upgrades a
   StrongBox pass into a claim about "Postern OS" or "measured-boot."
7. **TPM2 sequencing honesty.** Confirm any TPM2-related doc states plainly
   that `os_roothash` is currently a design-reference placeholder (not yet
   produced by a real `nix build .#attested-image`), and that this item is
   VM-gated before it is hardware-gated — not just hardware-gated as the
   original brief implied.

**Deliverable:** a pass/fail per document (RUNBOOK, PARTITION, each dev's new
files) plus the `check-trust-labels.sh` output, with any over-claim quoted
verbatim and the exact fix (usually: add the missing qualifier, don't remove
the claim).
