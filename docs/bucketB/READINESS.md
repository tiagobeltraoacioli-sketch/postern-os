# Bucket B — Readiness Snapshot

Scoring: **prep-ready-for-hardware** (code+config+docs complete; only a
physical hardware day is missing) · **partial** (real hardware-day-usable
progress exists, but a specific code/config/design gap remains that isn't
"just get the hardware") · **blocked-needs-hardware-only** (nothing further
is HOST-doable; waiting is correct) — with a fourth honest label,
**blocked-needs-non-hardware-work-first**, for items where hardware isn't
even the next gate.

| # | Item | Files | Score | Why |
|---|---|---|---|---|
| 1 | SEV-SNP live report fetch + gate/verify handshake | `snp.rs`, `gate.rs`, `binding.rs`, `HARDWARE-RUNBOOK.md`, `tests/snp_vectors.rs` | **prep-ready-for-hardware** | Full guest-side ioctl acquisition + client-side VCEK→ASK→ARK chain verify exist; offline-vector-tested against a real captured Milan report+VCEK (`testdata/`); fail-closed guards unit-tested off-hardware (non-Linux and non-TEE-Linux both covered); a complete, current HARDWARE-RUNBOOK.md with exact CLI flags, proof-bundle checklist, and 6 negative controls already exists. Nothing left but renting a real GCP N2D Milan instance and running it. |
| 2 | AMD-KDS CRL revocation enforcement | `snp.rs` (`check_kds_crl`, `RevocationPolicy`), `tests/snp_crl.rs` | **prep-ready-for-hardware** | Real X.509 CRL parse + ASK-signature check + `nextUpdate` freshness + serial-revocation lookup, tested against a synthetic AMD-style CRL. Revocation is mandatory-by-design (no silent skip). Only gap is operational: fetch a live CRL from `kdsintf.amd.com` at hardware time — not a code or config gap. |
| 3 | TDX quote verification against the real Intel root | `tdx.rs`, `tests/tdx_collateral.rs` | **partial** | The brief's "empty root CA" is stale — the root is now Intel's real, published DER, and a full DCAP chain verifier (PCK→processor-CA→root, QE binding, quote signature, CRL freshness/revocation, TCB floor) exists and is tested — but only against a synthetic anchor, never Intel's, and never against a real quote. Two concrete gaps beyond "get a TDX box": (a) the default/primary entry points (`verify_td_quote`, `verify_td_quote_bound`) are unconditionally closed and don't even call the real path — an API-clarity/wiring decision is needed so a hardware-day operator doesn't call the wrong function; (b) no PCK-chain certificate-expiry check (only CRL freshness is checked) — flagged for Advisor 1. No TDX-specific HARDWARE-RUNBOOK exists yet (SNP's explicitly excludes TDX). |
| 4 | StrongBox mobile Key Attestation | `mobile.rs` | **prep-ready-for-hardware**, with one open config item | Most complete of the three verifiers: full ASN.1 `KeyDescription` parser, chain-verify to a caller-pinned root, and — uniquely among the three — end-to-end tests over a REAL `rcgen`-built X.509 chain (not just hand-built DER), covering happy path, wrong root, and broken chain link. Open item: `MobileExpected::roots` needs Google's *current* attestation root(s) fetched and pinned before a hardware day (Google rotated the RKP root 2026-02-01, mandatory 2026-04-10) — a real but bounded, HOST-doable prep task, not a code gap. No CRL/revocation check exists for the Google chain; stated as a limitation, not silently missing. |
| 5 | TPM2 measured boot / `os_roothash` (Postern OS) | `os/attested.nix`, `os/ATTESTATION.md` (outside this crate) | **blocked-needs-non-hardware-work-first** | Two gates stacked: `os/attested.nix` is written but has never been built (`nix build .#attested-image` has not run) — that's a VM/Nix gate, not a hardware gate. `os_roothash` today is a "design-reference placeholder," and the measured-boot chain has never been exercised even once, on any tier. TPM2 hardware only becomes the blocking gate AFTER the image builds. Scheduling a hardware day for this before the VM-build gate closes would waste it. |
| 6 | Chiostro confidential-VM build/boot | `os/cloud.nix`, `enterprise/cloud/image/**` (outside this crate) | **blocked-needs-non-hardware-work-first**, adjacent to Bucket B | Same shape as #5: unbuilt/unbooted, needs a Nix/VM gate closed first. Not required as a prerequisite for the SNP/TDX *verifier* hardware days above (those only need a generic Linux confidential VM with the right guest driver, not Postern's own cloud image) — but IS required before the full "Postern Cloud" product can be demoed end to end on hardware. Out of this bucket's file ownership; flagged for sequencing awareness only. |
| 7 | Azure vTPM/paravisor `report_data` adapter | not yet written | **blocked-needs-non-hardware-work-first** | Explicitly out of scope in `HARDWARE-RUNBOOK.md` §0/§8: Azure surfaces the SNP report via a paravisor + vTPM instead of direct `/dev/sev-guest`, so the nonce‖pubkey binding must compose through a vTPM quote — new adapter code is needed before Azure hardware time would even exercise anything meaningful. Also needs an Azure account (external-cred gate, separate from Bucket B). |
| 8 | Trust-label guardrail | `scripts/check-trust-labels.sh` | **closed, not hardware-gated at all** | Currently `critical: 0` on this branch as verified during this review (3 BLOCKING checks: the trademark string, attestation-grade-word bleed onto non-attestable tiers, and Porog's key-attested qualifier-companion rule). Must be re-run after every Bucket-B doc/code change and must stay green — it is the standing guardrail this entire bucket's honesty claims depend on, not a one-time item to "complete." |

## Headline

Of the 4 crate-scoped verifiers, **3 are genuinely prep-ready or nearly so**
(SNP, its CRL enforcement, and StrongBox mobile) — real, tested, offline-
exercisable code with a clear hardware-day script and named placeholders that
are pure operational fetches (a CRL, a root cert list), not code gaps. **TDX
is the outlier**: its headline blocker changed since the brief was written
(root DER populated, not empty) but its practical status — *cannot produce
`Genuine` here* — did not, because a second, now-primary gate (the
unconditionally-closed default entry point) sits in front of the real,
still-unaudited chain verifier. TPM2 measured boot and the Chiostro CVM image
are the two items where hardware isn't even the next gate — both need a
Nix/VM build to close first, and scheduling hardware time for them now would
be premature. Nothing scored here claims or implies a `Genuine` verdict was
produced against real hardware; none was — this is entirely bucket-B
preparation, consistent with the hard honesty constraint.
