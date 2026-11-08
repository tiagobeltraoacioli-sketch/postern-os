# Bucket B — Hardware-Day Runbook

Base: `roadmap/fleet2-integrate`, `crates/postern-seal-companion/src/{snp.rs,tdx.rs,mobile.rs,gate.rs,binding.rs}`.

**HARD CONSTRAINT: we have no TEE hardware today.** Nothing in this document
was run against real silicon. Every "success signal" below is what a human
operator with real hardware should observe — it is a plan, not a report.
Every artifact this PMO produces is labeled *hardware-gated, NOT verified on
real TEE here*, and `scripts/check-trust-labels.sh` must stay `critical:0`
(verified current: two BLOCKING checks — the trademark string and
attestation-grade-word bleed onto non-attestable tiers — plus a
qualifier-companion rule for Porog's "key-attested"; it passes today).

## Correction to the standing brief (read this first)

The brief states "`PINNED_INTEL_SGX_ROOT_CA_DER = &[]`" as a known truth.
**That is now stale.** As of `roadmap/fleet2-integrate`,
`crates/postern-seal-companion/src/tdx.rs` (inside `mod dcap`, feature
`tdx-verify`) has the root populated with Intel's genuine, published SGX Root
CA DER (self-signed, `CN=Intel SGX Root CA`, SHA-256 fingerprint
`44A0196B2B99F889B8E149E95B807A350E7424964399E885A7CBB8CCFAB674D3`, asserted
in `tests/tdx_collateral.rs`). A real PCK→processor-CA→root chain verifier
(x509-parser + raw P-256 ECDSA via `p256`, CRL freshness/revocation) exists
and is exercised in tests — but only against a **synthetic** anchor, never
Intel's. **The conclusion is unchanged and if anything stronger than the
brief implied**: TDX still cannot return `Genuine` here, for two independent,
stacked reasons —

1. the primitive `verify_td_quote` / `verify_td_quote_bound` (the functions a
   naive caller reaches for) call the *unconditional* stub `verify_collateral`,
   which returns `Err` no matter what — it does not even call into the real
   chain-verify code. This is a deliberate default-closed API split, not a bug,
   but it means "the pinned root now exists" is NOT sufficient for `Genuine`
   through the ordinary entry point.
2. the real path, `dcap::verify_td_quote_with_collateral` (feature
   `tdx-verify`), does chain to the genuine Intel root — but is UNAUDITED and
   has **never been run against a real TDX quote from hardware we control**.

State this correction in `docs/bucketB/READINESS.md` and repeat it to Dev B —
do not let "the root DER is populated" get mis-read as "TDX works now."

---

## Platform 1 — AMD SEV-SNP (primary TEE)

**Chip / machine:** 3rd-gen EPYC (Milan) confidential VM. **Validate on GCP
N2D first** — it exposes `/dev/sev-guest` directly to the guest kernel with no
paravisor, so `snp::request_bound_evidence` works unmodified. Azure
DCasv5/ECasv5 surfaces the report via a Microsoft **paravisor** + vTPM instead
— do **not** claim Azure end-to-end without a separate `report_data` adapter
(explicitly out of scope; tracked as its own item, see READINESS).

**Provisioning:** spin up a GCP N2D confidential VM (Milan), Linux guest
kernel with the `sev-guest` driver, VMPL 0.

**Ordered steps** (full detail in
`crates/postern-seal-companion/HARDWARE-RUNBOOK.md`, which already exists and
is current):

1. **Baseline off-hardware** — `cargo test -p postern-seal-companion --features sev-snp`
   on the dev host; confirm the non-TEE fail-closed tests pass
   (`non_linux_acquisition_fails_closed` / `linux_non_tee_host_fails_closed`).
   This proves the guard fires BEFORE any hardware claim is possible.
2. **Guest identity** — inside the guest, generate the WireGuard keypair from
   TEE randomness: `wg genkey | tee wg0.key | wg pubkey > wg0.pub`. Private
   key never leaves the guest.
3. **Fetch a live, channel-bound report** — either drive
   `postern-seal-gate --wg-pubkey wg0.pub --listen 0.0.0.0:16510` (add
   `--vcek vcek.der` if the hypervisor provisions no cert-table VCEK), or call
   `snp::request_bound_evidence(nonce, wg_pub, Some(0), None)` directly from a
   small in-guest harness.
4. **Determine the pinned expected values** — from the signed release
   manifest: `--generation milan`, `--measurement <96 hex M>` (precompute with
   `sev-snp-measure` for the exact OVMF/UKI/vCPU shape, or read once from a
   first trusted boot), `--host-data <64 hex P>` (only if the provider allows
   setting HOSTDATA), `--min-tcb bl,tee,snp,ucode` (read the platform's first
   reported TCB and floor at or below it), `--vmpl 0`.
5. **Verify from the client** —
   `postern-seal-verify --gate <guest-ip>:16510 --generation milan --measurement <M> --host-data <P> --min-tcb <floor> --vmpl 0 --crl <AMD-KDS CRL fetched out of band>`.
6. **Observable success signal:** exit 0, stdout prints `Genuine` and the
   guest WireGuard public key as *"the ONLY sound tunnel peer."* Anything else
   (`REJECTED — <reason>`, exit 1) names the exact failed check — chain,
   measurement, hostdata, report_data, tcb, vmpl, or (if `--crl` was passed)
   revocation.
7. **Capture the proof bundle** (7 artifacts, see HARDWARE-RUNBOOK.md §6) and
   **run the 6 negative controls** (§7: stale nonce, substituted pubkey, wrong
   generation, bit-flipped measurement, TCB floor violation, debug policy) —
   a `Genuine` next to failing controls is what makes the pass trustworthy.

**Exact config/placeholders a human must supply — nothing else is missing:**
- `--measurement` (M), `--host-data` (P), `--min-tcb` floor — all come from
  the signed release manifest / a first trusted boot; there is no code
  placeholder left in `snp.rs` for these (the struct fields are real and
  required).
- `--crl` — an AMD-KDS CRL fetched out of band per product line
  (`https://kdsintf.amd.com/vcek/v1/Milan/crl`). **Without it, revocation is
  not checked** — `postern-seal-verify` prints a warning if omitted. This is
  the one "config" gap that is genuinely still open (not code — an
  operational fetch step).
- Nothing needs pinning in code: the AMD ARK/ASK roots are already compiled
  in (`virtee/sev` builtins), selected by `AmdGeneration::{Milan,Genoa,Turin}`.

## Platform 2 — Intel TDX (secondary TEE)

**Chip / machine:** TDX-capable Xeon (4th/5th-gen Scalable, "Sapphire
Rapids"+) confidential VM/instance.

**Provisioning:** a TDX-enabled cloud instance (or on-prem Xeon host) with
`tdx_guest` kernel support, and a way to fetch Intel PCS/DCAP collateral
(TCB-info, QE-identity, CRLs) out of band.

**Ordered steps:**

1. Build `postern-seal-companion` with `--features tdx-verify` and run
   `cargo test -p postern-seal-companion --features tdx-verify` on the dev
   host first — confirms `well_formed_full_match_still_fails_closed` and the
   synthetic-anchor DCAP vectors are green, i.e. the crypto is correct against
   a fake root before ever pointing it at a real one.
2. On the TDX instance, obtain a real DCAP v4 TD quote (`tdx_guest` device /
   Intel's DCAP quote-generation service) bound to
   `binding::report_data(nonce, guest_pubkey)` in `report_data`.
3. Fetch real Intel PCS/DCAP collateral out of band: root-CA CRL, PCK CRL,
   current time, and an anti-rollback `TEE_TCB_SVN` floor from a first trusted
   boot — assembled into a `TdxCollateral`.
4. **Call the real entry point directly** —
   `dcap::verify_td_quote_with_collateral(quote, &expected, &collateral)` —
   **not** `verify_td_quote`/`verify_td_quote_bound`, which are permanently
   closed regardless of hardware (see correction above). This is the single
   most important operational note for whoever runs this: using the wrong
   function silently "fails closed" for a reason that has nothing to do with
   the hardware.
5. **Observable success signal:** `Verdict::Genuine` from
   `verify_td_quote_with_collateral`. Any `Verdict::Unverified`/`Mismatch`
   names the exact stage (parse, `PinnedRootUnset`, `RootNotAnchored`,
   `ChainInvalid`, `CrlInvalid`, `Revoked`, `QeBindingMismatch`,
   `QeReportSignature`, `QuoteSignature`, `TcbTooLow`, or a bound-field
   mismatch).

**Exact config/placeholders a human must supply:**
- **None left for the root anchor** — `PINNED_INTEL_SGX_ROOT_CA_DER` is
  already Intel's real, published root (verify the fingerprint above against
  Intel's published cert as a sanity check before trusting a hardware run).
- `TdxExpected{mrtd, mr_config_id, rtmr, report_data}` — the TD measurement
  values from the release manifest / a first trusted boot, same discipline as
  SNP's `measurement`/`host_data`.
- `TdxCollateral{root_ca_crl_der, pck_crl_der, now_unix, tcb_svn_floor}` — CRLs
  fetched from Intel PCS out of band; the crate does no network I/O.
- **A wiring decision, not a config value:** decide (and document) whether
  `verify_td_quote_bound` should be made feature-aware to call the real DCAP
  path when `tdx-verify` is compiled in, or whether the two-entry-point split
  stays permanent API. Flagged for Dev B in PARTITION.md.
- No HARDWARE-RUNBOOK.md exists yet for TDX (SNP's is explicitly scoped to
  SNP only, TDX "out of scope"). Dev B should write one, mirroring the SNP
  structure (baseline → guest identity is N/A here, quote fetch → collateral
  → verify → proof bundle → negative controls).

## Platform 3 — StrongBox mobile (Android Key Attestation)

**Device:** a real Android phone with a discrete StrongBox HSM (Pixel 3+,
recent Samsung Knox devices — Tier C per `docs/plan/porog-wave1-plan.md`).
This attests the **phone**, not a measured-boot workspace — an intentionally
different, weaker claim than SNP/TDX (rooted in Google + the OEM, classical
P-256 StrongBox key, not the PQ Falcon‖ML-DSA device key).

**Provisioning:** the Postern Container / Porog app installed on the device,
signed with the production signing key.

**Ordered steps:**

1. On the dev host, run
   `cargo test -p postern-seal-companion --features mobile-attest` — confirms
   both the hand-built-DER unit vectors AND the full `rcgen`-built real
   leaf←intermediate←root chain vectors (`full_path_genuine_through_real_chain`,
   `wrong_root_is_rejected_full_path`, `broken_chain_link_is_rejected_full_path`)
   are green. This is the most complete of the three verifiers today.
2. On the device, generate a StrongBox-backed key with Android's
   `KeyGenParameterSpec.Builder(...).setAttestationChallenge(nonce)`, requesting
   `StrongBoxSecurityLevel` explicitly.
3. Extract the returned certificate chain (leaf-first) via
   `KeyStore.getCertificateChain(alias)`.
4. Fetch Google's **current** attestation root certificate(s) — see
   placeholder note below — and build `MobileExpected`.
5. Call `mobile::verify_key_attestation_detailed(&chain_der, &expected)`.
6. **Observable success signal:** `Verdict::Genuine` (or, via `_detailed`, a
   `MobileAttestation{security_level: StrongBox, device_locked: true,
   verified_boot_state: Verified, ...}`). Any mismatch names the exact reason
   (nonce, security level, verified boot, device locked, patch level, app
   identity, trust anchor, chain signature).

**Exact config/placeholders a human must supply:**
- **`MobileExpected::roots`** — Google rotated its RKP attestation root on
  2026-02-01 (mandatory 2026-04-10 per the module docs). Fetch the **current**
  Google Hardware Attestation root cert(s) from Google's published attestation
  root list before the hardware day, and pin more than one across the rotation
  window. This is the single blocking config item — everything else in
  `MobileExpected` (challenge, `min_os_patch_level`, `expected_app`) is
  deployment policy the operator already controls.
- No CRL/revocation check exists for the mobile path (stated limitation, not
  a placeholder to fill — a design gap to track separately if StrongBox
  becomes a production trust anchor).

## Platform 4 — TPM2 measured boot (Postern OS, `os/attested.nix`)

**This item is two gates stacked, not one.** Per `docs/gap/os-platform-gaps.md`
item 4: `os/attested.nix` (dm-verity erofs root, UKI, systemd-repart, TPM2
measured boot) is **written but never built** — it needs a Linux+Nix+QEMU
host first (VM-gated), and only THEN does proving the TPM2 PCR measurement
chain become hardware-gated. Do not schedule a hardware day for this without
first confirming `nix build .#attested-image` succeeds and `os_roothash` is a
real, reproducible value rather than the current "design-reference
placeholder."

**Chip/machine:** any PC with a discrete or firmware TPM2 (dTPM/fTPM), for
proving PCR extension is real silicon behavior, not a software simulator.

**Ordered steps (once the VM-build gate is closed):**

1. `nix build .#attested-image`; record the resulting `os_roothash`.
2. Boot the image on the TPM2-equipped host; confirm the UKI is measured into
   the expected PCRs (kernel+initrd+cmdline as one signed PE, per
   `os/ATTESTATION.md`'s chain diagram).
3. Read back the PCR quote; bind `os_roothash` to `AttestationReport` per the
   node-side `bloch::attestation` chain documented in `os/ATTESTATION.md`.
4. **Observable success signal:** `verify(&report, &expected, nonce) ==
   Verdict::Trusted` where `expected.os_roothash` is the value from step 1.

**Placeholder to replace:** `os_roothash` is currently a "design-reference
placeholder, not a verified value" (`docs/gap/os-platform-gaps.md` #4). It can
only be replaced by actually running `nix build .#attested-image` and reading
the real output — there is no code constant to edit.

**HOST-doable prep, honestly scoped:** `swtpm` (TPM2 software emulator) +
`tpm2-tools` can exercise PCR-extend/quote *plumbing* on this dev host today.
That is legitimate bucket-B prep (tests the harness logic) but it is **not** a
substitute for real hardware — a software TPM has no hardware root of trust,
so a `swtpm` pass must never be reported as a hardware result.

## Out of scope for this hardware day (tracked, not scheduled)

- **Azure vTPM/paravisor `report_data` adapter** — needs new code (not just
  hardware) before Azure SEV-SNP can be claimed end to end; explicitly called
  out as out of scope in `HARDWARE-RUNBOOK.md` §0 and §8.
- **Full Chiostro CVM boot** (`os/cloud.nix`) — VM-gated (unbuilt) before it
  is hardware-gated; the SNP/TDX *verifier* hardware day above does not
  require this image, only a generic Linux confidential VM with the right
  guest driver. Building `os/cloud.nix` is a separate, larger item (adjacent
  bucket, likely Bucket A/Cloud-Seal track).
