# TPM2 measured-boot prep (Bucket B / Dev C) — HARDWARE-GATED, PREP ONLY

**Read this before touching anything under `tpm2/`.** Nothing in this
directory or `src/tpm2.rs` was run against a real TPM2 chip. Everything here
was produced against `swtpm` — a **software TPM emulator**
(<https://github.com/stefanberger/swtpm>) — which has **no hardware root of
trust**. A green `cargo test` in this crate is never evidence of a real
measured-boot chain. Every fixture file and test name below says
`swtpm` explicitly for this reason.

This is Platform 4 in `docs/bucketB/RUNBOOK.md`. Per that doc, TPM2
measured boot for Postern OS is **two gates stacked, not one**:

1. `os/attested.nix` (dm-verity erofs root, UKI, systemd-repart, TPM2
   measured boot) is written but has **never been built** — `nix build
   .#attested-image` has not run. That is a **Nix/VM build gate**, not a
   hardware gate. `os_roothash` today is a "design-reference placeholder"
   (`docs/gap/os-platform-gaps.md` #4), not a verified value.
2. Only AFTER that gate closes does proving the TPM2 PCR chain become
   **hardware-gated** (a real TPM2 chip, dTPM or fTPM).

Nothing in this bucket moves either gate forward — Bucket B is HOST-runnable
verifier-logic prep only (per `docs/bucketB/PARTITION.md`'s rails: no
hardware, no deploy). What follows is that prep, honestly scoped.

## What's here

- `../src/tpm2.rs` — pure-Rust PCR-extend / measured-boot-replay comparison
  logic (`pcr_extend_sha256`, `pcr_replay_sha256`, `verify_pcr_replay`). No
  TPM binary dependency; it is the TCG TPM2 Part 1 §19.3 PCR-extend algorithm
  (`PCR_new = SHA-256(PCR_old ‖ event_digest)`), which is silicon-independent
  — the same math a hardware TPM's SHA-256 PCR bank must satisfy.
- `fixtures/pcr16_swtpm_single_extend.txt`,
  `fixtures/pcr15_swtpm_three_event_replay.txt` — REAL captures from a
  genuine `swtpm` 0.10.1 process (installed via Homebrew, verified with
  `swtpm --version`). Consumed by `../tests/tpm2_pcr_vectors.rs`, in the
  default (no-feature-flag) build, the same "vector-tested against a real
  captured fixture" pattern `tests/snp_vectors.rs` uses for the real Milan
  report+VCEK.

## How the real `swtpm` fixtures were captured (exact recipe, reproducible)

`tpm2-tools` (the usual CLI for talking to a TPM) is **not packaged for
Homebrew on macOS** — confirmed: `brew search tpm2-tools` finds nothing;
building it from source (it needs `tpm2-tss` + a TCTI, both Linux-oriented)
was judged out of scope for this bucket's time budget, and out of keeping
with "prep only" — a rushed from-source build with no way to cross-check its
output against a known-good tool would risk shipping unverified glue, not
verified prep.

Instead, the fixtures were captured with a **raw TPM2 command-byte harness**
(a throwaway Python script, not part of this crate) speaking the TCG TPM2
wire format directly to `swtpm`'s data socket:

```sh
swtpm socket --tpm2 --tpmstate dir=<tmp> \
    --server type=tcp,port=32321 --ctrl type=tcp,port=32322 \
    --flags not-need-init,startup-clear
```

then, over a TCP connection to port 32321: `TPM2_PCR_Read` (command code
`0x0000017E`) and `TPM2_PCR_Extend` (`0x00000182`, using the empty-password
`TPM_RS_PW` session TPM2 requires for a PCR handle's authorization). PCRs 15
and 16 were used — both are TCG "debug"/static PCRs that reset to all-zero
and are freely re-extendable, so repeat captures never depend on prior state.
Each fixture records: the PCR's value before extending, the event digest(s)
extended, and the PCR's value after — as read back from swtpm itself, not
computed independently first. The Python harness then independently
predicted the expected final value with `hashlib.sha256(old + event)` and
asserted it matched swtpm's own read-back before writing the fixture file —
i.e., the "our math agrees with a real TPM" claim was checked twice: once at
capture time (Python vs. swtpm) and again in `tests/tpm2_pcr_vectors.rs`
(Rust vs. the captured fixture).

## Scoped OUT this bucket (named gaps, not silently missing)

- **`TPM2_Quote` (a TPM-signed attestation over PCR values + a nonce).** Not
  captured, not implemented. Producing one needs an attestation key created
  and loaded inside the TPM (`TPM2_CreatePrimary` → `TPM2_Create` →
  `TPM2_Load`) and marshalling `TPM2_Quote`'s request and its
  `TPM2B_ATTEST` + `TPMT_SIGNATURE` response — substantially more raw
  TPM2-protocol surface than PCR-extend/read, and with no `tpm2-tools`
  available on this host to cross-check a hand-rolled implementation against.
  Attempting it anyway risked shipping an unverified `TPMS_ATTEST` parser
  with nothing real to validate it against — worse than not shipping it.
  **This is the natural next step once a Linux host with `tpm2-tools` (or a
  from-source build) is available**, not a design decision against doing it.
- **Signature verification of a quote.** Follows from the above — no quote,
  no signature to check.
- **PCR bank other than SHA-256.** swtpm and real TPM2 chips also carry a
  SHA-1 bank (deprecated) and sometimes SHA-384; only SHA-256 was exercised,
  matching what `os/ATTESTATION.md`'s chain diagram implies for a modern UKI
  measurement.
- **The event-log format itself** (e.g. TCG `EFI_TCG2_EVENT` structures a
  real UEFI firmware would log). `pcr_replay_sha256` takes raw 32-byte event
  digests, not a parsed boot event log — parsing whatever `os/attested.nix`'s
  UKI actually produces is OS-track work (outside this crate's write scope,
  and only meaningful once that image builds).

## The PCR → `os_roothash` binding (design reference, per `os/ATTESTATION.md`)

`os/ATTESTATION.md` (this dev reads it, does not edit it — owned by the
OS/images track) diagrams the intended chain:

```
UKI + measured boot (kernel+initrd+cmdline, one signed PE)
        │  measured into TPM PCRs / covered by the CVM launch measurement
        ▼
SEV-SNP / TDX launch measurement  ───────────▶  AttestationReport {
   (or, on a bare-metal TPM2 host,                  measurement,   // boot/launch
    a PCR quote)                                    os_roothash,   // OS integrity
                                                     image_digest,  // L1
                                                     hostdata }     // policy binding
```

`os_roothash` is the dm-verity roothash of the immutable rootfs — a
TEE-independent integrity fact a bare-metal (non-CVM) node can also prove,
PROVIDED the roothash value itself was actually measured into a PCR during
boot (so a verifier reading the PCR back can trust it reflects what actually
booted, not merely what the node claims post-hoc). This crate's
`pcr_replay_sha256` is the exact primitive that binding needs on the verifier
side: given the claimed measured-boot event log (which would include an
event digest derived from `os_roothash`) and a real signed `TPM2_Quote`'s PCR
values, replay the log and compare against the quote — reject if the roothash
event wasn't actually measured or was measured with a different value than
claimed. **This module supplies that primitive. It does not implement the
binding itself** — that needs (a) the OS track's real event-log format from a
booted `os/attested.nix` image, and (b) this bucket's scoped-out
`TPM2_Quote`/signature-verification step.

## Operator steps to read back a REAL PCR quote (once `os/attested.nix` boots)

This dev writes this procedure; **building/booting the image is the OS
track's job**, out of this bucket's file ownership (per
`docs/bucketB/PARTITION.md`).

1. Confirm the prior gate closed: `nix build .#attested-image` succeeds and
   produces a real, reproducible `os_roothash` (not the current placeholder).
2. Boot the image on a TPM2-equipped host (dTPM or fTPM — NOT `swtpm`).
   Confirm the UKI was measured into the expected PCR(s) as
   `os/ATTESTATION.md`'s chain diagram describes.
3. With `tpm2-tools` (available on essentially any Linux distro, unlike this
   macOS dev host): create/load an attestation key, then
   `tpm2_quote --key-context ak.ctx --pcr-list sha256:<PCR list> --qualifying-data
   <fresh nonce>` to get a REAL signed `TPM2B_ATTEST` + signature.
4. Read the quoted PCR value(s) back (`tpm2_quote`'s own output, or
   `tpm2_pcrread`) and independently replay the claimed event log with this
   crate's `pcr_replay_sha256` — the two must match (this is
   `verify_pcr_replay`'s job, once wired to a real quote's PCR field).
5. Verify the quote's signature under the attestation key's certificate
   chain (a step this crate does not implement yet — see "Scoped OUT" above)
   before trusting step 4's comparison at all; an unverified quote's PCR
   values are just a claim.
6. Bind `os_roothash` into `AttestationReport` per the node-side
   `bloch::attestation` chain (`os/ATTESTATION.md`) and call
   `verify(&report, &expected, nonce)` — success signal `Verdict::Trusted`,
   per `docs/bucketB/PARTITION.md`'s hardware-day command for this platform.

No step above was run in this bucket. This is the plan, not a report — same
discipline as `docs/bucketB/RUNBOOK.md`'s framing for every other platform.
