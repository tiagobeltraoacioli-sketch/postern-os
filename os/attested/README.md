<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# `os/attested/` — the real `os_roothash` produce + verify pipeline

**Status: SCAFFOLD / UNAUDITED. `os_roothash` is a PLACEHOLDER, not a verified
value, until the VM steps below actually run on a Linux + Nix host.** Everything
in this directory is written and statically checked on a macOS workstation that
has **no Nix, no systemd-repart, no QEMU, no TPM2**. Nothing here has produced a
roothash or measured a PCR. Do not read a green checkmark in code review as a
green checkmark in reality.

This directory closes the gap flagged as backlog item #4: `os/attested.nix`
builds a dm-verity erofs root + UKI, but the roothash it reports was a
**design-reference placeholder**. Here is the pipeline that (1) **produces** a
real roothash from the built image and (2) **verifies** that roothash binds
through `roothash=` → `attestation::read_os_roothash` → the reported
`Expected.os_roothash`.

## The claim, and what actually earns it

Measured boot is **the** attestation claim. It is not asserted by wiring — it is
earned by a boot chain that measures the roothash into hardware. There are two
distinct properties, and conflating them is the classic attestation lie:

| Property | What gives it | Where it is proven |
|---|---|---|
| **Tamper-evidence** | paired `root` + `root-verity` partitions (dm-verity): any modified rootfs block faults at read time | automatic once the image builds (VM) |
| **Attestation** (measured boot) | the roothash `R` sits on the UKI cmdline (`roothash=R`), and the UKI is measured into **TPM PCR 11** / covered by the SEV-SNP/TDX **launch measurement** | **hardware-gated** (real TPM2 / TEE) |

Tamper-evidence is free with the verity partitions. **Attestation is not** — it
requires `R` inside something measured, and a verifier comparing that measurement
to a precomputed reference. This directory builds the pipeline for both and is
scrupulous about which rung each step actually reaches.

## The chicken-and-egg (why it is a two-pass build)

`R` is the hash of the built rootfs, so it does not exist until *after* the image
is built — but to bind it into the measured UKI it must be on the cmdline
*before* the UKI is built. That is a **two-pass build**:

1. **Pass 1** — `nix build .#attested-image` builds the erofs rootfs + verity
   hash tree. systemd-repart emits `repart-output.json` in the result, and the
   `root-verity` partition object carries the real `"roothash"`. That hex string
   **is** `os_roothash`.
2. **Pass 2** — rebuild with `bloch.attested.osRoothash = R` set (module option
   added to `os/attested.nix`), which injects `roothash=R` onto the UKI cmdline.
   Now `R` is measured. `extract-roothash.sh --bind` drives both passes and
   asserts `R` is stable across them (verity is deterministic; if it changed,
   something is non-reproducible and neither value should be trusted).

> Discoverable-Partitions note: with `Verity=data/hash` + `VerityMatchKey`,
> systemd-repart also derives the two partition UUIDs *from* `R`, so systemd can
> auto-assemble verity at boot without `roothash=` on the cmdline. That gives
> **runtime tamper-evidence** but **not** measured-boot attestation — the UUIDs
> are not in PCR 11. Pass 2 is what makes it attestable. `verify-boot-binding.sh`
> accepts either binding for check A but is explicit about which one it found.

## Scripts

### `extract-roothash.sh` — PRODUCE (VM-gated)
Builds the image and reads the real roothash out of `repart-output.json`.
```
# on a Linux + Nix (flakes) host, from the repo root:
./os/attested/extract-roothash.sh -f . -a attested-image -o /tmp/roothash.txt
# add --bind to also run pass 2 (rebind R into the measured UKI cmdline):
./os/attested/extract-roothash.sh -f . -a attested-image --bind
```
On macOS it exits 3 ("no nix — nothing produced"): it **cannot** fabricate a
value. The bare 64-hex roothash is printed on stdout; diagnostics go to stderr.

### `verify-boot-binding.sh` — VERIFY (VM software chain + HW TPM2 rung)
Run **on the booted attested node**. Pass the roothash from `extract-roothash.sh`:
```
./os/attested/verify-boot-binding.sh -r <64-hex-roothash> -p 8645
```
It checks three bindings and labels each honestly:
- **A/cmdline** — running kernel cmdline carries `roothash=R` (or the active
  dm-verity target reports `R`). *Software chain — VM-provable.*
- **B/report** — the node's `getattestation` JSON-RPC reports `os_roothash == R`.
  *Software chain — VM-provable.* (RPC port default `8645`, per `os/bloch-node.nix`.)
- **C/PCR** — TPM2 PCR 11 is populated (a live measurement). **Hardware-gated**;
  comparing PCR 11 to the reference predicted for this exact UKI+roothash is
  marked `TODO-HW` — a populated PCR is *not* a measured-boot proof by itself.

On macOS it exits 3 ("no /proc/cmdline — nothing proven").

## Runbooks

### VM runbook (software chain — proves A + B, NOT measured boot)
On a Linux + Nix + QEMU box:
```
# 1. Produce + bind the real roothash
R=$(./os/attested/extract-roothash.sh -f . -a attested-image --bind)
echo "os_roothash = $R"        # ← pin this as Expected.os_roothash

# 2. Boot the attested image under QEMU (TCG is fine for the software chain)
#    then, INSIDE the guest, with the bloch node running:
./os/attested/verify-boot-binding.sh -r "$R" -p 8645
#    Expect: A/cmdline PASS, B/report PASS, C/PCR skip (no vTPM under plain TCG).
```
This confirms `getattestation` reports the true roothash. It does **not** prove
measured boot — QEMU/TCG has no real TPM.

### Hardware runbook (measured boot — the actual attestation claim)
On a machine with a real TPM2 (or a SEV-SNP/TDX confidential VM):
```
# Boot the pass-2 image (roothash= on the measured UKI cmdline). Then on the node:
./os/attested/verify-boot-binding.sh -r "$R" --pcr 11
#   A/cmdline PASS, B/report PASS, C/PCR PASS-as-live.
```
The remaining `TODO-HW` step — the part that cannot be faked in a VM — is
comparing PCR 11 (and, in a CVM, the launch measurement) to the **reference
value precomputed for this UKI+roothash** (systemd `--measure` output, or
`sev-snp-measure` for the CVM launch digest). Only that comparison turns "a
measurement exists" into "the audited image booted, measured, unaltered." Record
it in the hardware log (`untested-inventory.yml`), never as a CI exit code.

## Ownership + flake wiring

- **This directory + `os/attested.nix` are owned by OS Dev O5.** `os/cloud.nix`
  (Cloud/Seal) consumes `os/attested.nix` read-only and depends on it, so the
  measured-boot base is sequenced before the CVM profile.
- `flake.nix` is **O2's** — O5 does not edit it. O5 requests the optional
  `apps.x86_64-linux.attested-roothash` wrapper (see `O2-REQUEST.md`); until O2
  integrates it, `extract-roothash.sh --bind`'s inline `--expr` override is the
  self-contained fallback.

## Honesty (self-labelled, per the track discipline)
- **SCAFFOLD / UNAUDITED.** No roothash has been produced and no PCR measured on
  the dev host. `bloch.attested.osRoothash` defaults to `null` — the honest
  placeholder — and the module refuses a fabricated value.
- `os_roothash` **stays a placeholder** everywhere in the repo (SDK/companion
  fixtures, `os/ATTESTATION.md`, `flake.nix` comment) until a VM run of
  `extract-roothash.sh` fills it with a real value.
- A/B are the software chain (VM). Measured boot (C) is the claim that matters and
  it is **hardware-gated**; do not describe this pipeline as "attested" until the
  TPM2/TEE reference-compare rung is done and audited.
