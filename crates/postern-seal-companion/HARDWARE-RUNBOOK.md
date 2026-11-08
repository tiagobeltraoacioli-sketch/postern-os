<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
-->

# SEV-SNP live-attestation hardware runbook

**Status: reference-prototype / UNAUDITED. This is the procedure to move
`snp.rs` from "real code, offline-vector-tested" to a *live* report, and to
capture the proof.** As of this writing the SEV-SNP path is **verifiable TEE
code that has never been run on confidential-VM hardware Postern launched**
(`vector-tested ≠ attested`, roadmap gate F3-C3). Nothing here is a security
claim; nothing here is committed; no third-party audit exists. Where this doc
and the code disagree, the code wins.

This runbook is the hardware companion to
`docs/specs/POSTERN-CLOUD-CONFIDENTIAL.md` and the design in
`Postern-Cloud-Chiostro-Design.md` §1.2–§1.6. It exercises only the SNP path
(`crates/postern-seal-companion/src/snp.rs`). TDX (`tdx.rs`) is a fail-closed
stub and is out of scope. The `mobile` StrongBox provider is a different front
and is out of scope.

## What a passing run proves — and what it does not

A live `Genuine` verdict carrying **our** channel binding proves: *this exact
image booted as measured (`M`) under an admission policy that admits only it
(`P`), inside a genuine AMD SEV-SNP TEE whose firmware TCB is at or above our
floor, and the WireGuard key about to be tunneled to is the key attested from
inside that image — freshly, for the verifier's nonce.* It does **not** prove
availability, secrecy against a determined physical/side-channel adversary, or
revocation freshness. Two known gaps stand until closed out of band (a third,
certificate temporal validity, is now RESOLVED — see below):

- **Revocation freshness is opt-in via `--crl`.** The pinned ARK/ASK are AMD's
  published long-lived roots; a compromised-and-revoked VCEK still chains to them.
  `postern-seal-verify --crl <der>` closes this end-to-end: fetch the AMD-KDS CRL
  for the product line out of band (`https://kdsintf.amd.com/vcek/v1/Milan/crl`)
  and pass it — the verdict then also requires the CRL to be ASK-signed, fresh
  (`nextUpdate` not elapsed), and to not list the VCEK's serial. **Without
  `--crl` a since-revoked VCEK is NOT caught** (the tool prints a note saying so).
  The crate does no network I/O; refreshing the CRL is the operator's job.
- **Certificate temporal validity (`notBefore`/`notAfter`) — RESOLVED, now
  checked** on ARK, ASK, AND VCEK/VLEK. This USED to be an open gap:
  `verify_chain_and_fields` authenticated the signature chain only (the `sev`
  crate's `crypto_nossl` verifier it calls does not read X.509 validity
  windows), so a VCEK past its own expiry — or presented before its validity
  start — still chained and signed successfully unnoticed. That is now closed:
  every public verify entry (`verify_snp_report`,
  `verify_snp_report_without_revocation`, `verify_gate_evidence`,
  `verify_snp_report_with_crl`) takes a mandatory `now_unix` (seconds since the
  Unix epoch, the verifier's wall clock — threaded through the same way
  `RevocationPolicy`'s CRL-freshness clock is, never an implicit "skip"), and
  `verify_chain_and_fields` checks each cert's `notBefore`/`notAfter` window
  against it (via `x509-parser`, the same primitive the AMD-KDS CRL path uses)
  right after the certs parse and BEFORE the chain signature is verified. A cert
  outside its window is a named, fail-closed
  `SnpVerdict::Rejected("… validity — endorsement certificate is expired or not
  yet valid (notBefore/notAfter)")`. This is a DIFFERENT thing from revocation
  freshness (CRL `nextUpdate`, above): a fresh CRL says nothing about whether
  the certs themselves are still inside their own validity windows — both are
  required and both now run. Offline regression: `tests/snp_vectors.rs`
  (`expired_vcek_is_rejected`, `not_yet_valid_vcek_is_rejected`,
  `in_window_vcek_passes_the_temporal_check`, driving the real fixture VCEK's
  own 2023-04-03 .. 2030-04-03 dates) and `tests/snp_real_aws.rs`
  (`vlek_outside_its_validity_window_is_rejected`, the captured AWS VLEK's
  2026-03-09 .. 2027-03-09 window), with the Genuine cases still verifying at an
  in-window clock. This brings SNP to parity with `mobile.rs` (which already
  checked `now_unix`) and with TDX's PCK chain (see `tdx.rs` /
  `docs/bucketB/READINESS.md` item 3) — all three verifiers now enforce
  certificate temporal validity, not just CRL freshness.
- **Hosting is less private than self-hosting.** Chiostro narrows the provider's
  window (removes hypervisor/operators from the confidentiality+integrity TCB);
  it does not close it (availability, ciphertext access patterns, traffic shape,
  tenancy metadata stay with the provider). The on-device Postern editions
  remain the sovereignty ceiling. The coin is not involved and is not a security.

## The code paths this runbook drives

Guest side (added in `snp.rs`, guarded so a non-TEE host fails closed with a
named `ReportError`, never panics):

- `snp::sev_guest_device_present()` — runtime probe for `/dev/sev-guest`.
- `snp::request_bound_evidence(nonce, guest_pubkey, vmpl, static_vcek)` — the
  channel-binding wiring: computes `report_data = SHA-256(nonce ‖ guest_pubkey)`
  ([`binding`]), requests the **extended** report from `/dev/sev-guest`, pulls
  the VCEK from the hypervisor cert table (or uses `static_vcek`), and returns
  the `GateEvidence` a Seal-gate serves.
- `snp::request_ext_report` / `snp::request_raw_report` — the lower-level
  primitives, for callers that provision the VCEK separately.

Verifier side (already present): `snp::verify_gate_evidence` recomputes the
binding from the verifier's *own* nonce and the presented pubkey (the wire
`report_data` is never trusted) and runs the full VCEK → ASK → ARK chain +
field checks; `verify_snp_report` is the field-level core.

> The `postern-seal-gate` binary now drives `request_bound_evidence` directly —
> its old inline copy of the `/dev/sev-guest` ioctls is gone, so there is a
> single guest-side codepath (gate binary and the harness snippet below request
> the byte-identical report). The gate also probes `sev_guest_device_present()`
> at startup and fails closed with a named message off a confidential VM.

## 0 · Pick the host (GCP N2D first)

| Provider / shape | Report path | Notes |
|---|---|---|
| **GCP N2D (AMD Milan) confidential VM** | guest-driven `/dev/sev-guest` — the clean path, **no paravisor** | **Validate here first.** Publishes firmware measurements; `request_bound_evidence` works unmodified. |
| Azure DCasv5 / ECasv5 (Milan) | SNP report commonly surfaced via **vTPM**; `report_data` populated by Microsoft's **paravisor** | **Do not claim Azure end-to-end from this runbook.** Our nonce‖WG-pub binding must compose through a vTPM quote — a small adapter to add before Azure counts. Out of scope here. |

Everything below assumes GCP N2D, AMD Milan (`AmdGeneration::Milan`), a Linux
guest kernel with the `sev-guest` driver, VMPL 0.

## 1 · Confirm the guard fails closed OFF hardware (baseline)

Before touching a TEE, prove the fail-closed behavior on an ordinary host, so a
later `Genuine` cannot be a stub artifact.

```
# On the macOS/Linux dev host (no /dev/sev-guest):
cargo test -p postern-seal-companion --features sev-snp
# Expect (current count, re-verify after any local edit — this crate is not
# the only file this repo's bucket-B work touches, so the exact number drifts):
# 33 lib + 3 seal_verify-bin + 13 snp_crl + 12 snp_vectors = 61 tests green,
# including non_linux_acquisition_fails_closed (macOS) or
# linux_non_tee_host_fails_closed (ordinary Linux), and the debug-policy
# offline control (snp::tests::debug_bit_cannot_be_forged_post_hoc_in_a_real_report).
```

On an ordinary Linux box, also confirm by hand that the live path returns a
named error and does not panic:

```
# request_raw_report on a non-TEE Linux host → Err(DeviceUnavailable(...))
[ -e /dev/sev-guest ] && echo "this IS a snp guest" || echo "no device — expect fail-closed"
```

## 2 · Guest identity: the WireGuard key generated IN the guest

The channel binding endorses a key the host never sees. On first boot the guest
generates its WG keypair from TEE randomness and writes the public key where the
gate reads it:

```
umask 077
wg genkey | tee /persist/postern/wg0.key | wg pubkey > /persist/postern/wg0.pub
# The PRIVATE key never leaves the guest. Only wg0.pub feeds the binding.
```

## 3 · Fetch a live, channel-bound report

Option A — drive the existing gate + verifier over the wire (the §4.1 handshake):

```
# In the guest:
postern-seal-gate --wg-pubkey /persist/postern/wg0.pub --listen 0.0.0.0:16510
# If the hypervisor provisions no VCEK in the cert table, fetch it from AMD KDS
# at provision time and add:  --vcek /persist/postern/vcek.der
```

Option B — minimal in-guest harness against the library API (captures the raw
evidence for the proof bundle):

```rust
// bind a fresh nonce to wg0.pub, fetch the live extended report, print hex.
use postern_seal_companion::snp;
let nonce: [u8; 32] = /* 32 bytes from /dev/urandom */;
let wg_pub: Vec<u8> = /* 32 raw bytes decoded from wg0.pub */;
match snp::request_bound_evidence(&nonce, &wg_pub, Some(0), None) {
    Ok(ev) => {
        eprintln!("report    = {}", hex(&ev.report));
        eprintln!("vcek_der  = {}", hex(&ev.vcek_der));
        eprintln!("guest_pub = {}", hex(&ev.guest_pubkey));
        eprintln!("nonce     = {}", hex(&nonce));   // needed to recompute the binding
    }
    Err(e) => eprintln!("FAIL CLOSED (expected off TEE): {e}"),
}
```

`request_bound_evidence` is where the channel binding is wired: it feeds the
silicon `report_data = SHA-256(nonce ‖ wg_pub)`. A verifier that recomputes this
from a different nonce or a substituted pubkey rejects the report.

## 4 · Determine the pinned expected values (release manifest)

`verify_snp_report` compares against values from the signed release manifest
(`{D, R, M[shape], P}`, POSTERN-CLOUD.md §3/§7). For the run you need:

- **`--generation milan`** — selects the pinned AMD root the VCEK must chain to.
- **`--measurement <96 hex>`** (`M`) — the launch measurement for this image +
  provider firmware + VM shape. Precompute with `sev-snp-measure` for the exact
  OVMF/UKI/vCPU config, or read it once from a first trusted boot and record it
  in the manifest. *A verifier without a pinned `M` proves only "some SNP guest
  somewhere" — always pin it.*

  **How `sev-snp-measure`'s output maps into `SnpExpected::measurement`, per VM
  shape** (this is the one item `PARTITION.md` calls out as needing its own
  documentation — `snp.rs`'s doc comment on the `measurement` field carries the
  same content, kept in sync with this section):

  - `M` is the 48-byte SHA-384 digest AMD's SNP firmware computes over the
    *entire* launch sequence: the OVMF/firmware image, every
    `SNP_LAUNCH_UPDATE` page (kernel/initrd/cmdline for a direct-boot guest, or
    the UKI for a measured-UKI boot), and finally the vCPU count and model. It
    is **deterministic for one exact (firmware build, image, vCPU shape)
    tuple** and changes if any of those three change — so a fleet that ships
    two VM shapes (say, a 2-vCPU and an 8-vCPU tier) needs **two** separately
    pinned `M` values, one `SnpExpected` per shape, not one shared value.
  - Invocation shape (adapt paths/counts to your exact release):
    ```
    sev-snp-measure --mode snp --vcpus <N> --vcpu-type EPYC-Milan \
        --ovmf <path/to/OVMF.fd> \
        --kernel <path/to/vmlinuz> --initrd <path/to/initrd> \
        --append '<exact kernel cmdline>'
    # (or --guest-kernel / a single --uki flag if the pipeline is a measured
    # UKI boot instead of split kernel+initrd+cmdline — check the tool's
    # current --help for your `sev-snp-measure` version, since UKI-mode flags
    # have moved between releases)
    ```
    `sev-snp-measure` prints the 48-byte digest as a single 96-hex-character
    line on stdout. That string is exactly what `--measurement` /
    `SnpExpected::measurement` wants — **no reordering, no re-encoding**: parse
    it as 48 big-endian bytes and it drops straight into the struct field.
  - Run this in CI immediately after the image build, for every shipped VM
    shape, and commit the resulting `M` values into the signed release
    manifest alongside the shape identifier they belong to — `M` pinned after
    the fact (post-launch, by hand) is weaker provenance than `M` produced by
    the same pipeline that built the image.
  - Cross-check option: launch the exact release image once under your own
    physical control, request one report, and confirm `report.measurement`
    equals the CI-computed `M` for that shape *before* trusting either as the
    manifest value — a mismatch means either the launch inputs drifted from
    what CI measured, or the vCPU shape at launch differs from what was
    requested.
- **`--host-data <64 hex>`** (`P`) — the image-admission policy hash pinned into
  HOSTDATA at launch, **if** the provider lets you set HOSTDATA. If it does not,
  the policy must be measured into the boot chain and this check is consciously
  waived and documented per deployment.
- **`--min-tcb bl,tee,snp,ucode`** — the anti-rollback floor. Read the running
  platform's reported TCB from a first report, then set the floor at or below it
  (never above what genuine current firmware reports, or you reject good hosts;
  never so low that rolled-back firmware passes).
- **`--vmpl 0`** — the gate runs in the guest proper.

## 5 · Verify from the client (the honest gate)

```
postern-seal-verify --gate <guest-ip>:16510 --generation milan \
    --measurement <96 hex M> \
    --host-data  <64 hex P>            # omit only if HOSTDATA is unsettable \
    --min-tcb 3,0,8,115                # this host's floor, from step 4 \
    --vmpl 0 \
    --crl /persist/postern/milan-vcek.crl   # AMD-KDS CRL, fetched out of band \
                                            # (omit ⇒ no revocation check; the
                                            #  tool prints a warning if omitted)
```

- **Genuine** → exit 0; prints the guest WG public key as *"the ONLY sound
  tunnel peer"*. Only now open WireGuard, and only to that key.
- **REJECTED — <reason>** → exit 1, hard stop. The reason names the exact failed
  check (chain, measurement, hostdata, report_data, tcb, vmpl). Do **not**
  connect.

The verifier recomputes `report_data` from its *own* fresh nonce and the pubkey
the gate presented — the wire `report_data` is never trusted — so a MITM
relaying a valid quote from some other real CVM fails the binding recompute.

## 6 · Capture the proof bundle

Store these together (they let anyone re-run `verify_snp_report` offline and get
the same `Genuine`, and they document the environment):

1. `report.hex` — the raw live report bytes (from step 3).
2. `vcek.der` — the VCEK that signed it (cert-table or KDS).
3. `wg0.pub` and the **nonce** used — needed to recompute the binding.
4. `verify.stdout` — the full `postern-seal-verify` output (verdict + endorsed key).
5. `manifest.json` — `{git commit, D, R, M[shape], P, min-tcb, tool versions}`.
6. Environment: `uname -a`, kernel `sev-guest` presence, `dmesg | grep -i sev`,
   the reported TCB, OVMF/firmware build, provider + region + machine shape,
   and the `sev-snp-measure` invocation that produced `M`.
7. `sha256sum` of items 1–2 and 5, recorded in the manifest.

Then confirm reproducibility of the *check* (not the silicon signature): drop
`report.hex` + `vcek.der` into a `tests/snp_vectors.rs`-style offline case with
the manifest's expected values and confirm it re-verifies `Genuine` off-host.
(The offline fixture cannot mint *our* binding — that is exactly why the live
run is required; this only proves the captured evidence re-checks.)

## 7 · Negative controls to record alongside the pass

A `Genuine` is only trustworthy next to failing controls proving the checks bite
on real hardware:

- **Stale nonce / relayed report** → `report_data` mismatch (re-run verify with a
  fresh nonce against a captured old report).
- **Substituted pubkey (MITM)** → `report_data` mismatch.
- **Wrong `--generation`** (genoa/turin) → chain failure.
- **`--measurement` off by one bit** → measurement mismatch.
- **`--min-tcb` one component above reported** → tcb-floor rejection.
- **Debuggable guest policy** → policy rejection (do not ship, but demonstrate).

All six of the above already exist as OFFLINE fixture tests against the real
captured Milan report — `tests/snp_vectors.rs` (stale nonce/relay, substituted
pubkey, wrong generation, measurement, TCB floor) and `snp.rs`'s own
`#[cfg(test)]` module (debug policy: `debug_bit_cannot_be_forged_post_hoc_in_a_real_report`,
which self-verifies its byte-offset assumption before asserting the fail-closed
result — see that test's comment for why a debug=1 *signed* report can't be
minted offline at all, only tampered-then-rejected). Re-running them here on
real hardware is what turns "the logic rejects a synthetic tamper" into "the
logic rejects a tamper against a real chip's silicon-signed output" — a
strictly stronger statement, not a different one; a `Genuine` next to failing
copies of these same controls, run live, is the actual proof.

## 8 · Do NOT

- Do **not** weaken any check in `snp.rs` to make a stubborn host pass. A
  verifier that cannot check the chain must never say `Genuine`.
- Do **not** claim Azure end-to-end until the vTPM/paravisor `report_data`
  adapter lands and is validated.
- Do **not** market any of this as attested/audited/confidential until C3 passes
  on hardware **and** an external audit lands. Until then: *"RUNBOOK — software
  implemented and vector-tested; NOT validated on confidential hardware."*
- Do **not** `git commit` this work.
