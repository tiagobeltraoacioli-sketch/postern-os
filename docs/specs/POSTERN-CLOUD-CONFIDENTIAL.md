# Postern Cloud — confidential-VM RUNBOOK (SEV-SNP primary, TDX secondary)

**Product (Postern Labs). Status: RUNBOOK — software implemented and
vector-tested; NOT yet validated on confidential hardware.** This is the
step-by-step to take the implemented pieces (the `sev-snp` verifier, the Seal
gate, the channel binding, the `os/cloud.nix` guest profile) onto a real
SEV-SNP VM on **Azure** (primary) or **Google Cloud**, fetch a real quote, and
verify the full L1 → OS → L3 chain end to end.

> Extends `docs/specs/POSTERN-CLOUD.md` (design) and `os/ATTESTATION.md` (the
> Seal chain). Honesty discipline applies: nothing below the "needs hardware"
> line has been executed — this repo's dev host has no Nix, no cloud account,
> and no TEE. What HAS been executed is stated precisely in §0.

---

## 0 · Honest status ledger

### Implemented + tested NOW (offline, this repo, `cargo test`)

| Piece | Where | Evidence |
|---|---|---|
| SEV-SNP report verification: parse → VCEK→ASK→ARK chain to the **pinned AMD root** (virtee/sev builtins, compiled in — never taken from the wire) → report signature → measurement / HOSTDATA / report_data / TCB-floor / VMPL / debug-policy checks, fail-closed named verdicts | `crates/postern-seal-companion/src/snp.rs` (feature `sev-snp`) | 12 vector tests in `tests/snp_vectors.rs` against a REAL Milan report + VCEK (virtee/sev Apache-2.0 fixtures, vendored in `testdata/`): genuine → `Genuine`; tampered report body/signature, tampered VCEK, wrong AMD root generation, measurement/hostdata/report_data mismatch, stale TCB, wrong VMPL → all `Rejected` with the named reason |
| Channel binding `report_data = SHA-256(nonce ‖ guest_pub) ‖ 0×32` | `src/binding.rs` (default build) | known-answer vector + replay/MITM-substitution negative tests |
| Seal-gate wire format (challenge/evidence codec, size-capped, hostile-peer posture) | `src/gate.rs` (default build) | roundtrip + truncation/oversize/trailing-bytes rejection tests |
| Gate endpoint + verifier CLI | `src/bin/seal_gate.rs`, `src/bin/seal_verify.rs` (feature `sev-snp`) | compile on macOS/Linux; the ioctl path is `cfg(linux)` and **not executed anywhere yet** |
| TDX secondary | `src/tdx.rs` | honest fail-closed stub — never returns Genuine; required steps documented in the module |
| Supply chain | `cargo deny check` | licenses/bans/sources PASS (sev is Apache-2.0; pure-Rust `crypto_nossl` stack). Advisories: only the 3 pre-existing tracked IDs (2× hickory-proto via `bloch`, rsa Marvin via arti — `sev` adds a verify-only path to the same rsa ID, no new advisory) |

### Needs a NIX HOST (no hardware, no cloud account)

- `nix build .#cloud-image` — build the erofs + dm-verity + UKI guest image
  from `os/cloud.nix` (+ `os/attested.nix`); record digest `D`, roothash `R`.
- `nix build .#seal-gate` — `os/seal-gate.nix`, the gate + verifier package
  (pin the git-dep `outputHashes` on first build).
- Precompute launch measurements `M` per VM shape (`sev-snp-measure`-class
  tooling, virtee ecosystem, Apache-2.0).

### Needs REAL HARDWARE / a CLOUD ACCOUNT (nothing here is claimed until run)

- A quote produced by silicon we launched: gate ↔ `/dev/sev-guest` ioctl path,
  VCEK delivery via the extended report's cert table, end-to-end
  `Genuine`-with-our-binding.
- Per-provider items the design flags as unverified (POSTERN-CLOUD.md §5/§9):
  whose firmware is in `M`, whether HOSTDATA is settable at launch, how the
  guest fetches the raw report (Azure's paravisor mediation vs GCP's direct
  `/dev/sev-guest` — see §3.4).
- TDX entirely (secondary; stub refuses all quotes today).
- External audit of the chain before any user-facing trust claim.

---

## 1 · What you need

- A **Linux + Nix** build host (the image and gate package build there;
  reproducibility is the point — build twice, diff `D` and `R`).
- An **Azure** subscription (primary path, §3) or **GCP** project (§4).
- This repo. Verifier runs anywhere:
  `cargo build -p postern-seal-companion --features sev-snp --bins`
- **Fly.io is NOT an option.** Fly (the node's current `fly.toml` deploy
  target) does not offer confidential VMs — no SEV-SNP, no TDX, no guest
  attestation. The existing Fly deployment remains an ordinary container for
  the testnet node; Postern Cloud requires one of the CVM providers below.

## 2 · Build + identify the image (Nix host)

```sh
# 1. Build the confidential guest image (os/cloud.nix profile).
nix build .#cloud-image
# 2. L1 digest D + verity roothash R (printed by the repart build):
D=$(sha256sum result/postern-cloud.raw | cut -d' ' -f1)
R=<roothash= value from the build log / UKI cmdline>
# 3. Reference launch measurement M per provider firmware + VM shape:
#    sev-snp-measure --mode snp --ovmf <provider OVMF> --kernel ... --vcpus N
# 4. Policy hash P: hash of the admission policy that admits ONLY D.
# 5. Sign + publish the release manifest {git commit, D, R, M[shape], P}.
```

Repart/verity/UKI options drift across nixpkgs — expect to iterate here
(`os/attested.nix` note). None of this was run in this repo (no Nix).

## 3 · Azure (primary): DCasv5 / ECasv5 SEV-SNP

TDX note: Azure's **DCesv5/DCesv6 / ECesv5/ECesv6** families are the Intel TDX
equivalents — same flow, but our TDX verifier is a fail-closed stub, so today
an Azure TDX seat cannot verify as Genuine. Use the SEV-SNP families.

### 3.1 Upload the image as a confidential-VM gallery image

```sh
az group create -n postern-cloud -l <region-with-DCasv5>
# Convert the raw image to a fixed VHD, upload, then:
az sig create -g postern-cloud --gallery-name posternGallery
az sig image-definition create -g postern-cloud --gallery-name posternGallery \
  --gallery-image-definition postern-cloud --os-type Linux \
  --publisher PosternLabs --offer postern-cloud --sku attested \
  --hyper-v-generation V2 \
  --features SecurityType=ConfidentialVmSupported
az sig image-version create ... --os-vhd-uri <uploaded VHD>
```

### 3.2 Launch as a confidential VM

```sh
az vm create -g postern-cloud -n postern-seat-1 \
  --image <gallery image id> \
  --size Standard_DC4as_v5 \
  --security-type ConfidentialVM \
  --os-disk-security-encryption-type VMGuestStateOnly \
  --enable-vtpm true \
  --public-ip-sku Standard
# Inject the client's WireGuard pubkey allowlist via instance metadata/custom
# data — UNTRUSTED input by design (§4.1 of the spec): a tampered allowlist
# can only lock the rightful client out, never let the host in.
```

### 3.3 Fetch and verify a real quote

On the guest, `postern-seal-gate` (wired by `os/cloud.nix`) listens on 16510.
From your client:

```sh
cargo run -p postern-seal-companion --features sev-snp --bin postern-seal-verify -- \
  --gate <vm-ip>:16510 \
  --generation milan \
  --measurement <M for DC4as_v5 from your manifest> \
  --host-data  <P, if HOSTDATA was settable at launch> \
  --min-tcb    <bl,tee,snp,ucode floor from AMD's current Milan TCB> \
  --vmpl 0
# Exit 0 + "VERDICT: Genuine" prints the guest WG pubkey — the only key it is
# sound to `wg set ... peer <that key>` to. Any other verdict is a hard stop.
```

### 3.4 Azure caveat — the paravisor, stated honestly

Azure CVMs run a Microsoft paravisor between the silicon and your guest. On
these SKUs the SNP report is commonly surfaced through the **vTPM**
(NV index `0x01400001`), and `report_data` is populated by the *paravisor*
(binding the vTPM AK), not by an arbitrary guest-chosen value — in that mode
our nonce‖WG-pub binding must compose through a vTPM quote (TPM nonce +
AK certified by the SNP report) instead of raw `report_data`, and the launch
measurement `M` endorses Microsoft's firmware+paravisor blob (§1.3.3 trust
item). Whether a given SKU/kernel also exposes a guest-usable
`/dev/sev-guest` path changes over time. **This is exactly the per-provider
integration item POSTERN-CLOUD.md §5 flags: plan a hardware session to
determine which path the SKU gives you, and if it is vTPM-only, add the small
vTPM adapter to the gate before claiming Azure end-to-end.** The verifier
core (chain, fields, binding recompute) is unchanged either way.

### 3.5 Rough cost (verify current pricing before committing)

Order-of-magnitude, pay-as-you-go, region-dependent: **Standard_DC4as_v5
(4 vCPU/16 GiB) ≈ $0.20/hr ≈ $140–150/mo**; DC2as_v5 about half that. A full
validation session (upload, a few launches, a day of testing) is on the order
of **$5–20** plus a few GB of storage/egress. TDX (DCesv5) prices similarly.

## 4 · Google Cloud: Confidential VM (SEV-SNP)

GCP's N2D shapes expose SEV-SNP with the **guest-driven** report path — the
sev-guest driver with caller-chosen `report_data` — which is the cleanest
first validation of the gate exactly as written (no paravisor adapter):

```sh
gcloud compute images import postern-cloud --source-file postern-cloud.vhd ...
gcloud compute instances create postern-seat-1 \
  --machine-type n2d-standard-4 \
  --min-cpu-platform "AMD Milan" \
  --confidential-compute-type=SEV_SNP \
  --maintenance-policy=TERMINATE \
  --image postern-cloud --zone <zone with SEV-SNP N2D>
```

Then §3.3 verbatim (`--generation milan`). Notes: GCP publishes its guest
firmware measurements for confidential VMs — fold the published OVMF value
into `M`. HOSTDATA setability at launch is a per-provider item to confirm in
the same session; where unsettable, the policy binding falls back to the
UKI-cmdline-measured path (covered by `M`) and `--host-data` is omitted —
document that waiver in the deployment record. Cost: n2d-standard-4 with
confidential compute ≈ **$0.15–0.25/hr** (region-dependent; verify).

## 5 · End-to-end chain checklist (the claim being validated)

```
[Nix host]   D, R reproducible: two independent builds agree           (L1)
[launch]     policy P (admits only D) pinned into HOSTDATA             (L1→L3 bind)
[boot]       dm-verity roothash R on the UKI cmdline; UKI in M         (OS)
[gate]       report_data = SHA-256(nonce ‖ WG_guest_pub)               (channel bind)
[verifier]   postern-seal-verify: chain→AMD root ✓, M ✓, P ✓,
             binding ✓, TCB ≥ floor ✓, VMPL ✓, no-debug ✓  ⇒ Genuine
[client]     WireGuard ONLY to the endorsed pubkey; desktop inside     (§4.1 step 4–5)
```

Each ✓ above is already a tested reject-on-mismatch in `tests/snp_vectors.rs`;
what hardware adds is the *positive* end of the chain — a quote whose binding
is OURS, produced by silicon we launched, admitted by a policy we pinned.

## 6 · Failure modes you should see (fail-closed by construction)

- Gate on a non-SNP host: `postern-seal-gate` exits/refuses (`/dev/sev-guest`
  absent) — it never fabricates evidence.
- Verifier against anything else: `VERDICT: REJECTED — <named reason>`,
  exit 1. The reasons are the same strings the vector tests pin.
- No `--measurement`: the CLI refuses to run — a CVM verifier without a
  pinned measurement proves only "some SNP guest somewhere".
