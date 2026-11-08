# Postern Cloud edition — deployment architecture (SEV-SNP confidential VM)

**Role: designer/architect. Status: grounded in the repo's real code, verified 2026-07-10.**
This document is the concrete deployment design that ties the *built* verifier
(`crates/postern-seal-companion`, feature `sev-snp` — 23 unit + 12 SNP vector
tests pass against a real AMD Milan report fixture, confirmed by `cargo test`
this session) to the *unbuilt* deliverables (the deployable image, the launch/
provisioning, and the customer flow). It does not restate the design spec
(`docs/specs/POSTERN-CLOUD.md`) or the runbook
(`docs/specs/POSTERN-CLOUD-CONFIDENTIAL.md`); it makes the deployment
architecture explicit and names, precisely, the gap between built and missing.

Everything below the "AMD root of trust" is real code with file/line anchors.
Everything in the "MISSING" sections is honestly flagged as not-yet-built.

---

## 0 · One-paragraph statement of the edition

A customer runs a *headless Postern workstation* on a SEV-SNP confidential VM at
a cloud provider. The VM boots a reproducible, dm-verity-sealed image
(`.#cloud-image`, layered on `.#attested-image`). Before the customer's client
opens a session, it runs `postern-seal-verify` against the VM's Seal gate: the
gate returns a hardware-signed SEV-SNP attestation report, the verifier chains
it VCEK→ASK→ARK to AMD's pinned root, checks the launch measurement `M`, the
image-admission policy hash `P` (HOSTDATA), the reported-TCB floor, VMPL and
debug policy, and — the load-bearing addition — recomputes the channel binding
`report_data = SHA-256(nonce ‖ WG_guest_pub)` to prove the WireGuard key it is
about to tunnel to is the key the *silicon* endorsed from *inside the audited
image*. Only on `Genuine` does the WireGuard tunnel open; the desktop lives
entirely inside it. The provider's operators and hypervisor are removed from
the confidentiality/integrity trust base for the running guest; the price is
trusting AMD's TEE + CA infrastructure, and side channels / availability /
traffic metadata stay with the provider.

---

## 1 · What is BUILT (the trust engine), with code anchors

The verifier is not a sketch. It is the shipped, tested core of the edition.

### 1.1 The verification chain — `src/snp.rs`

`verify_snp_report(report_bytes, vcek_der, expected)` (`snp.rs:137`) runs a
strict, fail-closed, **authenticate-before-compare** sequence:

1. Parse the report (`AttestationReport::from_bytes`, virtee/sev). Malformed →
   `Rejected("report parse …")`.
2. Load the *pinned* AMD root for the expected generation — `pinned_ca()`
   (`snp.rs:111`) takes ARK/ASK from `sev::certs::snp::builtin::{milan,genoa,
   turin}`, i.e. **compiled-in AMD certificates, never read from the wire**.
3. Parse the presented VCEK (untrusted).
4. Verify the full chain `ARK self-sig → ARK→ASK → ASK→VCEK` via
   `Chain::verify()` (`snp.rs:154`). Failure → `Rejected("vcek chain …")`.
5. Verify the **VCEK signed this exact report body** — `(&chain, &report)
   .verify()` (`snp.rs:160`). Failure → `Rejected("report signature …")`.

Only after the report is authenticated silicon output does it compare fields,
each with a named reject reason (`snp.rs:166-200`):

| Check | Field | Reject reason |
|---|---|---|
| Debug policy off | `report.policy.debug_allowed()` | `guest policy — debug access is enabled` |
| VMPL (if pinned) | `report.vmpl` | `vmpl — … unexpected privilege level` |
| Launch measurement `M` | `report.measurement` (48 B) | `measurement — not the expected genuine image/boot chain` |
| HOSTDATA policy `P` (if pinned) | `report.host_data` (32 B) | `hostdata — launch policy binding does not match the audited image` |
| Channel binding | `report.report_data` (64 B) | `report_data — nonce/channel binding mismatch (stale, replayed, or relayed report)` |
| TCB anti-rollback floor | `report.reported_tcb` component-wise | `reported tcb — platform firmware below the accepted minimum` |

`SnpExpected` (`snp.rs:77`) is the reference-value bundle: `generation`,
`measurement: [u8;48]` (always required), `host_data: Option<[u8;32]>`
(`None` = provider can't set HOSTDATA, consciously waived), `report_data:
[u8;64]`, `min_reported_tcb: Option<MinTcb>`, `vmpl: Option<u32>`.

### 1.2 The channel binding — `src/binding.rs` (default build, TEE-independent)

`report_data(nonce, guest_pubkey) = SHA-256(nonce ‖ guest_pubkey) ‖ 0x00×32`
(`binding.rs:39`). Verified by a known-answer vector plus replay/MITM-splice
negative tests (`binding.rs:68-107`). `verify_gate_evidence()` (`snp.rs:213`)
**overwrites** `expected.report_data` with the binding recomputed from the
verifier's *own* nonce and the pubkey the gate presented — the caller supplies
measurement/hostdata/TCB policy, never the binding itself. This is what makes a
MITM who relays a genuine quote from a real CVM unable to terminate the tunnel:
the endorsed key is not his.

### 1.3 The wire format — `src/gate.rs` (default build)

`PSG1 ‖ nonce(32)` challenge; `PSE1 ‖ len‖report ‖ len‖vcek ‖ len‖pubkey`
evidence. Hostile-peer posture: strict magics, hard per-field size caps
(`MAX_REPORT_LEN=16K`, `MAX_CERT_LEN=8K`, `MAX_PUBKEY_LEN=1K`), cap-checked
**before** any allocation, no trailing bytes tolerated. Roundtrip + truncation/
oversize/trailing tests (`gate.rs:164-209`).

### 1.4 The two binaries — `src/bin/seal_gate.rs`, `src/bin/seal_verify.rs`

- **`postern-seal-gate`** (guest side): the ONLY pre-attestation listener. Per
  connection it reads a fixed-size challenge, computes the binding, requests the
  **extended** report via `Firmware::open()` → `get_ext_report(None,
  Some(report_data), Some(0))` from `/dev/sev-guest` at VMPL 0
  (`seal_gate.rs:169`), pulls the VCEK from the hypervisor-provisioned cert
  table (or a `--vcek` file if the provider doesn't provision one —
  `seal_gate.rs:173`), and returns the evidence bundle. Holds no secrets. On
  non-Linux it **fails closed** — `run()` prints an honest refusal and exits 1
  (`seal_gate.rs:50`); the ioctl path is `#[cfg(target_os = "linux")]` and, per
  its own header, **has never executed on hardware**.
- **`postern-seal-verify`** (client side): `--gate host:port --generation
  milan|genoa|turin --measurement <96 hex> [--host-data <64 hex>] [--min-tcb
  bl,tee,snp,ucode] [--vmpl N]`. Generates a fresh `/dev/urandom` nonce, does
  the challenge→evidence exchange, calls `verify_gate_evidence`. On `Genuine`
  it prints the guest WG pubkey — **the only key it is sound to
  `wg set … peer`**. Any other verdict: `exit 1`, hard stop. It **refuses to
  run without `--measurement`** (`seal_verify.rs:59`) — a CVM verifier without a
  pinned measurement proves only "some SNP guest somewhere".

### 1.5 What is honestly NOT built in the trust engine

- **TDX** (`src/tdx.rs`): a fail-closed stub. `verify_td_quote` **always**
  returns `Unverified` (`tdx.rs:36`); a real Intel PCS chain (PCK → processor CA
  → pinned Intel root + TCB/QE collateral, MRTD/MR_CONFIG_ID/RTMR checks) is
  documented but unwritten. So an Azure/GCP TDX seat **cannot** verify Genuine
  today — SEV-SNP only.
- **No CRL / revocation** (`snp.rs:16-18`): the pinned ARK/ASK are AMD's
  long-lived published keys; a compromised-and-revoked VCEK would still chain.
  Production must refresh CRLs from AMD KDS out of band.
- **The positive end of the chain**: no `Genuine`-with-*our*-binding verdict has
  ever been produced by silicon we launched — `report_data` sits in the
  silicon-signed region and cannot be minted offline. The 12 vector tests prove
  every *rejection*; hardware is required for the positive path.

---

## 2 · The deployment architecture (how it ties together)

```
 CUSTOMER'S CLIENT                          CLOUD PROVIDER (SEV-SNP host)
 (Postern desktop/CLI)                      ┌───────────────────────────────────┐
       │                                    │  Confidential VM (AMD EPYC Milan+) │
       │                                    │  ┌─────────────────────────────┐   │
       │                                    │  │ .#cloud-image (measured boot)│  │
       │  ── 1. TCP :16510, nonce(32) ──────┼──┼─▶ postern-seal-gate          │   │
       │                                    │  │   reads /dev/sev-guest       │   │
       │  ◀ 2. report ‖ VCEK ‖ WG_guest_pub ┼──┼── report_data =             │   │
       │                                    │  │   SHA-256(nonce‖WG_guest_pub)│  │
       │  3. postern-seal-verify:           │  └─────────────────────────────┘   │
       │     VCEK→ASK→ARK to pinned AMD ✓   │       wg0 (51820) ── desktop        │
       │     M ✓  P(HOSTDATA) ✓  binding ✓  │       (wayvnc/xrdp) bound to wg0    │
       │     TCB≥floor ✓  VMPL0 ✓  no-dbg ✓ │                                     │
       │        └── Genuine? ─── no ──▶ HARD STOP (exit 1, loud verdict)          │
       │  4. WireGuard → WG_guest_pub  ─────┼──▶  the SAME key the quote endorsed  │
       │  5. desktop session INSIDE tunnel  │                                     │
       └────────────────────────────────────┴─────────────────────────────────────
```

### 2.1 Provider / hardware choice

Grounded in `POSTERN-CLOUD.md §5` and the runbook §3–4:

| Provider | Shape | Report path | Why | Verdict for MVP |
|---|---|---|---|---|
| **GCP** ⭐ first validation | `n2d-standard-4`, `--min-cpu-platform "AMD Milan"`, `--confidential-compute-type=SEV_SNP`, `--maintenance-policy=TERMINATE` | **Guest-driven** `/dev/sev-guest`, caller-chosen `report_data` | Cleanest first bring-up: the gate works *exactly as written*, no paravisor adapter. GCP publishes guest-firmware measurements to fold into `M`. | **Start here** — matches the code with zero adaptation |
| **Azure** (primary at scale) | `Standard_DC4as_v5` (DCasv5/ECasv5), `--security-type ConfidentialVM`, `--enable-vtpm true` | **Paravisor-mediated**: SNP report commonly surfaced via **vTPM** (NV index `0x01400001`); `report_data` populated by the paravisor (binds the vTPM AK), *not* a guest value | Broadest SEV-SNP footprint (~57 regions). But the raw guest-chosen `report_data` binding may not be directly available. | **Needs a small vTPM adapter** to the gate before Azure end-to-end (see §2.5) |
| **AWS** | M6a/C6a/R6a; **Dedicated Hosts** for Brazil (`sa-east-1`) | SEV-SNP | Only surveyed path into Brazil (São Paulo); whole-host cost suits the corporate fleet, not a single seat | Corporate fleet, later |
| **OVH** (bare-metal) | AMD EPYC bare-metal | Full guest control of firmware/`/dev/sev-guest` | Removes the "provider's firmware in `M`" trust item (§1.3.3) — you own the OVMF | Best *trust* profile; more ops |

**Fly.io is explicitly excluded** — no confidential VMs (runbook §1). The
existing Fly deploy stays an ordinary testnet-node container.

**Cost (verify before committing):** GCP `n2d-standard-4` ≈ $0.15–0.25/hr;
Azure `DC4as_v5` (4 vCPU/16 GiB) ≈ $0.20/hr ≈ $140–150/mo. A full validation
session ≈ $5–20 + a few GB storage/egress.

### 2.2 How `.#cloud-image` boots measured

The image is `os/cloud.nix` layered on `os/attested.nix`:

- **`attested.nix`** builds an immutable **erofs** rootfs sealed by **dm-verity**
  (`image.repart` with paired `root` + `root-verity` partitions, `Verity=data`/
  `hash`, `VerityMatchKey="root"`), a **UKI** (kernel+initrd+cmdline as one
  signed PE), systemd-in-initrd, and TPM2 measured boot. systemd-repart writes
  the verity **roothash `R`** onto the kernel cmdline (`roothash=`), which the
  UKI measures — so the whole boot chain has a stable, measurable identity.
- Inside a SEV-SNP VM, the **launch measurement `M`** covers OVMF + UKI
  (kernel/initrd/cmdline, so it *transitively covers `R`*) + initial vCPU state.
  `M` is precomputed per {provider firmware, VM shape, vCPU count} with
  `sev-snp-measure`-class tooling (virtee, Apache-2.0) — one `M` per supported
  shape.
- **`cloud.nix`** makes it a headless confidential guest: loads `sev-guest` /
  `tdx_guest` kernel modules (`cloud.nix:43`), serial console for host-readable
  diagnostics only, firewall opens **only** 16510 (gate) + 51820 (WireGuard);
  everything else (SSH, desktop) binds to `wg0`. Deliberately **no cloud-init /
  provider guest agents** with host-writable command channels.

### 2.3 How the image digest binds to the attestation (the L1↔L3 knot)

This is the subtle part. The SEV-SNP report has no native "image digest" field.
The binding is achieved in two composed links:

1. **`R` (roothash) is inside `M`.** The UKI cmdline carries `roothash=R`, the
   UKI is in the launch measurement, so `report.measurement == M` *transitively*
   proves the running rootfs is exactly the audited erofs image. The provider
   cannot patch a byte of the rootfs undetected (dm-verity would fault; `R`
   would change; `M` would change).
2. **`P` (policy hash) is in HOSTDATA.** At VM launch the launch policy writes
   the image-admission-policy hash `P` — the policy that admits **only** digest
   `D` — into SNP **HOSTDATA** (`attested.nix:82-86`). The guest's report
   carries HOSTDATA back; the verifier pins it via `--host-data P`. This is the
   explicit L1 (build) → L3 (launch) binding.

**Fallback where HOSTDATA is not settable at launch** (a real per-provider
variance, `POSTERN-CLOUD.md §5`): `SnpExpected.host_data = None`, the check is
consciously waived, and the policy binding falls back entirely to the
UKI-cmdline-measured path (already covered by `M`). This waiver **must be
documented per deployment** in the deployment record.

### 2.4 Key management

- **WireGuard identity is generated *in-guest* on first boot, in-TEE.**
  `postern-wg-keygen.service` (`cloud.nix:121`) runs `wg genkey`/`wg pubkey`
  onto the encrypted `/persist` volume, `ConditionPathExists=!/persist/postern/
  wg0.key`. The **private half never leaves the TEE / never touches provider
  plaintext**; the **public half** is exactly what the quote's `report_data`
  endorses. The gate reads `wg0.pub` read-only (`cloud.nix:79`, `ReadOnlyPaths`).
- **The AMD root is compiled in**, not fetched — `pinned_ca()`. The wire never
  supplies the trust anchor.
- **The VCEK** comes from the hypervisor's extended-report cert table; where a
  provider doesn't provision it, fetch from **AMD KDS** at provision time and
  pass `--vcek /persist/postern/vcek.der` (wired as a commented option in
  `cloud.nix:80-82`).
- **State volume (`/persist`) is LUKS**, key derived in-guest (TEE-random) on
  first boot, sealed to measured-boot state; provider holds ciphertext only.
  - *Personal:* key recoverable only to the user's own client through the
    attested tunnel, never to the provider.
  - *Fleet:* key release via an org-hosted **KBS (Trustee, Apache-2.0)** gated
    on a `Trusted` verdict — an unattested VM cannot open its own state. **KBS
    flow is designed, not built.**
- **Client WG pubkey allowlist** is injected at launch via instance metadata —
  **untrusted by design**: a host that swaps it can only lock the rightful user
  out (a denial already in the provider's power), never let itself in.

### 2.5 The verifier core is provider-agnostic; only *transport of the quote* varies

Critically: the chain check, field comparisons, and binding recompute in
`snp.rs` are **identical** across GCP (raw `/dev/sev-guest`) and Azure (vTPM
paravisor). The only Azure-specific work is a **small gate-side adapter** that
composes the nonce‖WG-pub binding *through a vTPM quote* (TPM nonce + AK
certified by the SNP report) instead of raw `report_data`, plus accepting that
`M` endorses Microsoft's firmware+paravisor blob. `verify_snp_report` does not
change.

---

## 3 · The honest security statement

**What a `Genuine` verdict proves** (exactly, and no more): the presented report
was signed by a VCEK that chains to AMD's pinned root for the stated EPYC
generation; the guest booted the specific image/boot-chain whose launch
measurement is `M` (which transitively includes verity roothash `R`, so the
rootfs is the audited reproducible image); the launch policy `P` admitting only
digest `D` was pinned into HOSTDATA (where settable); the report is fresh and
channel-bound to *this* WireGuard key via the verifier's own nonce (no replay,
no MITM splice); reported TCB is at or above the configured floor; the report
was requested at VMPL 0; and the guest policy forbids host debug access.

**What it does NOT prove** (stated in `snp.rs:14-21`, `cloud.nix` MOTD, and
`POSTERN-CLOUD.md §1`):

- **Nothing about availability.** The provider schedules, throttles, and can
  kill the VM at will. Attestation proves integrity, never uptime.
- **Nothing about side channels.** SEV-SNP has a published history (ciphertext
  side channels, interrupt/single-stepping, power/frequency). A report proves
  *what ran*, not *that data stayed secret against a determined physical
  adversary*. This narrows the provider's window to side channels + DoS; it does
  not close it to zero. **Open research area, never claimed solved.**
- **Nothing about traffic metadata.** The provider sees ciphertext, memory/I-O
  access patterns, and network shape/timing/endpoints. WireGuard/Tor hide
  endpoints; volume and shape remain.
- **You substitute trust, you don't eliminate it.** The operator+hypervisor are
  removed from the confidentiality/integrity base **in exchange for trusting
  AMD's silicon, microcode, PSP firmware, and the ARK→ASK→VCEK CA + its
  revocation hygiene**, plus provider firmware baked into `M` on hyperscalers.
  A vendor backdoor or signed-firmware compromise defeats the model.
- **The reference values are only as good as the manifest pipeline.** `M` and
  `P` mean nothing if the release manifest that produced them is not itself
  reproducible and signed.
- **The client endpoint is in the TCB.** A compromised screen sees the session.
- **On-device Postern remains the sovereignty ceiling** — no vendor-TEE trust,
  no availability dependence, no hyperscaler metadata. Cloud is offered
  *alongside*, for workloads needing cloud economics, never as a replacement.

---

## 4 · The gap: BUILT vs MISSING

### BUILT and tested (verified this session — 23 unit + 12 SNP vector tests green)
- The entire verification chain (`snp.rs`), channel binding (`binding.rs`), wire
  codec (`gate.rs`), and both CLIs (`seal_gate.rs`, `seal_verify.rs`).
- Fail-closed rejection on every tamper: wrong root generation, tampered
  report/VCEK/signature, measurement/HOSTDATA/report_data/TCB/VMPL mismatch,
  garbage inputs — each with a named reason.
- `os/cloud.nix` + `os/attested.nix` + `os/seal-gate.nix` — the full NixOS
  expression for the measured image and the hardened gate service.
- Supply chain: `cargo deny` PASS; permissive-only (virtee/sev Apache-2.0,
  pure-Rust `crypto_nossl`, no OpenSSL).

### MISSING — three distinct layers
1. **Build layer (needs a Nix host, no hardware):** nobody has run
   `nix build .#cloud-image` / `.#seal-gate`. No `.#cloud-image` flake output is
   even present in *this* repo — the flake lives in the upstream
   `BlochSISPoW-project` git dependency and the outputs (`cloud-image`,
   `seal-gate`, `nixosConfigurations.postern-cloud`) are **specified in comments
   but not wired** (`cloud.nix:19-30`). So there is **no reproducible image, no
   digest `D`, no roothash `R`, no per-shape measurement `M`, no policy hash
   `P`, and no signed release manifest.** repart/verity/UKI options drift across
   nixpkgs — expect iteration.
2. **Launch/provisioning layer (needs a real CVM + cloud account):** the
   `/dev/sev-guest` ioctl path in `seal_gate.rs` has never executed. Unverified
   per-provider items: whose firmware is in `M`, whether HOSTDATA is settable at
   launch, and which report path each SKU exposes (GCP direct vs Azure vTPM). No
   positive `Genuine`-with-our-binding verdict from silicon we launched exists.
   The Azure vTPM adapter (§2.5) is unwritten.
3. **Customer-facing flow layer (entirely unbuilt):** there is no self-serve
   provisioning ("deploy a Postern confidential VM into *your* cloud account"),
   no client UI wrapping `postern-seal-verify` into a one-click
   verify-then-connect, no release-manifest fetch/pin UX, no fleet monitor /
   KBS key-release integration, no re-attestation scheduler (the design wants
   per-connect + hourly in-session). And **no external audit** of the chain —
   which the project's own honesty rule requires before any user-facing trust
   claim ships. TDX is a stub, so TDX SKUs are out.

---

## 5 · Recommended build sequence (to close the gap)

1. Wire the flake outputs (`.#cloud-image`, `.#seal-gate`,
   `nixosConfigurations.postern-cloud`) upstream; `nix build .#cloud-image`
   twice on two hosts, diff `D` and `R` (prove reproducibility). Pin the
   `bloch-crypto` `outputHashes` on first build.
2. Precompute `M` for `n2d-standard-4` with `sev-snp-measure`; author the
   admission policy admitting only `D`, hash → `P`; sign+publish the manifest
   `{commit, D, R, M[shape], P}`.
3. **GCP first** (guest-driven path, zero code change): import image, launch
   confidential VM, run `postern-seal-verify --generation milan --measurement M
   [--host-data P] --min-tcb … --vmpl 0` against the live gate. This is the
   first real `Genuine`. Record the deployment (HOSTDATA setability, firmware
   provenance, VCEK-in-cert-table yes/no).
4. Then Azure: add the vTPM binding adapter to the gate; re-validate.
5. Build the customer flow (self-serve BYO-tenancy provisioning + one-click
   client verify-then-connect) and commission the external audit before any
   trust claim ships.

---

## Appendix · Traceability

| Claim | Source |
|---|---|
| Chain verify, field checks, fail-closed reasons | `crates/postern-seal-companion/src/snp.rs:111-216` |
| Channel binding math + KAT/replay/MITM tests | `src/binding.rs:39-107` |
| Wire codec + hostile-peer caps | `src/gate.rs:23-210` |
| Gate ioctl path (never run on HW), VCEK from cert table | `src/bin/seal_gate.rs:60-192` |
| Verifier CLI, `--measurement` mandatory, Genuine→print WG key | `src/bin/seal_verify.rs:57-107` |
| TDX fail-closed stub | `src/tdx.rs:36` |
| Measured image (erofs+verity+UKI, roothash on cmdline) | `os/attested.nix:33-72` |
| Guest profile, gate service, in-TEE WG keygen, LUKS /persist | `os/cloud.nix:38-201` |
| L1→L3 HOSTDATA policy binding | `os/attested.nix:82-86` |
| Reproducible-build package for gate+verifier | `os/seal-gate.nix` |
| Design + trust model + provider survey | `docs/specs/POSTERN-CLOUD.md §1,§3,§5,§7,§9` |
| Provider bring-up runbook + honest ledger | `docs/specs/POSTERN-CLOUD-CONFIDENTIAL.md §0-6` |
| Tests pass (23 unit + 12 SNP vectors) | `cargo test -p postern-seal-companion --features sev-snp` (run 2026-07-10) |
