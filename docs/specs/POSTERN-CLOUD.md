# Postern Cloud — the confidential-VM edition of Postern OS (design spec)

**Product (Postern Labs). Status: DESIGN.** The cloud edition of the Postern
OS family: the same reproducible, attestable Postern OS (`os/attested.nix` +
`os/desktop.nix`), built as a **confidential-VM guest image** — AMD **SEV-SNP**
primary, Intel **TDX** secondary — so a cloud provider hosts the hardware but
the VM's memory is hardware-encrypted against the host, and **remote
attestation proves the genuine unmodified image is running in a real TEE
before the user's client ever opens a session**. Like Ubuntu/RHEL ship cloud
editions of their desktop/server OS — but confidential-by-default, and
verified-by-default.

> Codename **Chiostro** — the cloister: a private, enclosed garden built
> inside someone else's walls. (House naming: Chiave wears iris, Consiglio
> cobalt, Sarto madder; Chiostro wears slate.)
>
> This document EXTENDS, and must never contradict:
> - `os/ATTESTATION.md` — the Postern Seal chain (reproducible → immutable →
>   measured → attested) and the `AttestationReport` / `Expected` / `Verdict`
>   verifier shape. Postern Cloud is that chain, deployed to a hyperscaler.
> - `bloch-blockchain/docs/specs/BLOCH-SIS-ATTESTATION.md` — the L3 pluggable
>   attestation layer (`sev-snp` / `tdx` backends) and the HOSTDATA /
>   MR_CONFIG_ID image-policy binding.
> - `bloch-blockchain/docs/specs/BLOCH-SIS-LINUX.md` — the permissive-only
>   attestation stack survey and the honest integrity-not-secrecy scope.
> - `docs/specs/POSTERN-ENTERPRISE.md` — the corporate identity/governance
>   model that the corporate fleet variant plugs into unchanged.

---

## 0 · What it is, in one paragraph

`nix build .#cloud-image` produces the same immutable, dm-verity-sealed,
UKI-measured Postern OS disk image as `os/attested.nix` — with a headless
remote-desktop profile instead of a local display — packaged for a cloud
provider's confidential-VM service. The image's identity is three deterministic
values computed at build time: the **image digest** (L1), the **verity
roothash** (`os_roothash`), and the **precomputed launch measurement**. A user
runs the image as a SEV-SNP or TDX guest on Azure/GCP/AWS, and connects with a
Postern client that refuses to establish the desktop session until
`verify(report, Expected { … }, nonce)` returns `Verdict::Trusted` — the exact
verifier already implemented and unit-tested in the node's attestation layer.
The provider supplies electricity, silicon, and bandwidth; it does not get a
plaintext view of the guest.

### Use cases

| Use case | Why confidential-cloud fits |
|---|---|
| **Sovereign cloud workstation** | A personal Postern desktop reachable from anywhere, on rented hardware the renter cannot read. For people who need the privacy stack but not on-prem metal. |
| **Attestable build / CI hosts** | A build farm whose every runner *proves* it runs the audited image — reproducible builds, produced on attestably-reproducible builders. Closes the "who built the builder" loop. |
| **Enterprise fleets of confidential desktops** | Admin-provisioned Postern Enterprise machines (`POSTERN-ENTERPRISE.md` §5.1 machine profiles) as cloud VMs: same directory identity, same transparency panel, no laptops to ship, and the org can *prove* every fleet seat runs the genuine profile. |
| **Burst compute** | Spin up N attested workstations/build hosts for a project, destroy them after; persistent state on a separately-keyed encrypted volume or nowhere at all. |

What it is **not**: it is not the maximally-sovereign Postern. That remains
the on-device editions (§2).

---

## 1 · The confidential-computing trust model — stated honestly

Never say "the cloud can't see anything." Say precisely this:

### 1.1 What the hardware denies the provider

In a SEV-SNP or TDX guest, guest memory is encrypted by the CPU with keys held
in the CPU's security processor (AMD PSP / Intel SEAM domain), and the guest's
launch state is measured and signed by that hardware. By the hardware's design:

- the **hypervisor/operator cannot read or undetectably modify guest memory
  plaintext** — pages it can touch are ciphertext, and SNP's integrity
  protection (RMP) / TDX's TD memory protection turn tampering into faults;
- the operator **cannot substitute the image or the boot chain without
  detection** — the launch measurement changes and attestation fails;
- registers on VM-exit are encrypted/protected; the host does not get a
  debugger's view of the guest.

### 1.2 What the provider still sees and controls

- **Availability.** The provider schedules, pauses, throttles, and can simply
  kill the VM. Attestation proves *integrity*, never *availability*.
- **Ciphertext and access patterns.** Encrypted memory pages, encrypted disk
  blocks, page-fault and I/O patterns, network traffic shape/timing/endpoints
  (mitigate endpoints with WireGuard/Tor, §4 — shape and volume remain),
  power/billing telemetry. Traffic analysis is out of the TEE's scope.
- **The metadata of your tenancy.** That you run a VM, its size, its region,
  when it runs, what it costs.

### 1.3 The trust you DO take on — plainly

1. **The CPU vendor.** You trust AMD's (or Intel's) silicon, microcode, and
   security-processor firmware (PSP / SEAM) to implement the TEE as
   documented. A vendor bug, backdoor, or signed-firmware compromise defeats
   the model. This is a *vendor-trust* substitution: instead of trusting the
   cloud operator, you trust AMD/Intel plus the operator's inability to break
   them.
2. **The attestation CA chain.** SEV-SNP reports chain to AMD's ARK → ASK →
   VCEK certificates; TDX quotes chain to Intel's PCS. You trust those roots
   and their revocation hygiene. TCB rollback / outdated-firmware acceptance
   is a real attack class — the verifier must check the reported TCB version
   against a current minimum, not just signature validity.
3. **Provider-supplied firmware in the measurement.** On hyperscalers the
   guest firmware (OVMF/UEFI) is often the *provider's* build, and it is part
   of the launch measurement. Where the provider does not publish reproducible
   firmware (or support bring-your-own-firmware), the reference measurement
   necessarily endorses a provider blob — trust taken on, named. Prefer SKUs/
   paths where firmware reference values are published or BYO-firmware is
   supported; verify per provider (§5).
4. **Side channels remain an open research area.** SEV-SNP and TDX have a
   published history (ciphertext side channels, interrupt/stepping attacks,
   power/frequency channels); mitigations ship, new papers follow. Per the
   project's standing rule (`BLOCH-SIS-ATTESTATION.md` §5): a TEE report
   proves *what ran*, not *that data stayed secret against a determined
   physical adversary*. Postern Cloud narrows the provider's window to
   side channels and denial-of-service; it does not close it to zero.
5. **The client endpoint.** The screen you view the remote desktop on is part
   of the TCB. A compromised client sees everything the session shows. (The
   client should itself be a Postern desktop/app; the corporate variant can
   require an attested client, §6.)

**The honest one-liner:** *the provider's operators and hypervisor are removed
from the trust base for confidentiality and integrity of the running guest, in
exchange for trusting AMD/Intel's TEE implementation and certificate
infrastructure; availability and traffic metadata stay with the provider;
side channels are an open frontier.*

---

## 2 · The privacy tension, named

Postern's thesis is **on-device**: your keys, your hardware, no server —
`POSTERN-IDENTITY.md`'s wallet-as-identity, the desktop's local-first spine.
Cloud is *someone else's hardware*. That is the opposite direction, and this
spec does not paper over it:

- **Why it's acceptable for these use cases:** the alternatives users actually
  reach for are far worse. A conventional cloud VDI/VM gives the operator
  root-equivalent visibility; Postern Cloud replaces "trust the operator's
  entire stack and staff" with "trust the CPU vendor's TEE + verify the image
  cryptographically before every session." For a build farm, a burst fleet, or
  a workstation someone would otherwise run on plain EC2, that is a strict,
  measurable improvement — and uniquely, the user can *verify* it rather than
  take it on reputation.
- **What is not claimed:** parity with on-device. The on-device editions
  (Postern Desktop/Mobile on hardware you own) remain the **maximally
  sovereign** path — no vendor-TEE trust for confidentiality, no availability
  dependence, no traffic metadata at a hyperscaler. Postern Cloud is offered
  *alongside* them, for workloads that need cloud economics, never as a
  replacement for the personal thesis.
- **Product honesty rule:** every Postern Cloud surface (docs, console, MOTD)
  states the §1.3 trust list. Marketing that says "the cloud can't see
  anything" unqualified is wrong and gets fixed, the same discipline as
  `POSTERN-ENTERPRISE.md`'s compliance disclaimers.

---

## 3 · Attestation binding, end-to-end

Identical chain to `os/ATTESTATION.md`, deployed to a CVM; nothing new is
invented, one link (channel binding) is added for the remote-desktop session.

```
reproducible flake input          nix build .#cloud-image  (same input → same image)
        │
        ▼
immutable disk image              erofs rootfs, systemd-repart, Verity=data/hash
        │
        ▼
dm-verity roothash  R             seals the rootfs; on the cmdline as roothash=
        │
        ▼
UKI (kernel+initrd+cmdline)       one signed PE; cmdline includes R
        │
        ▼
SEV-SNP launch measurement  M     covers OVMF + UKI (kernel/initrd/cmdline) + vCPU
  (TDX: MRTD + RTMRs)             state — precomputable per SKU/vCPU shape (§7)
        │
        ▼
HOSTDATA  (TDX: MR_CONFIG_ID)     pins the image-admission policy hash P —
                                  the policy that admits ONLY image digest D
        │                         (the L1 binding, BLOCH-SIS-ATTESTATION.md §2)
        ▼
AttestationReport {               produced in-guest via /dev/sev-guest
    measurement:  M,              (TDX: the TD quote path), signed by the
    os_roothash:  R,              hardware, chained to AMD ARK→ASK→VCEK
    image_digest: D,              (Intel PCS for TDX)
    hostdata:     P,
    report_data:  H(nonce ‖ gate_pubkey)   ← freshness + channel binding (§4)
}
        │
        ▼
verify(report, Expected {         the EXISTING verifier — src/attestation,
    tee:          Tee::SevSnp,    implemented and unit-tested; the sev-snp
    image_digest: D,              quote-signature check is the feature-gated
    measurement:  Some(M),        provider path (virtee/sev)
    hostdata:     Some(P),
    os_roothash:  Some(R),
}, Some(nonce)) == Verdict::Trusted
```

The verifier's reference values `D`, `R`, `M`, `P` come from the signed
**release manifest** (§7) — or, for the trust-nobody path, the user reproduces
them: `nix build .#cloud-image` on their own machine yields the same `D` and
`R`, and `M` is recomputed from the image + firmware + VM shape with the
measurement tool (§7). Reproduce, pin, verify — the same discipline as
`os/ATTESTATION.md` "For a verifier."

**Layer table (unchanged from `os/ATTESTATION.md`, cloud column added):**

| Layer | Guarantee | Field | Cloud note |
|---|---|---|---|
| L1 reproducible build | image is the audited one | `image_digest` | manifest-published, anyone rebuilds |
| Verity (Postern OS) | running rootfs is exactly that image | `os_roothash` | provider can't patch a byte of the rootfs undetected |
| L2 hardening | least-privilege runtime | — (posture) | plus: no cloud agents, no provider guest-tools in the image |
| L3 TEE | all of it runs in a genuine SEV-SNP/TDX VM | `tee`, `measurement`, `hostdata` | the new hardware anchor vs the on-prem TPM path |

---

## 4 · The Seal-gated session — verify BEFORE you connect

The remote desktop is only reachable *through* an attestation gate. Transport
is concrete: **WireGuard** (primary; permissively-licensed implementations,
low overhead) or a **Tor onion service** (metadata-hardened variant — hides
the client↔VM relationship from network observers, at latency cost). The
desktop protocol runs only inside the tunnel: **wayvnc** (ISC) or
**FreeRDP/xrdp** (Apache-2.0) — see §8 for why not Sunshine/Moonlight.

### 4.1 Handshake

```
Client (Postern app / CLI)                     Guest (Postern Cloud VM)
        │                                              │
        │ 1. TCP to the gate port (the ONLY            │
        │    pre-attestation listener)                 │
        │──────────── nonce (32 B, fresh) ────────────▶│
        │                                              │ 2. request SNP report with
        │                                              │    report_data =
        │                                              │      SHA-256(nonce ‖ WG_guest_pub)
        │                                              │    (TDX: same, in the 64-B
        │                                              │     report_data of the TD quote)
        │◀── report + VCEK cert chain + WG_guest_pub ──│
        │                                              │
        │ 3. verify(report, Expected{D,M,P,R},         │
        │    nonce) == Trusted                         │
        │    AND report_data == H(nonce‖WG_guest_pub)  │
        │    AND TCB version ≥ minimum (§1.3.2)        │
        │    — ANY failure ⇒ hard stop, no session,    │
        │      loud verdict shown to the user          │
        │                                              │
        │ 4. WireGuard handshake to WG_guest_pub ─────▶│  ← the SAME key the quote
        │    (client key was enrolled at provision)    │    endorsed: no MITM splice
        │                                              │
        │ 5. desktop session (wayvnc / RDP) inside     │
        │    the tunnel; disconnected sessions persist │
        └──────────────────────────────────────────────┘
```

Design points:

- **Channel binding is the load-bearing addition.** The quote's `report_data`
  carries `H(nonce ‖ WG_guest_pub)`, so the key the client tunnels to is the
  key attested from inside the genuine image. Without this, a
  man-in-the-middle could relay a valid quote from a real CVM and terminate
  the tunnel itself. The nonce gives freshness (replay refusal — already a
  tested `verify()` reject case); the pubkey gives the binding.
- **Nothing else listens pre-attestation.** The gate is the entire
  unauthenticated surface: one small service (same hardened-systemd discipline
  as `os/bloch-node.nix`) that reads a nonce and returns evidence. SSH, RPC,
  desktop — all bound to the WireGuard interface only.
- **Re-attestation:** on every new connection, and periodically in-session
  (policy-tunable; default hourly) — a live session does not outlive a
  now-stale trust decision indefinitely.
- **Verdicts are user-facing.** The client renders the exact `Verdict` reason
  (wrong digest / stale nonce / TEE mismatch / hostdata mismatch / TCB too
  old) — the same taxonomy the unit tests already reject on.
- **Provisioning bootstrap:** the client's WireGuard public key is injected at
  VM launch (provider instance metadata / a provisioning volume). Instance
  metadata is host-writable and therefore **untrusted for anything
  security-critical except the client's own public key allowlist** — a host
  that swaps it can only lock the rightful user out (a denial, already in the
  provider's power), never let itself in.

### 4.2 Persistent state

The rootfs is read-only and sealed; mutable state lives on a separate volume
(the `attested.nix` `/persist` pattern), **LUKS-encrypted with a key that
never touches the provider's plaintext**:

- **Default (self-contained):** the LUKS key is derived in-guest on first boot
  (TEE-random), sealed so it is only released after the guest's own
  measured-boot state checks out, and — for recovery — exportable to the
  *user's client* through the attested tunnel, never to the provider.
- **Fleet variant:** key release via a KBS/relying-party flow (Trustee,
  Apache-2.0 — the `BLOCH-SIS-LINUX.md` §2.4 stack): the key server releases
  the volume key only to a guest presenting a `Trusted` verdict. The KBS is
  org-hosted (corporate, §6) or user-hosted; the KBS operator becomes a party
  who can deny (not read) the volume.

To the provider, the state volume is ciphertext at rest; block-access patterns
remain visible (§1.2).

---

## 5 · Which clouds, which regions

Grounded in the fact-checked survey in `BLOCH-SIS-ATTESTATION.md` §3 (2026);
availability shifts — **always verify current SKUs/regions with the provider
before committing a deployment**.

| Cloud | SEV-SNP | TDX | Regions (per the §3 survey) | Postern Cloud notes |
|---|---|---|---|---|
| **Azure** ⭐ primary | DCasv5/6, ECasv5/6, NCCadsH100v5 | DCesv6/ECesv6 | widest (~57 regions) | Best default: broadest SEV-SNP + TDX. Guest firmware is Azure's — §1.3.3 applies; Azure's attestation path exposes the SNP report to the guest. Brazil South availability of these SKUs: **verify with the provider**. |
| **GCP** | N2D (SEV-SNP) | (TDX on select shapes) | asia-southeast1, europe-west3/4, us-central1 — **no South America** in the survey | Narrower; fine for EU/US/SEA seats. |
| **AWS** | M6a/C6a/R6a | — (survey) | shared: Ohio + Ireland; **Dedicated Hosts: all AMD regions** | Dedicated Hosts are the survey's **only identified path into Brazil (sa-east-1, São Paulo)** — relevant to this project's Brazil footprint. Cost profile is whole-host; suits the corporate fleet, not a single personal seat. |

Notes:

- **Fly.io (the node's current deploy target, `fly.toml`, region `gru`) is NOT
  a confidential-VM platform** — the existing Fly deployment is an ordinary
  container for the testnet node. Postern Cloud requires one of the CVM
  providers above; the Fly discipline we keep is the *pipeline* (§7), not the
  host.
- Per-provider differences that the design must absorb: how the guest fetches
  the raw report (`/dev/sev-guest` vs provider attestation services), whether
  HOSTDATA is settable at launch (where it is not, the policy binding falls
  back to measuring the policy into the boot chain — the UKI cmdline is
  covered by `M`), and whose firmware is in `M`. These are **per-provider
  integration items, flagged as unverified until run on real hardware** (§9).

---

## 6 · Personal vs Corporate — two trust models, one image

Exactly the split `POSTERN-ENTERPRISE.md` §1 establishes; Postern Cloud adds a
deployment target, not a third identity model.

| Dimension | **Personal Cloud** | **Corporate Cloud** |
|---|---|---|
| Who provisions | The user, self-serve — ideally **into their own cloud account** (BYO-tenancy: the user, not Postern Labs, is the provider's customer; Postern Labs never holds the tenancy) | The org's admin-of-record; fleet VMs in the org's tenancy, machine profiles per role (`POSTERN-ENTERPRISE.md` §5.1 — a Nix expression per role) |
| Root of identity | The user's **self-custody wallet** (Chiave): unlock locally, sign the challenge — the cloud VM enrolls the wallet's login pubkey at provision | The **org directory** — enrollment certificate + short-lived assertions. **NOT self-custody wallet login**, by design: the org provisions, certifies, revokes (`POSTERN-ENTERPRISE.md` §3) |
| Who verifies attestation | The user's client, before every connect (§4) — no third party in the loop | The client **and** the org's fleet monitor: continuous attestation across the fleet, failures alarm; volume keys via org-hosted KBS (§4.2) so an unattested VM can't even open its state |
| Recovery | Seed phrase or nothing (personal doctrine); state-volume key recoverable only via the user's own attested tunnel | Dual-control escrow, M-of-N quorum, audited (`POSTERN-ENTERPRISE.md` §3.4) — corporate volumes only |
| Revocation | User destroys the VM/tenancy | Directory assertion stops + volume-key release stops + VM deprovision; instant, audited |
| Transparency | n/a (no admin exists) | The **transparency panel** renders in the cloud desktop exactly as on a fleet laptop — including the fact that the seat is cloud-hosted and in which region |
| Honest posture shown at login | §1.3 trust list + "on-device is the maximally sovereign option" | Same, plus the org's declared telemetry list |

Personal note, stated in-product: a personal cloud workstation leaks tenancy
metadata (§1.2) to the provider under the *user's* name unless the tenancy
itself is arranged otherwise. The Tor-onion transport option (§4) hides the
client↔VM link, not the tenancy.

---

## 7 · Reproducible image → digest → policy → deploy

The pipeline reuses the node's reproducibility discipline (`Dockerfile` pinned
base digests, `--locked` builds, `SOURCE_DATE_EPOCH`; Fly's
build-from-committed-config) at the OS level, where Nix does the heavy lifting:

```
1. BUILD        nix build .#cloud-image                     (Linux + Nix host)
                └─ same inputs ⇒ same erofs rootfs ⇒ same verity roothash R
                   image formats: raw / qcow2 (+ VHD for Azure, per-provider wrap)
2. IDENTIFY     D = sha256(image)               ← L1 digest
                R = verity roothash             ← printed by the repart build
                M = precomputed launch measurement per {provider firmware,
                    VM shape, vCPU count} — sev-snp-measure-class tooling
                    (virtee ecosystem, Apache-2.0); one M per supported shape
                P = hash of the admission policy that admits ONLY D
3. MANIFEST     release manifest { git commit, D, R, P, M[shape…], tool
                versions } — signed (hybrid Falcon‖ML-DSA, the project's
                signing stack) and published; anyone re-runs step 1–2 and
                diffs (reproducible-builds.org discipline, as in
                BLOCH-SIS-LINUX.md §2.1)
4. PIN          the launch policy for the CVM pins P into HOSTDATA (SNP) /
                MR_CONFIG_ID (TDX) at VM creation; guest firmware+UKI produce M
5. DEPLOY       upload image to the provider (AMI / Azure image / GCP image),
                launch as a confidential VM, inject the client WG pubkey
                (untrusted channel — §4.1 last bullet)
6. VERIFY       client Seal-gate handshake (§4); Expected{D,M,P,R} from the
                manifest or from the user's own rebuild
```

Update discipline: an update is a **new image** (new `D`, `R`, `M`), never an
in-place mutation — the rootfs is verity-sealed, so there is no other option,
which is the point. Fleet rollout = build, manifest, re-pin, redeploy;
`/persist` carries the state across. A VM presenting a superseded-but-valid
manifest entry is policy: personal default accepts N−1 for a grace window,
corporate default is the org's call, rendered in the transparency panel.

---

## 8 · Licensing — permissive-only, restated

Project rule (as established in `BLOCH-SIS-LINUX.md` §2.4, permissive-only, no
AGPL/GPL/LGPL in the shipped stack):

**In:** `virtee/sev` (Apache-2.0 — SNP report build/verify; the `sev-snp`
feature backend), Trustee/KBS (Apache-2.0 — fleet key release), Kata/CoCo
(Apache-2.0 — if the container-shaped variant is ever wanted), **wayvnc**
(ISC) and **FreeRDP/xrdp** (Apache-2.0) for the desktop protocol, WireGuard
userspace implementations with permissive licenses for the client side
(wireguard-go is MIT; the in-kernel module ships with Linux and is not a
distributed component of ours), NixOS/nixpkgs (MIT).

**Out, by the rule:** Sunshine and Moonlight (GPL-3.0 — the popular
game-streaming remote-desktop pair), TigerVNC (GPL), SPICE client libs (LGPL),
Gramine (LGPL-3.0), Constellation (BSL→AGPL, archived read-only Jan 2026 —
notable because it is the closest prior art to "attested cloud OS"; we cite
it, we do not link it).

License review is per-component at integration time (`deny.toml` discipline
extends to the OS package set).

---

## 9 · Honest status — designed vs needs-building vs needs-hardware

This document is a **design spec**. Per the project's honesty discipline
(no attestation claim is adopted until the chain is audited):

| Item | Status |
|---|---|
| Verifier (`verify`, `Expected`, `Verdict`, nonce freshness, reject cases) | **Implemented + unit-tested** (node `src/attestation/`) |
| `getattestation` RPC, pluggable providers, honest `attested:false` default | **Implemented** |
| Immutable/verity/UKI image profile | **Written** (`os/attested.nix`) — a profile to iterate on a Nix host; repart/verity/UKI options drift across nixpkgs |
| SEV-SNP verifier crypto (report parse, VCEK→ASK→ARK chain to the pinned AMD root, measurement/HOSTDATA/report_data/TCB checks) | **Implemented + vector-tested offline** (`postern-seal-companion` feature `sev-snp`, virtee/sev Apache-2.0; real Milan report fixture) — positive end-to-end still **needs real TEE hardware** (runbook: `POSTERN-CLOUD-CONFIDENTIAL.md`) |
| TDX quote verification | **Fail-closed stub** (`postern-seal-companion::tdx` — never Genuine); Intel PCS chain still to land |
| Cloud image profile (`os/cloud.nix`), gate service, Seal-gated WireGuard handshake, channel binding | **Gate + verifier CLI implemented** (`postern-seal-gate`/`postern-seal-verify`, binding + wire codec unit-tested); `os/cloud.nix` wires the hardened service — **image not built here (no Nix), not run on a CVM** |
| Precomputed launch measurements per provider/shape; HOSTDATA setability per provider; firmware reference values | **Unverified — requires real CVMs on each provider** |
| Cloud/region availability table | Survey data (2026) from `BLOCH-SIS-ATTESTATION.md` §3 — **verify with the provider** before any deployment commitment |
| KBS fleet key-release flow | **Designed; not built** (stack selected, Apache-2.0) |
| Side-channel posture | **Open research area, permanently monitored — never claimed solved** |
| External audit of the end-to-end chain | **Not done** — no user-facing trust claim ships before it |

Non-negotiables carried over: the image must be reproducible from public
source (an unverifiable image defeats the purpose); no unqualified
secrecy claim — cryptographic privacy is Coherence's job and no TEE is part of
its trust base; the on-device editions remain the sovereignty ceiling and the
product says so.
