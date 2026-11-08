# Postern Labs — Designed-Items Execution Backlog

**Purpose.** Move the three products the site marks `design / spec` from
**designed → built · tested**, honestly. This is a PMO backlog: milestones,
the foundation each builds on, dependencies, owner-type, effort, and
acceptance criteria — plus explicit honesty gates so nothing over-claims.

**The three items (site `products.html` §"bigger surfaces"):**

1. **Postern Container (Android)** — hardened, attestable privacy workspace on a
   phone the user already owns; the planned *entry* product. Status today:
   `design / spec`.
2. **Cloud edition** — confidential-VM deployment (AMD SEV-SNP primary, Intel TDX
   secondary). Status today: `design / spec`.
3. **Enterprise edition** — identity & governance (wallet-as-login, org controls);
   Consiglio is its console prototype. Status today: `design / spec` +
   `reference prototype`.

**Honesty gates (apply to ALL three — non-negotiable):**

- **G1 — built≠designed.** A product's site badge stays `design / spec` until the
  code that implements it **compiles AND its tests pass**. "Reference prototype"
  (a working front-end demoing the design) is its own badge and never counts as
  "built".
- **G2 — built≠booted≠hardware.** For anything with an OS image or TEE claim, the
  badge must state exactly how far it is proven: *built* is not *booted*, *boots
  on QEMU* is not *tested on hardware*. (This mirrors the existing OS-image
  badges on the site.)
- **G3 — attestation claims are hardware-gated.** No SEV-SNP / TDX / Android
  Key-Attestation claim flips to "working" from offline vectors alone. It flips
  only after a quote produced by **hardware we launched** verifies end-to-end.
- **G4 — unaudited, always.** Every item keeps the `unaudited` badge. Building
  and testing does not remove it; only a completed third-party audit does, and
  none is contracted for these three.

**What agents actually produce (read this before trusting any effort estimate):**
designs, scaffolds, Rust cores with unit tests, and reference front-ends —
**not** finished, audited, hardware-validated products. Every "L" below implies
work that needs a Nix host, real devices/VMs, platform SDKs, and human review
that an agent cannot self-certify.

---

## Foundation inventory — what already exists (built vs prototype vs absent)

Graded by inspection of the repo at `/Users/tiagoacioli/dev/bloch-protocol`.

### BUILT · tests pass (Rust cores)

| Component | Path | State |
|---|---|---|
| **Postern Seal Companion** | `crates/postern-seal-companion` | **Built + tested.** Default build: `binding.rs` (channel-binding math `report_data = SHA-256(nonce‖pubkey)`), `gate.rs` (the `PSG1`/`PSE1` attestation-before-connect wire format), `lib.rs` (peer-verify + self-audit verifier, fail-closed without a trust anchor), `tdx.rs` (fail-closed TDX stub). Feature `sev-snp`: `snp.rs` — **real** VCEK→ASK→ARK chain verification to the pinned AMD root, measurement/HOSTDATA/report_data/TCB/VMPL/debug-policy checks, all fail-closed; plus two binaries (`postern-seal-gate` guest side, `postern-seal-verify` client side) and `tests/snp_vectors.rs` verifying a **real Milan report + VCEK fixture** (13 vectors: genuine + every tamper). ~1,500 LOC. **Not hardware-validated** (own admission in `snp.rs` header + `snp_vectors.rs`). |
| Other product cores | `crates/postern-{core,courier,hygiene,keys,messenger,panic,quarantine,sdk,telephony,tor,vault}` | Built · tests pass · unaudited (per site). `postern-core::seal::attestation_transcript` is the canonical transcript both producer and verifier share. |
| **bloch-mobile core** | `mobile/core` | Pure-Rust wallet core: mnemonic↔address, hybrid Falcon‖ML-DSA sign, JSON-RPC shaping, attestation-challenge plumbing; unit-tested. **UniFFI export done** (`ffi.rs`, `bin/uniffi-bindgen.rs`). Lean cross-compile + UniFFI export confirmed in `docs/PROJECT-STATUS.md`. |

### PROTOTYPE · scaffold (works as a demo, not the product)

| Component | Path | State |
|---|---|---|
| **Consiglio** (enterprise console) | `apps/postern-enterprise/index.html` | Single-file front-end, ~1,847 lines. Fully local: org/role model, Chinese-Wall segment editor, dual-control escrow, provision/offboard ceremonies, tamper-evident audit chain, employee transparency panel. **State lives in `localStorage`; no backend.** Only network egress is the user's *own* optional Claude policy-assistant call to `api.anthropic.com`. Self-labels the stand-ins (audit chain "catches accidental edits, not a local attacker"). This is the design made tangible — **not** a running governance system. |
| **Chiave** (wallet-as-login flow) | `apps/postern-login/index.html` | Reference login ceremony (Sign-In-With-Postern-Wallet), fully local, browser stand-ins labeled. Grounds the Enterprise/Identity identity root. |
| **Android app shell** | `mobile/android/` | Kotlin/Compose **skeleton**: `MainActivity`, `WalletViewModel`, `NodeRpc`, `StrongBoxKey`, `ui/WalletScreen.kt`; `build.gradle.kts` present. `jniLibs/` and `uniffi/bloch_mobile/` are **placeholders** (`PLACE_*_HERE.md`). Not built on real SDKs; **no DPC / managed-profile code**. |
| iOS app shell | `mobile/ios/` | SwiftUI skeleton (Secure Enclave, App Attest stubs). Same "not built on SDK" caveat. |

### OS PROFILES · written, NOT built

| Component | Path | State |
|---|---|---|
| **Attested image profile** | `os/attested.nix` | erofs + dm-verity + UKI + measured-boot NixOS profile. Produces the `os_roothash` the verifier pins. Self-labels: written on a non-Nix host, **iterate on a Nix host** (`nix build .#attested-image`); repart/verity/UKI options drift across nixpkgs. |
| **Cloud guest profile** | `os/cloud.nix` | Confidential-VM guest (codename Chiostro): headless, Seal-gate is the only pre-attestation listener (port 16510), WireGuard-only desktop (wayvnc), in-guest TEE-random WG keygen, LUKS `/persist`, systemd hardening spine. Wires `postern-seal-gate` as a service. Self-labels: **NOT built here**; per-provider firmware/measurement/HOSTDATA unverified until run on real SEV-SNP/TDX. |
| `seal-gate.nix`, `attested.nix` docs | `os/seal-gate.nix`, `os/ATTESTATION.md`, `docs/specs/POSTERN-CLOUD-CONFIDENTIAL.md` | Packaging + the hardware runbook exist. |

### ABSENT · not started

- **The `flake.nix` with `.#attested-image` / `cloud-image` outputs is not in this
  repo tree** — referenced in `os/ATTESTATION.md` and `os/cloud.nix` comments but
  assembled/lives elsewhere (see `assemble-public.sh`). Image builds cannot be
  invoked from this checkout as-is.
- **No hardware-validated attestation** — no quote from a SEV-SNP/TDX VM we launched
  has been verified end-to-end (only the offline Milan fixture).
- **Android DPC** — managed-profile provisioning, lockdown policy, always-on Tor
  VPN wiring: absent (spec only, `POSTERN-CONTAINER.md §"Build path"`).
- **`bloch-core` lean split** — documented as needed for container cross-compile
  "only if drift-risk demands"; largely obviated by `mobile/core` already
  cross-compiling.
- **Enterprise backend** — self-hosted Postern Directory, OIDC/SAML federation,
  M-of-N escrow quorum service, KBS/Trustee key-release: absent (Consiglio fakes
  all of it in `localStorage`).

**Bottom line on foundation depth:** **Cloud edition** is by far the most built —
its cryptographic core (`postern-seal-companion` with `sev-snp`) is a real,
tested attestation verifier with the exact production wire protocol, plus both
OS profiles. **Enterprise** has the richest *prototype* (Consiglio) but its
backend is entirely absent. **Container** has a wallet core and app skeleton but
its defining piece — the DPC/managed-profile isolation — is unstarted.

---

## Item 1 — Cloud edition (confidential-VM)

**Foundation:** `postern-seal-companion` (built+tested SEV-SNP verifier, both gate
binaries, wire format, channel binding) · `os/cloud.nix` + `os/attested.nix` ·
`docs/specs/POSTERN-CLOUD.md` + `POSTERN-CLOUD-CONFIDENTIAL.md` runbook.
**This item is closest to real, demonstrable progress.**

| # | Milestone | Foundation it builds on | Deps | Owner | Effort | Acceptance criteria |
|---|---|---|---|---|---|---|
| C1 | Build `.#attested-image` on a real Nix host; read + pin the `os_roothash` | `os/attested.nix`, missing flake wiring | Nix host; recover/assemble `flake.nix` outputs | infra | M | `nix build .#attested-image` succeeds; roothash reproduced twice identically; pinned value recorded |
| C2 | Build `cloud-image` (Chiostro guest) from `os/cloud.nix` | C1, `os/cloud.nix` | C1 | infra | M | Image builds; boots on QEMU to a headless session; seal-gate + WG services come up |
| C3 | Launch a real SEV-SNP VM; `postern-seal-gate` serves a live quote | `bin/seal_gate.rs`, cloud provider (Azure DCasv5 / GCP / bare EPYC) | C2; `/dev/sev-guest` | infra | L | Gate returns a real report‖VCEK‖WG-pubkey bundle from launched hardware |
| C4 | End-to-end: `postern-seal-verify` returns `Genuine` against the launched VM before the tunnel opens | `snp.rs`, `bin/seal_verify.rs`, `snp_vectors.rs` | C3; per-shape reference measurement `M` + HOSTDATA `P` | dev+infra | L | Fresh-nonce handshake → `SnpVerdict::Genuine`; tamper/replay → named `Rejected`; WG tunnel opens only after Genuine (**satisfies G3**) |
| C5 | Release-manifest pipeline: publish reference `M`, `P`, TCB floor per VM shape | `POSTERN-CLOUD.md §7` | C4 | infra | M | Signed manifest maps (image, firmware, shape) → expected values; verifier consumes it |
| C6 | TDX secondary: replace the fail-closed stub with real Intel TDX quote verification | `tdx.rs` (stub today) | Intel TDX hardware; DCAP/QVL | dev+infra | L | TDX quote from launched hardware verifies; still fail-closed on any gap |
| C7 | Fleet key-release variant: LUKS `/persist` key via org KBS (Trustee) gated on a Trusted verdict | `cloud.nix` `/persist` LUKS notes | C4; Enterprise E4 | dev+infra | L | Key released only on Genuine attestation; provider holds ciphertext only |

**Flip to "built · tested" when:** C1–C5 done — an image we build, a VM we launch,
a verifier that returns `Genuine` on a real quote and `Rejected` on every tamper.
Until then the site stays `design / spec`, and SEV-SNP claims stay hardware-gated
(**G3**). TDX (C6) and fleet key-release (C7) can flip independently, later.

---

## Item 2 — Postern Container (Android)

**Foundation:** `mobile/core` (built+tested wallet core, UniFFI-exported) ·
`mobile/android/` app skeleton · `docs/specs/POSTERN-CONTAINER.md`. The
*defining* piece (the DPC / managed-profile isolation) is unstarted.

| # | Milestone | Foundation it builds on | Deps | Owner | Effort | Acceptance criteria |
|---|---|---|---|---|---|---|
| K1 | Build `bloch-mobile` for `aarch64-linux-android`; drop real `.so` into `jniLibs/` | `mobile/core` (UniFFI done), `build-android.sh` | cargo-ndk, Android SDK/NDK | dev | M | Native lib builds; UniFFI Kotlin bindings generated (replace `PLACE_*_HERE` placeholders) |
| K2 | Wallet app shell runs on a device/emulator against a node RPC | `mobile/android/` skeleton, `NodeRpc.kt`, `WalletViewModel.kt` | K1 | dev | M | App installs, unlocks wallet, shows balance/tx via node RPC; golden byte-compat test vs node passes |
| K3 | StrongBox key + Key-Attestation plumbing | `StrongBoxKey.kt` (stub), spec §"Key protection" | K2; StrongBox-capable device | dev | M | Non-exportable StrongBox key generated with verifier nonce as attestation challenge; X.509 chain retrieved |
| K4 | **DPC: self-enrolled managed profile** (the actual container) | spec §"Isolation model" — **absent today** | K2; `DevicePolicyManager` | dev | L | "Create Postern Container" provisions a work profile with separate FBE storage; container apps run as separate user |
| K5 | Container lockdown policy | spec §"Critical pieces" | K4 | dev | M | Screenshots disabled, unknown sources blocked, secure IMEs enforced, per-profile always-on lockdown VPN set |
| K6 | Always-on Tor VPN (Orbot `VpnService`), container-only | spec §"Private-by-default networking" | K5 | dev | M | Container traffic is Tor-only, cannot leak outside tunnel; personal profile networking untouched |
| K7 | Verify Key-Attestation chain in the `mobile` attestation backend | `postern-core` transcript, spec §4 | K3; Google attestation root | dev | M | Verifier chains the Key-Attestation X.509 to Google's CA, checks verified-boot state + nonce; fail-closed on mismatch |
| K8 | Optional Play Integrity verdict | spec | K7; Play Integrity API | dev | S | Device/app integrity verdict surfaced (honest: trusts Google) |

**Flip to "built · tested" when:** K1–K7 done — a real managed-profile container with
StrongBox-backed keys, Tor-only networking, and a Key-Attestation chain that
verifies. Keep the spec's own honest limits visible in-product (**not a separate
OS; mobile TEE is classical P-256; attestation trusts Google + the vendor; needs
a StrongBox device**). Attestation claims stay hardware-gated (**G3**): a chain
that verifies against a real device's Keystore, not an emulator.

---

## Item 3 — Enterprise edition

**Foundation:** Consiglio (`apps/postern-enterprise/index.html`, rich front-end
prototype) · Chiave (`apps/postern-login/index.html`, wallet-as-login flow) ·
`bloch-crypto` wallet/HD-wallet/`postern-vault`/`postern-panic` (built) ·
`docs/specs/POSTERN-ENTERPRISE.md` + `POSTERN-IDENTITY.md`. The identity *model*
reuses built crypto; the *governance backend* is entirely absent.

| # | Milestone | Foundation it builds on | Deps | Owner | Effort | Acceptance criteria |
|---|---|---|---|---|---|---|
| E1 | Wallet-as-login (Chiave) as a real, testable ceremony (not browser stand-ins) | `bloch-crypto` wallet/crypto/hd_wallet, `postern-vault`, Chiave flow | — | dev | M | Setup → seed → sealed keyfile (Argon2id + AES-256-GCM) → local challenge-sign login; unit + integration tested |
| E2 | Postern Directory (self-hosted directory of record) | spec §3.2 — **absent** | E1 | dev | L | Org provisions/certifies/revokes device keypairs; directory assertion issued + verifiable |
| E3 | OIDC / SAML federation to an existing org IdP | spec §3.2 | E2 | dev | L | Login federates to an external IdP; assertion maps to a Postern org identity |
| E4 | M-of-N dual-control escrow quorum service (real, not `localStorage`) | Consiglio escrow UI, spec §3.4 | E1 | dev | L | Escrow release / data access needs M-of-N officer signatures; **no single admin** can; tamper-evident audit entry emitted |
| E5 | Tamper-evident audit chain with dual-custody replica | Consiglio audit-chain UI, spec §7 | E4 | dev | M | Append-only hash-chained audit with compliance-officer countersignature; verifiable off the primary host |
| E6 | Instant deprovision / revocation | spec §6.2 | E2, C7 | dev+infra | M | Directory assertion stops, volume keys stop releasing (ties to Cloud KBS), sessions killed |
| E7 | Consiglio wired to the real backend (retire the `localStorage` stand-ins) | Consiglio front-end | E2–E6 | dev | M | Console drives the live directory/escrow/audit services; no fake state |
| E8 | Chinese-Wall (Brewer–Nash) policy engine enforced on devices | Consiglio segment editor, spec §"barriers" | E7 | dev | L | Segment assignments enforced at the device policy layer, not just visualized |

**Flip to "built · tested" when:** E1–E7 done — a real directory, real M-of-N escrow,
a verifiable audit chain, and Consiglio driving them (not `localStorage`). Keep
Consiglio's `reference prototype` badge until then. **The `NOT LEGAL ADVICE`
framing stays on every surface** — these controls *enable* compliance work
(LGPD/GDPR/CCPA); they never certify it, and each `LEGAL DETERMINATION REQUIRED
(DPO/counsel)` flag in the spec must survive into the product.

---

## What's realistic in 3 / 6 / 12 months (honest)

These are large products. Agents produce designs, scaffolds, and tested Rust/UI
cores — **not** finished, audited, hardware-validated software. Every hardware or
backend milestone needs a Nix host, real devices/VMs, platform SDKs, and human
review no agent can self-certify. Realistic outcomes, given that:

- **3 months — Cloud reaches a real, demonstrable milestone.** Build
  `.#attested-image` and `cloud-image` on a Nix host (C1–C2), launch one SEV-SNP
  VM, and get `postern-seal-verify` to return `Genuine` end-to-end on a live quote
  with tamper/replay rejected (C3–C4). That is the single highest-value, most
  credible flip available. In parallel: Container K1–K2 (native lib + wallet shell
  on a device) and Enterprise E1 (real wallet-as-login ceremony) — all still
  `design`/`prototype` on the site, but genuinely progressing.

- **6 months — Cloud edition can honestly flip to `built · tested` (still
  unaudited).** C1–C5 complete: image, launched VM, verifier, release manifest.
  Container reaches K3–K5 (StrongBox keys + the DPC managed profile — the hard,
  defining piece — plus lockdown), likely not yet the full attestation chain.
  Enterprise reaches E1 + a first real backend service (E2 Directory *or* E4
  escrow), Consiglio still a prototype.

- **12 months — Container flips to `built · tested`; Enterprise substantially
  built.** Container K1–K7 done (managed profile, StrongBox, Tor-only, verified
  Key-Attestation chain on a real device) → honest flip. Enterprise reaches
  E1–E6 with Consiglio wired to a live backend (E7) — a defensible flip if the
  Chinese-Wall enforcement (E8) is at least in progress. Cloud picks up TDX (C6)
  and fleet key-release (C7).

**What does NOT happen in 12 months (state it plainly):** third-party security
audits (none contracted for these three — the `unaudited` badge stays on
everything, **G4**); removal of the SEV-SNP/TDX/Key-Attestation hardware gates
without real launched-hardware evidence (**G3**); any "compliant" claim for
Enterprise (only "enables compliance", DPO/counsel own the determination); and
turning "boots on QEMU" into "tested on hardware" for the OS images without
physical-hardware boots (**G2**).

**Sequencing recommendation:** fund **Cloud first** — it converts the most
existing, tested foundation into a real, on-hardware demonstration fastest, and
that demonstration (attestation-before-connect working on a launched confidential
VM) is the proof-point the whole "trust but verify" thesis rests on.
