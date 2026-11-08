# Postern OS & Platform — Gap Analysis

Architect A1 (fable5), read-only pass. Repo: `bloch-protocol` (branch
`roadmap/wave1-base`). Site claims read from `bp-wt-site/site/build.js` (the OS &
platform section, lines ~468, 900–911, 1044–1109).

**Legend**
- **DONE** — host-proven here (builds/tests pass on the macOS dev host, against
  fixtures where a TEE/device is unavailable).
- **SCAFFOLD** — code/profile exists and is idiomatic, but **unbuilt/unbooted**
  in-repo (the dev host has no Nix), or built off-repo but never verified here.
- **MISSING** — no code/artifact exists yet.
- **OVERCLAIMED** — the site asserts more than the repo can prove.

**Prove-tier**
- **HOST** — a Rust/`cargo` box (any OS, incl. this macOS host). No Nix needed.
- **VM** — a Linux + Nix (+ flakes, + QEMU) host. Gated *only* by "no Nix here."
- **HW** — real measured-boot / TEE / phone hardware. Cannot be faked in a VM.

The repo's honesty discipline is excellent — every profile self-labels
"written, not built / built ≠ booted / QEMU ≠ hardware," and the site badges
match. The gaps below are therefore mostly **maturity/proof** gaps, not
dishonesty gaps. The one true site-vs-repo overclaim is the x86 QEMU-boot
validation (no in-repo harness or evidence for it).

---

## The recurring gap, quantified

Almost everything OS-side is blocked on exactly one of three tiers:

**Blocked only on a Linux+Nix VM (no hardware needed) — the biggest bucket:**
- `flake.lock` generation + `nix flake check` (flake is authored on non-Nix mac,
  no lock committed).
- `nix build .#iso / .#desktop-iso / .#mobile-image / .#attested-image /
  .#cloud-image` — all "written, not built" here.
- `seal-gate.nix`: resolve the 5 `lib.fakeHash` `outputHashes` sentinels
  (fail-closed by design) and add a `.#seal-gate` flake output.
- QEMU x86_64 boot of node/desktop ISOs (no harness exists — see below).
- QEMU aarch64 boot of the mobile image via `os/boot-harness/` (harness exists,
  **never run**).
- Waydroid/Sloboda bring-up (binder kernel config + `waydroid init`).

**Blocked on real measured-boot / TEE / device hardware:**
- TPM2 PCR measurement of the attested image (roothash → PCR binding).
- Live `/dev/sev-guest` on a **real SEV-SNP VM** (seal-gate live report + gate).
- A **real TDX instance** + a populated (non-placeholder) Intel SGX Root CA.
- First **PinePhone** boot of the mobile image; first **postmarketOS device**
  boot of the pmOS apks.
- StrongBox key-attestation on a real Android device.

**Genuinely doesn't exist yet (MISSING code/values):**
- x86_64 QEMU boot harness / CI + any committed boot evidence.
- `.#seal-gate` flake output (packaging file exists, orphaned).
- Secure Boot / signed-shim signing.
- A **verified** `os_roothash` value (attested.nix ships a design-reference
  placeholder).
- The mobile touch wallet **UI** (mobile.nix ships the engine only; UI "tracked
  separately").

---

## Capability-by-capability

### OS images

| # | Capability | Status | What's missing | Tier | Prio | Effort |
|---|---|---|---|---|---|---|
| 1 | **Node appliance ISO** (`.#iso`, `os/configuration.nix` — mines on boot, hardened `services.bloch`) | SCAFFOLD | Built + signed off-repo (on R2); not built here (no Nix), no `flake.lock`, no in-repo boot proof; hardware boot pending | VM to reproduce/QEMU-boot; HW for real install | P1 | M |
| 2 | **Desktop ISO** (`.#desktop-iso`, `os/desktop.nix`+`browser.nix` — GNOME/GDM Wayland, LUKS+TPM2, Tor, DoT/DNSSEC, hardened Postern Browser) | SCAFFOLD | Same as node: off-repo build, unbuilt/unbooted here; hardware boot pending | VM / HW | P1 | M |
| 3 | **Mobile image** (`.#mobile-image`, `os/mobile.nix`+`telephony.nix`, Mobile-NixOS PinePhone) | SCAFFOLD | Least-proven: built+signed off-repo but **never booted anywhere** (not even QEMU). Mobile-NixOS output attr may drift per pinned rev | VM (QEMU-aarch64 via boot-harness) → HW (PinePhone) | P1 | M |
| 4 | **Attested / measured-boot image** (`.#attested-image`, `os/attested.nix` — dm-verity erofs root, UKI, systemd-repart, TPM2 measured boot, `roothash=` → `attestation::read_os_roothash`) | SCAFFOLD | Written, not built; **`os_roothash` is a design-reference placeholder, not a verified value**; measured-boot chain never exercised; repart/verity/UKI option drift risk | VM to build; **HW (TPM2)** to prove PCR measurement | P1 | L |
| 5 | **Mobile wallet touch UI** (referenced by mobile.nix as "app layer on top") | MISSING | mobile.nix ships the wallet **engine** only; the UniFFI/web mobile shell is "tracked separately" — no UI in this profile | HOST/VM | P2 | M |

### Seal & attestation (`crates/postern-seal-companion`)

| # | Capability | Status | What's missing | Tier | Prio | Effort |
|---|---|---|---|---|---|---|
| 6 | **Peer-verify / self-audit core** (default build: `AttestationReport`, `Expected`, fail-closed without a trust anchor, PQ-signature check via `bloch_crypto`) | DONE (host, unaudited) | Nothing structural — builds/tests on host. Unaudited; needs a real running OS to self-audit `os_roothash` against (ties to #4) | HOST | — | — |
| 7 | **SEV-SNP report verify** (`snp.rs`, feat `sev-snp`: parse report, VCEK→ASK→ARK to pinned AMD root, HOSTDATA/measurement/TCB, **AMD-KDS CRL** freshness) | DONE-vs-fixture / SCAFFOLD-vs-hardware | Crypto path proven offline against a **real Milan** report+VCEK fixture (`testdata/`), host-runnable (`--features sev-snp`). **Never run against a live `/dev/sev-guest` / real SEV-SNP VM** — "gate handshake → Genuine" is untested | HOST (done) → **HW** (real SEV-SNP) | P2 | M |
| 8 | **TDX quote verify** (`tdx.rs`, feat `tdx-verify`: DCAP quote parse, PCK→Intel CA→pinned Intel SGX Root CA, QE-report binding, CRL) | SCAFFOLD (fail-closed) | **Pinned Intel SGX Root CA is a placeholder → never returns `Genuine` on this host by design.** Crypto exercised only vs a **synthetic** anchor in tests. Needs the real Intel root pinned + a real TDX instance | HOST (partial) → **HW** + populate root | P2 | M |
| 9 | **Mobile Key-Attestation** (`mobile.rs`, feat `mobile-attest`: parse StrongBox/TEE X.509 chain to pinned Google root; nonce/verified-boot/patch/app-id) | SCAFFOLD | Attests the *phone*, not the workspace; pinned Google root is a "moving target"; never run against a real device attestation. (Backs Porog's `StrongBoxKey.kt`) | HOST (fixtures) → **HW** (Android device) | P2 | M |
| 10 | **Seal gate** (`gate.rs` + `snp.rs` live acquisition: guest-side attestation-before-connect endpoint, reads `/dev/sev-guest`, fail-closed non-TEE guards) | SCAFFOLD | Live report acquisition needs a real SEV-SNP VM; non-TEE host correctly fails closed. Wire format + binding are TEE-independent and host-testable | HOST (guards) → **HW** (live gate) | P2 | M |
| 11 | **`seal-gate.nix` packaging** (`.#seal-gate` build of the gate + verifier bins) | SCAFFOLD / MISSING output | **Not wired into `flake.nix`** (no `.#seal-gate` output; only `os/cloud.nix` calls it via `callPackage`). All 5 `cargoLock.outputHashes` are `lib.fakeHash` sentinels → **un-buildable until filled on a Nix host** (deliberate fail-closed). Cargo.lock has a dual-git-rev dedupe caveat | VM | P1 | S |

### Platform editions

| # | Capability | Status | What's missing | Tier | Prio | Effort |
|---|---|---|---|---|---|---|
| 12 | **Cloud / Chiostro confidential-VM** (`os/cloud.nix`, `.#cloud-image`: repart, LUKS `/persist`, `sev-guest`/`tdx_guest` modules, seal-gate systemd unit as the only pre-attestation listener :16510, Seal-gated WireGuard) | SCAFFOLD | Written, not built/booted. Per-provider firmware/measurement/HOSTDATA unverified. Depends on #11 (seal-gate build) + #7/#8. Managed-node service is "a promise, no cryptography" | VM to build → **HW** (real SEV-SNP/TDX cloud instance) | P2 | L |
| 13 | **postmarketOS community edition** (`pmos-overlay/`: APKBUILDs for postern / -wallet / -apps / -flavor, phosh flavor, nftables+Tor, first-run) | SCAFFOLD | 3 apks built + **signed + published to R2 repo (live)**, but **never device-booted**; software keystore; no reproducibility/attestation claim (by design — non-attestable tier) | HOST (build apks) → **HW** (pmOS device) | P3 | M |
| 14 | **Sloboda — Waydroid escape hatch** (`os/sloboda-compat.nix` + `apps/sloboda` wrapper: binder kernel config, waydroid+LXC, compositor) | SCAFFOLD / DESIGN | Never evaluated/built; no Android container ever booted. **Deliberately non-attestable**, structurally excluded from the seal closure (never imported into any attested profile; RO-root assertion tripwire). Play-Integrity STRONG fails by design | VM (binder-capable kernel, `waydroid init`) | P3 | M |
| 15 | **Porog / NoporIS** (Android managed-profile + dual-persona bridge: `AttestationGateway.kt`, `apps/noporis-*`, `apps/porog-*` glue crates) | SCAFFOLD / DESIGN | StrongBox key-attest skeleton exists (#9); self-enrolled-DPC / managed-profile isolation + Tor-only egress are design/spec, largely unstarted. **Key-attested device, not measured-boot workspace**; never "Postern OS". Proposed names, pending trademark | HOST (glue) → **HW** (Android) | P3 | L |

### Boot / verification infrastructure

| # | Capability | Status | What's missing | Tier | Prio | Effort |
|---|---|---|---|---|---|---|
| 16 | **aarch64 QEMU boot harness** (`os/boot-harness/boot-qemu-aarch64.sh` + `check-boot-log.sh` + shared `success-markers.txt`; `.#boot-qemu` app) | SCAFFOLD | Well-built marker ladder (bootloader→kernel→stage-1→systemd→login), but **never run** (no Nix/QEMU here). Interactive `bloch-wallet --help` + CI wiring are follow-ups | VM | P1 | S |
| 17 | **x86_64 QEMU boot harness / CI** | **MISSING (OVERCLAIMED)** | Site says node+desktop ISOs are "**boot-validated on QEMU x86_64**," but **no x86 boot harness, no committed boot log/evidence** exists in-repo — the validation (if done) happened off-repo, same as the R2 ISO builds. No reproducible x86 boot-check | VM | P2 | S |
| 18 | **Secure Boot / signed-shim signing** | MISSING | ISOs not signed for MS-endorsed Secure Boot; user must disable SB or enroll own keys. "Signed-shim support is planned, not shipped" | HW/infra | P3 | M |
| 19 | **Two-builder bit-for-bit reproduction** (the core "reproducibility is the product" claim) | MISSING | No `flake.lock`, so nobody has rebuilt any image to a matching hash; "reproducible-by-design ≠ reproduced" (flake header). Independent second-builder confirmation absent | VM (×2 builders) | P1 | M |
