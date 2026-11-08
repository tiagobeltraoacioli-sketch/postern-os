<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Postern Labs — product roadmap (owned; a company plans and builds these)

**Layer: the owned products.** This is a real roadmap in the ordinary sense: a
company — **Postern Labs** — plans, builds, sequences, and is accountable for
everything on it. It is the deliberate opposite of
[`BLOCH-ROADMAP.md`](BLOCH-ROADMAP.md), which lists open items on the
**ownerless** Bloch-SIS-PoW protocol that no one (Postern included) owns or
schedules.

**The rule that separates the two** (see [`POSTERN-LABS.md`](POSTERN-LABS.md),
also published as `public/Postern-Two-Layers.pdf`): *the base is ownerless;
anything with an operator, a service, or a "who runs it?" answer is a Postern
product.* That is why the **Layer-2 RWA / BaaS products are on THIS
roadmap** — they have an operator (Postern) — while the base they anchor to
stays on the ownerless list. *(Checkpoint finality — **FFG-BFT** — is **not** a
Postern product: it is a gated **protocol-level finality overlay** on the
ownerless base and lives on [`BLOCH-ROADMAP.md`](BLOCH-ROADMAP.md), not here.)*

**Money hygiene, stated once:** the coin (BLCH) is **not a security and not an
asset**; Postern's revenue is software, support, signed builds, and
enterprise/service lines — it **never touches the token**. Personal products
are free; corporate is where revenue lives.

This document and [`BLOCH-ROADMAP.md`](BLOCH-ROADMAP.md) together **replace
the old single "Future Roadmap" PDF** that mixed both layers. Grounding docs:
[`PROJECT-STATUS.md`](PROJECT-STATUS.md),
[`POSTERN-APPS-ROADMAP.md`](POSTERN-APPS-ROADMAP.md) (per-app license tables),
[`EVOLUTION.md`](EVOLUTION.md), [`gap/00-postern-systems-inventory.md`](gap/00-postern-systems-inventory.md).

> **Honesty baseline:** everything here is **unaudited**. Statuses below are
> the repo's real state, not aspiration. If a claim isn't true yet, it is
> phrased as the plan — and a plan is all it is.

**Status markers:** `done` · `in-progress` · `candidate` (planned, not
started) · `blocked-on-audit-or-hardware`.

---

## 1. Postern Suite — the desktop flagship and its cores

The flagship path (Decision D1, [`EVOLUTION.md`](EVOLUTION.md)): Postern
Desktop reborn as a privacy toolbox, with **Hygiene as the wedge**. The cores
are built, tested Rust crates; the product work is UI, packaging, and honesty
text in every pane.

| Item | Status | Notes |
|---|---|---|
| **Hygiene** (`crates/postern-hygiene`) — metadata scrub (OOXML/JPEG-EXIF/PDF) + opt-in seal | `done` (core + `check` dry-run CLI + ODF path + **`--json` machine report + stdin/stdout embed-hook mode** (`scrub -`/`check -`, tested black-box) + **Suite GUI pane** wired to the Tauri command) / `in-progress` (GUI polish; OS/file-manager embed not wired yet) | The ethos-defining app; CLI ships as static signed binaries. JSON `format` token is `ooxml` for ODF too (single library variant, documented). |
| **Vault** (`crates/postern-vault`) — AEAD-sealed secrets, tamper-detected, zeroized | `done` (core + **TOTP (RFC 6238) + typed encrypted notes** folded in) / `in-progress` (OS-keychain/TEE key-wrap, UI) | Desktop keychain honesty text: "not a TEE until Container." |
| **Courier** (`crates/postern-courier`) — P2P file drop over ephemeral Tor onion, hybrid ML-KEM-1024+X25519 seal | `done` (seal/open core + DropTransport trait + **real Arti onion transport** carrying a signed drop frame, verified-receive wiring; folded into the Suite; runnable two-terminal `examples/onion_drop.rs` CLI — verified-receive only, offline unit tests, clippy-clean; **a live in-process Arti onion round-trip HAS now been performed + transcribed, BOTH variants** — bare seal AND the ML-DSA-signed verified-receive drop: publish → real Tor circuit → fetch through the DropSender/DropFetcher seam → (verify signature FIRST, replay-guard) → open the original plaintext, 2026-07-16, evidence: [`crates/postern-courier/evidence/live-onion-drop.evidence`](../crates/postern-courier/evidence/live-onion-drop.evidence); it is a PLUMBING proof only — NOT an anonymity/security claim, classical onion crypto, length-revealing AEAD) / `in-progress` (the live round-trip is network-timing-dependent — the signed variant needed a second run to catch a descriptor-propagation window, honestly transcribed; the live tests stay `#[ignore]` + `POSTERN_LIVE_TOR=1`-gated, never CI; UI polish) | Beats OnionShare's model without GPL code. `postern-tor` gained an onion status/`wait_reachable` API for it. The live run also found + fixed a host-only rustls crypto-provider gap and a service-teardown ordering race (no gate weakened, no GPL binary fetched). |
| **Keys** (`crates/postern-keys`) — passkey/FIDO2 credential core | `done` (ES256 core + PRF-extension credential v2 + **passphrase-sealed versioned credential export/import** (Argon2id+XChaCha20 via postern-core) + **Suite Keys pane**) / `in-progress` (full UI) | At-rest is Argon2id+XChaCha20 today; TEE key-wrap is planned, not shipped. |
| **Seal Companion** (`crates/postern-seal-companion`) — user-facing attestation verifier | `done` (verify_report + self-audit) / `blocked-on-audit-or-hardware` (real SEV-SNP/TDX quote end-to-end) | The differentiator made tangible; real-TEE wiring needs rented confidential-VM hours. |
| **Panic Lock** (`crates/postern-panic`) — instant re-lock, deny-not-destroy | `done` (core) | Destructive-erase variant stays deferred (D9) — an ethics call, kept. |
| **Quarantine** (`crates/postern-quarantine`) — rebuild untrusted files safely | `done` (image path + **pure-Rust flat-PDF rebuild core** from page rasters) / `in-progress` (office paths, renderer wiring) | — |
| **Tor layer** (`crates/postern-tor`, Arti in-process) | `done` (node RPC over Tor, Desktop-wired) / `in-progress` (WireGuard/boringtun, mobile FFI) | — |
| **Suite v0.1** — fold the cores into the Tauri desktop app; node/wallet demoted to an "Advanced / testnet (zero value)" tab | `in-progress` (**four cores folded**: `hygiene_scrub` + `vault_totp_code` + `courier_*` + `keys_*` Tauri commands, capability-scoped + tested; **frontend panes** for Hygiene/Vault/Courier/Keys with per-pane honest caveats; **node/wallet/miner demoted** to an "Advanced / testnet (zero value)" section) | Per-pane honesty text is a shipping requirement, not a nice-to-have. Remaining: real packaging/signing + polishing the panes. |
| **Packaging** — Tauri bundles (Linux/macOS/Windows), signed checksums (Falcon‖ML-DSA + minisign), **TUF update channel** (`tough`) | `in-progress` (**TUF channel scaffolded** in `packaging/`: tough-based metadata + signed-bundle build script + roundtrip test; **root rotation** per TUF 5.3.4 dual-sign with crash-recoverable key swap + **snapshot/timestamp refresh** — dev keys only, LOCAL metadata, no endpoint; rotation/refresh/expiry fail-closed tests) / `candidate` (the actual Tauri bundles) | Updates are where privacy apps get owned; the TUF core starts early. Reproducible where the platform allows. A lapsed dev repo rots by design (refresh cannot resurrect expired metadata); the real channel needs an explicit recovery/re-init design. |

## 2. Vestnik — the messenger

Renamed from "Postern Messenger" to **Vestnik** (Slavic *вестник*, "herald")
to steer clear of Meta's "Messenger" mark.

| Item | Status | Notes |
|---|---|---|
| E2EE core (`crates/postern-messenger`) — Megolm via vodozemac (Apache-2.0), offline roundtrip tested | `done` (core) | vodozemac's 2022 Least Authority audit covers vodozemac, not this product. |
| Matrix client (matrix-rust-sdk, feature-gated `matrix` slice: login/sync, fail-closed room tiers, tier-gated E2EE send, session save/restore; persisted `SavedSession` now **PQ-sealable at rest** via `SavedSession::seal_to`/`open_sealed` — postern-courier hybrid X25519+ML-KEM-1024, caller-opt-in) + UI | `in-progress` (library slice, offline-tested only — live login/sync/send are `#[ignore]`d, never booted in CI; no UI; sealing covers the SavedSession blob only, machine-checked in `matrix::SEALED_SESSION_LIMITS`) | Never fork Element (AGPL). Sqlite store passphrase stays SDK-layer-only (NOT PQ-vault-wrapped); Tor not wired for this client; recipient-secret custody is the caller's (vault wiring = desktop layer). UNAUDITED. |
| Honest limits, shipped in-product | standing | Homeserver sees the social graph (mitigate: self-hosted homeserver + Tor + no phone numbers); **Megolm is classical, not PQ** — at-rest keys PQ-wrapped in the Vault; transport E2EE classical pending upstream Matrix PQ. |
| Federation/bridges | `candidate` | Design: [`specs/POSTERN-MESSAGING-INTEROP.md`](specs/POSTERN-MESSAGING-INTEROP.md). |

## 3. Postern OS — the images

All images are unaudited and honestly labelled; "hosting a signed image is not
attestation."

| Item | Status | Notes |
|---|---|---|
| **Node ISO** (x86_64, `.#iso`) — hardened node, mines on boot | `done` (built, hosted, release-signed, **boots on QEMU x86_64**) / `blocked-on-audit-or-hardware` (first hardware boot) | The QEMU boot is new since the last consolidated status; hardware boot remains the headline pending proof. |
| **Desktop ISO** (x86_64, `.#desktop-iso`) — hardened GNOME daily-driver profile + Postern Browser + FDE/Tor/DoT | `done` (built, hosted, signed, QEMU-boots to GDM) / `blocked-on-audit-or-hardware` (hardware boot) | UI is hardened GNOME, not the concept-video shell (video is labelled "design preview"). |
| **Mobile image** (aarch64/PinePhone, Mobile NixOS) — wallet-first, no mining | `done` (a signed image is hosted) — **rung-0 EVAL now PASSES on a real Nix host** (777-derivation plan, rc=0); the real build got through ~770/777 and **needs a native aarch64 builder** for the last leg; **never boot-tested** yet | Root cause found + fixed: mobile-nixos is **actively maintained** (rev 2026-07-12) and tracks **`nixos-unstable`**, not a stable release — so 25.05/24.11/24.05 all failed. Fix: a mobile-only `nixpkgs-mobile` input on nixos-unstable (contained) + `lib.mkForce` on our getty greeting; the **"blocked-on-upstream" verdict is retracted.** The `nix build` on the x86_64 Fly host then died building `bloch-0.1.0` for aarch64 — **qemu-user emulation of the Rust toolchain crashes** (107 crash signals; not a code bug — the flake says the image must be built natively/cross, never emulated). **Next: build on a native aarch64 host (AWS Graviton) → artifact → QEMU boot.** Evidence: attempt 7 in `os/boot-harness/evidence/aarch64-mobile-boot.evidence`. |
| **postmarketOS community edition** — 3 signed apks on a live aarch64 repo | `done` (published) / `blocked-on-audit-or-hardware` (never device-booted) | F-Droid-style self-hosted repo model. |
| **Postern Seal** — dm-verity + UKI + measured boot → `os_roothash` → `getattestation`/`verify()` | `done` (L1 repro digest verified; L2 hardening verified; `verify()` tested on host) / `blocked-on-audit-or-hardware` (real SEV-SNP/TDX host) | — |
| **Terem** (OS portal v2) — run foreign apps/OSes in VMs from the sealed base | `in-progress` — `terem-core` has dry-run launch plan + mock QMP client + a **real `qemu-system` spawn path** (opt-in, `#[ignore]`-gated live test) with license-safe defaults; **marker boot executed once live** (2026-07-16, operator-run: SeaBIOS executed the 512-byte in-repo fixture sector to the `TEREM-LIVE-QEMU-MARKER-V1` serial marker under an operator-supplied QEMU 11.0.2 — evidence: [`os-portal-v2/terem-core/evidence/live-qemu-marker.evidence`](../os-portal-v2/terem-core/evidence/live-qemu-marker.evidence)) | Default attested build ships zero GPL-linked code; QEMU/Wine paths are opt-in, user-fetched ([`os-portal-v2/LICENSE-DECISION.md`](os-portal-v2/LICENSE-DECISION.md)). Spawn path compiles + unit-tests; **no VM boots in CI** (both live tests stay `#[ignore]` + env-double-gated, never CI gates). The one-time marker run is NOT "an OS booted" and NOT an isolation/TEE claim — a real guest-OS boot needs a real guest image and remains unclaimed. |
| **Porog / NoporIS / Sloboda** (Android bridge tier) | `in-progress` (Porog: real StrongBox key-attestation skeleton) / `candidate` (the rest: design + scaffolds, not shipping) | Honest tier where data leaves the sealed base; Sloboda is never Seal-covered, by design. |
| **Kalinov Bridge** (Postern backups on Filecoin) — the *Kalinov* bridge between worlds, a **Bloch ↔ Postern ↔ Filecoin** path for private user backups of Postern OS files: sealed client-side with the **Postern seal** (XChaCha20-Poly1305) *before* leaving the sealed base, then stored on **Filecoin** (ciphertext only — Filecoin never sees plaintext; keys never leave the device). Post-quantum integrity/authenticity via a **SHAKE-256** manifest signed **ML-DSA-65 ‖ Falcon**, anchored to the ownerless Bloch base as an ordinary **zero-value on-chain commitment** ("DATA0"). Tagline: *"Bloch-SIS-PoW + Postern Labs + Filecoin — privacy and post-quantum security for your Postern OS files."* | `candidate` (design doc + scaffold crate being written now; **nothing operational, nothing audited, no file protected by this today**) | The "who runs it?" answer is the user's own device for the seal + Filecoin as a dumb ciphertext store, so this is a **Postern product**, not a base item. Filecoin sees only ciphertext; the ownerless base sees only a zero-value anchor tx (no file bytes, no metadata). **Designed ≠ built ≠ booted.** Unaudited; BLCH is **not a security** and revenue never touches the token. |

## 4. Wallet, Desktop, Explorer (chain-facing products)

These consume the ownerless protocol via RPC — they are Postern products, not
"official" anything. Their value inherits the chain's zero-security testnet
status and they say so.

| Item | Status | Notes |
|---|---|---|
| Postern Wallet core (`mobile/core` + UniFFI) — byte-compatible with the node | `done` | Golden-tested; lean cross-compile verified. |
| Android/iOS wallet shells on real SDKs (cargo-ndk / xcframework) | `blocked-on-audit-or-hardware` | Needs platform SDKs + devices. |
| Phone-as-signer (mobile↔desktop pairing, PQ-hybrid channel) | `done` (v1 reference interop) / `candidate` (v2 unified wire) | "Reference of the shape, not a shipped feature." |
| Postern Desktop (Tauri node companion) | `done` (builds; node ctl, wallet, send-tx, miner, logs) | Becomes the Suite host (§1). |
| Bloch Explorer / Blochscan | `done` (deployed) | Like mempool.space: an independent product on an ownerless chain. |

## 5. Layer-2 products — EVM L2, RWA, BaaS (owned; anchor to the ownerless base)

These are on the **Postern** roadmap — never the Bloch one — because each has
an operator. The base's consensus stays **pure PoW**; these products anchor to
it by writing **ordinary transactions**, never by changing a base rule.

> **FFG-BFT finality is not a Postern product and is not on this roadmap.**
> Checkpoint/BFT finality over the base has been **reclassified as a
> protocol-level finality overlay on the ownerless Bloch-SIS-PoW base** — a
> **Bloch protocol item**, gated and tracked in
> [`BLOCH-ROADMAP.md`](BLOCH-ROADMAP.md), not here. Because a finality overlay
> anchors checkpoints as ordinary transactions and has **no operator**, it
> belongs to the protocol, not to Postern. The reference scaffold code
> (`bft/postern-bft-finality`, `ffg/`) and its design spec
> ([`specs/POSTERN-FFG-BFT-FINALITY.md`](specs/POSTERN-FFG-BFT-FINALITY.md))
> stay in-repo, **reclassified — not deleted**.

The **EVM L2** below follows the same rule: it has a sequencer (an operator),
so it is an owned product; it anchors state to the base as **ordinary
transactions** and needs no base consensus change. Everything shipped for it
today is a **SCAFFOLD, UNAUDITED, not a working L2** — compiling skeletons plus
honest stubs, testnet / zero-value only. An L2 inherits its L1's finality, so
this one inherits the base's **k=4-forgeable, 51%-attackable, unaudited**
security: a base reorg can unwind anchored L2 state. Real value is gated on the
base security ramp (k=8, WAN hashrate, checkpoint finality) **plus** a
third-party audit **plus** legal review.

| Item | Status | Notes |
|---|---|---|
| **Bloch L2 (EVM)** — zk-validity EVM rollup: execution core + sequencer + prover + base anchor, anchoring state roots to the ownerless base as ordinary txs | `candidate` (**SCAFFOLD / UNAUDITED — not a working L2**: compiling skeletons `l2/bloch-l2-{evm,sequencer,prover,anchor}` + honest labelled stubs, ~160 offline tests across the L2 crates; **not a node, not a real zk prover** — the `MockProver` proves nothing cryptographically; no ethereum/tests or EEST conformance claimed; testnet / zero-value) | Designed ≠ built ≠ booted. Native gas token is an L2 representation of bridged BLCH — zero issuance, never sold, never burned. Inherits the base's k=4/51%-attackable finality (see section note); real value gated on base security + audit + legal review. Design: [`specs/BLOCH-L2-EVM-DESIGN.md`](specs/BLOCH-L2-EVM-DESIGN.md). |
| **wBLCH bridge** (`l2/bloch-l2-bridge`) — BLCH ↔ L2 lock-and-mint wrapper (wBLCH), 1:1, no new issuance | `candidate` (**SCAFFOLD / UNAUDITED** crate + stubs; nothing operational, no value bridged, no custody wired) | The bridge is the highest-risk surface and is unaudited; do not rely on it for anything of value. Same finality inheritance as the L2. Design: [`specs/POSTERN-WBLCH-BRIDGE.md`](specs/POSTERN-WBLCH-BRIDGE.md). |
| **PosternDex** — AMM DEX on the L2 (wBLCH pairs) + cross-L2 asset bridge | `candidate` (**design only — no crate yet**: specs written, nothing built, nothing deployed, no liquidity, no offer) | Runs on the L2 above, so it inherits every caveat: testnet / zero-value, unaudited, k=4/51%-attackable base finality. No token pitch anywhere; BLCH is **not a security** and revenue never touches the token. Design: [`specs/POSTERNDEX-AMM-DESIGN.md`](specs/POSTERNDEX-AMM-DESIGN.md), [`specs/POSTERNDEX-BRIDGE-DESIGN.md`](specs/POSTERNDEX-BRIDGE-DESIGN.md). |
| **RWA** (real-world-asset settlement on the owned layer) | `candidate` (reference state kernels: deterministic in-process tests; state only in the owned layer; nothing operational or offered; legal review still a HARD GATE) | RWA state lives ONLY in the owned layer; the base has no knowledge of it — only 32-byte roots anchor as ordinary txs (no proofs, no DA). `LegalGate::NotObtained` is the only constructible value and no offer/sell/list op exists ([`specs/POSTERN-FFG-RWA-BAAS-REFERENCE.md`](specs/POSTERN-FFG-RWA-BAAS-REFERENCE.md)). |
| **BaaS** (blockchain-as-a-service anchored to the base) | `candidate` (reference state kernels: deterministic in-process tests; state only in the owned layer; nothing operational or offered; legal review still a HARD GATE) | N isolated tenant kernels, ONE batch anchor as ONE ordinary tx; same anchoring pattern; Postern is one L2 builder among many on an open rail ([`specs/BLOCH-PERMISSIONLESS-TOKENS-L2.md`](specs/BLOCH-PERMISSIONLESS-TOKENS-L2.md)). |

## 6. Enterprise and cloud (the revenue side)

Corporate is where Postern's revenue lives; personal products stay free. All
honest-labelled per the site's badge discipline.

| Item | Status | Notes |
|---|---|---|
| License spine / master-license generator | `done` (live at `/license/master`; offline-verified, no telemetry) | The one live enterprise endpoint. CRL endpoint merged, not deployed. |
| Consiglio (admin console, wallet-as-login, PQ verifier) | `in-progress` (reference prototype; 3 dual-control gaps closed + **RBAC enforced at runtime** (server-side `authorize(session_id, volume)` over live state) + **session-bound control plane**: `propose/approve/reject_change_by_session` resolve the acting admin from the live session store and re-read the role from the current enrollment — the reject hole that trusted a caller-claimed admin role is closed — + **dynamic Brewer–Nash wall on data access**: first granted dataset in a volume's conflict-of-interest class binds the user, competing datasets in the same class are denied fail-closed, history is bounded, purged on offboard, and snapshot-persisted (schema `/2`; old `/1` snapshots restore with an empty wall history). All with tests) | Still a reference prototype, unaudited; enforcement is userland, not a kernel boundary. It demonstrates controls that enable compliance; it is NOT compliance. |
| Ezekiel 1 (policy/governance engine) + Gramota (onboarding/KYC-for-orgs) | `in-progress` (reference prototypes) | Org-level diligence only — **never user-KYC** (constitutional; see EVOLUTION §3). |
| Sarto (`apps/postern-onboard`) — onboarding / managed-device policy configurator | `candidate` (**design-only**: a site product card and a real demo-video walkthrough exist; the `index.html` is an unaudited BYO-Claude-key scaffold, not a shipping app — nothing packaged, nothing deployed) | Managed-device policy is always visible to its subject, never covert (transparency is the product). Designed ≠ built ≠ shipped. |
| Org messenger on the **Vestnik core** + compliance-engine prototypes | `candidate` (designed, not shipping) | Employer-run ⇒ honestly "not fully private": bodies E2EE, org sees metadata, retention disclosed. |
| Chiostro (confidential-VM cloud profile) + managed-node service | `candidate` / `blocked-on-audit-or-hardware` (attestation code exists, unbuilt/unbooted; no real infra provisioned) | "A promise, not a proof" until real TEE hosts run it. |
| Postern Store / Depot (attested app + update channel: TUF, PQ signing, chain-anchored build hashes) | `in-progress` (**TUF-style role metadata core** — root/targets/snapshot/timestamp, thresholds, expiry, rotation — on the repo-poc, with tests; store prototype) | Honest chain use — anchoring hashes, never a token pitch. |

---

*Cross-links: the ownerless protocol's open items live in
[`BLOCH-ROADMAP.md`](BLOCH-ROADMAP.md); the layer split is defined in
[`POSTERN-LABS.md`](POSTERN-LABS.md) / `public/Postern-Two-Layers.pdf`.
Postern builds ON the base; it does not own, operate, schedule, or speak for
it.*
