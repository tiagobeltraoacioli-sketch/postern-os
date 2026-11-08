# Postern Labs — app portfolio roadmap

Which privacy/security apps to build on Postern OS (desktop + mobile) + the
container, judged against `PRINCIPLES.md` (privacy+security, honesty, audit-gated)
and the **permissive-license rule** (MIT / Apache-2.0 / BSD; MPL tolerated for
*unmodified aggregation* only per `deny.toml`; **AGPL/GPL = no fork, no embed**).
Each app names its building blocks and their licenses.

> **Scope note — this is the *apps subset*.** The full owned-products roadmap
> is [`POSTERN-ROADMAP.md`](POSTERN-ROADMAP.md) (suite cores + packaging, the
> OS images, Vestnik, Terem, the Layer-2 RWA/BaaS products, enterprise).
> This document deliberately stays narrower — per-app ordering, building
> blocks, and license tables — and does not duplicate the full roadmap. The
> ownerless protocol's open items live separately in
> [`BLOCH-ROADMAP.md`](BLOCH-ROADMAP.md), which nobody (Postern included)
> owns or schedules.

## Layer separation — what belongs to whom

Everything in this roadmap is **owned Postern Labs product**, separate from the
**ownerless Bloch-SIS-PoW base**. Keep the line explicit:

**Ownerless commons — Bloch-SIS-PoW (no owner, no company, no maintainers):**
the PoW consensus (SHAKE-256 hashcash + Module-SIS gate), the BlockDAG, the
post-quantum crypto (Falcon‖ML-DSA), the P2P network, and the coin. Anyone runs
a node; **nobody owns or operates it** (Bitcoin model).

**Owned Postern Labs products (built *on* the base, sold/operated by Postern):**
the apps, OS, wallet, vault, courier, messenger, hygiene, panic, keys — **and the
Layer-2 stack: RWA, BaaS.**

- **FFG-BFT finality is NOT a Postern product.** It has been **reclassified as a
  protocol-level finality overlay on the ownerless Bloch-SIS-PoW base** — a
  **Bloch protocol item** tracked (gated) in
  [`BLOCH-ROADMAP.md`](BLOCH-ROADMAP.md), **not** on this Postern roadmap. A
  finality overlay anchors checkpoints as **ordinary transactions** and has
  **no operator**, so it belongs to the commons, not to Postern; the base stays
  **pure PoW** and no base consensus rule changes. The reference scaffold code
  (`bft/postern-bft-finality`, `ffg/`) stays in-repo, reclassified — **not
  deleted**. **RWA** and **BaaS** remain owned Postern Layer-2 products anchored
  to the base. (Design scaffold today — nothing operational, audited, or secure.)

**The rule:** the base is ownerless; **anything with an operator, a service, or a
"who runs it?" answer is a Postern product** — never part of the commons.

## Ordered roadmap

| # | App | When | Status |
|---|---|---|---|
| 1 | **Tor / VPN layer** | **now** | ✅ **`crates/postern-tor`** (Arti in-process) + `json_rpc` over Tor + plugged into Postern Desktop (`rpc_tor`). Left: boringtun/WireGuard, UI toggle, Arti-on-mobile via FFI |
| 2 | **Document & media hygiene** | now / next | ✅ **`crates/postern-hygiene`** — scrubs OOXML/ODF + JPEG(EXIF) + PDF(Info/XMP) + opt-in `seal` (SHAKE-256 + caller signer); CLI with `check` dry-run, `--json` report, stdin/stdout embed-hook mode. Left: GUI polish, embed in the OS/file manager |
| 3 | **Vestnik** (Matrix messenger) | **next** | ✅ **`crates/postern-messenger`** — Megolm E2EE core (vodozemac), offline roundtrip tested. Left: the matrix-rust-sdk client (login/sync/rooms/calls) + UI. **Renamed from "Postern Messenger" → Vestnik** (Slavic *вестник*, "herald") to steer clear of Meta's "Messenger" mark ([`POSTERN-ROADMAP.md`](POSTERN-ROADMAP.md) §2) |
| 4 | **Postern Vault** (secrets) | next | ✅ **`crates/postern-vault`** — AEAD-sealed vault, TEE/Argon2 key, tamper-detected, zeroized. OS-keychain unlock now wired into the desktop vault pane (opt-in `vault-keychain` feature — SOFTWARE convenience, not hardware protection, honestly labelled). Left: TEE key-wrap (blocked: no real hardware) + UI polish |
| 5 | **Encrypted backup** | later | `rustic` engine; office = aggregate LibreOffice, never fork AOO |

---

## 1. Tor / VPN layer — **now** (container dependency)
Always-on, lockdown, per-profile Tor (see `POSTERN-CONTAINER.md`). Strategic
upgrade: **Arti** (MIT/Apache-2.0, Rust Tor in-process — no external app) +
WireGuard via **boringtun** (BSD-3-Clause). Start with Orbot (BSD-3) integration,
migrate to Arti.

## 2. Document & media hygiene — **next** (the ethos-defining app)
Metadata is a real, documented privacy hole (OOXML `docProps` author/company,
tracked changes, RSIDs, printer paths; PDF XMP; image EXIF/GPS). Three functions:
1. **Scrub** (default) — strip metadata across OOXML/ODF/PDF/images. Blocks:
   `zip`+`quick-xml` (MIT), `lopdf` (MIT), `kamadak-exif` (BSD-2), `img-parts`
   (MIT/Apache). Own it in Rust (auditable); avoid `mat2` (LGPL) / ExifTool (GPL).
2. **Prove** (opt-in) — SHAKE-256 digest + Falcon‖ML-DSA signature (in-house PQ
   stack), optional **hash-anchor to the Bloch chain** for third-party timestamping;
   **c2pa-rs** (MIT/Apache) for the C2PA provenance standard.
3. **Attest** — bind "sealed on a genuine Postern build" via Postern Seal.

Design rule (privacy vs provenance tension): **scrub by default, prove by opt-in**
(like view keys). Fold the **camera/media** capture (strip EXIF/GPS by default,
opt-in C2PA sign) into this app rather than a separate product.

**Office editing:** skip an Apache OpenOffice fork — AOO is at ASF "red" security
status (Jul 2025), maintenance-only, and cannot write OOXML. A permissive OOXML
*viewer* is tractable (`calamine`/`docx-rs`/`quick-xml`, all MIT). Full editing:
**aggregate unmodified LibreOffice** (MPL-2.0, flagged — never fork). **ONLYOFFICE
is AGPL — do not touch.**

## 3. Vestnik (Matrix messenger) — **next** (flagship comms)
**Renamed from "Postern Messenger" to Vestnik** (Slavic *вестник*, "herald") to
steer clear of Meta's "Messenger" mark — see [`POSTERN-ROADMAP.md`](POSTERN-ROADMAP.md)
§2. Text + voice/video, Megolm/Olm E2EE. Build a **fresh Apache/MIT client** —
never fork Element.

| Component | License | Use |
|---|---|---|
| Matrix spec · **vodozemac** (Olm/Megolm, Rust) · **matrix-rust-sdk** | Apache-2.0 | **yes** — the SDK does E2EE/sync/timeline |
| Element / Element X / Element Call | AGPL-3.0 | **no** — no fork, no code, no UI port |
| Synapse / Dendrite | AGPL-3.0 | users self-host only |
| continuwuity / Conduit (Rust homeservers) | Apache-2.0 | yes (verify continuwuity maturity) |
| **libsignal** | AGPL-3.0 | **no** — kills the "use Signal's crypto" path |
| libwebrtc | BSD-3 | yes (1:1 calls) · LiveKit SFU (Apache) for group later |

**Pin/vendor matrix-rust-sdk versions** (Element controls it; published Apache
versions stay Apache). **Honest limits:** the homeserver sees the **social graph**
(metadata — mitigate with a Postern/self-hosted homeserver + Tor + no phone
numbers); **Megolm is classical (not PQ)** — harvest-now-decrypt-later applies, so
v1 = "at-rest keys PQ-wrapped in the vault; transport E2EE classical pending
upstream Matrix PQ." Group calls (MatrixRTC) are a later phase.

## 4. Postern Vault — **next** (secrets manager on the TEE)
The container already builds StrongBox key-wrapping for the wallet; a secrets/
password manager is the **same vault engine, different UI** — highest reuse.
Blocks: RustCrypto/`orion` (MIT/Apache), `keepass-rs` (MIT, KDBX import), `rage`
(MIT/Apache, file encryption). **Avoid Bitwarden (GPL/AGPL), KeePassXC (GPL-2).**
PQ: hybrid-wrap the vault key (Falcon‖ML-DSA + ML-KEM).

## 5. Encrypted backup — later
Engine: **rustic** (MIT/Apache, restic-compatible) or restic (BSD-2). Crypto is
classical AES at rest — fine; PQ-hybrid-wrap the repo key with the Vault. Avoid
Cryptomator (GPL); Syncthing is MPL (aggregation-only).

## Contacts / calendar — later
Local-first vCard/iCal, optional self-hosted CalDAV. Rust ical/vcard crates
(MIT/Apache). **Avoid DAVx5 / Radicale (GPL)** — users self-host. Real value
(contact graphs are prime surveillance data) but low differentiation.

## Deliberately NOT built
A separate encrypted-photos vault on mobile — the managed profile's FBE already
encrypts at rest. Don't sell the same protection twice.

## License uncertainties to re-verify at adoption
continuwuity's maintenance health · LiveKit's current license · Orbot's exact
license text · the status of Matrix PQ MSCs · any future matrix-rust-sdk license
change (pin versions).

---

# Research round 2 — new candidate apps (Fable-5)

Beyond the ordered roadmap above, a second research pass proposed apps judged by
whether Postern's real differentiators (**attestation**, **PQ crypto**, **in-process
Tor**, **TEE wrapping**, **local-first**) make a genuine difference over stock FOSS.
**Core crates already built + tested this round are marked ✅.**

| App | Platform | What it is / differentiator | License notes | Status |
|---|---|---|---|---|
| **Seal Companion** | both | user-facing attestation verifier (self-audit + peer-verify). *The* differentiator made tangible; every "attestation-gated X" depends on it | `x509-parser`, `qrcode`/`rqrr` (MIT/Apache) | ✅ **`crates/postern-seal-companion`** (verify_report + self-audit) |
| **Courier** | both | serverless P2P file drop over ephemeral Tor onion, **ML-KEM payload seal** (beats OnionShare = GPL + classical) + hygiene scrub | `arti`, in-house ML-KEM (Apache/MIT); OnionShare GPL / magic-wormhole EUPL — concept only | ✅ **`crates/postern-courier`** (PQ seal/open) — **a live in-process Arti onion round-trip has now been performed + transcribed (2026-07-16), BOTH variants** (bare seal + ML-DSA-signed verified-receive): publish → real Tor circuit → fetch → verify → open. **PLUMBING proof only, NOT an anonymity/security claim** (classical onion crypto, length-revealing AEAD); live tests stay `#[ignore]` + `POSTERN_LIVE_TOR=1`-gated, never CI ([`POSTERN-ROADMAP.md`](POSTERN-ROADMAP.md) §1) |
| **Postern Keys** | both | passkey/FIDO2 authenticator, credential keys TEE-wrapped in the vault. Fills the identity gap (Bitwarden GPL/AGPL, KeePassXC GPL-2) | `passkey-rs` (MIT/Apache); webauthn-rs MPL (server-side, avoid) | ✅ **`crates/postern-keys`** (ES256 credential core) |
| **Quarantine** | desktop→both | inbound-doc safety: rebuild untrusted files from pixels/render in a sandbox (mirror of hygiene). Dangerzone concept (AGPL) reimplemented | `image` (MIT/Apache), PDFium (BSD), `landlock` (MIT/Apache); LibreOffice MPL aggregation | ✅ **`crates/postern-quarantine`** (image path; PDF/office documented) |
| **Deadbolt** | both | **Panic Lock** (instant re-lock, encryption — no destruction) + anti-forensics | `postern-vault`; native triggers (Apache) | ✅ **Panic Lock built — `crates/postern-panic`** (locks, never wipes → can't be misused for evidence-destruction). Destructive erase variant ⏸️ deferred. Spec `docs/specs/POSTERN-DEADBOLT.md` |
| **Depot** | both | attested update + app channel: TUF metadata, PQ signing, build hashes anchored to the chain (honest chain use, not a token) | `tough` (AWS, MIT/Apache); F-Droid GPL/AGPL — no code | later (start the TUF core early) |

**Extensions (fold into existing crates), not new apps:** TOTP/2FA + encrypted
notes into `postern-vault`; a "verify any sealed file" UI into `postern-hygiene`.

**NOT worth building — ship stock / out of scope (honesty):** email → Thunderbird
(MPL) / K-9 (Apache); maps → CoMaps (Apache); file sync → Syncthing (MPL); IMSI-
catcher detector → rejected as heuristic snake oil; VeraCrypt deniable volumes →
overclaim; encrypted photo vault → FBE already covers it; desktop firewall → an OS
feature, not a product; media/RSS → aggregate permissive options.
