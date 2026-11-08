# Gap Analysis — Apps, SDK & Comms (Architect A4)

Read-only audit of the vault/consumer apps, `postern-sdk`, the comms crates
(messenger / courier / tor / shield), phone-as-signer, and Seal Companion, vs
the posternlabs.com claims in `bp-wt-site/site/build.js`.

Repo: `/Users/tiagoacioli/dev/bloch-protocol` (code) · `/Users/tiagoacioli/dev/bp-wt-site` (site).
Date: 2026-07-13. Everything below is **UNAUDITED** by construction; that is not
re-flagged per row.

## Proof-tier legend
- **T1 host-test** — Rust unit/integration tests pass on host (no device, no network).
- **T2 offline-fixture** — verified only against a committed fixture, never real hardware/network.
- **T3 live-interop** — real cross-component interop demonstrated (reference impl).
- **T4 design/unbuilt** — code/profile or spec only; never built, booted, or run.
- **BYOK** — depends on the user's own key / browser primitive; nothing Postern-side.

---

## Headline

The **cryptographic cores are real and honestly labeled**; the **product seams
around them are the gap**. Three specific, load-bearing shortfalls:

1. **SDK real-crypto is NOT adopted by the shipping apps.** The wasm
   Argon2id+XChaCha20 seam is real in Rust, but the single-file HTML apps
   (Chiave et al.) still run a WebCrypto **PBKDF2-SHA-256 (310k)** stand-in and
   a **classical** sign stand-in. The wasm bundle isn't even in the main tree
   (only in a worktree, gitignored); apps merely probe an optional
   `globalThis.PosternSDK` a host shell would inject. Site label matches — but
   "real Argon2id in the SDK" ≠ "the app you open uses it."
2. **Every network/transport path is feature-gated OFF by default** — courier
   Tor onion, messenger Tor, messenger Matrix federation. The *default* builds
   are crypto-seal-only / loopback-only. "Delivered over an ephemeral Tor onion
   service" describes an opt-in feature, not what a default build does.
3. **Phone-as-signer is a v1 reference, not a shipped feature** — real interop
   exists, but desktop and phone ends are **not unified on one wire**, keystore
   is **software not hardware**, and the protocol crate's default signer is an
   explicit non-crypto stand-in.

No hard OVERCLAIM found: the site's per-card labels are unusually faithful to
the code. The two soft-overclaim risks are the courier/messenger Tor phrasing
(default build ships no Tor) and the store catalog (all signatures null).

---

## Structured findings

### SDK — `crates/postern-sdk`

| Capability | Status | What's missing | Proof | Prio | Effort |
|---|---|---|---|---|---|
| UniFFI native surface — single `setup_scaffolding!` over whole suite (Android/iOS/desktop), CI-checked exactly-one | **DONE** | nothing structural; unaudited | T1 | — | — |
| wasm Argon2id (64 MiB, t=3) + XChaCha20-Poly1305 AEAD seam (`wasm.rs`, `postern_core`) | **DONE (core) / SCAFFOLD (delivery)** | wasm bundle not built into main tree (only worktree, gitignored); no loader shipped with apps | T1 | P1 | S |
| **App adoption of the real KDF/AEAD** — Chiave/Sotto/Vedetta/Tolmach still PBKDF2 stand-in; SDK is optional probe only | **MISSING** | wire `PosternSDK` into the HTML apps (host-shell inject or relaxed-CSP build); flip Chiave off PBKDF2 | T4 | P1 | M |
| Hybrid PQ signing in browser (Falcon‖ML-DSA) | **MISSING / BLOCKED** | `bloch-crypto` PQClean C won't target `wasm32`; `has_pq_sign()=false` by design → **phone-as-signer is the intended answer**, or a pure-Rust PQ backend | T4 | P2 | L |

### Consumer / vault apps — `apps/*` (single-file HTML)

| Capability | Status | What's missing | Proof | Prio | Effort |
|---|---|---|---|---|---|
| Sotto (voice assistant) | **SCAFFOLD** | reference prototype; Claude via **BYOK**; voice = browser→Google (not on-device); no SDK-real-crypto | BYOK | P3 | — |
| Vedetta (markets lookout) | **SCAFFOLD** | prototype; BYOK Claude + market-data providers see symbols; holdings local | BYOK | P3 | — |
| Tolmach (interpreter/minutes) | **SCAFFOLD** | prototype; BYOK-only today; "subscription/proxy tier" planned, not enabled | BYOK | P3 | — |
| Chiave (`postern-login`) — wallet login ceremony | **SCAFFOLD** | ceremony logic real+tested (`test-core.mjs`: nonce single-use, expiry, origin-bind, KDF-downgrade clamp); but **PBKDF2 stand-in** for Argon2id, **classical** stand-in for PQ sign, **software** keystore (hardware-backed unlock is the stated goal) | T1 (ceremony) | P1 | M |
| Sarto (`postern-onboard`) — configurator | **SCAFFOLD** | manual editor keyless/offline; AI path BYOK-optional | T1 | P3 | — |
| Postern Store (`apps/postern-store`) — catalog + NL search | **SCAFFOLD** | `catalog.json` is self-declared scaffold: **every `signing.state="unpublished"`, checksum/signature null, index_signature null**; no apk built/mirrored/published; NL search BYOK-optional | T4 | P2 | M |

### Comms — messenger / courier / tor / shield

| Capability | Status | What's missing | Proof | Prio | Effort |
|---|---|---|---|---|---|
| Messenger E2EE core — default `channel`+`store`+`transport`, vodozemac **Megolm**, persistent, replay-reject, encrypted-at-rest, **default-on (no feature)** | **DONE** | key distribution is **out-of-band** on default path (not SDK-automated); Megolm is classical (not PQ) — HNDL on transport ciphertext | T1 | — | — |
| Messenger **Tor transport** (`tor` feature) | **SCAFFOLD** | feature OFF by default; wire codec tested in default build, socket plumbing behind `arti` feature | T1 (codec) | P2 | M |
| Messenger **Matrix federation** (`matrix` feature) — login/sync/E2EE, SDK-automated Olm key dist, fail-closed room classification | **SCAFFOLD** | feature OFF by default; SDK store is **in-memory** (no persistence → fresh device each login); **device cross-signing/verification is Phase-2, not done**; Tor-wrapping the matrix client is remaining work | T1 | P2 | L |
| Courier **hybrid PQ seal** — ML-KEM-1024‖X25519, X-Wing HKDF combiner, XChaCha20-Poly1305 | **DONE** | RustCrypto `ml-kem` is pre-1.0/unaudited (why the classical leg exists); **no sender authentication**, key authenticity out-of-band | T1 | — | — |
| Courier **Tor onion transport** (`onion-transport` feature) | **SCAFFOLD** | feature OFF by default (default build = seal only, no arti/net); real HS publish only via **ignored live test**; **no anti-replay/DoS beyond 64 MiB cap**, no sender auth, onion key in arti software keystore; sender must stay online (live transfer, not mailbox) | T3 (ignored live) | P2 | M |
| `postern-tor` (in-process Arti) | **DONE (dep)** | thin wrapper; all consumers feature-gate it | T1 | — | — |
| Shield (BYOD container) — `enterprise/shield/container` (seal + seal-wasm + self-check) | **SCAFFOLD** | container seal/self-check present; containment "by construction — a rooted phone defeats it", offline-revoke best-effort; not shipping | T4 | P3 | L |

### Phone-as-signer — `integration/signer-protocol`, `integration/pairing`, `mobile/signer`

| Capability | Status | What's missing | Proof | Prio | Effort |
|---|---|---|---|---|---|
| Signer **protocol shape** — `SignRequest`/`Approval`, replay guard (nonce+monotonic counter+session), WYSIWYS + 3 consequence tiers, revocable grants, watermark persist | **SCAFFOLD (by self-declaration)** | compiling reference; default `ScaffoldSigner` is a deterministic **non-crypto** stand-in; standalone workspace | T1 | P1 | — |
| **Structural key-denylist** — secret types have no `Serialize`; build-failing golden census that no wire type carries key material | **DONE** | strongest guarantee in the seam; keeps its own test | T1 | — | — |
| Pairing — QR + spoken-code (SAS) over ML-KEM-1024‖X25519 hybrid channel | **DONE (reference)** | `integration/pairing`; reference, unaudited | T1 | — | — |
| `mobile/signer` — **real** `WalletCoreSigner` (Falcon‖ML-DSA WalletCore) + `PairedSignerChannel`, tx WYSIWYS, per-sign presence, monotonic per-grant revoke | **DONE (v1 reference, real interop)** | **software keystore, not hardware** (rooted phone forges approval UI); **desktop & phone ends not unified on one wire**; **v2 message shape forward-declared, not built** | T3 | P1 | L |

### Seal Companion — `crates/postern-seal-companion`

| Capability | Status | What's missing | Proof | Prio | Effort |
|---|---|---|---|---|---|
| Core verifier — self-audit + peer-verify, pinned-device trust anchor, **fail-closed** without anchor (`Verdict::Unverified`), PQ signature check, nonce-bound | **DONE** | attests the *build*, not absence of 0-day/coercion (documented) | T1 | — | — |
| SEV-SNP verify (`sev-snp` feature) — VCEK→ASK→ARK AMD root chain | **SCAFFOLD** | feature-gated; verified only against an **offline report fixture — never real SEV-SNP hardware** | T2 | P2 | L |
| TDX (`tdx`) — quote parser | **SCAFFOLD** | fail-closed parser that **never returns `Genuine`** (secondary, documented) | T2 | P3 | L |
| Mobile attest (`mobile-attest`) — Android StrongBox X.509 chain to Google root | **SCAFFOLD** | feature-gated; attests the *phone*, not the workspace | T2 | P2 | M |

---

## Quantifying the gap to shippable

**What the make-it-work round genuinely made real (not prose):**
- Messenger Megolm E2EE **default-on** (persistent, replay-reject, at-rest sealed) — the strongest win.
- Courier hybrid PQ **seal** (ML-KEM-1024‖X25519) — real, tested.
- SDK **Argon2id KDF + XChaCha20 AEAD** — real in Rust/wasm.
- Phone-as-signer **v1 real interop** (real WalletCore signer over PQ-hybrid paired channel, per-grant revoke).
- Seal Companion **core verifier** + feature-gated SNP/TDX/mobile attestation (fixtures only).

**Still stubbed / BYOK-only / unbuilt:**
- Apps don't consume the real SDK crypto — **PBKDF2 + classical stand-ins ship**.
- All Tor/federation transports **off by default**; courier onion + messenger Tor/Matrix are opt-in reference prototypes.
- Browser PQ signing **impossible** in current stack (wasm32 blocker) — unresolved without phone-as-signer or a pure-Rust PQ backend.
- Phone-as-signer **not unified end-to-end**, software keystore, v2 unbuilt.
- Store catalog **entirely unpublished** (null signatures), no apk pipeline run.
- Attestation never touched **real hardware** (SNP/TDX/StrongBox all fixture-only).

**Distance to a defensibly "shippable" (still-unaudited) consumer beta**, by priority:

- **P0** — none. No safety-critical misrepresentation on the site; labels are honest. (The one thing to watch: keep the "Tor onion" / "Argon2id" phrasing tied to the feature/seam, not the default app.)
- **P1 (adopt what's built)** — wire the wasm SDK into the HTML apps and retire Chiave's PBKDF2 stand-in; unify the phone-as-signer wire so desktop↔phone is one path, not two references. Effort: **M + L**.
- **P2 (make transports real by default or clearly promote them)** — courier onion + messenger Tor/Matrix out of "feature-gated reference"; publish the store catalog (run the signing pipeline); get one attestation path onto real hardware. Effort: **M–L each**.
- **P3 (front-end polish / enterprise)** — Sotto/Vedetta/Tolmach hardening, shield container, TDX. Effort: varies.

**Bottom line:** the seam between "verified core" and "thing a user runs" is the
entire gap. The cores are ~DONE; the *product* is SCAFFOLD because the apps
haven't adopted the cores, the transports are off by default, and PQ-in-browser
is blocked (deferred to phone-as-signer, itself a v1 reference). Nothing here is
dishonestly claimed — but "built and test-verified" is doing a lot of work that
"shippable" would not accept.
