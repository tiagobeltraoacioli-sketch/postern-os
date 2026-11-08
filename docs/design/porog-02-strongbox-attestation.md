# Porog 02 — StrongBox hardware key-attestation & Play Integrity reality

**Architect:** A2 (fleet of 10). **Scope:** Porog's hardware attestation path only —
Android hardware-backed Keystore + StrongBox, Key-Attestation certificate-chain
verification, the honest Play Integrity story, and how the result binds into
Postern's identity spine (Consiglio) without overclaiming.

**Status:** design/spec that ratifies and extends what is *already in the tree*. The
StrongBox key generator (`StrongBoxKey.kt`) and the `mobile-attest` verifier backend
(`crates/postern-seal-companion/src/mobile.rs`) already exist and compile; this doc
pins the architecture around them, closes the gaps (Play Integrity, tier UI, identity
binding, on-device proof), and states plainly what can be proven where.

**Reference/prototype — UNAUDITED. No security claim until an audit gate.**

---

## 0. The one honest qualifier (non-negotiable, repo-enforced)

Porog is a **key-attested device, not a measured-boot workspace.** Android Key
Attestation measures the **phone** — its keystore, its verified-boot state, its OS
patch level — and *identifies* the attesting app. It does **NOT** measure Porog's
workspace code or contents. There is no `os_roothash`, no dm-verity, no Postern Seal
(measured-boot) coverage of the workspace. That measured-boot property is exclusive to
**Postern OS Mobile**; never claim it for Porog.

Everything below respects the honesty rails: stock un-rooted Android, no OS
replacement, no root, no Play-Integrity circumvention (we design *honest* use of the
API and report the real verdict — we never spoof or bypass it), Google/Android marks
used nominatively only. `scripts/check-trust-labels.sh` is the mechanical tripwire; the
words "attested / StrongBox / hardware-backed" are only ever paired with this qualifier.

---

## 1. Mechanism — StrongBox-backed Keystore key, attested

Porog runs inside a self-enrolled **managed profile** (owned by architect A1 / the DPC
track; out of scope here). Inside that profile Porog generates a **non-exportable,
user-auth-gated EC P-256 key in the device's StrongBox** (a discrete hardware security
module — Pixel 3+ Titan M, some Samsung), using `KeyGenParameterSpec`:

- `setIsStrongBoxBacked(true)` — pins the key into the discrete HSM (not just the TEE).
- `setAttestationChallenge(nonce)` — binds a fresh verifier/node nonce into the
  attestation, giving anti-replay / freshness.
- `setUserAuthenticationRequired(true)` — key use gated behind device unlock/biometric.
- `PURPOSE_SIGN | PURPOSE_VERIFY`, `secp256r1`, `DIGEST_SHA256`.

`KeyStore.getCertificateChain(alias)` then returns an **X.509 chain** whose leaf carries
the Android Key-Attestation extension. That chain — leaf-first DER — is the wire proof
Porog hands a verifier. This is the **mobile form of the Postern Seal** (device-level),
distinct from the OS-level measured-boot Seal.

**Role of the StrongBox key (state this plainly):**
1. **Attest** the device + app to a verifier (the chain below).
2. **Wrap** the post-quantum wallet key material *at rest*. StrongBox is a **classical
   P-256 HSM** — it does **NOT** hold or sign with the Falcon‖ML-DSA key. PQ signing runs
   in the Rust core in RAM (zeroized on drop). This limit is non-negotiable and already
   documented across `mobile/README.md`.

### What STRONG (StrongBox) gives — and what it REFUSES

| STRONG gives | STRONG refuses |
|---|---|
| A key provably resident in a discrete, side-channel-resistant HSM | To hold/sign the PQ wallet key (it is P-256 only) |
| A Google-CA-rooted chain proving hardware backing + boot/patch state | To say anything about the *workspace* contents or code |
| Freshness (verifier nonce echoed in `attestationChallenge`) | To work on devices with no StrongBox chip (→ TEE fallback tier) |
| App identity binding (package + signing-cert digest) | To defend against a rooted host / malicious vendor image |
| Anti-rollback (OS patch level) | To be a self-sovereign root (it trusts Google's CA + the OEM) |

---

## 2. The Key-Attestation verify code path (leaf → Google root)

The verifier already exists: **`crates/postern-seal-companion/src/mobile.rs`**, behind
the **`mobile-attest`** cargo feature (`x509-parser` dep, off by default to keep the
lean workspace gate green). It returns the crate-shared `Verdict` (`Genuine` /
`Mismatch(&'static str)` / `Unverified(&'static str)`), **fail-closed on any doubt**.

**Entry points:**
- `verify_key_attestation(chain_der: &[&[u8]], expected: &MobileExpected) -> Verdict`
- `verify_key_attestation_detailed(...) -> Result<MobileAttestation, Verdict>` — returns
  the authenticated facts (security level, device-locked, verified-boot state, patch
  level) for the honest **tier UI**.

**`MobileExpected` (what the deployment pins):** `roots` (pinned Google attestation root
DER — **empty ⇒ `Unverified`**, fail-closed), `challenge` (the issued nonce),
`require_device_locked`, `require_verified_boot`, `min_security_level`
(`StrongBox` for the hardened tier, `TrustedEnvironment` for the fallback tier),
`min_os_patch_level` (YYYYMM anti-rollback), `expected_app` (package + signing digest),
`now_unix` (validity-window clock).

**The verify pipeline (in order, each a named `Mismatch` on failure):**
1. **Chain build** — parse each DER cert; verify every link is signed by its issuer;
   check each cert's validity window against `now_unix`; require the terminal cert to be
   (or be signed by) a pinned Google root. No pinned root ⇒ `Unverified` (proves nothing).
2. **Locate the attestation extension** — OID **`1.3.6.1.4.1.11129.2.1.17`** in the leaf
   (DER content bytes `2B 06 01 04 01 D6 79 02 01 11`), parse the `KeyDescription`.
3. **Nonce** — `attestationChallenge` must equal the issued nonce (freshness).
4. **Security level** — the `KeyDescription.attestationSecurityLevel` ENUMERATED
   (`Software=0 < TrustedEnvironment=1 < StrongBox=2`) must be ≥ `min_security_level`.
5. **Root of Trust** (context tag 704, hardware-enforced list): `verifiedBootState`
   must be `Verified` (locked, OEM-signed chain) and `deviceLocked == true` when required.
6. **OS patch level** (tag 706) ≥ `min_os_patch_level` (anti-rollback).
7. **AttestationApplicationId** (tag 709, software-enforced): every expected package name
   AND every expected signing-cert SHA-256 digest must be present, so a foreign app
   cannot mint an attestation that passes as Porog's.

Only if all pass → `Verdict::Genuine` + `MobileAttestation{ security_level, device_locked,
verified_boot_state, os_patch_level, ... }`.

**A↔C seam (the wire contract):** Porog (`StrongBoxKey.attestationChainDer()`) emits
`List<ByteArray>`, index 0 = leaf, each signed by the next, terminating at/under the
pinned Google root. The verifier consumes exactly that. This is the only cross-boundary
data structure; keep it stable.

**Operational limits (state, don't solve):** Google **rotated** the RKP attestation root
(2026-02-01, mandatory 2026-04-10), so `roots` is caller-supplied *by design* — pin more
than one across a rotation window and track the current root out of band. The backend
does **no CRL / status-list revocation** — a compromised-and-revoked device key would
still chain; production must refresh Google's attestation CRL out of band.

---

## 3. Play Integrity — the honest reality

Play Integrity is a **second, independent** device-integrity signal layered *on top of*
Key Attestation. It is **NOT implemented in the tree yet** (referenced in docs only);
this section specifies the honest integration. **We never circumvent it** — Porog reports
the real verdict and degrades gracefully; it never spoofs `MEETS_STRONG_INTEGRITY`.

**The three device verdicts, and what a self-enrolled managed profile on stock Android
can realistically achieve:**

| Verdict | What it means | Porog reality |
|---|---|---|
| `MEETS_STRONG_INTEGRITY` | Locked bootloader + certified OEM image + recent security update, **hardware-backed** attestation | Achievable **only** on a stock, locked, Play-certified device. **Will FAIL** on rooted / unlocked-bootloader / custom-ROM / pre-Android-8 devices — the users who most want Porog. Not a bug; by Google's design. |
| `MEETS_DEVICE_INTEGRITY` | Genuine Android device, Play-enabled | The realistic baseline for a stock certified phone. |
| `MEETS_BASIC_INTEGRITY` | Weak signal; may pass emulators/uncertain devices | Treat as "barely a signal." |

**Design rules (honesty rails):**
- **Report, never gate hard, never spoof.** Porog obtains the token
  (`StandardIntegrityManager` / `IntegrityManager`), decodes it **server-side** (never
  trust a client-decoded verdict), and **displays the real verdict**. If STRONG fails,
  the UI says so plainly ("this device reaches DEVICE integrity, not STRONG — bootloader
  state / certification is why"). No fabrication.
- **Play Integrity is a *signal*, not the trust anchor.** The cryptographic anchor is
  Key Attestation (§2), which works even where Play Integrity is unavailable (no GMS).
  A custom-ROM privacy user may fail STRONG yet still present a valid TEE/StrongBox Key
  Attestation — do not exclude them by making Play Integrity a hard requirement.
- **microG / Google-free devices** cannot produce a Play Integrity token at all — Porog
  must treat "no token" as *absence of a signal*, not as failure, and fall back to Key
  Attestation as the sole anchor.
- **Nominative use only:** "Play Integrity" / "Google Play" named as the API, never
  implying endorsement or certification of Porog.

---

## 4. Binding the attestation into Postern identity (Consiglio) — without overclaiming

Porog's attestation is a **device-posture attribute**, not an identity by itself. The
identity spine is **wallet-as-login** (`crates/postern-consiglio-auth`): the Postern PQ
wallet key (hybrid **Falcon-1024 ‖ ML-DSA-65**) *is* the identity; the server issues a
challenge, the wallet signs a domain-separated transcript (`consiglio:wallet-login:v1`),
the server verifies against the enrolled pubkey via `bloch_crypto::crypto::verify`.

**How the device attestation composes with that — the correct, non-overclaiming design:**

1. **Same nonce, two proofs.** At enrollment/login the verifier issues one challenge. It
   is used **both** as the Consiglio login-transcript nonce **and** as the Key-Attestation
   `attestationChallenge`. The client returns: (a) the PQ signature over the login
   transcript, and (b) the Key-Attestation chain. Both are fresh and bound to the same
   session nonce.
2. **Two independent facts, kept separate.** The PQ signature proves *"the holder controls
   the enrolled wallet key."* The attestation proves *"that holder is on a device whose
   keystore/boot/patch state is AS REPORTED, and the attesting app is Porog."* Keep these
   as **distinct claims** in the session record — never collapse "attested device" into
   "attested identity" or "attested workspace."
3. **Attestation as an RBAC/posture gate, not the auth root.** Consiglio's `rbac_check`
   (role + clearance) can additionally require a `MobileAttestation` tier (e.g. "clearance
   ≥ N requires `SecurityLevel::StrongBox` + `Verified` boot"). This is *device posture
   raising the bar*, layered on the wallet-key auth — it never replaces it. A verifier that
   does not pin `expected_app` accepts an attestation minted by any app, so pin it.
4. **What this binding does NOT prove:** that the workspace ran unmodified logic, that the
   wallet key lives in the StrongBox (it does not — StrongBox only *wraps* it at rest), or
   that the device is un-rooted beyond what verified-boot/`deviceLocked` report. A rooted
   host that still reports `Verified` (unlikely but not impossible against a kernel
   compromise) crosses the boundary. State the ceiling.

Consiglio-auth itself is honestly an **UNAUDITED scaffold** (in-memory enrollment/nonce
stores are stubs; the PQ verify + transcript + anti-replay are real). The binding
inherits that status.

---

## 5. Files / components

| Path | Role | Status |
|---|---|---|
| `mobile/android/app/src/main/java/labs/postern/wallet/StrongBoxKey.kt` | StrongBox key generation, `setAttestationChallenge`, chain export (`attestationChainDer()`), **TEE fallback** (`generateTeeFallbackKey`) | **Exists** (skeleton, unbuilt here) |
| `crates/postern-seal-companion/src/mobile.rs` | Key-Attestation X.509 verifier: chain build, OID `…11129.2.1.17` parse, nonce / boot / patch / app-id / security-level checks; `Verdict` fail-closed | **Exists**, feature `mobile-attest` |
| `crates/postern-seal-companion/src/lib.rs` | Shared `Verdict` enum (`Genuine`/`Mismatch`/`Unverified`) | Exists |
| `crates/postern-seal-companion/Cargo.toml` | `mobile-attest = ["dep:x509-parser"]` (off by default) | Exists |
| `crates/postern-consiglio-auth/*` | Wallet-as-login identity spine (challenge/response, enroll, rbac) | Exists (scaffold) |
| **NEW** `…/wallet/PlayIntegrity.kt` | Obtain Play Integrity token; hand raw token to server; never decode/trust client-side | **To build** |
| **NEW** `…/wallet/AttestationTier.kt` | StrongBox→TEE graceful fallback orchestration + honest tier UI ("the tier it actually got") | **To build** |
| **NEW** server-side Play Integrity token decode + a `PostureClaim{ attestation_tier, play_integrity_verdict }` composed into the Consiglio `Session` | **To build** (verifier side, likely in `postern-seal-companion` or a Consiglio adapter) |

---

## 6. Toolchain, infra & device requirements

**Host reality:** macOS host has **NO Android SDK**. A **Linux + Nix VM is coming** and is
the intended Android build host.

**What builds where:**
- **Rust verifier (`mobile-attest`)** builds/tests **anywhere** (macOS included) — it is
  pure Rust over `x509-parser`:
  `cargo test -p postern-seal-companion --features mobile-attest`.
- **The Kotlin app + native core** need the **Android SDK/NDK + cross-compiled Rust core**
  (`cargo-ndk`, `rustup target add aarch64-linux-android …`, UniFFI bindgen, `./gradlew`).
  This runs on the **Linux+Nix VM**, not macOS, not this repo's CI.
- **StrongBox itself CANNOT be proven on an emulator.** An emulator has no discrete HSM;
  it can at best return a software/TEE-emulated attestation. **StrongBox (`SecurityLevel=2`)
  requires a real device with a StrongBox chip** — Pixel 3 or newer (Titan M), some Samsung
  (not the EMM-gated Knox container — the plain Keystore StrongBox). Play `STRONG` integrity
  additionally requires that device to be **stock, locked-bootloader, Play-certified**.

---

## 7. Functional-proof test — and exactly where it must run

The proof splits into three tiers by *what each can actually establish*:

**Tier A — verifier correctness (host, deterministic, provable now).**
`cargo test -p postern-seal-companion --features mobile-attest`. Hand-built DER
`KeyDescription` vectors exercise every branch: `Genuine`, nonce mismatch, unverified
boot, unlocked device, stale patch, below-tier security level, wrong app package, wrong
signing digest, empty chain, no pinned root → `Unverified`. **Proves the verify logic;
proves NOTHING about a real StrongBox** (`vector-tested ≠ attested`).

**Tier B — app build + emulated attestation (Linux+Nix VM).** Cross-compile the core,
UniFFI-bind, `./gradlew :app:assembleDebug`, run in an emulator. Proves the app compiles,
`KeyGenParameterSpec` is accepted, a chain is produced and reaches the verifier over the
A↔C seam. **Cannot prove StrongBox** — the emulator will report software/TEE level; the
StrongBox-required path will (correctly) fail or fall back.

**Tier C — the real functional proof (REAL StrongBox device — Pixel 3+ / Samsung).**
This is the *only* place the end-to-end claim is proven:
1. Verifier issues nonce.
2. Porog `generateAttestedKey(nonce)` → StrongBox key + chain (or catches
   `StrongBoxUnavailableException` → TEE fallback, and the UI must then say "TEE tier,
   not StrongBox").
3. `attestationChainDer()` → verifier `verify_key_attestation_detailed` with pinned
   **current** Google root(s).
4. **Assert** `Verdict::Genuine` with `security_level == StrongBox`, `verified_boot_state
   == Verified`, `device_locked == true`, expected app id, nonce echoed.
5. Play Integrity: obtain token, decode **server-side**, record the **real**
   `MEETS_STRONG/DEVICE/BASIC` verdict — and confirm STRONG *fails* on an
   unlocked/custom-ROM device (that failing case is itself a required, honest result).

Only Tier C on real hardware substantiates "StrongBox key-attested device." Until then
every on-device claim is UNPROVEN.

---

## 8. Honesty constraints (checklist the deliverable must keep true)

- Say **key-attested device, not measured-boot workspace** wherever attestation is
  mentioned. Never claim Postern Seal (measured boot) / `os_roothash` / dm-verity for Porog.
- Stock un-rooted Android; no root; no OS replacement.
- **Report** Play Integrity verdicts; **never** spoof/circumvent them. STRONG *will* fail
  on some devices — design for that, surface it honestly.
- StrongBox is **classical P-256** — attests + wraps at rest; does **not** hold/sign the PQ
  key. Not every device has StrongBox → TEE fallback, and **report the tier actually got**.
- Trust roots in **Google's CA + the OEM** — a real third-party dependency (ironic for an
  ownerless protocol); the self-sovereign answer is Postern OS Mobile, not Porog.
- No CRL/revocation in the verifier; RKP root is a moving target — pin current + rotate.
- Nominative marks only ("Play Integrity", "Google Play", "Android"). Porog name is
  **proposed, pending trademark clearance**.
- Everything here is **reference/prototype, UNAUDITED** — no security claim until an audit.

---

## 9. Phased dev task-list

**Phase 0 — ratify verifier (host, ~0.5 dev-wk).** Lock the `mobile.rs` API + `mobile-attest`
feature as the A↔C contract; add any missing negative-vector tests; document root-pinning +
rotation config. *Runs on macOS now.*

**Phase 1 — tier orchestration + UI (Linux+Nix VM, ~1 dev-wk).** `AttestationTier.kt`:
StrongBox→TEE fallback (catch `StrongBoxUnavailableException`), honest "tier you actually
got" surface. Wire `attestationChainDer()` → verifier round-trip in an emulator (Tier B).

**Phase 2 — Play Integrity, honest (Linux+Nix VM + server, ~1.5 dev-wk).** `PlayIntegrity.kt`
obtains the token; **server-side** decode; surface the real STRONG/DEVICE/BASIC verdict;
handle "no token" (microG) as absence-of-signal, not failure. No spoofing, no gating-out
custom-ROM users.

**Phase 3 — Consiglio identity binding (~1.5 dev-wk).** Single-nonce composition of the
PQ login transcript + Key-Attestation chain; `PostureClaim` into the Consiglio `Session`;
optional RBAC posture gate (clearance → required tier). Keep device-attested and
identity-attested claims distinct.

**Phase 4 — real-device functional proof (REAL StrongBox device, ~1 dev-wk + hardware).**
Tier C end-to-end on Pixel 3+/Samsung: assert `Genuine`+`StrongBox`+`Verified`; confirm
STRONG-fail cases on unlocked/custom-ROM; validate against the **current** Google root
(post-2026 RKP rotation). This is the gate that turns "designed" into "proven on device."

**Dev-count:** ~1 Android/Kotlin dev + shared use of the Rust verifier owner; ~5.5 dev-weeks
across phases, plus real StrongBox hardware for Phase 4. Depends on architect A1's
managed-profile/DPC track for the profile Porog runs in.
