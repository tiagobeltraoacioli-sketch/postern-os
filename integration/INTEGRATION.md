<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Postern phone-as-signer — integration developer guide

> **SCAFFOLD — not a secure, audited, or deployed system.** This document
> describes a **reference** protocol implemented by compiling, tested crates over
> primitives that exist in-tree. Nothing here is built on hardware, attested, or
> shipped. Internal review is not an audit. Treat every security word as design
> intent, not a guarantee.

This is the developer guide for building an end that interoperates with the
Postern mobile↔desktop **phone-as-signer** flow: the **desktop requests** a
signature, the **phone** (which holds the wallet key) **parses the actual bytes,
shows a human "what you see is what you sign" prompt, and approves + signs**. The
private key never crosses the wire.

It covers the protocol shape, the exact wire formats, the security model, what is
implemented vs `[planned]`, and how to build a conformant end. Two runnable
artifacts accompany it:

| Dir | What | Run |
|---|---|---|
| [`e2e-demo/`](./e2e-demo) | end-to-end demo of the whole flow over an in-process loopback, ending in a **real hybrid-signature verify** | `cd e2e-demo && cargo run` |
| [`conformance/`](./conformance) | canonical wire-format **vectors** + a build-failing **drift guard** | `cd conformance && cargo test` · `cargo run --bin dump-vectors` |

---

## 1. The three layers

The flow composes three independently-buildable crates (each carries its own
empty `[workspace]`, so each `cargo build`/`cargo test`s in isolation):

```
 ┌───────────────────────────┐   postern-pairing (Dev1)
 │  QR/SAS pairing ceremony   │   integration/pairing
 │  + PQ-hybrid channel       │   ML-KEM-1024‖X25519 · XChaCha20-Poly1305 frames
 └────────────┬──────────────┘
              │ opaque, encrypted, replay-guarded byte frames
 ┌────────────┴──────────────┐   postern-signer-protocol (Dev2)
 │  SignRequest / Approval    │   integration/signer-protocol
 │  + replay guard + WYSIWYS  │   fresh nonce · monotonic counter · session bind
 └────────────┬──────────────┘
              │ WalletSigner + Channel trait seams
 ┌────────────┴──────────────┐   postern-mobile-signer (Dev3)
 │  phone side: MobileSigner  │   mobile/signer
 │  + real WalletCore signer  │   hybrid Falcon‖ML-DSA · bridge to the paired chan
 └───────────────────────────┘
```

**Trust asymmetry is deliberate.** The phone is the *custodian* (strong device,
holds the wallet key, verifies). The desktop is the *terminal* (weak, unattested,
software-only, holds **nothing**).

---

## 2. Protocol shape (the honest happy path)

```
 Desktop (terminal, holds NOTHING)                Phone (custodian, holds the key)
 ─────────────────────────────────                ────────────────────────────────
 1. begin_desktop() ── QR (anchor) ──────────────▶ 2. scan_desktop_qr(): PIN anchor
      ephemeral ML-KEM‖X25519 keypair                  off the glass, encapsulate →
           ◀──────── PairingInit (kem_ct) ─────────    session key, derive 6-digit SAS
 3. accept(): decapsulate → SAME session key
 4. [both compare the 6-digit SAS] ◀── human ──▶  4. [both compare the 6-digit SAS]
 5. confirm_sas(true) → Record + Channel          5. confirm_sas(true) → Record + Channel
 ── a mutually-authenticated PQ-hybrid channel now exists ──
 6. request_login(challenge) ────────────────────▶ 7. receive_frame(): replay guard
      SignRequest{session,nonce,counter,payload}       (session/counter/nonce),
      sealed over the paired channel                   decode payload from ACTUAL bytes,
                                                        render WYSIWYS + consequence tier
                                                     8. per-sign presence → sign the
 9. recv_approval() ◀──── Approval ───────────────    CANONICAL digest (key stays put)
      {signature, public_key, digest}
10. verify(pubkey, digest, signature) with the REAL hybrid Falcon‖ML-DSA verifier
```

Steps 1–5 are `postern-pairing`; 6, 9 are `postern-signer-protocol`
(`DesktopRequester`); 7, 8 are `postern-mobile-signer` (`MobileSigner` + real
`WalletCore`); 10 is `bloch_crypto::crypto::verify` — the same verifier the node
/ consiglio server runs. The demo drives exactly this and prints each step.

---

## 3. Wire formats (pinned by `conformance/`)

Every format below is pinned as a byte-for-byte vector in
`conformance/src/lib.rs` and re-checked on every `cargo test`. `‖` is
concatenation; `len16`/`len32_le` are unsigned length prefixes.

### 3.1 Pairing (Dev1)

**QR payload** (`QrPayload::to_bytes`, shown on the desktop's glass, scanned by
the phone):

```
"PPQR" ‖ version(1) ‖ len16‖anchor_pubkey ‖ nonce(32) ‖ len16‖lan_hint ‖ len16‖terminal_identity
```

- `anchor_pubkey` = ML-KEM-1024 encapsulation key (1568 B) ‖ X25519 pubkey (32 B) = **1600 B**.
- `nonce` = fresh 32-byte pairing nonce.
- A text-safe `to_hex()`/`from_hex()` form exists for QR libraries that want a string.
- Parsing enforces the magic, the version, and the 1600-byte anchor length — anything else is `MalformedQr`.

**PairingInit** (phone → desktop, over the untrusted transport):

```
len16‖kem_ct ‖ len16‖custodian_identity
```

- `kem_ct` = ML-KEM ciphertext (1568 B) ‖ X25519 ephemeral pubkey (32 B) = **1600 B**.

**Channel binding** (anti-MITM anchor, mirrors `postern-seal-companion`):

```
binding = SHA-256(nonce ‖ anchor_pubkey)      // 32 bytes
```

**SAS** (the mandatory human MITM tripwire — a comparison, **never** a PAKE seed,
**never** typed-then-trusted):

```
sas_bytes = HKDF-SHA-256(ikm = session_key, info = "postern-pairing/sas/v1", L = 4)
digits    = be_u32(sas_bytes) mod 1_000_000, zero-padded to 6   // e.g. "966542"
```

**Session key combiner** (X-Wing-style; the traffic key and the SAS are separate
HKDF branches so displaying the SAS leaks nothing about traffic):

```
session_key = HKDF-SHA-256(
    ikm  = ss_MLKEM(32) ‖ ss_X25519(32),
    info = "postern-pairing/session/hybrid" ‖ version ‖ SHA256(kem_ct) ‖ SHA256(anchor_pubkey) ‖ nonce)
```

**Channel** (once open): `session_id = HKDF(session_key, "postern-pairing/session-id/v1")`,
`traffic_key = HKDF(session_key, "postern-pairing/traffic/v1")`. Each frame:

```
frame = counter(8, BE) ‖ nonce(24) ‖ XChaCha20-Poly1305_ct
AAD   = "postern-pairing/frame/v1" ‖ session_id(32) ‖ direction_label ‖ counter(8, BE)
```

Direction labels `custodian->terminal` / `terminal->custodian` are opposite on the
two ends (anti-reflection); the counter must strictly advance (anti-replay).

### 3.2 Signer protocol (Dev2)

**Signing digests** — domain-separated SHA3-256 over the *decoded fields* (so what
is signed is a canonical function of meaning, independent of transport framing):

```
LOGIN_DOMAIN  = "consiglio:wallet-login:v1"      // byte-identical to postern-consiglio-auth
SIGNER_DOMAIN = "postern:signer-protocol:v1"

login_digest    = SHA3-256(LOGIN_DOMAIN ‖ len64_le(org) ‖ org ‖ len64_le(user) ‖ user ‖ nonce(32) ‖ issued_at(i64 LE))
transfer_digest = SHA3-256(SIGNER_DOMAIN ‖ "transfer:v1" ‖ chain_tag ‖ len64_le(to) ‖ to ‖ amount(u64 LE) ‖ fee(u64 LE) ‖ nonce(32))
```

A login digest **cannot move funds** — the domain separator guarantees a signature
over it is only ever a login.

**Messages** (`serde_json` on the wire; the signed digest is recomputed from the
decoded fields, so the JSON framing is not trust-bearing):

```
SignRequest  = { session_id[16], req_nonce[32], counter: u64, payload: bytes(encode(SignPayload)) }
Approval     = { session_id[16], req_nonce[32], counter: u64, signature: bytes, public_key: bytes, payload_digest[32] }
SignPayload  = { "Login": LoginChallenge } | { "Transfer": TransferIntent }
```

There is **deliberately no human-text field** on the wire — the phone parses the
payload itself, so a compromised desktop cannot narrate a lie.

**Protocol frame codec** (over the Dev1 channel):

```
frame = "PSG1" ‖ len32_le(body) ‖ body       // cap 64 KiB; magic + length checked before alloc
```

**WYSIWYS confirmation fragment** (shown on BOTH screens — mismatch ⇒ decline):

```
fragment = hex( SHA3-256("postern:approval-fragment:v1" ‖ session_id(16) ‖ req_nonce(32))[..3] )  // 6 hex chars
```

### 3.3 Reference signer (deterministic, NOT real crypto)

`ScaffoldSigner` produces `SHA3-256("scaffold-sig:v1" ‖ secret ‖ digest)`. It is a
deterministic stand-in the protocol crate uses to build/test **without** the PQ
dependency. The real signer is the phone's hybrid Falcon‖ML-DSA `WalletCore`,
whose Falcon leg is randomized — so its signatures are **not byte-pinnable**;
their *verification* is exercised in the e2e-demo instead. The conformance
vectors pin the deterministic reference signature only.

---

## 4. Security model

**What the ceremony buys you**

- **QR-pin + SAS are MANDATORY and fail-closed.** The transport (LAN/mDNS) is an
  *unauthenticated bearer*. The QR pins the desktop's **ephemeral** key off the
  glass; the 6-digit SAS is a human comparison of a value derived from the
  already-agreed key. Under an active MITM the two sides agree on *different*
  session keys ⇒ different SAS ⇒ the human aborts. Refuse the SAS and **no record
  and no channel are produced** — there is no timeout auto-accept, no skip.
- **No PAKE.** A typed PIN is never a secret or key entropy.
- **PQ-hybrid, labeled.** ML-KEM-1024 ‖ X25519. ML-KEM (RustCrypto `ml-kem`) is
  **pre-1.0 and UNAUDITED** — the X25519 leg is the classical hedge. This is
  defense-in-depth, **not** a PQ guarantee. Classical-only would be
  harvest-now-decrypt-later exposed.
- **Forward secrecy.** Fresh ephemeral hybrid keys per pairing; the session key is
  **never** derived from the wallet seed.
- **Replay resistance is doubled.** The pairing channel enforces AEAD + direction
  + monotonic-counter + session binding; the signer protocol adds fresh-nonce +
  monotonic-counter + session-id on top. A request captured on session A cannot
  replay on session B, and a replayed frame is refused (the demo proves this).
- **Keys never cross the wire — structurally.** The seed and Falcon‖ML-DSA secret
  live in non-`Serialize` types that cannot be a field of any wire message; a
  compile-time census + a build-failing golden test enforce it. Only signatures
  and public keys travel back.
- **WYSIWYS + consequence tiers.** The phone renders the prompt from the actual
  signed bytes. Three tiers: `SilentReadOnly` (no key use), `SingleTap` (login —
  cannot move funds), `ExplicitReview` (moves funds — deliberate confirm). A
  time-boxed, revocable grant may auto-approve *single-tap logins only* — never a
  value transfer, and never a blanket "approve all".

**Honest limits (carry these — do not let a UI round them off)**

- **A rooted/malware endpoint (A5) defeats this.** Ring-0 on either device reads
  keys from RAM and can forge the approval UI. Pairing authenticates the *device
  key you scanned*, not that the software is genuine — the desktop attests
  **nothing** (a software SHA-256 pin is tamper-evidence, not attestation).
- **This is not a hardware wallet.** Even on the phone the PQ secret is in RAM to
  sign (zeroized on drop). The community edition is a pure software keystore.
- **Coercion (A6) is out of scope.** A coerced user can pair an attacker's device.
- **Metadata leak by construction.** mDNS discovery (opt-in, off by default) tells
  the subnet you run this.
- **The coin (BLCH) is not a security** and is not involved. Personal use is free,
  no token, no login — the pairing *is* the account, and it is local. The community
  mobile edition is **"Postern for postmarketOS — community edition"**, never
  "Postern OS"; the assurance name is never "BABA YAGA".

---

## 5. Implemented vs `[planned]`

**Implemented (compiles + tested here):**

- Full QR/SAS pairing ceremony, fail-closed, with the MITM-diverges-SAS test.
- PQ-hybrid (ML-KEM-1024 ‖ X25519) session key + XChaCha20-Poly1305 frames with
  counter/direction/session-binding anti-replay.
- SignRequest/Approval protocol, replay guard, WYSIWYS + three tiers, revocable
  grants, structural key-material denylist.
- The real phone side: `MobileSigner` + `WalletCoreSigner` (hybrid Falcon‖ML-DSA),
  the pairing↔protocol bridge, and a login signature that verifies with the node
  verifier (the e2e-demo).
- **Sealed-at-rest `PairingRecord` persistence + forward-secret resume**
  (`persist.rs` / `seal.rs` / `resume.rs`): a record is sealed under a 32-byte
  storage KEK bound to `RECORD_CONTEXT`, opens fail-closed on the wrong key or a
  tampered/rolled-back blob, and the reconnect-without-re-SAS path derives fresh
  per-session channels (fail-closed on a pin rotation or binding change). Tested.
- **Paired-terminals manager + monotonic revoke + panic-revoke**
  (`terminals.rs`, `PairedTerminals`): the persist-on-pair wiring
  (`confirm_sas` → `add`), a UI-safe `list` (no secrets), one-tap `revoke`
  (wipe-in-RAM then **delete** the blob — no un-revoke, because `persist::save`
  refuses to re-seal a revoked record), and `panic_revoke_all` (the
  `postern-panic` re-lock hook that evicts every reconnect channel at once).
  Storage is pluggable behind the `RecordStore` trait (`postern-vault` desktop /
  StrongBox·SE mobile); an in-memory `MemStore` backs the tests. Tested.
- Canonical conformance vectors + a drift guard.

**`[planned]` / out of scope here:**

- `[planned]` A real network transport. `postern-pairing` ships only a loopback +
  a `NullDiscovery`; the LAN socket / mDNS is a Dev-layer plug-in behind the
  `Transport`/`Discovery` traits. **Tor onion is OUT** (hosting unimplemented);
  **BLE is OUT** (widens the MITM surface).
- `[planned]` **Hardware** custody of the storage KEK. `terminals.rs` seals every
  record under a KEK, but where that KEK lives is the `RecordStore`'s job: real
  StrongBox/SE wrapping is a Dev/app-layer concern (community-edition software
  keystores are "hardware-assisted at rest" only where the platform provides it).
  The sealing + revoke/panic surface above is real and tested; the hardware
  binding underneath it is not proven here.
- `[planned]` Value-transfer signing end to end (the `Transfer` shape is proven,
  the tx decode for its WYSIWYS lives in `mobile/signer::txwysiwys`).
- `[planned]` Hardware attestation of the software on either device (there is
  none — a software SHA-256 pin only).
- `[planned]` The UniFFI app surface is wired (feature `ffi`) but the mobile image
  is **UNBOOTED** — this is a core/binding, not a shipped app.

---

## 6. How to build a conformant end

1. **Reproduce the wire formats.** Implement §3 exactly. Verify against the vectors:
   `cd conformance && cargo run --bin dump-vectors`. Every value there is
   reproducible from the documented fixtures (fixed keys, nonces, and fields).
2. **Pairing (either side).** Emit/parse the QR and PairingInit byte-for-byte;
   compute the channel binding and the SAS with the exact HKDF labels; run the
   ML-KEM‖X25519 combiner with the exact `info` transcript. If your SAS does not
   match the reference for the pinned session key, you will not interoperate.
3. **Channel.** Frame as `counter ‖ nonce ‖ ct` with the pinned AAD; enforce the
   strictly-increasing counter and the opposite direction label for your role.
4. **Signer protocol.** Build `SignRequest` with a fresh nonce + monotonic counter
   + the paired `session_id` (first 16 bytes of the pairing session id). Compute
   the signing digest from the **decoded** fields with the domain separators in
   §3.2. On the phone side, run the replay guard *before* any human decision,
   render WYSIWYS from the actual bytes (never desktop prose), require per-sign
   presence, then sign the canonical digest and return only public material.
5. **Verify** with `bloch_crypto::crypto::verify(public_key, digest, signature)`
   — the same hybrid verifier the node runs.
6. **Guard against drift.** Wire `conformance`'s `cargo test` into CI. If a format
   must change, bump the relevant version (`PROTOCOL_VERSION`, a domain suffix)
   and regenerate the pinned table with `cargo run --bin dump-vectors -- --emit` —
   deliberately, in a reviewed change.

---

## 7. Repro & licensing

- Demo: `cd e2e-demo && cargo run` (pulls `bloch-crypto` for the real verify).
- Vectors: `cd conformance && cargo test` (drift guard) and
  `cargo run --bin dump-vectors` (table).
- Both crates are `SPDX-License-Identifier: MIT OR Apache-2.0`, dual-licensed
  under the `LICENSE-MIT` / `LICENSE-APACHE` files in each directory.
