<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# postern-pairing

**SCAFFOLD — not a secure, audited, or deployed system.** v1, LAN-first
mobile↔desktop **pairing** + **secure channel** for the Postern integration
(`Postern-Mobile-Desktop-Integration-Design.md` §2, security-reviewed in
`Postern-MD-Integration-Security.md` §3). Standalone crate: its `Cargo.toml`
carries an empty `[workspace]`, so it builds and tests in isolation and is **not**
a member of the ancestor bloch-protocol workspace.

## What it is (and is not)

- **Pairing:** the desktop (terminal) shows a **QR** carrying its **ephemeral**
  hybrid public key + a nonce (the out-of-band anchor); the phone (custodian)
  pins it off the glass, runs the KEM, and both compare a **6-digit SAS**. The
  SAS is **mandatory and fail-closed** — no confirmation, no pairing.
- **No PAKE.** A typed PIN is **never** a secret or key entropy. The SAS is a
  human comparison of a value derived from the already-agreed session key.
- **Channel:** a mutually-authenticated, **PQ-hybrid (ML-KEM-1024 ‖ X25519)**
  encrypted session, forward-secret (ephemeral keys), bound to the paired anchor
  and a per-session id, with monotonic-counter anti-replay and direction
  separation. Carries **opaque frames** — higher layers own their meaning.
- **PQ labeled honestly:** ML-KEM (RustCrypto `ml-kem`, pre-1.0) is **unaudited**;
  the X25519 leg is the classical **hedge** — defense-in-depth, not a guarantee.
- **Local-first:** LAN mDNS discovery only (opt-in, off by default, a metadata
  leak — stated). **Tor onion is OUT** (hosting unimplemented); **BLE is OUT**.
  No cloud, no relay, no telemetry.
- **Reuses in-tree primitives by mirroring their math** (not by workspace path
  deps, so it stays offline-buildable): the courier X-Wing hybrid combiner and
  the seal-companion `SHA-256(nonce‖pubkey)` channel binding.
- **Sealed persistence (`persist` / `seal`):** a `PairingRecord` (peer pins +
  forward-secret `session_root`) is sealed at rest with the canonical Postern v2
  seal (`0x02 ‖ nonce ‖ commit ‖ ct`, XChaCha20-Poly1305, HKDF subkeys, **key-
  committing**, **context-bound**), so a pairing survives an app restart. The
  session root is **never** written in plaintext; load is **fail-closed** (wrong
  key / tamper ⇒ no record).
- **Reconnect / resume (`resume`):** a **fresh, forward-secret re-handshake** on
  each reconnect (new session key + id, counters from zero), authenticated by
  proving both sides hold the persisted `session_root` — so the human SAS is not
  repeated, and there is **no fragile counter-continuity to roll back**. A
  `session_root` mismatch fails closed to a full re-pair.

**A rooted/malware endpoint (A5) defeats this** — it reads keys from RAM and can
forge the approval UI. Pairing authenticates the *device key you scanned*, not
that the software is genuine; the desktop attests **nothing**. Coercion (A6) is
out of scope. **This is not a hardware wallet.** The coin (BLCH) is not a
security and is not involved. Community mobile edition is "Postern for
postmarketOS — community edition", never "Postern OS".

## The API contract (Dev2 / Dev3 / Dev4)

```rust
use postern_pairing::{Pairing, PairingInit, QrPayload, Role};

// --- Terminal (desktop) ---
let (pending, qr) = Pairing::begin_desktop("ThinkPad", "192.168.1.20:47001", desktop_id_pub);
let qr_bytes = qr.to_bytes();            // screen -> camera (out of band)

// --- Custodian (phone) ---
let scanned = QrPayload::from_bytes(&qr_bytes)?;
let (phone_confirm, init) = Pairing::scan_desktop_qr(&scanned, "Pixel", phone_id_pub)?;
//   init.to_bytes() travels back over the (unauthenticated) transport

// --- Terminal ---
let desk_confirm = pending.accept(&PairingInit::from_bytes(&init_bytes)?)?;

// --- Both screens: human compares the 6-digit SAS ---
let matched: bool = phone_confirm.sas().digits() == desk_confirm.sas().digits();
let (record, mut channel) = phone_confirm.confirm_sas(matched)?;  // fail-closed

// --- Talk (opaque frames) ---
let frame = channel.seal_frame(b"...opaque request...")?;   // -> transport
let plaintext = channel.open_frame(&received_frame)?;        // anti-replay enforced
```

- `Pairing` / `QrPayload` / `PairingInit` — the ceremony.
- `SasConfirm::confirm_sas(user_confirmed)` — the fail-closed gate.
- `PairingRecord` — pins the peer identity (TOFU), `revoke()` on unpair.
- `Channel` (`seal_frame` / `open_frame`) — the encrypted session.
- `transport::Transport` + `transport::Discovery` — the LAN/mDNS seam, **stubbed**
  (`LoopbackPair`, `NullDiscovery`) so the crate compiles and tests offline.

### Persist a pairing across restarts

```rust
use postern_pairing::persist;
// storage_key: 32 bytes from your device keystore (vault/Argon2id on desktop,
// StrongBox/Secure-Enclave-wrapped on mobile). `persist` does NOT manage it.
let blob = persist::save(&record, &storage_key)?;   // the ONLY thing on disk
// ...restart...
let record = persist::load(&blob, &storage_key)?;   // wrong key/tamper => Err, no record
```

`save` refuses a revoked record (delete the blob instead); channel counters are
intentionally NOT persisted — reconnect starts a fresh session.

### Reconnect without a new SAS

```rust
use postern_pairing::Resume;
let (pending, offer)   = Resume::offer(&record)?;                 // + send `offer`
let (mut chan, accept) = Resume::accept(&peer_record, &offer)?;   // responder: live channel
let mut chan           = pending.finish(&accept)?;                // offerer: verifies tag, live channel
// Fresh forward-secret key + session id, counters at zero.
// Bad session_root / MITM => ResumeError::Unauthenticated (fall back to full re-pair).
```

See `demo::pair_and_talk` for a full run over the loopback transport.

## Build & test

```
cargo build      # standalone, no network sockets
cargo test       # 48 tests (31 original + 17 for seal/persist/resume):
                 # hybrid handshake, SAS divergence under MITM, channel
                 # replay/reflection/cross-session, fail-closed SAS, QR codec,
                 # key-committing seal, sealed-record roundtrip + fail-closed load,
                 # forward-secret reconnect + session_root authentication
```

Licensed under **MIT OR Apache-2.0** (see `LICENSE-MIT`, `LICENSE-APACHE`).
Unaudited scaffold — do not rely on it to protect anything of value.
