// SPDX-License-Identifier: MIT OR Apache-2.0
//! # Postern Pairing — mobile <-> desktop pairing + secure channel (scaffold)
//!
//! ## ⚠️ SCAFFOLD — not a secure, audited, or deployed system
//!
//! This crate is the **v1, LAN-first** implementation of the pairing ceremony
//! and the encrypted session channel described in
//! `Postern-Mobile-Desktop-Integration-Design.md` (§2) and stress-tested in
//! `Postern-MD-Integration-Security.md` (§3). **Nothing here is built on
//! hardware, audited, attested, or shipped.** It is a compiling, tested
//! reference of the *protocol* over primitives that already exist in-tree —
//! not a product. Treat every security word below as a design intent, not a
//! guarantee.
//!
//! ## Binding rails (carry these wherever this crate's concepts appear)
//!
//! - **Scaffold, unaudited — nothing built, secure, attested, or deployed.**
//!   No third-party audit exists. Internal review is not an audit.
//! - **QR + SAS are MANDATORY and fail-closed.** Pairing establishes a
//!   session key over an *unauthenticated bearer* transport (LAN/mDNS). The
//!   out-of-band human step is the ONLY thing that stops an active MITM /
//!   evil-twin (adversary A2): the QR pins the desktop's **ephemeral** public
//!   key off the glass, and a short **6-digit SAS** is compared on both screens
//!   to confirm the channel. If neither the QR-pin nor the SAS is confirmed,
//!   [`Pairing::confirm_sas`] refuses and **no [`PairingRecord`] is produced.**
//! - **There is NO PAKE.** A typed PIN is **never** treated as a secret or a
//!   source of key entropy. The SAS is a *human comparison of a value derived
//!   from the already-agreed session key* — never typed-then-trusted, never a
//!   PAKE seed. (See [`sas`].)
//! - **PQ-hybrid, labeled.** The channel key is the X-Wing-style
//!   **ML-KEM-1024 || X25519** combiner (mirrors `postern-courier`). ML-KEM via
//!   RustCrypto `ml-kem` is **pre-1.0 and UNAUDITED** — the X25519 leg is the
//!   classical hedge, so this is **defense-in-depth, not a PQ guarantee**. A
//!   classical-only channel would be harvest-now-decrypt-later (HNDL) exposed.
//! - **Ephemeral keys => forward secrecy.** The handshake uses fresh ephemeral
//!   hybrid keys per pairing. The session key is **NEVER** derived from the
//!   wallet seed or any long-lived key.
//! - **Bound to the paired anchor.** The session key and every frame are bound
//!   to the pairing transcript via `SHA-256(nonce || pubkey)` channel binding
//!   (mirrors `postern-seal-companion`) and a per-session id, so a frame
//!   captured on session A cannot replay on session B.
//! - **Local-first, no cloud, no telemetry.** Discovery is LAN mDNS
//!   (opt-in, off by default, minimal advertisement — a metadata leak, stated).
//!   **Tor onion is OUT** (hosting unimplemented in `postern-tor`); **BLE is
//!   OUT** (widens the MITM surface). No relay, no push, no phone-home.
//! - **A rooted/malware endpoint (A5) defeats this.** Ring-0 on either device
//!   reads keys from RAM and can forge the approval UI. Pairing authenticates
//!   the *device key you scanned*, not that the software is genuine; the desktop
//!   attests **nothing** (only a software SHA-256 pin). Coercion (A6) is not in
//!   scope — a coerced user can simply pair the attacker's device.
//! - **This is not a hardware wallet.** Even on the phone the wallet secret is
//!   in RAM to sign; the desktop has no hardware protection at all. This crate
//!   never moves a wallet seed or secret across the wire — only the ephemeral
//!   channel key material does.
//! - **The coin (BLCH) is not a security** and is not involved here. Personal
//!   use is **free forever, no token, no login**; the pairing *is* the account
//!   and it is local. The community mobile edition is **"Postern for
//!   postmarketOS — community edition"**, never "Postern OS"; the assurance
//!   name is never "BABA YAGA".
//!
//! ## The API contract (for Dev2 / Dev3 / Dev4)
//!
//! Two surfaces, deliberately small:
//!
//! - [`Pairing`] — the ceremony. [`Pairing::begin_desktop`] (terminal side;
//!   emits the [`QrPayload`]) and [`Pairing::scan_desktop_qr`] (custodian side;
//!   consumes it). Both drive to a [`sas::Sas`] the human compares, then
//!   [`Pairing::confirm_sas`] yields a [`PairingRecord`] + a live [`Channel`].
//! - [`Channel`] — the mutually-authenticated PQ-hybrid encrypted session.
//!   [`Channel::seal_frame`] / [`Channel::open_frame`] with monotonic-counter
//!   anti-replay, direction separation, and session-id binding. Higher layers
//!   (remote-signer, panic propagation, watch-only sync) ride *inside* frames;
//!   this crate carries opaque bytes and does not interpret them.
//! - [`transport::Transport`] — the seam the LAN socket / mDNS discovery plugs
//!   into. It is a trait so the crate compiles and tests with no network; a
//!   [`transport::LoopbackPair`] in-memory duplex stands in for a socket.
//!
//! A concrete end-to-end run of the whole ceremony over the loopback transport
//! is in [`demo::pair_and_talk`] and in the crate tests.

#![forbid(unsafe_code)]

pub mod binding;
pub mod channel;
pub mod hybrid;
pub mod pairing;
pub mod persist;
pub mod record;
pub mod resume;
pub mod sas;
pub mod seal;
pub mod terminals;
pub mod transport;

pub mod demo;

pub use channel::{Channel, ChannelError, Frame};
pub use pairing::{Pairing, PairingError, PairingInit, QrPayload};
pub use persist::{load, save, PersistError, RECORD_CONTEXT};
pub use record::{PairingRecord, Role};
pub use resume::{Resume, ResumeAccept, ResumeError, ResumeOffer, ResumePending};
pub use sas::Sas;
pub use seal::{SealError};
pub use terminals::{MemStore, PairedTerminals, RecordStore, TerminalId, TerminalInfo, TerminalsError};
pub use transport::{Transport, TransportError};

/// Pairing/channel protocol version. Bound into every KDF transcript and the
/// QR payload; bump on ANY change to the wire, the QR encoding, or the KDF
/// labels so a v1 peer can never silently interoperate with a v2 one.
pub const PROTOCOL_VERSION: u8 = 1;
