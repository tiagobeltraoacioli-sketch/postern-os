// SPDX-License-Identifier: MIT OR Apache-2.0
//! # Postern Pairing — REAL LAN transport (scaffold)
//!
//! ## ⚠️ SCAFFOLD — not a secure, audited, or deployed system
//!
//! This crate gives [`postern_pairing`]'s two network seams a **real LAN
//! implementation**, replacing the in-memory stubs (`LoopbackPair` /
//! `NullDiscovery`) for actual mobile↔desktop use on the same subnet:
//!
//! - [`TcpTransport`] / [`TcpTransportListener`] — a length-prefixed TCP
//!   [`Transport`](postern_pairing::transport::Transport). Message boundaries,
//!   a bounded frame size, timeouts, and a clean close, over a plain LAN socket.
//! - [`MdnsDiscovery`] — an mDNS / DNS-SD
//!   [`Discovery`](postern_pairing::transport::Discovery) advertising and
//!   browsing `_postern-pair._tcp.local` on the link-local group.
//!
//! ## The one thing to remember: this is a DUMB PIPE
//!
//! Every byte this crate moves is **already sealed** by `postern-pairing`. The
//! PQ-hybrid KEM, the mandatory QR-pin + 6-digit SAS, the XChaCha20-Poly1305
//! channel with anti-replay — **all of it lives in the pairing crate.** This
//! layer authenticates nothing, decrypts nothing, and interprets nothing. It
//! finds a socket and shuttles opaque frames.
//!
//! ## Binding rails (carry these wherever this crate's concepts appear)
//!
//! - **LAN-ONLY.** Multicast is the reserved link-local group
//!   `224.0.0.251:5353`; TCP dials only the address discovery handed it. **No
//!   cloud, no relay, no Tor, no internet path, no telemetry, no phone-home.**
//! - **Discovery is a metadata leak, opt-in, off by default.** Advertising tells
//!   the subnet a Postern endpoint is present. `postern-pairing` ships
//!   `NullDiscovery` as the default for exactly this reason; turn mDNS on
//!   deliberately. The advertisement is minimal — a version and an opaque,
//!   rotating instance tag. **No wallet address, no identity, no account.**
//! - **Discovery ≠ authentication.** A browsed peer is an untrusted dial hint;
//!   an evil twin can advertise too. Only the QR-pin + SAS ceremony authenticates
//!   the peer. This layer just points the ceremony at a socket.
//! - **Scaffold, unaudited** — nothing here is built, secure, attested, or
//!   deployed. Internal review is not an audit.
//! - **A rooted/malware endpoint (A5) defeats the whole feature.** Ring-0 on
//!   either device reads the session key from RAM and forges the approval UI. A
//!   byte pipe cannot defend that; nor can it. Every consequential action still
//!   needs on-device WYSIWYS approval upstream.
//! - **The coin (BLCH) is not a security** and is not involved. Personal use is
//!   free forever — no token, no login; the pairing is the local account. The
//!   community mobile edition is **"Postern for postmarketOS — community
//!   edition"**, never "Postern OS"; the assurance name is never "BABA YAGA".
//!
//! ## Offline / `LoopbackPair`-compatible test path
//!
//! Both new types implement the *same* traits as the stubs, so anything written
//! against `postern-pairing`'s `Transport`/`Discovery` runs unchanged on either.
//! The crate builds and tests offline: the socket path is exercised over
//! `127.0.0.1` (see [`demo::pair_over_tcp`] and the `tests/` suite), the loopback
//! path via `postern_pairing::demo::pair_and_talk`, and the mDNS wire codec by
//! deterministic unit tests. The live-multicast path is an `#[ignore]`d test you
//! run on a real LAN (multicast is typically unavailable in a sandbox).

#![forbid(unsafe_code)]

pub mod dns;
pub mod mdns;
pub mod tcp;

pub mod demo;

pub use mdns::MdnsDiscovery;
pub use tcp::{TcpTransport, TcpTransportListener, DEFAULT_MAX_FRAME_LEN};

// Re-export the seam types so downstream code has one import surface.
pub use postern_pairing::transport::{
    Discovery, LoopbackPair, LoopbackTransport, NullDiscovery, PeerHint, Transport, TransportError,
};
